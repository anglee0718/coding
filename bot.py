import asyncio
import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, unquote, urlparse

from bs4 import BeautifulSoup
import discord
from discord.ext import commands
from dotenv import load_dotenv
import requests

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)

TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
CONFIG_PATH = BASE_DIR / "users_config.json"
HISTORY_PATH = BASE_DIR / "web" / "history.json"
MAX_HISTORY_ITEMS = 200

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    )
}

KEY_SIGNAL_WORDS = (
    "핵심",
    "중요",
    "이유",
    "원인",
    "방법",
    "주의",
    "결론",
    "차이",
    "장점",
    "단점",
    "조건",
    "설정",
    "해결",
    "필요",
    "가능",
    "제한",
    "필수",
    "보안",
    "오류",
    "영향",
    "key",
    "important",
    "reason",
    "cause",
    "method",
    "note",
    "warning",
    "result",
    "summary",
    "must",
    "should",
)


def sanitize_text(text: str) -> str:
    if not text:
        return ""
    cleaned = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP 비공개]", text)
    cleaned = re.sub(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b", "[IP 비공개]", cleaned)
    return " ".join(cleaned.split())


def make_summary(text: str, max_len: int = 1200) -> str:
    cleaned = sanitize_text(text)
    if len(cleaned) <= max_len:
        return cleaned
    # 단어/문장 경계 근처에서 자르되 잘림을 최소화
    cut = cleaned[:max_len]
    for sep in (". ", "! ", "? ", "다. ", "요. ", " "):
        idx = cut.rfind(sep)
        if idx >= int(max_len * 0.7):
            return cut[: idx + len(sep)].strip()
    return cut.strip()


def _split_sentences(text: str) -> list[str]:
    cleaned = sanitize_text(text)
    if not cleaned:
        return []
    parts = [
        s.strip()
        for s in re.split(r"(?<=[.!?다요])\s+", cleaned)
        if len(s.strip()) >= 10
    ]
    return parts if parts else [cleaned]


def _extract_issue_tokens(query: str) -> list[str]:
    tokens = []
    for tok in re.findall(r"[\w가-힣]+", (query or "").lower()):
        if len(tok) >= 2 and tok not in tokens:
            tokens.append(tok)
    return tokens


def _score_sentence(sentence: str, tokens: list[str], index: int, total: int, prefer_issue: bool = False) -> float:
    low = sentence.lower()
    score = 0.0

    matched_count = sum(1 for t in tokens if t in low)
    if tokens:
        score += matched_count * (4.5 if prefer_issue else 3.0)
        if matched_count >= 2:
            score += 2.0

    signal_hits = sum(1 for sig in KEY_SIGNAL_WORDS if sig in low)
    if signal_hits:
        score += signal_hits * (2.5 if prefer_issue else 1.2)

    if re.search(r"\d+(?:%|ms|초|분|시간|개|건|배|원|px|MB|GB)?", sentence):
        score += 1.0

    if index == 0:
        score += 1.5
    elif total > 2 and index == total - 1:
        score += 1.0

    if len(sentence) < 20:
        score -= 1.0
    elif len(sentence) > 360:
        score -= 0.8

    return score


def summarize_by_issue(text: str, query: str = "", max_len: int = 1200) -> str:
    cleaned = sanitize_text(text)
    if not cleaned:
        return ""
    if len(cleaned) <= max_len:
        return cleaned

    sentences = _split_sentences(cleaned)
    tokens = _extract_issue_tokens(query)
    total = len(sentences)

    scored = [
        (idx, sent, _score_sentence(sent, tokens, idx, total, prefer_issue=False))
        for idx, sent in enumerate(sentences)
    ]

    top_indices = sorted(
        [idx for idx, _, _ in sorted(scored, key=lambda x: x[2], reverse=True)[:5]]
    )
    selected = [sentences[i] for i in top_indices if sentences[i]]
    combined = " ".join(selected) if selected else cleaned
    return make_summary(combined, max_len=max_len)


def extract_key_point(text: str, query: str = "", max_len: int = 450) -> str:
    cleaned = sanitize_text(text)
    if not cleaned:
        return f"'{sanitize_text(query)}' 관련 핵심 쟁점 확인 필요" if query else "핵심 요약 정보"

    sentences = _split_sentences(cleaned)
    tokens = _extract_issue_tokens(query)
    total = len(sentences)

    best_idx, best_sent, _ = max(
        (
            (idx, sent, _score_sentence(sent, tokens, idx, total, prefer_issue=True))
            for idx, sent in enumerate(sentences)
        ),
        key=lambda x: x[2],
    )

    candidates = [best_sent]
    if best_idx + 1 < total:
        next_sent = sentences[best_idx + 1]
        if any(sig in next_sent.lower() for sig in KEY_SIGNAL_WORDS) or any(t in next_sent.lower() for t in tokens):
            candidates.append(next_sent)

    return make_summary(" ".join(candidates), max_len=max_len)


def is_safe_public_url(url: str) -> bool:
    try:
        parsed = urlparse((url or "").strip())
        if parsed.scheme not in ("http", "https"):
            return False
        host = (parsed.hostname or "").strip().lower()
        if not host or host in ("localhost", "ip6-localhost"):
            return False
        try:
            ip = ipaddress.ip_address(host)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return False
        except ValueError:
            if host.endswith(".local") or host.endswith(".internal"):
                return False
        return True
    except Exception:
        return False


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_linked_users() -> list[int]:
    cfg = load_json(CONFIG_PATH, {"linked_users": []})
    users = []
    for uid in cfg.get("linked_users", []):
        try:
            val = int(uid)
            if val > 0 and val not in users:
                users.append(val)
        except (TypeError, ValueError):
            continue
    return users


def add_linked_user(user_id: int) -> list[int]:
    uid = int(user_id)
    users = get_linked_users()
    if uid > 0 and uid not in users:
        users.append(uid)
        save_json(CONFIG_PATH, {"linked_users": users})
    return users


def remove_linked_user(user_id: int) -> list[int]:
    uid = int(user_id)
    users = [u for u in get_linked_users() if u != uid]
    save_json(CONFIG_PATH, {"linked_users": users})
    return users


def is_linked_user(user_id: int) -> bool:
    return int(user_id) in get_linked_users()


def normalize_link(href: str) -> str:
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        qs = parse_qs(parsed.query)
        if "uddg" in qs and qs["uddg"]:
            return unquote(qs["uddg"][0])
    return href


def extract_page_content(url: str, fallback: str, query: str = "") -> tuple[str, str]:
    content_source = fallback
    if is_safe_public_url(url):
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
            if is_safe_public_url(resp.url):
                resp.raise_for_status()
                resp.encoding = resp.apparent_encoding or "utf-8"
                soup = BeautifulSoup(resp.text, "html.parser")

                meta_desc = soup.find("meta", attrs={"name": "description"})
                meta_text = meta_desc.get("content", "").strip() if meta_desc else ""

                paragraphs = [
                    p.get_text(" ", strip=True)
                    for p in soup.select("article p, main p, p")
                    if len(p.get_text(" ", strip=True)) >= 25
                ]
                tokens = _extract_issue_tokens(query)
                if tokens and len(paragraphs) > 4:
                    ranked_paras = sorted(
                        enumerate(paragraphs),
                        key=lambda pair: sum(1 for t in tokens if t in pair[1].lower()),
                        reverse=True,
                    )
                    chosen_indices = sorted(idx for idx, _ in ranked_paras[:4])
                    body_text = " ".join(paragraphs[i] for i in chosen_indices)
                else:
                    body_text = " ".join(paragraphs[:4]) if paragraphs else ""

                combined = " ".join([part for part in (meta_text, body_text) if part]).strip()
                if len(combined) >= 30:
                    content_source = combined
        except Exception:
            pass

    summary = summarize_by_issue(content_source, query=query, max_len=1200)
    key_point = extract_key_point(content_source, query=query, max_len=450)
    return summary, key_point


def search_via_ddgs(query: str, limit: int = 4) -> list[dict]:
    try:
        from ddgs import DDGS
    except ImportError:
        return []

    items = []
    try:
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=limit * 2):
                title = sanitize_text(r.get("title") or "")
                link = normalize_link((r.get("href") or "").strip())
                body = sanitize_text(r.get("body") or "")
                if not title or not is_safe_public_url(link):
                    continue
                summary, key_point = extract_page_content(link, body or title, query=query)
                items.append({
                    "title": title,
                    "summary": summary,
                    "key_point": key_point,
                    "link": link,
                })
                if len(items) >= limit:
                    break
    except Exception as e:
        if "No results found" not in str(e):
            print(f"[검색 보조 안내] {sanitize_text(str(e))}")
    return items


def search_via_ddg_html(query: str, limit: int = 4) -> list[dict]:
    url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        if "anomaly-modal" in resp.text or "bots use duckduckgo" in resp.text.lower():
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        items = []
        for row in soup.select(".result"):
            a_tag = row.select_one(".result__a")
            snip_tag = row.select_one(".result__snippet")
            if not a_tag:
                continue
            title = sanitize_text(a_tag.get_text(strip=True))
            link = normalize_link(a_tag.get("href", ""))
            if not title or not is_safe_public_url(link):
                continue
            snippet = snip_tag.get_text(strip=True) if snip_tag else title
            summary, key_point = extract_page_content(link, snippet, query=query)
            items.append({
                "title": title,
                "summary": summary,
                "key_point": key_point,
                "link": link,
            })
            if len(items) >= limit:
                break
        return items
    except Exception:
        return []


def search_via_wikipedia(query: str, limit: int = 4) -> list[dict]:
    items = []
    for lang in ("ko", "en"):
        api_url = f"https://{lang}.wikipedia.org/w/api.php"
        params = {
            "action": "query",
            "list": "search",
            "srsearch": query,
            "format": "json",
            "srlimit": limit,
        }
        try:
            resp = requests.get(api_url, params=params, headers=HEADERS, timeout=8)
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("query", {}).get("search", []):
                title = sanitize_text(entry.get("title") or "")
                if not title:
                    continue
                page_url = f"https://{lang}.wikipedia.org/wiki/{quote_plus(title.replace(' ', '_'))}"
                if not is_safe_public_url(page_url):
                    continue
                raw_snip = entry.get("snippet") or title
                clean_snip = BeautifulSoup(raw_snip, "html.parser").get_text(" ", strip=True)
                summary, key_point = extract_page_content(page_url, clean_snip, query=query)
                items.append({
                    "title": f"[Wikipedia/{lang.upper()}] {title}",
                    "summary": summary,
                    "key_point": key_point,
                    "link": page_url,
                })
                if len(items) >= limit:
                    return items
        except Exception:
            continue
    return items


def search_and_crawl(query: str, limit: int = 4) -> list[dict]:
    safe_query = sanitize_text(query)
    if not safe_query:
        return []

    for fn in (search_via_ddgs, search_via_ddg_html, search_via_wikipedia):
        found = fn(safe_query, limit=limit)
        if found:
            return found
    return []


def _build_entry_id(time_str: str, user_id: str, query: str) -> str:
    raw = f"{time_str}|{user_id}|{query}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12]


def record_history(user_id: str, user_name: str, query: str, results: list[dict]) -> dict:
    history = load_json(HISTORY_PATH, [])
    if not isinstance(history, list):
        history = []

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_uid = sanitize_text(str(user_id))
    safe_q = sanitize_text(query)

    clean_results = []
    seen_links = set()
    for r in results:
        link = (r.get("link") or "").strip()
        if not is_safe_public_url(link) or link in seen_links:
            continue
        seen_links.add(link)
        summary = summarize_by_issue(r.get("summary", ""), query=safe_q, max_len=1200)
        key_point = make_summary(
            r.get("key_point") or extract_key_point(summary, query=safe_q),
            max_len=450,
        )
        clean_results.append({
            "title": sanitize_text(r.get("title", "")),
            "summary": summary,
            "key_point": key_point,
            "link": link,
        })

    entry = {
        "id": _build_entry_id(now_str, safe_uid, safe_q),
        "time": now_str,
        "user_id": safe_uid,
        "user_name": sanitize_text(str(user_name)),
        "query": safe_q,
        "results": clean_results,
    }
    history.insert(0, entry)
    save_json(HISTORY_PATH, history[:MAX_HISTORY_ITEMS])
    return entry


def delete_history_entry(entry_id: str) -> list[dict]:
    history = load_json(HISTORY_PATH, [])
    if not isinstance(history, list):
        return []
    target = (entry_id or "").strip()
    updated = [
        item for item in history
        if (item.get("id") or _build_entry_id(
            str(item.get("time", "")),
            str(item.get("user_id", "")),
            str(item.get("query", "")),
        )) != target
    ]
    save_json(HISTORY_PATH, updated)
    return updated


def clean_history(clear_all: bool = False) -> tuple[list[dict], dict]:
    if clear_all:
        save_json(HISTORY_PATH, [])
        return [], {"removed_entries": "all", "remaining": 0}

    history = load_json(HISTORY_PATH, [])
    if not isinstance(history, list):
        history = []

    before_count = len(history)
    seen_keys = set()
    cleaned_list = []

    for item in history:
        q = sanitize_text(str(item.get("query", ""))).lower()
        uid = sanitize_text(str(item.get("user_id", "")))
        raw_res = item.get("results") or []

        dedup_res = []
        seen_links = set()
        for r in raw_res:
            link = (r.get("link") or "").strip()
            if not is_safe_public_url(link) or link in seen_links:
                continue
            seen_links.add(link)
            summary = summarize_by_issue(r.get("summary", ""), query=q, max_len=1200)
            key_point = make_summary(
                r.get("key_point") or extract_key_point(summary, query=q),
                max_len=450,
            )
            dedup_res.append({
                "title": sanitize_text(r.get("title", "")),
                "summary": summary,
                "key_point": key_point,
                "link": link,
            })

        if not q or not dedup_res:
            continue

        dedup_key = f"{uid}|{q}|{'|'.join(sorted(seen_links))}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        t_str = sanitize_text(str(item.get("time", "")))
        entry_id = item.get("id") or _build_entry_id(t_str, uid, q)
        cleaned_list.append({
            "id": entry_id,
            "time": t_str,
            "user_id": uid,
            "user_name": sanitize_text(str(item.get("user_name", ""))),
            "query": sanitize_text(str(item.get("query", ""))),
            "results": dedup_res,
        })

    cleaned_list = cleaned_list[:MAX_HISTORY_ITEMS]
    save_json(HISTORY_PATH, cleaned_list)
    stats = {
        "removed_entries": max(0, before_count - len(cleaned_list)),
        "remaining": len(cleaned_list),
    }
    return cleaned_list, stats


def create_bot() -> commands.Bot:
    intents = discord.Intents.default()
    intents.message_content = True
    bot = commands.Bot(command_prefix="!", intents=intents)

    @bot.event
    async def on_ready():
        print(f"[Discord] 로그인 완료: {bot.user} (ID: {bot.user.id})")

    @bot.command(name="연동")
    async def link_user(ctx, target_id: int):
        if target_id <= 0:
            await ctx.send("올바른 디스코드 사용자 ID를 입력해 주세요.")
            return
        app_info = await bot.application_info()
        is_owner = app_info.owner is not None and ctx.author.id == app_info.owner.id
        is_admin = bool(ctx.guild and ctx.author.guild_permissions.administrator)
        if not (is_owner or is_admin):
            await ctx.send("연동 권한이 없습니다.")
            return

        users = add_linked_user(target_id)
        await ctx.send(f"디스코드 ID `{target_id}` 연동 완료! (현재 연동 인원: {len(users)}명)")

    @bot.command(name="연동해제")
    async def unlink_user(ctx, target_id: int):
        app_info = await bot.application_info()
        is_owner = app_info.owner is not None and ctx.author.id == app_info.owner.id
        is_admin = bool(ctx.guild and ctx.author.guild_permissions.administrator)
        if not (is_owner or is_admin):
            await ctx.send("연동 해제 권한이 없습니다.")
            return

        users = remove_linked_user(target_id)
        await ctx.send(f"디스코드 ID `{target_id}` 연동 해제 완료! (현재 연동 인원: {len(users)}명)")

    @bot.command(name="자료")
    async def fetch_info(ctx, *, query: str):
        if not is_linked_user(ctx.author.id):
            await ctx.send("연동되지 않은 디스코드 ID입니다. 웹이나 관리자에게 연동을 요청해 주세요.")
            return

        safe_q = sanitize_text(query)
        status_msg = await ctx.send(f"`{safe_q}` 관련 사이트를 찾아 쟁점별로 요약 중입니다...")

        try:
            items = await asyncio.to_thread(search_and_crawl, safe_q, 4)
        except Exception as e:
            await status_msg.edit(content=f"검색/크롤링 오류: `{sanitize_text(str(e))}`")
            return

        if not items:
            await status_msg.edit(content="관련 사이트를 찾지 못했습니다. 다른 키워드로 시도해 보세요.")
            return

        embed = discord.Embed(
            title=f"자료 검색 결과: {safe_q}",
            description=f"요청자: {ctx.author.mention}",
            color=discord.Color.blurple(),
        )
        for idx, item in enumerate(items, start=1):
            content_part = make_summary(item["summary"], max_len=520)
            important_part = make_summary(item["key_point"], max_len=240)
            field_val = (
                f"**내용:** {content_part}\n"
                f"**중요한것:** {important_part}\n"
                f"**링크:** {item['link']}"
            )[:1020]
            embed.add_field(
                name=f"{idx}. 제목: {make_summary(item['title'], max_len=220)}",
                value=field_val,
                inline=False,
            )

        await status_msg.edit(content="", embed=embed)
        record_history(str(ctx.author.id), str(ctx.author), safe_q, items)

    return bot


if __name__ == "__main__":
    if not TOKEN:
        raise ValueError(".env 파일에 DISCORD_TOKEN을 입력해 주세요.")
    create_bot().run(TOKEN)