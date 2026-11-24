import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator

from bot import (
    HISTORY_PATH,
    TOKEN,
    add_linked_user,
    clean_history,
    create_bot,
    delete_history_entry,
    get_linked_users,
    load_json,
    record_history,
    remove_linked_user,
    sanitize_text,
    search_and_crawl,
)

BASE_DIR = Path(__file__).resolve().parent
WEB_INDEX = BASE_DIR / "web" / "index.html"


class SearchRequest(BaseModel):
    query: str
    user_id: str = "web-https"
    user_name: str = "Web UI"
    limit: int = 4


class UserIdRequest(BaseModel):
    user_id: int

    @field_validator("user_id", mode="before")
    @classmethod
    def validate_discord_id(cls, v):
        raw = str(v).strip()
        if not raw.isdigit():
            raise ValueError("디스코드 사용자 ID는 숫자만 입력해야 합니다.")
        num = int(raw)
        if num <= 0:
            raise ValueError("올바른 디스코드 사용자 ID를 입력해 주세요.")
        return num


class CleanRequest(BaseModel):
    clear_all: bool = False


def _install_connection_reset_filter(loop: asyncio.AbstractEventLoop):
    previous_handler = loop.get_exception_handler()

    def handler(current_loop: asyncio.AbstractEventLoop, context: dict):
        exc = context.get("exception")
        if isinstance(exc, ConnectionResetError) or getattr(exc, "winerror", None) == 10054:
            return
        if previous_handler:
            previous_handler(current_loop, context)
        else:
            current_loop.default_exception_handler(context)

    loop.set_exception_handler(handler)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _install_connection_reset_filter(asyncio.get_running_loop())

    bot_task = None
    if TOKEN:
        discord_bot = create_bot()
        bot_task = asyncio.create_task(discord_bot.start(TOKEN))
    try:
        yield
    finally:
        if bot_task:
            bot_task.cancel()
            try:
                await bot_task
            except asyncio.CancelledError:
                pass


app = FastAPI(title="HTTPS Crawler & Discord Hub", lifespan=lifespan)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    return response


@app.get("/")
def home():
    return FileResponse(WEB_INDEX)


@app.get("/api/status")
def status():
    return {
        "https": True,
        "discord_enabled": bool(TOKEN),
        "linked_count": len(get_linked_users()),
    }


@app.get("/api/history")
def get_history():
    history, _ = clean_history(clear_all=False)
    return history


@app.delete("/api/history/{entry_id}")
def remove_history(entry_id: str):
    if not entry_id or len(entry_id) > 64:
        raise HTTPException(status_code=400, detail="잘못된 기록 ID입니다.")
    updated = delete_history_entry(entry_id)
    return {"history": updated}


@app.post("/api/history/clean")
def organize_history(req: CleanRequest):
    updated, stats = clean_history(clear_all=bool(req.clear_all))
    return {"history": updated, "stats": stats}


@app.get("/api/users")
def get_users():
    return {"linked_users": [str(u) for u in get_linked_users()]}


@app.post("/api/users")
def register_user(req: UserIdRequest):
    before = get_linked_users()
    already_linked = req.user_id in before
    users = add_linked_user(req.user_id)
    return {
        "linked_users": [str(u) for u in users],
        "already_linked": already_linked,
        "added_user_id": str(req.user_id),
    }


@app.delete("/api/users/{user_id}")
def unregister_user(user_id: int):
    if user_id <= 0:
        raise HTTPException(status_code=400, detail="올바른 디스코드 사용자 ID를 입력해 주세요.")
    users = remove_linked_user(user_id)
    return {"linked_users": [str(u) for u in users]}


@app.post("/api/search")
async def run_search(req: SearchRequest):
    safe_query = sanitize_text(req.query)
    if not safe_query or len(safe_query) > 120:
        raise HTTPException(status_code=400, detail="검색어를 1~120자 이내로 입력해 주세요.")

    limit = max(1, min(int(req.limit), 6))
    try:
        results = await asyncio.to_thread(search_and_crawl, safe_query, limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"크롤링 실패: {sanitize_text(str(e))}")

    entry = record_history(req.user_id, req.user_name, safe_query, results)
    return {"entry": entry, "history": load_json(HISTORY_PATH, [])}
