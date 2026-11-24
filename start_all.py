import datetime
import ipaddress
import ssl
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import uvicorn

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / "cert"
CERT_FILE = CERT_DIR / "cert.pem"
KEY_FILE = CERT_DIR / "key.pem"

BIND_HOST = "0.0.0.0"
PORT = 8443
URL_LOCAL_HTTPS = f"https://localhost:{PORT}"
URL_CHECK = f"https://127.0.0.1:{PORT}"


def _is_valid_pem_pair(cert_path: Path, key_path: Path) -> bool:
    if not cert_path.exists() or not key_path.exists():
        return False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        return True
    except Exception:
        return False


def ensure_self_signed_cert():
    if _is_valid_pem_pair(CERT_FILE, KEY_FILE):
        return

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    KEY_FILE.write_bytes(key_pem)
    CERT_FILE.write_bytes(cert_pem)


def run_https_server():
    uvicorn.run(
        "app_server:app",
        host=BIND_HOST,
        port=PORT,
        ssl_keyfile=str(KEY_FILE),
        ssl_certfile=str(CERT_FILE),
        log_level="warning",
        access_log=False,
    )


def wait_server_https(timeout: float = 12.0) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(URL_CHECK, timeout=1.5, context=ctx):
                return True
        except Exception:
            time.sleep(0.25)
    return False


if __name__ == "__main__":
    ensure_self_signed_cert()

    print("=" * 56)
    print("HTTPS 웹앱 & 디스코드 허브 시작")
    print(f"- PC 웹앱 주소: {URL_LOCAL_HTTPS}")
    print(f"- 동일 Wi-Fi 핸드폰: https://<컴퓨터_내부주소>:{PORT}")
    print("- 종료하려면 터미널에서 Ctrl+C를 누르세요.")
    print("=" * 56)

    server_thread = threading.Thread(target=run_https_server, daemon=True)
    server_thread.start()

    if wait_server_https():
        webbrowser.open(URL_LOCAL_HTTPS)
    else:
        print("서버 준비가 늦어지고 있습니다. 잠시 후 브라우저에서 직접 열어 주세요.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n종료합니다.")