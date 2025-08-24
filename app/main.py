import hashlib
import json
from pathlib import Path
from typing import Dict, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
)
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings


# =========================
# Settings
# =========================
class Settings(BaseSettings):
    # セッション/署名
    SECRET_KEY: str = "change-me"
    SESSION_TTL_SECONDS: int = 7200

    # nonstress CAPTCHA
    CAPTCHA_JS_URL: str = "https://hamutan86.pythonanywhere.com/nonstress/nonstress.js"
    CAPTCHA_VALIDATE_URL: str = "https://hamutan86.pythonanywhere.com/nonstress/validate"

    # 許容リスクレベル: clean,low,medium,high （カンマ区切り）
    ALLOWED_RISK_LEVELS: str = "clean,low"

    # 管理API Basic認証
    ADMIN_USER: str = "admin"
    ADMIN_PASS: str = "changeme"

    # Caddy の on-demand TLS 用 ask の共有トークン（使わなければ空でOK）
    CADDY_ASK_SHARED_TOKEN: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
ALLOWED_RISKS = {r.strip().lower() for r in settings.ALLOWED_RISK_LEVELS.split(",") if r.strip()}

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path("/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPSTREAMS_PATH = DATA_DIR / "upstreams.json"

# =========================
# Templates
# =========================
env = Environment(
    loader=FileSystemLoader(str(BASE_DIR / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
)

# =========================
# Auth (Basic)
# =========================
security = HTTPBasic()


def require_admin(credentials: HTTPBasicCredentials = Depends(security)) -> bool:
    if credentials.username != settings.ADMIN_USER or credentials.password != settings.ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True


# =========================
# Upstreams Store
# =========================
class Upstream(BaseModel):
    host: str
    upstream: AnyHttpUrl

    @field_validator("host")
    @classmethod
    def normalize_host(cls, v: str) -> str:
        v = v.strip().lower()
        # Host ヘッダ一致のため、ポートは消す
        if ":" in v:
            v = v.split(":", 1)[0]
        return v


class UpstreamStore:
    def __init__(self, path: Path):
        self.path = path
        self._data: Dict[str, str] = {}
        self.load()

    def load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text("utf-8"))
            except Exception:
                self._data = {}
        else:
            self._data = {}

    def save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), "utf-8")

    def set(self, host: str, upstream: str) -> None:
        self._data[host.lower()] = upstream
        self.save()

    def delete(self, host: str) -> bool:
        host = host.lower()
        existed = host in self._data
        if existed:
            self._data.pop(host, None)
            self.save()
        return existed

    def get(self, host: str) -> Optional[str]:
        return self._data.get(host.lower())

    def all(self) -> Dict[str, str]:
        return dict(self._data)


store = UpstreamStore(UPSTREAMS_PATH)

# =========================
# Session Helpers
# =========================
serializer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="ns-session")


def client_ip_from_request(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if req.client and req.client.host:
        return req.client.host
    return "0.0.0.0"


def ip_sha256(ip: str) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()


def make_session_token(host: str, ip_hash: str, risk: str) -> str:
    payload = {"host": host, "ip_hash": ip_hash, "risk": risk}
    return serializer.dumps(payload)


def load_session_token(token: str) -> dict:
    return serializer.loads(token, max_age=settings.SESSION_TTL_SECONDS)


# =========================
# App
# =========================
app = FastAPI(title="nonstress-gate-proxy")


# -------------------------
# Admin API
# -------------------------
class UpsertBody(BaseModel):
    host: str
    upstream: AnyHttpUrl


@app.get("/_proxy_admin/upstreams", dependencies=[Depends(require_admin)])
def list_upstreams():
    return store.all()


@app.post("/_proxy_admin/upstreams", dependencies=[Depends(require_admin)])
def upsert_upstream(body: UpsertBody):
    store.set(body.host, str(body.upstream))
    return {"ok": True, "data": store.all()}


@app.delete("/_proxy_admin/upstreams/{host}", dependencies=[Depends(require_admin)])
def delete_upstream(host: str):
    deleted = store.delete(host)
    return {"ok": True, "deleted": bool(deleted), "data": store.all()}


# -------------------------
# Caddy on-demand TLS ask
# -------------------------
from fastapi import Query
from fastapi.responses import Response


@app.get("/_caddy/ask")
def caddy_on_demand_ask(
    domain: str = Query(..., description="SNI domain"),
    token: Optional[str] = Query(None, description="shared token"),
):
    if settings.CADDY_ASK_SHARED_TOKEN:
        if not token or token != settings.CADDY_ASK_SHARED_TOKEN:
            return PlainTextResponse("forbidden", status_code=status.HTTP_403_FORBIDDEN)

    domain = (domain or "").strip().lower()
    if not domain:
        return PlainTextResponse("bad request", status_code=status.HTTP_400_BAD_REQUEST)

    if store.get(domain):
        return PlainTextResponse("ok", status_code=status.HTTP_200_OK)
    else:
        return PlainTextResponse("forbidden", status_code=status.HTTP_403_FORBIDDEN)


# -------------------------
# Challenge Page
# -------------------------
@app.get("/_challenge", response_class=HTMLResponse)
def challenge_page(request: Request, host: Optional[str] = None, next: Optional[str] = "/"):
    tpl = env.get_template("challenge.html")
    html = tpl.render(
        captcha_js_url=settings.CAPTCHA_JS_URL,
    )
    return HTMLResponse(html)


# -------------------------
# Verify token from client
# -------------------------
class VerifyBody(BaseModel):
    token: str
    host: Optional[str] = None
    next: Optional[str] = "/"


@app.post("/_verify")
async def verify_token(request: Request, body: VerifyBody):
    # host 判定
    host = (body.host or request.headers.get("host") or "").lower()
    if not host or not store.get(host):
        return JSONResponse({"ok": False, "error": "unknown host"}, status_code=400)

    # CAPTCHA 検証
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(settings.CAPTCHA_VALIDATE_URL, json={"token": body.token})
    except httpx.RequestError as e:
        return JSONResponse({"ok": False, "error": f"captcha upstream error: {e}"}, status_code=502)

    if r.status_code != 200:
        return JSONResponse({"ok": False, "error": f"captcha upstream {r.status_code}"}, status_code=502)

    data = r.json()
    if not bool(data.get("pass")):
        return JSONResponse({"ok": False, "error": data.get("error") or "captcha_not_passed"}, status_code=400)

    risk = (data.get("risk_rate") or "").strip().lower()
    if risk not in ALLOWED_RISKS:
        return JSONResponse({"ok": False, "error": f"risk_not_allowed({risk})"}, status_code=403)

    visitor = data.get("visitor_data") or {}
    captcha_ip_hash = visitor.get("ip") or ""
    client_ip = client_ip_from_request(request)
    if captcha_ip_hash and captcha_ip_hash != ip_sha256(client_ip):
        return JSONResponse({"ok": False, "error": "ip_mismatch"}, status_code=403)

    # セッションCookie発行（HTTPS前提）
    tok = make_session_token(host=host, ip_hash=ip_sha256(client_ip), risk=risk)
    resp = JSONResponse({"ok": True, "redirect_to": body.next or "/"})
    resp.set_cookie(
        "ns_session",
        tok,
        httponly=True,
        samesite="Lax",
        secure=True,
        path="/",
    )
    return resp


# -------------------------
# Nginx の auth_request 用
# -------------------------
@app.get("/_auth")
def auth_for_nginx(request: Request):
    """
    Nginx の internal サブリクエスト用。
    - セッションOKなら 204 No Content + `X-Upstream: <url>` を返す
    - セッションNGなら 401 Unauthorized + `X-Redirect: /_challenge?...` を返す
    """
    host = (request.headers.get("host") or "").lower()
    upstream = store.get(host)
    if not upstream:
        # 未登録ホスト → 401 + チャレンジへ
        next_path = request.headers.get("x-original-uri") or "/"
        redir = f"/_challenge?host={host}&next={next_path}"
        return Response(status_code=401, headers={"X-Redirect": redir})

    cookie = request.cookies.get("ns_session")
    if not cookie:
        next_path = request.headers.get("x-original-uri") or "/"
        redir = f"/_challenge?host={host}&next={next_path}"
        return Response(status_code=401, headers={"X-Redirect": redir})

    try:
        payload = load_session_token(cookie)
        if payload.get("host") != host:
            raise BadSignature("host mismatch")
        if payload.get("ip_hash") != ip_sha256(client_ip_from_request(request)):
            raise BadSignature("ip mismatch")
    except (BadSignature, SignatureExpired):
        next_path = request.headers.get("x-original-uri") or "/"
        redir = f"/_challenge?host={host}&next={next_path}"
        return Response(status_code=401, headers={"X-Redirect": redir})

    # 認可OK → Nginx に上流URLを渡す
    return Response(status_code=204, headers={"X-Upstream": upstream})


# -------------------------
# Health
# -------------------------
@app.get("/_proxy_health")
def health():
    return {"ok": True}
