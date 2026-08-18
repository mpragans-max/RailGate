"""RailGate admin application.

Serves, on Railway's ``$PORT``:

* ``/``, ``/dashboard``, ``/users`` ...  the admin web panel
* ``/api/*``                            the authenticated JSON API
* ``/health``                           unauthenticated, minimal health probe
* ``<random path>``                     the VLESS-over-WebSocket fallback

The WebSocket fallback terminates the WS framing and pipes the raw stream to a
loopback-only VLESS inbound, which is exactly what Xray's own ``ws`` transport
does — so standard clients work unmodified.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, WebSocket
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.websockets import WebSocketDisconnect, WebSocketState

from app import APP_VERSION
from app.auth import AuthService, SessionRecord, client_key_from_request
from app.backup import list_backups
from app.config import get_settings
from app.credential_generator import CredentialError
from app.credentials import build_credentials, client_config_json, qr_svg
from app.database import database_status, init_db
from app.expiry import expiry_loop
from app.logstore import CATEGORY_AUTH, CATEGORY_SYSTEM, log_event, recent_events, tail_file
from app.models import (
    UserError,
    get_user,
    list_users,
    user_stats,
)
from app.railway_info import (
    TCP_PROXY_SETUP_HINT,
    detect_railway,
    resolve_fallback_endpoint,
    resolve_public_endpoint,
)
from app.security import (
    CSRF_FIELD_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    SecurityHeadersMiddleware,
)
from app.service import (
    create_account,
    delete_account,
    find_account,
    regenerate_account_uuid,
    renew_account,
    resolve_expiry,
    set_account_enabled,
    set_account_notes,
    sync,
)
from app.system_info import (
    app_uptime_seconds,
    disk_usage,
    memory_usage,
    cpu_percent,
    outbound_ip,
    volume_writable,
)
from app.tools import TOOL_ACTIONS, run_tool
from app.util import format_bytes, format_uptime, to_iso
from app.xray_manager import (
    ensure_reality_keys,
    ensure_ws_path,
    load_reality_keys,
    port_open,
    xray_status,
    xray_version,
)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

logger = logging.getLogger("railgate")

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


class RedirectToLogin(Exception):
    """Raised by the HTML dependency when there is no valid session."""


@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db(settings.db_path)
    application.state.settings = settings
    application.state.auth = AuthService(settings)
    application.state.xray_version = xray_version(settings)

    try:
        application.state.reality_keys = ensure_reality_keys(settings)
    except Exception as exc:  # noqa: BLE001 - surfaced in the UI instead
        logger.error("REALITY keys unavailable: %s", exc)
        application.state.reality_keys = None

    try:
        application.state.ws_path = ensure_ws_path(settings)
    except Exception:  # noqa: BLE001
        application.state.ws_path = ""

    stop_event = asyncio.Event()
    application.state.stop_event = stop_event
    task = asyncio.create_task(expiry_loop(settings, stop_event))

    log_event(
        settings.db_path,
        "info",
        CATEGORY_SYSTEM,
        f"Admin application started on port {settings.port} (v{APP_VERSION}).",
    )
    try:
        yield
    finally:
        stop_event.set()
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        log_event(settings.db_path, "info", CATEGORY_SYSTEM, "Admin application stopped.")


app = FastAPI(
    title=settings.app_name,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(SecurityHeadersMiddleware, production=settings.is_production)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --------------------------------------------------------------------------- #
# authentication plumbing
# --------------------------------------------------------------------------- #
def get_auth(request: Request) -> AuthService:
    return request.app.state.auth


def _session_from_request(request: Request) -> SessionRecord | None:
    return get_auth(request).get_session(request.cookies.get(SESSION_COOKIE_NAME))


def web_session(request: Request) -> SessionRecord:
    session = _session_from_request(request)
    if session is None:
        raise RedirectToLogin()
    return session


def api_session(request: Request) -> SessionRecord:
    session = _session_from_request(request)
    if session is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        supplied = request.headers.get(CSRF_HEADER_NAME, "")
        if not AuthService.verify_csrf(session, supplied):
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid.")
    return session


@app.exception_handler(RedirectToLogin)
async def _handle_redirect_to_login(request: Request, exc: RedirectToLogin) -> Response:
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(UserError)
async def _handle_user_error(request: Request, exc: UserError) -> Response:
    if request.url.path.startswith("/api/"):
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    return RedirectResponse(f"/users?error={_quote(str(exc))}", status_code=303)


@app.exception_handler(CredentialError)
async def _handle_credential_error(request: Request, exc: CredentialError) -> Response:
    return JSONResponse({"ok": False, "error": str(exc)}, status_code=409)


def _quote(text: str) -> str:
    from urllib.parse import quote

    return quote(text, safe="")


# --------------------------------------------------------------------------- #
# shared template context
# --------------------------------------------------------------------------- #
def render(
    request: Request,
    template_name: str,
    session: SessionRecord | None = None,
    status_code: int = 200,
    **context,
) -> HTMLResponse:
    base = {
        "request": request,
        "settings": settings,
        "app_version": APP_VERSION,
        "session": session,
        "csrf_token": session.csrf_token if session else "",
        "csrf_field": CSRF_FIELD_NAME,
        "notice": request.query_params.get("ok", ""),
        "error": request.query_params.get("error", ""),
        "active_page": context.pop("active_page", ""),
    }
    base.update(context)
    return templates.TemplateResponse(template_name, base, status_code=status_code)


def _server_context() -> dict[str, object]:
    railway = detect_railway()
    endpoint = resolve_public_endpoint(settings, railway)
    fallback = resolve_fallback_endpoint(settings, railway)
    status = xray_status(settings)
    keys = load_reality_keys(settings)
    writable, write_error = volume_writable(settings.data_dir)
    return {
        "railway": railway,
        "endpoint": endpoint,
        "fallback": fallback,
        "xray": status,
        "keys_present": keys is not None,
        "reality_public_key": keys.public_key if keys else "",
        "reality_short_id": keys.short_id if keys else "",
        "ws_path": app.state.ws_path if hasattr(app.state, "ws_path") else "",
        "tcp_hint": TCP_PROXY_SETUP_HINT.format(port=settings.xray_port),
        "volume_writable": writable,
        "volume_error": write_error,
        "database": database_status(settings.db_path),
        "uptime": format_uptime(app_uptime_seconds()),
    }


# --------------------------------------------------------------------------- #
# health
# --------------------------------------------------------------------------- #
@app.get("/health", include_in_schema=False)
def health() -> JSONResponse:
    """Unauthenticated liveness probe. Deliberately reveals nothing sensitive."""
    db = database_status(settings.db_path)
    xray_running = port_open("127.0.0.1", settings.xray_port, timeout=1.0)
    healthy = bool(db["ok"]) and xray_running
    payload = {
        "status": "ok" if healthy else "degraded",
        "xray": "running" if xray_running else "stopped",
        "database": "ok" if db["ok"] else "error",
    }
    return JSONResponse(payload, status_code=200 if healthy else 503)


# --------------------------------------------------------------------------- #
# authentication routes
# --------------------------------------------------------------------------- #
@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request) -> Response:
    if _session_from_request(request) is not None:
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "login.html", error=request.query_params.get("error", ""))


@app.post("/login", include_in_schema=False)
def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
) -> Response:
    auth = get_auth(request)
    key = client_key_from_request(request)
    result = auth.authenticate(username, password, key)
    if not result.ok:
        log_event(settings.db_path, "warning", CATEGORY_AUTH, f"Failed login attempt from {key}.")
        return RedirectResponse(f"/login?error={_quote(result.error)}", status_code=303)

    token, _csrf = auth.create_session(
        settings.admin_username, ip=key, user_agent=request.headers.get("user-agent", "")
    )
    log_event(settings.db_path, "info", CATEGORY_AUTH, f"Administrator signed in from {key}.")
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=settings.admin_session_ttl_hours * 3600,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        path="/",
    )
    return response


@app.post("/logout", include_in_schema=False)
def logout(request: Request, csrf_token: str = Form("")) -> Response:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    session = get_auth(request).get_session(token)
    if session is not None and not AuthService.verify_csrf(session, csrf_token):
        return RedirectResponse("/dashboard?error=Invalid+CSRF+token", status_code=303)
    get_auth(request).destroy_session(token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


# --------------------------------------------------------------------------- #
# web pages
# --------------------------------------------------------------------------- #
@app.get("/", include_in_schema=False)
def index() -> Response:
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request, session: SessionRecord = Depends(web_session)) -> Response:
    context = _server_context()
    memory = memory_usage()
    disk = disk_usage(settings.data_dir)
    return render(
        request,
        "dashboard.html",
        session=session,
        active_page="dashboard",
        stats=user_stats(settings.db_path),
        system={
            "cpu_percent": cpu_percent(),
            "memory": memory,
            "memory_display": f"{format_bytes(memory['used_bytes'])} / {format_bytes(memory['total_bytes'])}",
            "disk": disk,
            "disk_display": f"{format_bytes(disk['used_bytes'])} / {format_bytes(disk['total_bytes'])}",
        },
        events=recent_events(settings.db_path, limit=8),
        xray_version=request.app.state.xray_version,
        **context,
    )


@app.get("/users", response_class=HTMLResponse, include_in_schema=False)
def users_page(request: Request, session: SessionRecord = Depends(web_session)) -> Response:
    return render(
        request,
        "users.html",
        session=session,
        active_page="users",
        users=list_users(settings.db_path),
        stats=user_stats(settings.db_path),
    )


@app.get("/users/new", response_class=HTMLResponse, include_in_schema=False)
def users_new_page(request: Request, session: SessionRecord = Depends(web_session)) -> Response:
    return render(
        request,
        "user_new.html",
        session=session,
        active_page="users",
        default_days=settings.vpn_default_expiry_days,
    )


@app.post("/users/new", include_in_schema=False)
def users_create(
    request: Request,
    session: SessionRecord = Depends(web_session),
    username: str = Form(""),
    expiry_choice: str = Form("never"),
    custom_date: str = Form(""),
    notes: str = Form(""),
    csrf_token: str = Form(""),
) -> Response:
    if not AuthService.verify_csrf(session, csrf_token):
        return RedirectResponse("/users/new?error=Invalid+CSRF+token", status_code=303)

    try:
        if expiry_choice == "custom":
            expires_at = resolve_expiry(expire=custom_date)
        elif expiry_choice == "never":
            expires_at = None
        else:
            expires_at = resolve_expiry(days=int(expiry_choice))
    except (ValueError, UserError) as exc:
        return RedirectResponse(f"/users/new?error={_quote(str(exc))}", status_code=303)

    try:
        result = create_account(settings, username, expires_at=expires_at, notes=notes)
    except UserError as exc:
        return RedirectResponse(f"/users/new?error={_quote(str(exc))}", status_code=303)

    assert result.user is not None
    suffix = "" if result.ok else f"&error={_quote(result.message)}"
    return RedirectResponse(f"/users/{result.user.id}?ok=Account+created{suffix}", status_code=303)


@app.get("/users/{user_id}", response_class=HTMLResponse, include_in_schema=False)
def user_detail(
    request: Request, user_id: int, session: SessionRecord = Depends(web_session)
) -> Response:
    user = get_user(settings.db_path, user_id)
    if user is None:
        return RedirectResponse("/users?error=Account+not+found", status_code=303)
    bundle = build_credentials(settings, user)
    return render(
        request,
        "user_detail.html",
        session=session,
        active_page="users",
        user=user,
        bundle=bundle,
        tcp_hint=TCP_PROXY_SETUP_HINT.format(port=settings.xray_port),
    )


@app.get("/server", response_class=HTMLResponse, include_in_schema=False)
def server_page(request: Request, session: SessionRecord = Depends(web_session)) -> Response:
    context = _server_context()
    return render(
        request,
        "server.html",
        session=session,
        active_page="server",
        xray_version=request.app.state.xray_version,
        outbound=outbound_ip(settings),
        **context,
    )


@app.get("/tools", response_class=HTMLResponse, include_in_schema=False)
def tools_page(request: Request, session: SessionRecord = Depends(web_session)) -> Response:
    return render(
        request,
        "tools.html",
        session=session,
        active_page="tools",
        actions=[(key, label) for key, (label, _) in TOOL_ACTIONS.items()],
        backups=list_backups(settings),
    )


@app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
def settings_page(request: Request, session: SessionRecord = Depends(web_session)) -> Response:
    context = _server_context()
    return render(
        request,
        "settings.html",
        session=session,
        active_page="settings",
        **context,
    )


@app.get("/logs", response_class=HTMLResponse, include_in_schema=False)
def logs_page(request: Request, session: SessionRecord = Depends(web_session)) -> Response:
    return render(
        request,
        "logs.html",
        session=session,
        active_page="logs",
        events=recent_events(settings.db_path, limit=200),
        xray_log=tail_file(settings.xray_log_path, 120),
    )


# --------------------------------------------------------------------------- #
# JSON API
# --------------------------------------------------------------------------- #
@app.get("/api/server")
def api_server(session: SessionRecord = Depends(api_session)) -> dict:
    context = _server_context()
    railway = context["railway"]
    endpoint = context["endpoint"]
    fallback = context["fallback"]
    return {
        "ok": True,
        "app": {
            "name": settings.app_name,
            "version": APP_VERSION,
            "environment": settings.app_env,
            "uptime_seconds": app_uptime_seconds(),
        },
        "railway": railway.as_dict(),  # type: ignore[union-attr]
        "vpn": {
            "internal_port": settings.xray_port,
            "public_host": endpoint.host,  # type: ignore[union-attr]
            "public_port": endpoint.port,  # type: ignore[union-attr]
            "configured": endpoint.available,  # type: ignore[union-attr]
            "reason": endpoint.reason,  # type: ignore[union-attr]
            "host_source": endpoint.host_source,  # type: ignore[union-attr]
            "port_source": endpoint.port_source,  # type: ignore[union-attr]
        },
        "fallback": {
            "enabled": settings.enable_ws_fallback,
            "available": fallback.available,  # type: ignore[union-attr]
            "host": fallback.host,  # type: ignore[union-attr]
            "port": fallback.port,  # type: ignore[union-attr]
            "path": context["ws_path"],
            "reason": fallback.reason,  # type: ignore[union-attr]
        },
        "reality": {
            "server_name": settings.reality_server_name,
            "destination": settings.reality_destination,
            "fingerprint": settings.reality_fingerprint,
            "public_key": context["reality_public_key"],
            "short_id": context["reality_short_id"],
        },
        "xray": context["xray"].as_dict(),  # type: ignore[union-attr]
        "database": context["database"],
        "users": user_stats(settings.db_path),
        "system": {
            "cpu_percent": cpu_percent(),
            "memory": memory_usage(),
            "disk": disk_usage(settings.data_dir),
        },
    }


@app.get("/api/users")
def api_list_users(session: SessionRecord = Depends(api_session)) -> dict:
    return {
        "ok": True,
        "users": [user.as_dict() for user in list_users(settings.db_path)],
        "stats": user_stats(settings.db_path),
    }


@app.post("/api/users", status_code=201)
async def api_create_user(request: Request, session: SessionRecord = Depends(api_session)) -> dict:
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON object.")
    expires_at = resolve_expiry(
        days=payload.get("days"),
        expire=payload.get("expire"),
        default_days=settings.vpn_default_expiry_days,
    )
    result = create_account(
        settings,
        str(payload.get("username", "")),
        expires_at=expires_at,
        notes=str(payload.get("notes", "")),
    )
    assert result.user is not None
    return {
        "ok": result.ok,
        "user": result.user.as_dict(),
        "credentials": build_credentials(settings, result.user).as_dict(),
        "apply": result.apply_result.as_dict(),
    }


def _require_user(user_id: int):
    user = get_user(settings.db_path, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail=f"No account with id {user_id} exists.")
    return user


@app.get("/api/users/{user_id}")
def api_get_user(user_id: int, session: SessionRecord = Depends(api_session)) -> dict:
    user = _require_user(user_id)
    return {
        "ok": True,
        "user": user.as_dict(),
        "credentials": build_credentials(settings, user).as_dict(),
    }


@app.delete("/api/users/{user_id}")
def api_delete_user(user_id: int, session: SessionRecord = Depends(api_session)) -> dict:
    _require_user(user_id)
    result = delete_account(settings, user_id)
    return {"ok": result.ok, "message": result.message, "apply": result.apply_result.as_dict()}


@app.post("/api/users/{user_id}/disable")
def api_disable_user(user_id: int, session: SessionRecord = Depends(api_session)) -> dict:
    result = set_account_enabled(settings, user_id, False)
    return {"ok": result.ok, "user": result.user.as_dict() if result.user else None,
            "message": result.message}


@app.post("/api/users/{user_id}/enable")
def api_enable_user(user_id: int, session: SessionRecord = Depends(api_session)) -> dict:
    result = set_account_enabled(settings, user_id, True)
    return {"ok": result.ok, "user": result.user.as_dict() if result.user else None,
            "message": result.message}


@app.post("/api/users/{user_id}/renew")
async def api_renew_user(
    user_id: int, request: Request, session: SessionRecord = Depends(api_session)
) -> dict:
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001 - empty body means "+30 days"
        payload = {}
    days = payload.get("days") if isinstance(payload, dict) else None
    expire = payload.get("expire") if isinstance(payload, dict) else None
    if days is None and not expire:
        days = 30
    result = renew_account(settings, user_id, days=days, expire=expire)
    return {"ok": result.ok, "user": result.user.as_dict() if result.user else None,
            "message": result.message}


@app.post("/api/users/{user_id}/regenerate")
def api_regenerate_user(user_id: int, session: SessionRecord = Depends(api_session)) -> dict:
    result = regenerate_account_uuid(settings, user_id)
    return {
        "ok": result.ok,
        "user": result.user.as_dict() if result.user else None,
        "credentials": build_credentials(settings, result.user).as_dict() if result.user else None,
        "message": result.message,
    }


@app.post("/api/users/{user_id}/notes")
async def api_update_notes(
    user_id: int, request: Request, session: SessionRecord = Depends(api_session)
) -> dict:
    payload = await request.json()
    result = set_account_notes(settings, user_id, str(payload.get("notes", "")))
    return {"ok": True, "user": result.user.as_dict() if result.user else None}


@app.get("/api/users/{user_id}/uri")
def api_user_uri(
    user_id: int, transport: str = "primary", session: SessionRecord = Depends(api_session)
) -> dict:
    user = _require_user(user_id)
    bundle = build_credentials(settings, user)
    link = bundle.fallback if transport == "fallback" else bundle.primary
    if not link.available:
        raise HTTPException(status_code=409, detail=link.reason)
    return {"ok": True, "uri": link.uri, "transport": transport, "fields": link.fields}


@app.get("/api/users/{user_id}/qr")
def api_user_qr(
    user_id: int, transport: str = "primary", session: SessionRecord = Depends(api_session)
) -> Response:
    user = _require_user(user_id)
    bundle = build_credentials(settings, user)
    link = bundle.fallback if transport == "fallback" else bundle.primary
    if not link.available:
        raise HTTPException(status_code=409, detail=link.reason)
    return Response(
        content=qr_svg(link.uri),
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/users/{user_id}/config")
def api_user_config(
    user_id: int, transport: str = "primary", session: SessionRecord = Depends(api_session)
) -> Response:
    user = _require_user(user_id)
    kind = "ws" if transport == "fallback" else "reality"
    content = client_config_json(settings, user, kind)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{user.username}-{kind}.json"',
            "Cache-Control": "no-store",
        },
    )


@app.get("/api/logs")
def api_logs(
    limit: int = 100,
    category: str = "",
    session: SessionRecord = Depends(api_session),
) -> dict:
    events = recent_events(settings.db_path, limit=limit, category=category)
    return {
        "ok": True,
        "events": [
            {"id": e["id"], "ts": e["ts"], "level": e["level"], "category": e["category"],
             "message": e["message"]}
            for e in events
        ],
    }


@app.post("/api/tools/{action}")
def api_tools(action: str, session: SessionRecord = Depends(api_session)) -> dict:
    if action not in TOOL_ACTIONS:
        raise HTTPException(status_code=404, detail=f"Unknown action {action!r}.")
    result = run_tool(settings, action)
    log_event(settings.db_path, "info", CATEGORY_SYSTEM, f"Admin tool '{action}' executed.")
    return {"ok": result.ok, **result.as_dict()}


@app.post("/api/resync")
def api_resync(session: SessionRecord = Depends(api_session)) -> dict:
    result = sync(settings, "manual resync from dashboard")
    return {"ok": result.ok, **result.as_dict()}


@app.delete("/api/sessions")
def api_revoke_sessions(request: Request, session: SessionRecord = Depends(api_session)) -> dict:
    removed = get_auth(request).destroy_all_sessions()
    log_event(settings.db_path, "warning", CATEGORY_AUTH, f"All {removed} dashboard session(s) revoked.")
    return {"ok": True, "revoked": removed}


# --------------------------------------------------------------------------- #
# VLESS over WebSocket fallback
# --------------------------------------------------------------------------- #
async def _pump_ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter) -> None:
    while True:
        message = await websocket.receive()
        kind = message.get("type")
        if kind == "websocket.disconnect":
            return
        data = message.get("bytes")
        if data is None and message.get("text") is not None:
            data = message["text"].encode("utf-8")
        if data:
            writer.write(data)
            await writer.drain()


async def _pump_tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader) -> None:
    while True:
        chunk = await reader.read(65536)
        if not chunk:
            return
        await websocket.send_bytes(chunk)


@app.websocket("/{full_path:path}")
async def websocket_gateway(websocket: WebSocket, full_path: str) -> None:
    """Terminate the WebSocket transport and hand the raw stream to Xray."""
    expected = getattr(websocket.app.state, "ws_path", "") or ""
    requested = "/" + full_path.lstrip("/")

    if not settings.enable_ws_fallback or not expected or requested != expected:
        await websocket.close(code=1008)
        return

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", settings.xray_ws_backend_port), timeout=5.0
        )
    except (OSError, asyncio.TimeoutError):
        logger.warning("WebSocket fallback: Xray backend is not reachable.")
        await websocket.close(code=1011)
        return

    await websocket.accept()
    tasks = [
        asyncio.create_task(_pump_ws_to_tcp(websocket, writer)),
        asyncio.create_task(_pump_tcp_to_ws(websocket, reader)),
    ]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001 - never leak a stack trace to the peer
        logger.debug("WebSocket fallback ended: %s", exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass
        if websocket.client_state is WebSocketState.CONNECTED:
            try:
                await websocket.close()
            except RuntimeError:
                pass


@app.get("/robots.txt", include_in_schema=False)
def robots() -> PlainTextResponse:
    return PlainTextResponse("User-agent: *\nDisallow: /\n")
