from __future__ import annotations

import argparse
import asyncio
import hashlib
import inspect
import secrets
import sys
import threading
import time
import webbrowser
from getpass import getpass
from pathlib import Path
from typing import Annotated, Iterable
from urllib.parse import quote, urlparse

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from .config import BASE_DIR, Settings, human_bytes, load_settings
from .db import Database, StoredFile
from .network import client_ip_allowed
from .security import (
    FileCipher,
    FileTooLargeError,
    FixedWindowRateLimiter,
    ShareTokenManager,
    StreamingDecryptError,
    hash_password,
    new_csrf_token,
    verify_password,
)
from .tls import ensure_local_tls_bundle


class FileEventHub:
    def __init__(self, db: Database) -> None:
        self._db = db
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)

    async def broadcast(self, payload: dict[str, object] | None = None) -> None:
        payload = payload or build_files_state_payload(self._db)
        async with self._lock:
            connections = list(self._connections)

        if not connections:
            return

        stale: list[WebSocket] = []
        for websocket in connections:
            try:
                await websocket.send_json(payload)
            except Exception:
                stale.append(websocket)

        if stale:
            async with self._lock:
                for websocket in stale:
                    self._connections.discard(websocket)


def format_bytes(value: int) -> str:
    return human_bytes(value)


def compute_files_signature(files: Iterable[StoredFile]) -> str:
    digest = hashlib.sha256()
    count = 0
    for stored in files:
        count += 1
        digest.update(stored.id.encode("utf-8"))
        digest.update(b"\0")
        digest.update(stored.original_name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(stored.uploaded_at.encode("utf-8"))
        digest.update(b"\0")
        digest.update(stored.sha256_hex.encode("utf-8"))
        digest.update(b"\0")
    return f"{count}:{digest.hexdigest()}"


def build_files_state_payload(db: Database, *, event: str = "files_changed") -> dict[str, object]:
    files = db.list_files()
    return {
        "event": event,
        "signature": compute_files_signature(files),
        "count": len(files),
        "generated_at": int(time.time()),
    }


def render_content_disposition(filename: str) -> str:
    quoted = quote(filename, safe="")
    ascii_fallback = "".join(ch if 32 <= ord(ch) < 127 and ch not in {'"', '\\'} else "_" for ch in filename)
    return f"attachment; filename=\"{ascii_fallback or 'download'}\"; filename*=UTF-8''{quoted}"


def static_asset_version() -> int:
    candidates = [
        BASE_DIR / "app" / "static" / "app.js",
        BASE_DIR / "app" / "static" / "styles.css",
        BASE_DIR / "app" / "static" / "logo-mark.svg",
        BASE_DIR / "app" / "static" / "favicon.svg",
        BASE_DIR / "app" / "static" / "favicon.png",
        BASE_DIR / "app" / "static" / "favicon.ico",
    ]
    mtimes: list[int] = []
    for path in candidates:
        try:
            mtimes.append(int(path.stat().st_mtime))
        except FileNotFoundError:
            continue
    return max(mtimes, default=1)


def set_flash(request: Request, *, kind: str, text: str) -> None:
    request.session["flash"] = {"kind": kind, "text": text}


def pop_flash(request: Request) -> dict[str, str] | None:
    flash = request.session.get("flash")
    if flash:
        request.session.pop("flash", None)
    return flash


def current_username(request: Request) -> str | None:
    username = request.session.get("username")
    return username if isinstance(username, str) and username else None


def websocket_current_username(websocket: WebSocket) -> str | None:
    session = websocket.scope.get("session", {})
    if not isinstance(session, dict):
        return None
    username = session.get("username")
    return username if isinstance(username, str) and username else None


def ensure_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not isinstance(token, str) or not token:
        token = new_csrf_token()
        request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, submitted_token: str | None) -> None:
    session_token = request.session.get("csrf_token")
    if not submitted_token or not session_token or submitted_token != session_token:
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")


def require_auth(request: Request) -> str:
    username = current_username(request)
    if not username:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return username


def flash_redirect(request: Request, location: str, *, kind: str | None = None, text: str | None = None) -> RedirectResponse:
    if kind and text:
        set_flash(request, kind=kind, text=text)
    return RedirectResponse(url=location, status_code=303)


def make_templates() -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))
    templates.env.filters["filesize"] = format_bytes
    return templates


def render_template(templates: Jinja2Templates, request: Request, name: str, **extra):
    context = build_template_context(request, **extra)
    params = list(inspect.signature(templates.TemplateResponse).parameters)
    if params and params[0] == "request":
        return templates.TemplateResponse(request, name, context)
    return templates.TemplateResponse(name, context)


def build_template_context(request: Request, **extra) -> dict[str, object]:
    settings: Settings = request.app.state.settings
    return {
        "request": request,
        "app_name": settings.app_name,
        "flash": pop_flash(request),
        "csrf_token": ensure_csrf_token(request),
        "lan_url": settings.lan_url,
        "allowed_subnets": settings.detected_subnets,
        "primary_lan_ip": settings.primary_lan_ip,
        "current_user": current_username(request),
        "max_upload_label": settings.max_upload_label,
        "share_token_ttl_minutes": settings.share_token_ttl_seconds // 60,
        "static_version": request.app.state.static_version,
        "tls_enabled": settings.tls_enabled,
        "tls_trusted_on_host": settings.tls_trusted_on_host,
        "tls_ca_download_url": "/ca-cert.pem" if settings.tls_ca_cert_path else None,
        **extra,
    }


def origin_is_allowed(websocket: WebSocket) -> bool:
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    if not origin or not host:
        return True
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"}:
        return False
    return parsed.netloc == host


def schedule_browser_open(url: str, *, delay_seconds: float = 1.2) -> None:
    def _open() -> None:
        try:
            webbrowser.open_new_tab(url)
        except Exception:
            pass

    timer = threading.Timer(delay_seconds, _open)
    timer.daemon = True
    timer.start()


def persist_upload_to_path(
    file_cipher: FileCipher,
    upload: UploadFile,
    destination: Path,
    *,
    max_upload_bytes: int,
    chunk_size: int,
) -> tuple[int, str]:
    source = upload.file
    try:
        source.seek(0)
    except (AttributeError, OSError):
        pass
    return file_cipher.encrypt_fileobj_to_path(
        source,
        destination,
        max_plaintext_bytes=max_upload_bytes,
        chunk_size=chunk_size,
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    db = Database(settings.database_url)
    db.init()

    app = FastAPI(title=settings.app_name)
    app.state.settings = settings
    app.state.db = db
    app.state.templates = make_templates()
    app.state.rate_limiter = FixedWindowRateLimiter()
    app.state.share_tokens = ShareTokenManager(settings.session_secret)
    app.state.file_cipher = FileCipher(settings.encryption_key)
    app.state.file_events = FileEventHub(db)
    app.state.static_version = static_asset_version()

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie=settings.session_cookie_name,
        same_site=settings.same_site,
        https_only=settings.https_only_cookies,
        max_age=settings.session_max_age_seconds,
    )

    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        if not client_ip_allowed(request.client.host if request.client else None, settings.detected_subnets):
            return PlainTextResponse(
                "This file sharer only accepts requests from the local network it's running on.",
                status_code=403,
            )

        response = await call_next(request)
        host_header = request.headers.get("host", "")
        connect_sources = ["'self'"]
        if host_header:
            connect_sources.extend([f"ws://{host_header}", f"wss://{host_header}"])
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            f"connect-src {' '.join(connect_sources)}; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        if settings.tls_enabled and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=86400"
        if request.url.path in {"/", "/login", "/api/files/state"}:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.api_route("/favicon.ico", methods=["GET", "HEAD"], include_in_schema=False)
    async def favicon() -> FileResponse:
        favicon_path = BASE_DIR / "app" / "static" / "favicon.ico"
        if not favicon_path.exists():
            raise HTTPException(status_code=404, detail="favicon.ico is missing.")
        return FileResponse(
            favicon_path,
            media_type="image/x-icon",
            filename="favicon.ico",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

    @app.get("/ca-cert.pem", include_in_schema=False)
    async def ca_certificate():
        if not settings.tls_ca_cert_path or not settings.tls_ca_cert_path.exists():
            raise HTTPException(status_code=404, detail="Local CA certificate is not available.")
        return FileResponse(
            settings.tls_ca_cert_path,
            media_type="application/x-pem-file",
            filename="OctaneDropLAN-CA.pem",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        if not current_username(request):
            return RedirectResponse(url="/login", status_code=303)
        files = db.list_files()
        templates: Jinja2Templates = app.state.templates
        return render_template(
            templates,
            request,
            "index.html",
            files=files,
            files_signature=compute_files_signature(files),
            user_count=db.count_users(),
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if current_username(request):
            return RedirectResponse(url="/", status_code=303)
        templates: Jinja2Templates = app.state.templates
        return render_template(templates, request, "login.html", user_count=db.count_users())

    @app.post("/login")
    async def login(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        csrf_token: Annotated[str, Form()],
    ):
        validate_csrf(request, csrf_token)
        limiter: FixedWindowRateLimiter = app.state.rate_limiter
        client_ip = request.client.host if request.client else "unknown"
        limit = limiter.check(
            f"login:{client_ip}",
            max_events=settings.login_attempt_limit,
            window_seconds=settings.login_attempt_window_seconds,
        )
        if not limit.allowed:
            return flash_redirect(
                request,
                "/login",
                kind="error",
                text=f"Too many login attempts. Try again in about {limit.retry_after_seconds} seconds.",
            )

        if db.count_users() == 0:
            return flash_redirect(
                request,
                "/login",
                kind="error",
                text="No admin account exists yet. Run: python run.py create-admin --username admin",
            )

        user = db.get_user_by_username(username.strip())
        if not user or not verify_password(password, user.password_hash):
            return flash_redirect(request, "/login", kind="error", text="Invalid username or password.")

        request.session.clear()
        request.session["username"] = user.username
        request.session["csrf_token"] = new_csrf_token()
        return flash_redirect(request, "/", kind="success", text=f"Signed in as {user.username}.")

    @app.post("/logout")
    async def logout(request: Request, csrf_token: Annotated[str, Form()]):
        validate_csrf(request, csrf_token)
        request.session.clear()
        return RedirectResponse(url="/login", status_code=303)

    @app.post("/upload")
    async def upload_files(
        request: Request,
        csrf_token: Annotated[str, Form()],
        files: Annotated[list[UploadFile], File()],
    ):
        username = require_auth(request)
        validate_csrf(request, csrf_token)

        limiter: FixedWindowRateLimiter = app.state.rate_limiter
        client_ip = request.client.host if request.client else "unknown"
        limit = limiter.check(
            f"upload:{client_ip}",
            max_events=settings.upload_limit,
            window_seconds=settings.upload_window_seconds,
        )
        if not limit.allowed:
            return flash_redirect(
                request,
                "/",
                kind="error",
                text=f"Upload rate limit reached. Try again in about {limit.retry_after_seconds} seconds.",
            )

        if not files:
            return flash_redirect(request, "/", kind="error", text="Select at least one file to upload.")

        file_cipher: FileCipher = app.state.file_cipher
        file_events: FileEventHub = app.state.file_events
        saved_count = 0

        for incoming in files:
            original_name = Path(incoming.filename or "upload.bin").name
            file_id = secrets.token_urlsafe(12)
            stored_name = f"{file_id}.bin"
            temp_path = settings.storage_dir / f".{stored_name}.part"
            final_path = settings.storage_dir / stored_name
            total_size = 0
            sha256_hex = ""

            try:
                total_size, sha256_hex = await run_in_threadpool(
                    persist_upload_to_path,
                    file_cipher,
                    incoming,
                    temp_path,
                    max_upload_bytes=settings.max_upload_bytes,
                    chunk_size=settings.stream_chunk_bytes,
                )
            except FileTooLargeError:
                temp_path.unlink(missing_ok=True)
                await incoming.close()
                if saved_count:
                    await file_events.broadcast()
                    return flash_redirect(
                        request,
                        "/",
                        kind="error",
                        text=(
                            f"{original_name} is larger than the {settings.max_upload_label} limit. "
                            f"Uploaded {saved_count} earlier file(s) before the limit was hit."
                        ),
                    )
                return flash_redirect(
                    request,
                    "/",
                    kind="error",
                    text=f"{original_name} is larger than the {settings.max_upload_label} limit.",
                )
            except Exception as exc:
                temp_path.unlink(missing_ok=True)
                await incoming.close()
                if saved_count:
                    await file_events.broadcast()
                    return flash_redirect(
                        request,
                        "/",
                        kind="error",
                        text=(
                            f"{original_name} could not be uploaded. Uploaded {saved_count} earlier file(s) first. "
                            f"Reason: {str(exc) or exc.__class__.__name__}"
                        ),
                    )
                return flash_redirect(
                    request,
                    "/",
                    kind="error",
                    text=f"{original_name} could not be uploaded. Reason: {str(exc) or exc.__class__.__name__}",
                )
            finally:
                await incoming.close()

            if total_size == 0:
                temp_path.unlink(missing_ok=True)
                continue

            try:
                temp_path.replace(final_path)
                db.insert_file(
                    file_id=file_id,
                    original_name=original_name,
                    stored_name=stored_name,
                    content_type=incoming.content_type or "application/octet-stream",
                    size_bytes=total_size,
                    sha256_hex=sha256_hex,
                    uploaded_by=username,
                )
            except Exception as exc:
                temp_path.unlink(missing_ok=True)
                final_path.unlink(missing_ok=True)
                if saved_count:
                    await file_events.broadcast()
                    return flash_redirect(
                        request,
                        "/",
                        kind="error",
                        text=(
                            f"{original_name} could not be saved. Uploaded {saved_count} earlier file(s) first. "
                            f"Reason: {str(exc) or exc.__class__.__name__}"
                        ),
                    )
                return flash_redirect(
                    request,
                    "/",
                    kind="error",
                    text=f"{original_name} could not be saved. Reason: {str(exc) or exc.__class__.__name__}",
                )

            saved_count += 1

        if saved_count == 0:
            return flash_redirect(request, "/", kind="error", text="Nothing was uploaded.")

        await file_events.broadcast()
        return flash_redirect(request, "/", kind="success", text=f"Uploaded {saved_count} file(s).")

    @app.post("/files/{file_id}/delete")
    async def delete_file(
        request: Request,
        file_id: str,
        csrf_token: Annotated[str, Form()],
    ):
        require_auth(request)
        validate_csrf(request, csrf_token)

        stored = db.get_file(file_id)
        if not stored:
            return flash_redirect(request, "/", kind="error", text="File not found.")

        disk_path = settings.storage_dir / stored.stored_name
        try:
            if disk_path.exists():
                disk_path.unlink()
        finally:
            db.delete_file(file_id)

        file_events: FileEventHub = app.state.file_events
        await file_events.broadcast()
        return flash_redirect(request, "/", kind="success", text=f"Deleted {stored.original_name}.")

    @app.get("/api/files/state")
    async def files_state(request: Request):
        require_auth(request)
        return JSONResponse(build_files_state_payload(db), headers={"Cache-Control": "no-store"})

    @app.websocket("/ws/files")
    async def files_websocket(websocket: WebSocket):
        client_host = websocket.client.host if websocket.client else None
        if not client_ip_allowed(client_host, settings.detected_subnets):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        if not origin_is_allowed(websocket):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        if not websocket_current_username(websocket):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await websocket.accept()
        file_events: FileEventHub = app.state.file_events
        await file_events.connect(websocket)

        try:
            await websocket.send_json(build_files_state_payload(db, event="ready"))
            while True:
                message = await websocket.receive_text()
                if message == "ping":
                    await websocket.send_json({"event": "pong", "generated_at": int(time.time())})
        except WebSocketDisconnect:
            pass
        finally:
            await file_events.disconnect(websocket)

    @app.post("/api/files/{file_id}/share")
    async def create_share_link(request: Request, file_id: str):
        require_auth(request)
        csrf_header = request.headers.get("X-CSRF-Token")
        validate_csrf(request, csrf_header)

        stored = db.get_file(file_id)
        if not stored:
            return JSONResponse({"error": "File not found."}, status_code=404)

        token_manager: ShareTokenManager = app.state.share_tokens
        token = token_manager.create(file_id)
        request_base_url = str(request.base_url).rstrip("/")
        request_host = request.url.hostname or ""
        if settings.public_base_url:
            base_url = settings.public_base_url.rstrip("/")
        elif settings.host in {"127.0.0.1", "localhost"}:
            base_url = request_base_url
        elif request_host in {"127.0.0.1", "localhost", "::1"} and settings.primary_lan_ip:
            base_url = settings.lan_url
        else:
            base_url = request_base_url
        return {
            "url": f"{base_url}/download/{file_id}?token={token}",
            "expires_in_seconds": settings.share_token_ttl_seconds,
            "filename": stored.original_name,
        }

    @app.get("/download/{file_id}")
    async def download_file(request: Request, file_id: str, token: str | None = None):
        username = current_username(request)
        if not username:
            token_manager: ShareTokenManager = app.state.share_tokens
            verified_id = token_manager.verify(token or "", max_age=settings.share_token_ttl_seconds)
            if verified_id != file_id:
                return PlainTextResponse("This download link is missing or expired.", status_code=401)

        stored = db.get_file(file_id)
        if not stored:
            return PlainTextResponse("File not found.", status_code=404)

        disk_path = settings.storage_dir / stored.stored_name
        if not disk_path.exists():
            return PlainTextResponse("Stored file is missing from disk.", status_code=410)

        file_cipher: FileCipher = app.state.file_cipher
        headers = {
            "Content-Disposition": render_content_disposition(stored.original_name),
            "Content-Length": str(stored.size_bytes),
            "X-Checksum-SHA256": stored.sha256_hex,
            "Cache-Control": "no-store",
        }

        try:
            iterator = file_cipher.iter_decrypt_path(disk_path, expected_plaintext_size=stored.size_bytes)
        except StreamingDecryptError:
            return PlainTextResponse("Stored file could not be decrypted.", status_code=500)

        return StreamingResponse(iterator, media_type=stored.content_type, headers=headers)

    return app


def create_or_update_admin(username: str, password: str) -> None:
    settings = load_settings()
    db = Database(settings.database_url)
    db.init()
    db.upsert_user(username.strip(), hash_password(password))


def interactive_create_admin(username: str) -> None:
    password = getpass("New password: ")
    confirm = getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords do not match.")
    if len(password) < 10:
        raise SystemExit("Use at least 10 characters for the admin password.")
    create_or_update_admin(username, password)
    print(f"Admin account ready: {username}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OctaneDrop LAN secure file sharer")
    subparsers = parser.add_subparsers(dest="command", required=False)

    create_admin_parser = subparsers.add_parser("create-admin", help="Create or reset the admin account")
    create_admin_parser.add_argument("--username", default="admin", help="Admin username")

    serve_parser = subparsers.add_parser("serve", help="Run the web app")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--ssl-keyfile", default=None)
    serve_parser.add_argument("--ssl-certfile", default=None)
    serve_parser.add_argument("--no-auto-tls", action="store_true", help="Disable auto-generated local HTTPS certificates")
    serve_parser.add_argument(
        "--no-trust-local-ca",
        dest="trust_local_ca",
        action="store_false",
        help="Do not add the generated local CA to the current Windows user trust store",
    )
    serve_parser.set_defaults(trust_local_ca=True)
    serve_parser.add_argument("--open-browser", dest="open_browser", action="store_true", help="Open the local UI in the default browser")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "create-admin":
        interactive_create_admin(args.username)
        return

    host = getattr(args, "host", "0.0.0.0")
    port = getattr(args, "port", 8765)
    ssl_keyfile = getattr(args, "ssl_keyfile", None)
    ssl_certfile = getattr(args, "ssl_certfile", None)
    open_browser = getattr(args, "open_browser", False)
    auto_tls_enabled = not getattr(args, "no_auto_tls", False)
    trust_local_ca = getattr(args, "trust_local_ca", True)
    bootstrap_settings = load_settings(host=host, port=port)
    tls_bundle = None

    if not (ssl_keyfile and ssl_certfile) and auto_tls_enabled:
        tls_bundle = ensure_local_tls_bundle(
            bootstrap_settings.data_dir,
            primary_lan_ip=bootstrap_settings.primary_lan_ip,
            trust_windows_host=trust_local_ca,
        )
        ssl_keyfile = str(tls_bundle.key_path)
        ssl_certfile = str(tls_bundle.cert_path)

    settings = load_settings(
        host=host,
        port=port,
        tls_enabled=bool(ssl_keyfile and ssl_certfile),
        tls_ca_cert_path=tls_bundle.ca_cert_path if tls_bundle else None,
        tls_cert_path=Path(ssl_certfile) if ssl_certfile else None,
        tls_key_path=Path(ssl_keyfile) if ssl_keyfile else None,
        tls_trusted_on_host=tls_bundle.trusted_on_host if tls_bundle else False,
    )

    db = Database(settings.database_url)
    db.init()
    if db.count_users() == 0:
        print("No admin account found.")
        print("Create one first with: python run.py create-admin --username admin")
        sys.exit(1)

    if open_browser:
        schedule_browser_open(f"{settings.local_url}/login")

    print(f"Local URL: {settings.local_url}")
    if settings.primary_lan_ip:
        print(f"LAN URL:   {settings.lan_url}")
    if settings.tls_enabled and settings.tls_ca_cert_path:
        print(f"CA cert:   {settings.tls_ca_cert_path}")
        if settings.tls_trusted_on_host:
            print("Windows host trust: installed in CurrentUser Root store")
        else:
            print("Windows host trust: not installed automatically on this platform or run")

    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        loop="asyncio",
        http="h11",
        ws="websockets",
        log_level="info",
    )
