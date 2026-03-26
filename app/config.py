from __future__ import annotations

import base64
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .network import detect_primary_lan_ip, detect_private_subnets

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_APP_SLUG = "OctaneDropLAN"
DEFAULT_MAX_UPLOAD_BYTES = 1024 ** 4  # 1 TiB
DEFAULT_STREAM_CHUNK_BYTES = 8 * 1024 * 1024  # 8 MiB


def human_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{value} B"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def detect_runtime_data_dir() -> Path:
    override = os.getenv("FILESHARE_DATA_DIR", "").strip() or os.getenv("FILESHARE_APP_HOME", "").strip()
    if override:
        return Path(override).expanduser().resolve()

    if getattr(sys, "frozen", False):
        if os.name == "nt":
            local_app_data = os.getenv("LOCALAPPDATA")
            if local_app_data:
                return Path(local_app_data) / DEFAULT_APP_SLUG
            return Path.home() / "AppData" / "Local" / DEFAULT_APP_SLUG
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / DEFAULT_APP_SLUG
        return Path.home() / ".local" / "share" / DEFAULT_APP_SLUG

    return BASE_DIR / "data"


def ensure_secret_file(path: Path, *, size: int = 32, encoder: str = "base64url") -> str:
    ensure_dir(path.parent)
    if path.exists():
        return path.read_text(encoding="utf-8").strip()

    raw = secrets.token_bytes(size)
    if encoder == "base64url":
        value = base64.urlsafe_b64encode(raw).decode("utf-8")
    else:
        value = raw.hex()

    path.write_text(value, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
    return value


def parse_positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    value = int(raw)
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer.")
    return value


def parse_max_upload_bytes() -> int:
    raw_bytes = os.getenv("FILESHARE_MAX_UPLOAD_BYTES", "").strip()
    if raw_bytes:
        value = int(raw_bytes)
        if value <= 0:
            raise ValueError("FILESHARE_MAX_UPLOAD_BYTES must be a positive integer.")
        return value

    raw_mb = os.getenv("FILESHARE_MAX_UPLOAD_MB", "").strip()
    if raw_mb:
        value = int(raw_mb)
        if value <= 0:
            raise ValueError("FILESHARE_MAX_UPLOAD_MB must be a positive integer.")
        return value * 1024 * 1024

    return DEFAULT_MAX_UPLOAD_BYTES


def parse_stream_chunk_bytes() -> int:
    raw_bytes = os.getenv("FILESHARE_STREAM_CHUNK_BYTES", "").strip()
    if raw_bytes:
        value = int(raw_bytes)
        if value <= 0:
            raise ValueError("FILESHARE_STREAM_CHUNK_BYTES must be a positive integer.")
        return value

    raw_mb = os.getenv("FILESHARE_STREAM_CHUNK_MB", "").strip()
    if raw_mb:
        value = int(raw_mb)
        if value <= 0:
            raise ValueError("FILESHARE_STREAM_CHUNK_MB must be a positive integer.")
        return value * 1024 * 1024

    return DEFAULT_STREAM_CHUNK_BYTES


@dataclass(slots=True)
class Settings:
    app_name: str
    host: str
    port: int
    database_url: str
    storage_dir: Path
    data_dir: Path
    session_secret: str
    encryption_key: bytes
    max_upload_bytes: int
    stream_chunk_bytes: int
    session_cookie_name: str
    session_max_age_seconds: int
    share_token_ttl_seconds: int
    login_attempt_window_seconds: int
    login_attempt_limit: int
    upload_window_seconds: int
    upload_limit: int
    same_site: str
    https_only_cookies: bool
    tls_enabled: bool
    tls_ca_cert_path: Path | None
    tls_cert_path: Path | None
    tls_key_path: Path | None
    tls_trusted_on_host: bool
    detected_subnets: List[str]
    primary_lan_ip: str | None
    public_base_url: str | None

    @property
    def max_upload_label(self) -> str:
        return human_bytes(self.max_upload_bytes)

    @property
    def lan_url(self) -> str:
        host = self.primary_lan_ip or "127.0.0.1"
        scheme = "https" if self.tls_enabled else "http"
        return f"{scheme}://{host}:{self.port}"

    @property
    def local_url(self) -> str:
        scheme = "https" if self.tls_enabled else "http"
        return f"{scheme}://127.0.0.1:{self.port}"


def load_settings(
    host: str = "0.0.0.0",
    port: int = 8765,
    https_only_cookies: bool = False,
    *,
    tls_enabled: bool = False,
    tls_ca_cert_path: Path | None = None,
    tls_cert_path: Path | None = None,
    tls_key_path: Path | None = None,
    tls_trusted_on_host: bool = False,
) -> Settings:
    data_dir = detect_runtime_data_dir()
    storage_dir = data_dir / "storage"
    db_path = data_dir / "fileshare.db"
    session_secret_file = data_dir / ".session_secret"
    encryption_key_file = data_dir / ".encryption_key"

    ensure_dir(data_dir)
    ensure_dir(storage_dir)

    session_secret = ensure_secret_file(session_secret_file, size=48)
    encryption_key_text = ensure_secret_file(encryption_key_file, size=32)
    encryption_key = base64.urlsafe_b64decode(encryption_key_text.encode("utf-8"))

    subnets_env = os.getenv("FILESHARE_ALLOWED_SUBNETS", "").strip()
    if subnets_env:
        detected_subnets = [item.strip() for item in subnets_env.split(",") if item.strip()]
    else:
        detected_subnets = detect_private_subnets()

    primary_lan_ip = detect_primary_lan_ip()

    secure_cookies = bool(https_only_cookies or tls_enabled)

    return Settings(
        app_name=os.getenv("FILESHARE_APP_NAME", "OctaneDrop LAN"),
        host=os.getenv("FILESHARE_HOST", host),
        port=int(os.getenv("FILESHARE_PORT", str(port))),
        database_url=str(db_path),
        storage_dir=storage_dir,
        data_dir=data_dir,
        session_secret=session_secret,
        encryption_key=encryption_key,
        max_upload_bytes=parse_max_upload_bytes(),
        stream_chunk_bytes=parse_stream_chunk_bytes(),
        session_cookie_name=os.getenv("FILESHARE_SESSION_COOKIE", "octane_drop_session"),
        session_max_age_seconds=parse_positive_int_env("FILESHARE_SESSION_MAX_AGE_SECONDS", 60 * 60 * 12),
        share_token_ttl_seconds=parse_positive_int_env("FILESHARE_SHARE_TOKEN_TTL_SECONDS", 60 * 10),
        login_attempt_window_seconds=parse_positive_int_env("FILESHARE_LOGIN_WINDOW_SECONDS", 60 * 15),
        login_attempt_limit=parse_positive_int_env("FILESHARE_LOGIN_LIMIT", 8),
        upload_window_seconds=parse_positive_int_env("FILESHARE_UPLOAD_WINDOW_SECONDS", 60 * 10),
        upload_limit=parse_positive_int_env("FILESHARE_UPLOAD_LIMIT", 20),
        same_site=os.getenv("FILESHARE_COOKIE_SAMESITE", "lax"),
        https_only_cookies=secure_cookies,
        tls_enabled=tls_enabled,
        tls_ca_cert_path=tls_ca_cert_path,
        tls_cert_path=tls_cert_path,
        tls_key_path=tls_key_path,
        tls_trusted_on_host=tls_trusted_on_host,
        detected_subnets=detected_subnets,
        primary_lan_ip=primary_lan_ip,
        public_base_url=os.getenv("FILESHARE_PUBLIC_BASE_URL", "").strip() or None,
    )
