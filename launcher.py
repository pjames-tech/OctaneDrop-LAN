from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import webbrowser
from getpass import getpass
from pathlib import Path

import uvicorn

from app.config import load_settings
from app.db import Database
from app.main import create_app, create_or_update_admin
from app.tls import ensure_local_tls_bundle


def _prompt_admin_credentials() -> tuple[str, str]:
    print()
    print("First-time setup")
    print("No admin account exists yet for this EXE.")
    username = input("Admin username [admin]: ").strip() or "admin"

    while True:
        password = getpass("New password: ")
        confirm = getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match. Try again.")
            continue
        if len(password) < 10:
            print("Use at least 10 characters.")
            continue
        return username, password


def _ensure_admin(settings) -> None:
    db = Database(settings.database_url)
    db.init()
    if db.count_users() > 0:
        return

    username, password = _prompt_admin_credentials()
    create_or_update_admin(username, password)
    print(f"Admin account ready: {username}")
    print()


def _print_startup_banner(settings) -> None:
    print(f"Starting {settings.app_name}")
    print(f"App data:  {settings.data_dir}")
    print(f"Local URL: {settings.local_url}")
    if settings.primary_lan_ip:
        print(f"LAN URL:   {settings.lan_url}")
    if settings.tls_enabled and settings.tls_ca_cert_path:
        print(f"CA cert:   {settings.tls_ca_cert_path}")
        if settings.tls_trusted_on_host:
            print("Host trust: installed in the current Windows user's trusted root store")
        else:
            print("Host trust: not installed automatically on this platform or run")
    if settings.detected_subnets:
        print("Allowed subnets:", ", ".join(settings.detected_subnets))
    print("Press Ctrl+C to stop sharing.")


def _open_browser_later(url: str) -> None:
    def _worker() -> None:
        time.sleep(1.25)
        try:
            webbrowser.open_new_tab(url)
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch the OctaneDrop LAN Windows EXE host")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=8765, help="Bind port")
    parser.add_argument("--ssl-keyfile", default=None, help="Optional TLS private key path")
    parser.add_argument("--ssl-certfile", default=None, help="Optional TLS certificate path")
    parser.add_argument("--no-auto-tls", action="store_true", help="Disable auto-generated local HTTPS certificates")
    parser.add_argument(
        "--no-trust-local-ca",
        dest="trust_local_ca",
        action="store_false",
        help="Do not add the generated local CA to the current Windows user trust store",
    )
    parser.set_defaults(trust_local_ca=True)
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open the local browser")
    parser.add_argument(
        "--setup-admin",
        action="store_true",
        help="Create or reset the admin account, then exit without starting the server",
    )
    parser.add_argument("--username", default="admin", help="Admin username when using --setup-admin")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    bootstrap_settings = load_settings(host=args.host, port=args.port)
    ssl_keyfile = args.ssl_keyfile
    ssl_certfile = args.ssl_certfile
    tls_bundle = None

    if not (ssl_keyfile and ssl_certfile) and not args.no_auto_tls:
        tls_bundle = ensure_local_tls_bundle(
            bootstrap_settings.data_dir,
            primary_lan_ip=bootstrap_settings.primary_lan_ip,
            trust_windows_host=args.trust_local_ca,
        )
        ssl_keyfile = str(tls_bundle.key_path)
        ssl_certfile = str(tls_bundle.cert_path)

    settings = load_settings(
        host=args.host,
        port=args.port,
        tls_enabled=bool(ssl_keyfile and ssl_certfile),
        tls_ca_cert_path=tls_bundle.ca_cert_path if tls_bundle else None,
        tls_cert_path=Path(ssl_certfile) if ssl_certfile else None,
        tls_key_path=Path(ssl_keyfile) if ssl_keyfile else None,
        tls_trusted_on_host=tls_bundle.trusted_on_host if tls_bundle else False,
    )

    if args.setup_admin:
        print(f"App data:  {settings.data_dir}")
        password = getpass("New password: ")
        confirm = getpass("Confirm password: ")
        if password != confirm:
            raise SystemExit("Passwords do not match.")
        if len(password) < 10:
            raise SystemExit("Use at least 10 characters for the admin password.")
        create_or_update_admin(args.username, password)
        print(f"Admin account ready: {args.username}")
        return

    _ensure_admin(settings)
    _print_startup_banner(settings)

    auto_open = os.getenv("FILESHARE_AUTO_OPEN_BROWSER", "1").strip() != "0"
    if auto_open and not args.no_browser:
        _open_browser_later(f"{settings.local_url}/login")

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


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOctaneDrop stopped.")
        sys.exit(0)
