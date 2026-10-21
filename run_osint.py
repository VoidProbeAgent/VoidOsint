#!/usr/bin/env python3
"""
VoidOsint Platform CLI Launcher
===============================
Boots the FastAPI ASGI backend, verifies dependencies and engine binaries,
initializes the SQLite WAL database, and automatically launches the browser cockpit.

Conforms to Section 4 of hive/specs/osint-platform-spec.md.
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def check_dependencies() -> bool:
    """Verifies Python version and critical third-party dependencies."""
    print("=" * 65)
    print(" VoidOsint Environment & Dependency Pre-Flight Validation")
    print("=" * 65)

    py_version = sys.version_info
    print(f"[*] Python Runtime: {py_version.major}.{py_version.minor}.{py_version.micro} ({sys.executable})")
    if py_version < (3, 10):
        print("[!] ERROR: VoidOsint requires Python 3.10 or newer.")
        return False

    required_modules = [
        ("fastapi", "FastAPI web framework"),
        ("uvicorn", "Uvicorn ASGI server"),
        ("pydantic", "Pydantic schema validation"),
        ("aiohttp", "aiohttp asynchronous client"),
        ("bs4", "BeautifulSoup4 HTML parser"),
        ("sqlite3", "SQLite3 embedded database"),
    ]

    all_ok = True
    for mod_name, desc in required_modules:
        try:
            __import__(mod_name)
            print(f" [+] [OK] {mod_name:<15} - {desc}")
        except ImportError:
            print(f" [!] [FAIL] {mod_name:<13} - {desc} (MISSING)")
            all_ok = False

    # Check OSINT Engine Binaries
    print("-" * 65)
    try:
        from backend.engines.maigret_runner import MaigretRunner
        from backend.engines.spiderfoot_runner import SpiderFootRunner
        from backend.engines.google_search import GoogleSearchRunner

        maigret_ok = MaigretRunner.is_available()
        sf_ok = SpiderFootRunner.is_available()
        gs_ok = GoogleSearchRunner.is_available()

        print(f" [{'+' if maigret_ok else '!'}] Maigret Engine:     {'Available (' + MaigretRunner.get_version() + ')' if maigret_ok else 'Not Found (falling back to search)'}")
        print(f" [{'+' if sf_ok else '!'}] SpiderFoot Engine:  {'Available (' + SpiderFootRunner.get_version() + ')' if sf_ok else 'Not Found (native recon active)'}")
        print(f" [+] Search Dork Engine: Available ({GoogleSearchRunner.get_version()})")
    except Exception as ex:
        print(f" [!] Engine check warning: {ex}")

    print("=" * 65)
    return all_ok


def open_browser_delayed(url: str, delay_sec: float = 0.8) -> None:
    """Opens browser after server starts listening."""
    def _open() -> None:
        time.sleep(delay_sec)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_open, daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VoidOsint Platform Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host interface to bind (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5002,
        help="Port to listen on (default: 5002)",
    )
    parser.add_argument(
        "--db",
        dest="db_path",
        type=str,
        default="data/osint_nexus.db",
        help="Path to SQLite database file (default: data/osint_nexus.db)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Enable auto-reload for development (default: False)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Do not launch the default browser automatically (default: False)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of uvicorn worker processes (default: 1)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log verbosity level (default: INFO)",
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        default=False,
        help="Validate availability of maigret, spiderfoot, and dependencies without launching",
    )

    args = parser.parse_args()

    if args.check_deps:
        success = check_dependencies()
        sys.exit(0 if success else 1)

    # 1. Dependency and Environment Check
    if not check_dependencies():
        print("[!] Warning: Some optional or core dependencies failed verification.")

    # 2. Ensure data and logs directories exist
    db_file = Path(args.db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    logs_dir = PROJECT_ROOT / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # 3. Initialize SQLite Schema in WAL mode
    from backend.database import DatabaseManager
    print(f"[*] Initializing SQLite database in WAL mode at {db_file}...")
    db_mgr = DatabaseManager(db_file)
    db_mgr.init_db()
    print(" [+] Database schema ready.")

    # 4. Set process environment for FastAPI
    os.environ["VOID_HOST"] = args.host
    os.environ["VOID_PORT"] = str(args.port)
    os.environ["VOID_DB_PATH"] = str(db_file)

    server_url = f"http://{args.host}:{args.port}"
    print(f"\n[+] VoidOsint Cockpit starting on: {server_url}")
    print("[*] Press Ctrl+C to safely terminate backend.\n")

    # 5. Launch browser if not headless
    if not args.headless:
        open_browser_delayed(server_url, delay_sec=0.8)

    # 6. Launch Uvicorn
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        log_level=args.log_level.lower(),
        app_dir=str(PROJECT_ROOT),
    )


if __name__ == "__main__":
    main()
