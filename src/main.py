#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KittyProxy marketplace entry point.

Resolves the KittySploit framework root, then starts the proxy UI.
Application code lives under src/kittyproxy/.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _extension_base() -> Path:
    base = globals().get("__extension_base__")
    if base:
        return Path(base)
    return Path(__file__).resolve().parent.parent


def find_framework_root(start: Path | None = None) -> Path:
    """Locate KittySploit root (directory containing core/)."""
    env_home = os.environ.get("KITTYSPLOIT_HOME")
    if env_home:
        candidate = Path(env_home).resolve()
        if (candidate / "core").is_dir():
            return candidate

    search_from = (start or _extension_base()).resolve()
    for directory in (search_from, *search_from.parents):
        if (directory / "core").is_dir() and (directory / "core" / "framework").is_dir():
            return directory

    raise FileNotFoundError(
        "KittySploit framework root not found. Set KITTYSPLOIT_HOME or install KittySploit."
    )


def setup_paths() -> tuple[Path, Path]:
    """Configure sys.path for extension + framework."""
    ext_base = _extension_base()
    framework_root = find_framework_root(ext_base)

    for path in (framework_root, ext_base, ext_base / "src"):
        path_str = str(path)
        if path.exists() and path_str not in sys.path:
            sys.path.insert(0, path_str)

    return ext_base, framework_root


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="KittySploit Proxy Interface")
    parser.add_argument("--framework-path", type=str, default=None, help="Framework root directory")
    parser.add_argument("--proxy-port", type=int, default=8080, help="Proxy port (default: 8080)")
    parser.add_argument("--api-port", type=int, default=8443, help="API port (default: 8443)")
    parser.add_argument("--api-host", type=str, default="127.0.0.1", help="API bind address")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    return parser.parse_args()


def _run_proxy() -> int:
    args = _parse_args()

    from core.utils.venv_helper import ensure_venv

    ensure_venv(str(find_framework_root()))

    try:
        from mitmproxy import http  # noqa: F401
    except ImportError:
        from core.output_handler import print_error, print_info

        print_error("mitmproxy is not installed!")
        print_info("Install it with: pip install mitmproxy")
        return 1

    try:
        import uvicorn
    except ImportError:
        from core.output_handler import print_error, print_info

        print_error("uvicorn is not installed!")
        print_info("Install it with: pip install uvicorn")
        return 1

    from core.framework.framework import Framework
    from core.output_handler import print_error, print_info, print_success

    from kittyproxy.proxy_core import MitmProxyWrapper
    from kittyproxy.api import app, set_framework

    if args.framework_path:
        fw_path = str(Path(args.framework_path).resolve())
        if fw_path not in sys.path:
            sys.path.insert(0, fw_path)

    print_success("=" * 60)
    print_success("KittySploit Proxy Interface")
    print_success("=" * 60)

    proxy = None
    try:
        if args.verbose:
            print_info("Initializing framework...")
        framework = Framework(clean_sessions=False)
        if not framework.check_charter_acceptance():
            print_info("First startup of KittySploit")
            if not framework.prompt_charter_acceptance():
                print_error("Charter not accepted. Stopping.")
                return 1
        if not framework.is_encryption_initialized():
            print_info("Setting up encryption...")
            if not framework.initialize_encryption():
                print_error("Failed to initialize encryption.")
                return 1
        elif not framework.load_encryption():
            print_error("Failed to load encryption. Database remains locked.")
            return 1
        set_framework(framework)
        if args.verbose:
            print_success("Framework initialized")

        proxy = MitmProxyWrapper(
            host="127.0.0.1",
            port=args.proxy_port,
            api_host=args.api_host,
            api_port=args.api_port,
        )
        proxy.start()
        print_success(f"Proxy started on 127.0.0.1:{args.proxy_port}")

        print_success("=" * 60)
        print_info(f"Web interface: http://{args.api_host}:{args.api_port}")
        print_info(f"Proxy: 127.0.0.1:{args.proxy_port}")
        print_info("Press Ctrl+C to stop")
        print_success("=" * 60)

        uvicorn.run(
            app,
            host=args.api_host,
            port=args.api_port,
            log_level="info" if args.verbose else "warning",
        )
    except KeyboardInterrupt:
        print_info("\nStopping server...")
    except Exception as exc:
        print_error(f"Error: {exc}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1
    finally:
        if proxy is not None:
            try:
                proxy.stop()
            except Exception:
                pass

    print_success("Server stopped.")
    return 0


def main() -> int:
    setup_paths()
    return _run_proxy()


if __name__ == "__main__":
    sys.exit(main())
