"""Path helpers for KittyProxy (framework root, static assets)."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def framework_root() -> Path:
    """Return KittySploit installation root (directory containing core/)."""
    env_home = os.environ.get("KITTYSPLOIT_HOME")
    if env_home:
        candidate = Path(env_home).expanduser().resolve()
        if (candidate / "core").is_dir():
            return candidate

    here = Path(__file__).resolve().parent
    for directory in (here, *here.parents):
        if (directory / "core").is_dir() and (directory / "core" / "framework").is_dir():
            return directory

    raise FileNotFoundError(
        "KittySploit framework root not found. Set KITTYSPLOIT_HOME to the install directory."
    )


def shared_static_img_dir() -> Path:
    """Logo/favicon shipped with the framework (interfaces/static/img)."""
    return framework_root() / "interfaces" / "static" / "img"


def browser_icons_dir() -> Path:
    return framework_root() / "core" / "browser_static" / "icons" / "browsers"
