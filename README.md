# KittyProxy

HTTP/HTTPS intercepting proxy with a web UI, packaged as a **UI** extension for [KittySploit](https://github.com/SIA-IOTechnology). It captures browser and API traffic through [mitmproxy](https://mitmproxy.org/), exposes a FastAPI backend, and ties into KittySploit modules, workspaces, and collaboration.

## Features

- **Traffic capture** — Live HTTP/HTTPS flows with search, replay, and custom requests
- **Intercept** — Hold, edit, and resume requests; configurable breakpoints
- **Scope** — Limit capture to selected hosts and paths
- **Repeater & API tester** — Resend and craft requests from the UI
- **PCAP import** — Load `.pcap` / `.pcapng` files into the flow list
- **Plugins** — Extensible interception pipeline (header modification, payload injection, URL blocklist, and more)
- **KittySploit modules** — Discover, suggest, configure, and run framework modules directly from a captured flow
- **Security tooling** — Parameter fuzzing, reflection checks, IDOR tests, JWT crack/sign, side-channel helpers
- **Collaboration** — Shared sessions, flow sync, annotations, and browser mirroring over WebSockets
- **Workspaces** — Switch between KittySploit workspace contexts from the proxy UI
- **UI extensions** — Load optional front-end extensions via a small manifest API

## Requirements

- KittySploit **≥ 1.0.0** (framework root with `core/`)
- Python dependencies (installed in the framework venv): `mitmproxy`, `uvicorn`, `fastapi`, `starlette`, `requests`, `websockets`

Without the marketplace install, the KittySploit CLI `proxy` command prompts you to run `market install kittyproxy`.

## Installation

From the KittySploit shell:

```bash
kittysploit> market install kittyproxy
```

This installs the extension under `extensions/kittyproxy/latest/` and generates **`launch_kittyproxy.py`** at the framework root (generated file, not tracked in this repository).

**Local development** (clone of this repo):

```bash
kittysploit> market install /path/to/KittyProxy
```

## Usage

After installation:

```bash
python launch_kittyproxy.py
```

Or from the extension entry point:

```bash
python src/main.py
```

| Option | Default | Description |
|--------|---------|-------------|
| `--proxy-port` | `8080` | mitmproxy listen port |
| `--api-port` | `8443` | Web UI / API port |
| `--api-host` | `127.0.0.1` | API bind address |
| `--framework-path` | *(auto)* | KittySploit root if not detected |
| `-v`, `--verbose` | off | Verbose logging |

1. Point your browser or client at **`127.0.0.1:8080`** (HTTP proxy).
2. Install the mitmproxy CA certificate when prompted (required for HTTPS).
3. Open the web UI at **`http://127.0.0.1:8443`** (or the host/port you configured).

Set `KITTYSPLOIT_HOME` to the framework install directory if auto-detection fails.

## Project layout

```
KittyProxy/
├── extension.toml          # Marketplace manifest
├── README.md
├── LICENSE
└── src/
    ├── main.py             # Entry point (paths, CLI, startup)
    └── kittyproxy/
        ├── api.py              # FastAPI routes & WebSockets
        ├── proxy_core.py       # mitmproxy wrapper & plugins
        ├── flow_manager.py
        ├── plugins/            # Built-in interception plugins
        ├── payloads/           # Fuzzing wordlists (XSS, SQLi, …)
        ├── static/             # Web UI assets
        └── ui_extensions/      # Optional UI extension loader
```

## Built-in plugins

| Plugin | Role |
|--------|------|
| `header_modifier` | Add or override request/response headers |
| `payload_injector` | Inject payloads into requests |
| `url_blocklist` | Block matching URLs |
| `kittysploit_badge` | KittySploit branding marker |

Enable and configure plugins from the web UI or via `/api/plugins`.

## Development

- Application code lives under `src/kittyproxy/`.
- `src/main.py` resolves the KittySploit framework root, initializes encryption/database via `Framework`, then starts mitmproxy and uvicorn.
- Add interception plugins by subclassing `InterceptionPlugin` in `src/kittyproxy/plugins/` (see `plugins/template.py`).

## License

MIT — see [LICENSE](LICENSE).
