"""Browser-oriented security analysis for captured KittyProxy flows.

The workbench deliberately stays dependency-free so it can analyze live,
database-restored, and PCAP-imported flow dictionaries alike.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import time
from collections import Counter, defaultdict
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, parse_qsl, quote_plus, urlencode, urlparse, urlunparse


ASVS_VERSION = "5.0.0"
ALL_CATEGORIES = ("dom", "csp", "headers", "cookies", "auth", "websocket", "graphql")
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
MAX_ANALYZED_BODY_BYTES = 2_000_000
MAX_EVIDENCE_LENGTH = 420

SENSITIVE_NAME_RE = re.compile(
    r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|authorization|session|sid|jwt|authorization[_-]?code)",
    re.IGNORECASE,
)
AUTH_COOKIE_RE = re.compile(
    r"(?:session|sess|sid|auth|token|jwt|remember|identity|sso|connect\.sid)",
    re.IGNORECASE,
)
AUTH_PATH_RE = re.compile(
    r"/(?:login|signin|sign-in|logout|signout|register|signup|oauth|oidc|authorize|"
    r"callback|token|refresh|session|mfa|2fa|password|forgot|reset)(?:/|$)",
    re.IGNORECASE,
)
CSRF_NAME_RE = re.compile(r"(?:csrf|xsrf|anti[-_]?forgery|requestverificationtoken)", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*\b")
SECRET_VALUE_RE = re.compile(
    r'(?i)(?:access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|secret|password)'
    r'\s*["\']?\s*[:=]\s*["\']([^"\']{6,})'
)

DOM_SINKS = {
    "innerHTML": re.compile(r"\.(?:innerHTML|outerHTML)\s*(?:=|\+=)", re.IGNORECASE),
    "document.write": re.compile(r"document\.(?:write|writeln)\s*\(", re.IGNORECASE),
    "insertAdjacentHTML": re.compile(r"\.insertAdjacentHTML\s*\(", re.IGNORECASE),
    "eval": re.compile(r"(?:^|[^\w])eval\s*\(", re.IGNORECASE),
    "Function": re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
    "string timer": re.compile(r"(?:setTimeout|setInterval)\s*\(\s*['\"]", re.IGNORECASE),
    "jQuery.html": re.compile(r"\.(?:html|append|prepend)\s*\(", re.IGNORECASE),
}
DOM_SOURCES = {
    "location": re.compile(r"(?:window\.)?location\.(?:hash|search|href)", re.IGNORECASE),
    "document URL": re.compile(r"document\.(?:URL|documentURI|referrer)", re.IGNORECASE),
    "window.name": re.compile(r"window\.name", re.IGNORECASE),
    "postMessage": re.compile(r"(?:addEventListener\s*\(\s*['\"]message|onmessage\s*=)", re.IGNORECASE),
    "URLSearchParams": re.compile(r"(?:new\s+)?URLSearchParams\s*\(", re.IGNORECASE),
    "storage": re.compile(r"(?:localStorage|sessionStorage)\.getItem\s*\(", re.IGNORECASE),
}

RULE_ASVS = {
    "DOM_TAINTED_SINK": ("v5.0.0-1.2.1", "v5.0.0-1.3.2", "v5.0.0-3.2.2"),
    "DOM_DANGEROUS_SINK": ("v5.0.0-1.3.2", "v5.0.0-3.2.2"),
    "POSTMESSAGE_ORIGIN_UNCHECKED": ("v5.0.0-3.5.5",),
    "TOKEN_IN_WEB_STORAGE": ("v5.0.0-10.1.1",),
    "CSP_MISSING": ("v5.0.0-3.4.3",),
    "CSP_REPORT_ONLY": ("v5.0.0-3.4.3",),
    "CSP_UNSAFE_SCRIPT": ("v5.0.0-3.4.3",),
    "CSP_WEAK_BASELINE": ("v5.0.0-3.4.3",),
    "HSTS_MISSING": ("v5.0.0-3.4.1",),
    "HSTS_WEAK": ("v5.0.0-3.4.1",),
    "NOSNIFF_MISSING": ("v5.0.0-3.4.4",),
    "FRAME_ANCESTORS_MISSING": ("v5.0.0-3.4.6",),
    "REFERRER_POLICY_MISSING": ("v5.0.0-3.4.5",),
    "COOP_MISSING": ("v5.0.0-3.4.8",),
    "CORS_WILDCARD_CREDENTIALS": ("v5.0.0-3.4.2",),
    "CORS_ORIGIN_REFLECTION": ("v5.0.0-3.4.2",),
    "COOKIE_SECURE_MISSING": ("v5.0.0-3.3.1",),
    "COOKIE_HTTPONLY_MISSING": ("v5.0.0-3.3.4",),
    "COOKIE_SAMESITE_MISSING": ("v5.0.0-3.3.2",),
    "COOKIE_SAMESITE_NONE_INSECURE": ("v5.0.0-3.3.1", "v5.0.0-3.3.2"),
    "COOKIE_PREFIX_INVALID": ("v5.0.0-3.3.1", "v5.0.0-3.3.3"),
    "SENSITIVE_DATA_IN_URL": ("v5.0.0-3.4.5", "v5.0.0-10.1.1"),
    "AUTH_OVER_HTTP": ("v5.0.0-3.4.1", "v5.0.0-10.1.1"),
    "AUTH_RESPONSE_CACHEABLE": ("v5.0.0-10.1.1",),
    "JWT_NONE_ALGORITHM": ("v5.0.0-9.1.1", "v5.0.0-9.1.2"),
    "OAUTH_STATE_MISSING": ("v5.0.0-10.2.1",),
    "OAUTH_PKCE_MISSING": ("v5.0.0-10.4.6",),
    "OAUTH_IMPLICIT_OR_PASSWORD_GRANT": ("v5.0.0-10.4.4",),
    "POTENTIAL_CSRF": ("v5.0.0-3.5.1", "v5.0.0-3.5.2"),
    "WEBSOCKET_CLEAR_TEXT": ("v5.0.0-4.4.1",),
    "WEBSOCKET_ORIGIN_MISSING": ("v5.0.0-4.4.2",),
    "WEBSOCKET_TOKEN_IN_URL": ("v5.0.0-4.4.3", "v5.0.0-10.1.1"),
    "WEBSOCKET_SECRET_EXPOSURE": ("v5.0.0-4.4.3",),
    "GRAPHQL_INTROSPECTION_ENABLED": ("v5.0.0-4.3.2",),
    "GRAPHQL_MUTATION_OVER_GET": ("v5.0.0-3.5.3",),
    "GRAPHQL_DEBUG_ERROR": ("v5.0.0-4.3.1",),
    "GRAPHQL_COMPLEX_QUERY": ("v5.0.0-4.3.1",),
    "GRAPHQL_BATCHING_ENABLED": ("v5.0.0-4.3.1",),
    "GRAPHQL_CSRF_SURFACE": ("v5.0.0-3.5.1", "v5.0.0-3.5.2"),
}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _headers_dict(headers: Any) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    if not headers:
        return normalized
    items = headers.items() if hasattr(headers, "items") else []
    for key, value in items:
        name = _as_text(key).strip().lower()
        if not name:
            continue
        if isinstance(value, (list, tuple)):
            text = ", ".join(_as_text(item) for item in value)
        else:
            text = _as_text(value)
        normalized[name] = text
    return normalized


def _decode_body(part: Optional[Dict[str, Any]]) -> Tuple[bytes, str]:
    if not isinstance(part, dict):
        return b"", ""
    encoded = part.get("content_bs64") or part.get("body_b64") or ""
    if encoded:
        try:
            raw = base64.b64decode(encoded, validate=False)
        except Exception:
            raw = b""
    else:
        value = part.get("content") or part.get("body") or b""
        raw = value if isinstance(value, bytes) else _as_text(value).encode("utf-8", errors="replace")
    raw = raw[:MAX_ANALYZED_BODY_BYTES]
    return raw, raw.decode("utf-8", errors="replace")


def _redact(text: Any) -> str:
    value = _as_text(text).replace("\r", " ").replace("\n", " ").strip()
    value = JWT_RE.sub("<redacted-jwt>", value)
    value = re.sub(
        r"(?i)(authorization\s*[:=]\s*)(?:bearer|basic)\s+\S+",
        r"\1<redacted>",
        value,
    )
    value = re.sub(
        r"""(?ix)
        (["']?(?:authorization|cookie|set-cookie|password|secret|token|api[_-]?key)["']?
        \s*[:=]\s*["']?)
        ([^"',;\s}\]]+)
        """,
        r"\1<redacted>",
        value,
    )
    if len(value) > MAX_EVIDENCE_LENGTH:
        value = value[:MAX_EVIDENCE_LENGTH] + "…"
    return value


def _evidence(text: str, match: Optional[re.Match[str]] = None) -> str:
    if not text:
        return ""
    if match is None:
        return _redact(text[:MAX_EVIDENCE_LENGTH])
    start = max(0, match.start() - 90)
    end = min(len(text), match.end() + 160)
    return _redact(text[start:end])


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return url
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _is_sensitive_name(name: str) -> bool:
    normalized = (name or "").strip().lower()
    return normalized == "code" or bool(SENSITIVE_NAME_RE.search(normalized))


def _is_html(url: str, response_headers: Dict[str, str], body: str) -> bool:
    content_type = response_headers.get("content-type", "").lower()
    return (
        "text/html" in content_type
        or "application/xhtml+xml" in content_type
        or urlparse(url).path.lower().endswith((".html", ".htm"))
        or bool(re.search(r"<(?:!doctype\s+html|html|head|body)\b", body[:4000], re.IGNORECASE))
    )


def _is_script(url: str, response_headers: Dict[str, str]) -> bool:
    content_type = response_headers.get("content-type", "").lower()
    return "javascript" in content_type or urlparse(url).path.lower().endswith((".js", ".mjs"))


def _is_local_host(hostname: str) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".localhost")


def _parse_csp(value: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for chunk in (value or "").split(";"):
        parts = chunk.strip().split()
        if parts:
            directives[parts[0].lower()] = [part.lower() for part in parts[1:]]
    return directives


def _set_cookie_headers(response: Dict[str, Any], headers: Dict[str, str]) -> List[str]:
    values = response.get("set_cookie_headers") if isinstance(response, dict) else None
    if isinstance(values, list):
        return [_as_text(value) for value in values if value]
    raw = headers.get("set-cookie", "")
    return [raw] if raw else []


def _parse_cookie(header: str) -> Optional[Dict[str, Any]]:
    if not header or "=" not in header:
        return None
    first, *attribute_parts = header.split(";")
    name, _, value = first.partition("=")
    name = name.strip()
    if not name:
        return None
    attrs: Dict[str, Any] = {}
    for part in attribute_parts:
        key, sep, attr_value = part.strip().partition("=")
        if key:
            attrs[key.lower()] = attr_value.strip() if sep else True
    return {"name": name, "value": value.strip(), "attributes": attrs}


def _extract_graphql_payload(method: str, url: str, headers: Dict[str, str], body: str) -> Tuple[str, Any]:
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    if query_params.get("query"):
        return query_params["query"][0], None
    if not body.strip():
        return "", None
    try:
        payload = json.loads(body)
    except Exception:
        payload = None
    if isinstance(payload, dict):
        return _as_text(payload.get("query")), payload
    if isinstance(payload, list):
        queries = [_as_text(item.get("query")) for item in payload if isinstance(item, dict)]
        return "\n".join(queries), payload
    if "application/graphql" in headers.get("content-type", "").lower():
        return body, None
    return "", payload


def _jwt_algorithm(token: str) -> str:
    try:
        header = token.split(".", 1)[0]
        padding = "=" * (-len(header) % 4)
        decoded = base64.urlsafe_b64decode(header + padding)
        data = json.loads(decoded.decode("utf-8", errors="replace"))
        return _as_text(data.get("alg")).lower()
    except Exception:
        return ""


def _query_without_sensitive_values(url: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qs(parsed.query, keep_blank_values=True)
    cleaned = []
    for key, values in pairs.items():
        for value in values:
            cleaned.append((key, "<redacted>" if _is_sensitive_name(key) else value))
    return urlunparse(parsed._replace(query=urlencode(cleaned, doseq=True)))


class SecurityWorkbench:
    """Analyze captured browser/API flows and generate regression artifacts."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_report: Optional[Dict[str, Any]] = None

    def get_last_report(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return deepcopy(self._last_report)

    def clear(self) -> None:
        with self._lock:
            self._last_report = None

    def analyze(
        self,
        flows: Sequence[Dict[str, Any]],
        categories: Optional[Iterable[str]] = None,
        host: Optional[str] = None,
        store: bool = True,
    ) -> Dict[str, Any]:
        enabled = {item.lower() for item in (categories or ALL_CATEGORIES)}
        enabled &= set(ALL_CATEGORIES)
        if not enabled:
            enabled = set(ALL_CATEGORIES)
        host_filter = (host or "").strip().lower()
        started = time.perf_counter()
        findings: List[Dict[str, Any]] = []
        observations = {
            "auth_flows": [],
            "websocket_flows": [],
            "graphql_flows": [],
        }
        scanned: List[Dict[str, Any]] = []

        for raw_flow in flows:
            if not isinstance(raw_flow, dict):
                continue
            flow = raw_flow
            url = _as_text(flow.get("url") or (flow.get("request") or {}).get("url"))
            if not url:
                continue
            if host_filter and host_filter not in _host(url):
                continue
            scanned.append(flow)
            context = self._context(flow, url)
            if "dom" in enabled:
                self._analyze_dom(context, findings)
            if "csp" in enabled:
                self._analyze_csp(context, findings)
            if "headers" in enabled:
                self._analyze_headers(context, findings)
            if "cookies" in enabled:
                self._analyze_cookies(context, findings)
            if "auth" in enabled:
                self._analyze_auth(context, findings, observations)
            if "websocket" in enabled:
                self._analyze_websocket(context, findings, observations)
            if "graphql" in enabled:
                self._analyze_graphql(context, findings, observations)

        findings = self._deduplicate(findings)
        findings.sort(
            key=lambda item: (
                -SEVERITY_RANK.get(item["severity"], 0),
                item["category"],
                item["title"],
                item["url"],
            )
        )
        severity_counts = Counter(item["severity"] for item in findings)
        category_counts = Counter(item["category"] for item in findings)
        asvs_requirements = sorted({req for item in findings for req in item.get("asvs", [])})
        flow_ids = [_as_text(flow.get("id")) for flow in scanned if flow.get("id")]
        report_id = hashlib.sha256(
            ("|".join(flow_ids) + "|" + str(time.time_ns())).encode("utf-8")
        ).hexdigest()[:16]

        report = {
            "report_id": report_id,
            "generated_at": time.time(),
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "scope": {
                "host": host_filter or None,
                "categories": sorted(enabled),
                "flow_count": len(scanned),
            },
            "summary": {
                "total_findings": len(findings),
                "severity": {name: severity_counts.get(name, 0) for name in SEVERITY_RANK},
                "categories": {name: category_counts.get(name, 0) for name in ALL_CATEGORIES},
                "replayable_flows": len(set(flow_ids)),
            },
            "asvs": {
                "version": ASVS_VERSION,
                "mapped_requirements": asvs_requirements,
                "mapped_requirement_count": len(asvs_requirements),
                "note": "Heuristic evidence mapping; this is not an ASVS compliance certification.",
            },
            "findings": findings,
            "observations": observations,
        }
        if store:
            with self._lock:
                self._last_report = deepcopy(report)
        return report

    def _context(self, flow: Dict[str, Any], url: str) -> Dict[str, Any]:
        request = flow.get("request") if isinstance(flow.get("request"), dict) else {}
        response = flow.get("response") if isinstance(flow.get("response"), dict) else {}
        request_headers = _headers_dict(request.get("headers"))
        response_headers = _headers_dict(response.get("headers"))
        _, request_body = _decode_body(request)
        _, response_body = _decode_body(response)
        method = _as_text(flow.get("method") or request.get("method") or "GET").upper()
        status = flow.get("status_code")
        if status is None:
            status = response.get("status_code")
        parsed = urlparse(url)
        is_websocket = bool(flow.get("is_websocket")) or response_headers.get("upgrade", "").lower() == "websocket"
        is_websocket = is_websocket or request_headers.get("upgrade", "").lower() == "websocket"
        is_graphql = bool(
            re.search(r"/(?:graphql|gql)(?:/|$)", parsed.path, re.IGNORECASE)
            or "application/graphql" in request_headers.get("content-type", "").lower()
            or re.search(r"\b(?:query|mutation|subscription)\b", request_body[:2000], re.IGNORECASE)
        )
        return {
            "flow": flow,
            "flow_id": _as_text(flow.get("id")),
            "url": url,
            "origin": _origin(url),
            "host": (parsed.hostname or "").lower(),
            "scheme": parsed.scheme.lower(),
            "path": parsed.path,
            "method": method,
            "status": status,
            "request": request,
            "response": response,
            "request_headers": request_headers,
            "response_headers": response_headers,
            "request_body": request_body,
            "response_body": response_body,
            "is_html": _is_html(url, response_headers, response_body),
            "is_script": _is_script(url, response_headers),
            "is_websocket": is_websocket,
            "is_graphql": is_graphql,
            "ws_messages": flow.get("ws_messages") or flow.get("messages") or [],
        }

    def _add(
        self,
        findings: List[Dict[str, Any]],
        ctx: Dict[str, Any],
        rule_id: str,
        title: str,
        severity: str,
        category: str,
        description: str,
        remediation: str,
        evidence: str = "",
        confidence: str = "high",
        scope_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        identity = f"{rule_id}|{scope_key or ctx['url']}|{(metadata or {}).get('cookie_name', '')}"
        finding_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        findings.append(
            {
                "id": finding_id,
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "category": category,
                "description": description,
                "remediation": remediation,
                "evidence": _redact(evidence),
                "url": _query_without_sensitive_values(ctx["url"]),
                "host": ctx["host"],
                "flow_ids": [ctx["flow_id"]] if ctx["flow_id"] else [],
                "asvs": list(RULE_ASVS.get(rule_id, ())),
                "metadata": metadata or {},
                "_dedupe_key": identity,
            }
        )

    def _analyze_dom(self, ctx: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        if not (ctx["is_html"] or ctx["is_script"]):
            return
        body = ctx["response_body"]
        if not body:
            return
        sinks = [(name, pattern.search(body)) for name, pattern in DOM_SINKS.items()]
        sinks = [(name, match) for name, match in sinks if match]
        sources = [(name, pattern.search(body)) for name, pattern in DOM_SOURCES.items()]
        sources = [(name, match) for name, match in sources if match]
        if sinks and sources:
            sink_names = ", ".join(name for name, _ in sinks[:3])
            source_names = ", ".join(name for name, _ in sources[:3])
            self._add(
                findings,
                ctx,
                "DOM_TAINTED_SINK",
                "Attacker-controlled DOM source and executable sink coexist",
                "high",
                "dom",
                f"The client code contains source(s) {source_names} and sink(s) {sink_names}. "
                "Static proximity is not proof of exploitability, but this is a high-value DOM XSS path.",
                "Trace the data flow, replace HTML/code sinks with textContent or typed DOM APIs, and apply "
                "context-appropriate sanitization at the final sink.",
                _evidence(body, sinks[0][1]),
                "medium",
                scope_key=f"{ctx['url']}|{sink_names}|{source_names}",
                metadata={"sinks": [name for name, _ in sinks], "sources": [name for name, _ in sources]},
            )
        elif sinks and any(name in {"eval", "Function", "string timer"} for name, _ in sinks):
            self._add(
                findings,
                ctx,
                "DOM_DANGEROUS_SINK",
                "Dynamic JavaScript execution primitive detected",
                "medium",
                "dom",
                "The response uses a JavaScript execution primitive that becomes dangerous when any input "
                "can influence its argument.",
                "Remove dynamic code execution. If unavoidable, strictly validate against an allowlist and "
                "keep untrusted data out of the executed expression.",
                _evidence(body, sinks[0][1]),
                "medium",
                metadata={"sinks": [name for name, _ in sinks]},
            )

        message_handler = re.search(
            r"(?:addEventListener\s*\(\s*['\"]message['\"]|onmessage\s*=)", body, re.IGNORECASE
        )
        if message_handler:
            nearby = body[message_handler.start() : message_handler.start() + 2400]
            if not re.search(r"\b(?:event|e|message)\.origin\b", nearby):
                self._add(
                    findings,
                    ctx,
                    "POSTMESSAGE_ORIGIN_UNCHECKED",
                    "postMessage handler has no visible origin validation",
                    "high",
                    "dom",
                    "A message event handler was found without an origin check in the surrounding code.",
                    "Validate event.origin against an exact allowlist and validate the message schema before "
                    "using any received data.",
                    _evidence(body, message_handler),
                    "medium",
                )

        storage_token = re.search(
            r"(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*['\"][^'\"]*"
            r"(?:token|jwt|session|auth)",
            body,
            re.IGNORECASE,
        )
        if storage_token:
            self._add(
                findings,
                ctx,
                "TOKEN_IN_WEB_STORAGE",
                "Authentication material is handled in Web Storage",
                "high",
                "dom",
                "Client code stores or reads token-like authentication material from localStorage/sessionStorage, "
                "where any successful XSS can access it.",
                "Prefer an HttpOnly, Secure, SameSite cookie or a backend-for-frontend pattern that keeps access "
                "and refresh tokens outside JavaScript.",
                _evidence(body, storage_token),
                "high",
            )

    def _analyze_csp(self, ctx: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        if not ctx["is_html"] or not ctx["response"]:
            return
        headers = ctx["response_headers"]
        csp = headers.get("content-security-policy", "").strip()
        report_only = headers.get("content-security-policy-report-only", "").strip()
        if not csp:
            rule = "CSP_REPORT_ONLY" if report_only else "CSP_MISSING"
            title = "CSP is report-only and not enforced" if report_only else "Content Security Policy is missing"
            self._add(
                findings,
                ctx,
                rule,
                title,
                "medium",
                "csp",
                "The rendered document has no enforced Content-Security-Policy header.",
                "Deploy an enforced CSP. Start with a restrictive default-src and include object-src 'none', "
                "base-uri 'none', and frame-ancestors; use nonces or hashes for scripts.",
                report_only or "No Content-Security-Policy response header",
                "high",
                scope_key=ctx["origin"],
            )
            return
        directives = _parse_csp(csp)
        script_sources = directives.get("script-src", directives.get("default-src", []))
        unsafe = [token for token in ("'unsafe-inline'", "'unsafe-eval'", "*") if token in script_sources]
        if unsafe:
            severity = "high" if "'unsafe-eval'" in unsafe or "*" in unsafe else "medium"
            self._add(
                findings,
                ctx,
                "CSP_UNSAFE_SCRIPT",
                "CSP permits unsafe script execution",
                severity,
                "csp",
                f"The effective script policy contains: {', '.join(unsafe)}.",
                "Remove unsafe-eval and wildcard script sources. Replace unsafe-inline with per-response nonces "
                "or hashes and migrate inline handlers.",
                csp,
                "high",
                scope_key=ctx["origin"],
                metadata={"unsafe_tokens": unsafe},
            )
        missing = []
        if directives.get("object-src") != ["'none'"]:
            missing.append("object-src 'none'")
        if directives.get("base-uri") != ["'none'"]:
            missing.append("base-uri 'none'")
        if "frame-ancestors" not in directives:
            missing.append("frame-ancestors")
        if missing:
            self._add(
                findings,
                ctx,
                "CSP_WEAK_BASELINE",
                "CSP misses baseline hardening directives",
                "medium",
                "csp",
                "The policy is enforced but omits or weakens required baseline directives: " + ", ".join(missing),
                "Add object-src 'none', base-uri 'none', and an explicit frame-ancestors policy appropriate "
                "for the application.",
                csp,
                "high",
                scope_key=ctx["origin"],
                metadata={"missing_directives": missing},
            )

    def _analyze_headers(self, ctx: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        if not ctx["response"]:
            return
        headers = ctx["response_headers"]
        origin_scope = ctx["origin"]
        if ctx["scheme"] == "https":
            hsts = headers.get("strict-transport-security", "")
            if not hsts:
                self._add(
                    findings,
                    ctx,
                    "HSTS_MISSING",
                    "HSTS header is missing",
                    "medium",
                    "headers",
                    "An HTTPS response does not declare Strict-Transport-Security.",
                    "Return Strict-Transport-Security on all HTTPS responses with max-age of at least 31536000; "
                    "includeSubDomains is expected for ASVS level 2 and above.",
                    "No Strict-Transport-Security response header",
                    scope_key=origin_scope,
                )
            else:
                max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
                if not max_age_match or int(max_age_match.group(1)) < 31_536_000:
                    self._add(
                        findings,
                        ctx,
                        "HSTS_WEAK",
                        "HSTS max-age is below one year",
                        "low",
                        "headers",
                        "The HSTS policy is present but does not meet the ASVS one-year minimum.",
                        "Set max-age to at least 31536000 and assess includeSubDomains and preload.",
                        hsts,
                        scope_key=origin_scope,
                    )
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            self._add(
                findings,
                ctx,
                "NOSNIFF_MISSING",
                "MIME sniffing protection is missing",
                "low",
                "headers",
                "The response does not set X-Content-Type-Options: nosniff.",
                "Add X-Content-Type-Options: nosniff to every response and return an accurate Content-Type.",
                headers.get("x-content-type-options") or "Header absent",
                scope_key=origin_scope,
            )
        if ctx["is_html"]:
            csp = _parse_csp(headers.get("content-security-policy", ""))
            if "frame-ancestors" not in csp:
                self._add(
                    findings,
                    ctx,
                    "FRAME_ANCESTORS_MISSING",
                    "No enforced frame-ancestors policy",
                    "medium",
                    "headers",
                    "The rendered document can potentially be embedded because CSP frame-ancestors is absent.",
                    "Set CSP frame-ancestors 'none' or a minimal allowlist. X-Frame-Options can remain as a "
                    "legacy defense but is not the ASVS control.",
                    headers.get("x-frame-options") or "frame-ancestors absent",
                    scope_key=origin_scope,
                )
            if not headers.get("referrer-policy"):
                self._add(
                    findings,
                    ctx,
                    "REFERRER_POLICY_MISSING",
                    "Referrer Policy is missing",
                    "low",
                    "headers",
                    "The document does not explicitly limit referrer information sent to other origins.",
                    "Set Referrer-Policy, commonly strict-origin-when-cross-origin or no-referrer for sensitive apps.",
                    "No Referrer-Policy response header",
                    scope_key=origin_scope,
                )
            if not headers.get("cross-origin-opener-policy"):
                self._add(
                    findings,
                    ctx,
                    "COOP_MISSING",
                    "Cross-Origin-Opener-Policy is missing",
                    "low",
                    "headers",
                    "The document does not isolate its top-level browsing context from cross-origin windows.",
                    "Set Cross-Origin-Opener-Policy: same-origin, or same-origin-allow-popups when required.",
                    "No Cross-Origin-Opener-Policy response header",
                    scope_key=origin_scope,
                )
        acao = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
        if acao == "*" and credentials:
            self._add(
                findings,
                ctx,
                "CORS_WILDCARD_CREDENTIALS",
                "Credentialed CORS uses a wildcard origin",
                "critical",
                "headers",
                "The response combines Access-Control-Allow-Origin: * with credentialed CORS.",
                "Use an exact allowlist of trusted origins and never combine wildcard origins with credentials.",
                f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true",
                scope_key=ctx["origin"],
            )
        request_origin = ctx["request_headers"].get("origin", "")
        if credentials and request_origin and acao == request_origin and request_origin != ctx["origin"]:
            self._add(
                findings,
                ctx,
                "CORS_ORIGIN_REFLECTION",
                "Credentialed CORS may reflect arbitrary origins",
                "high",
                "headers",
                "The response mirrors the request Origin while allowing credentials. A single observation cannot "
                "prove the origin is untrusted, so replay with a controlled origin.",
                "Validate Origin against an exact server-side allowlist before reflecting it, and send Vary: Origin.",
                f"Origin: {request_origin}; Access-Control-Allow-Origin: {acao}",
                "medium",
                scope_key=ctx["origin"],
            )

    def _analyze_cookies(self, ctx: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        if not ctx["response"]:
            return
        for header in _set_cookie_headers(ctx["response"], ctx["response_headers"]):
            cookie = _parse_cookie(header)
            if not cookie:
                continue
            name = cookie["name"]
            attrs = cookie["attributes"]
            auth_cookie = bool(AUTH_COOKIE_RE.search(name))
            metadata = {"cookie_name": name}
            scope = f"{ctx['origin']}|{name.lower()}"
            if ctx["scheme"] == "https" and "secure" not in attrs:
                self._add(
                    findings,
                    ctx,
                    "COOKIE_SECURE_MISSING",
                    f"Cookie {name} lacks Secure",
                    "high" if auth_cookie else "medium",
                    "cookies",
                    "A cookie issued over HTTPS can be sent over an unencrypted connection because Secure is absent.",
                    "Set Secure on every cookie. Prefer __Host- for host-bound cookies or __Secure- where sharing "
                    "across paths/domains is required.",
                    f"Set-Cookie: {name}=<redacted>; attributes={', '.join(attrs) or 'none'}",
                    scope_key=scope,
                    metadata=metadata,
                )
            if auth_cookie and "httponly" not in attrs:
                self._add(
                    findings,
                    ctx,
                    "COOKIE_HTTPONLY_MISSING",
                    f"Session-like cookie {name} lacks HttpOnly",
                    "high",
                    "cookies",
                    "A session-like cookie is readable by JavaScript, increasing token theft impact after XSS.",
                    "Set HttpOnly and ensure the same session token is never exposed through response bodies or "
                    "JavaScript-accessible storage.",
                    f"Set-Cookie: {name}=<redacted>; attributes={', '.join(attrs) or 'none'}",
                    scope_key=scope,
                    metadata=metadata,
                )
            same_site = _as_text(attrs.get("samesite")).lower()
            if not same_site:
                self._add(
                    findings,
                    ctx,
                    "COOKIE_SAMESITE_MISSING",
                    f"Cookie {name} has no SameSite attribute",
                    "medium" if auth_cookie else "low",
                    "cookies",
                    "The cookie relies on browser defaults instead of declaring its intended cross-site behavior.",
                    "Set SameSite=Lax or Strict where possible. Use SameSite=None only for a documented cross-site "
                    "use case and always combine it with Secure.",
                    f"Set-Cookie: {name}=<redacted>; SameSite absent",
                    scope_key=scope,
                    metadata=metadata,
                )
            elif same_site == "none" and "secure" not in attrs:
                self._add(
                    findings,
                    ctx,
                    "COOKIE_SAMESITE_NONE_INSECURE",
                    f"Cookie {name} uses SameSite=None without Secure",
                    "high",
                    "cookies",
                    "Modern browsers may reject this cookie, and older clients can send it cross-site over HTTP.",
                    "Add Secure and confirm that cross-site cookie delivery is actually required.",
                    f"Set-Cookie: {name}=<redacted>; SameSite=None",
                    scope_key=scope,
                    metadata=metadata,
                )
            prefix_problem = False
            if name.startswith("__Host-"):
                prefix_problem = "secure" not in attrs or "domain" in attrs or attrs.get("path") != "/"
            elif name.startswith("__Secure-"):
                prefix_problem = "secure" not in attrs
            if prefix_problem:
                self._add(
                    findings,
                    ctx,
                    "COOKIE_PREFIX_INVALID",
                    f"Cookie prefix contract is invalid for {name}",
                    "high",
                    "cookies",
                    "The cookie uses a security prefix without satisfying the browser-enforced attribute contract.",
                    "For __Host-, set Secure and Path=/ and omit Domain. For __Secure-, set Secure.",
                    f"Set-Cookie: {name}=<redacted>; attributes={attrs}",
                    scope_key=scope,
                    metadata=metadata,
                )

    def _analyze_auth(
        self,
        ctx: Dict[str, Any],
        findings: List[Dict[str, Any]],
        observations: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        parsed = urlparse(ctx["url"])
        params = parse_qs(parsed.query, keep_blank_values=True)
        auth_header = ctx["request_headers"].get("authorization", "")
        cookie_header = ctx["request_headers"].get("cookie", "")
        is_auth_path = bool(AUTH_PATH_RE.search(parsed.path))
        has_auth_material = bool(auth_header or cookie_header or is_auth_path)
        if has_auth_material:
            kind = "authentication"
            lower_path = parsed.path.lower()
            if "logout" in lower_path or "signout" in lower_path:
                kind = "logout"
            elif "refresh" in lower_path:
                kind = "token_refresh"
            elif "callback" in lower_path:
                kind = "oauth_callback"
            observations["auth_flows"].append(
                {
                    "flow_id": ctx["flow_id"],
                    "method": ctx["method"],
                    "url": _query_without_sensitive_values(ctx["url"]),
                    "status_code": ctx["status"],
                    "kind": kind,
                }
            )
        sensitive_params = sorted(key for key in params if _is_sensitive_name(key))
        if sensitive_params:
            self._add(
                findings,
                ctx,
                "SENSITIVE_DATA_IN_URL",
                "Sensitive authentication data appears in the URL",
                "high",
                "auth",
                "Token or credential-like query parameters can leak through history, logs, analytics, and referrers: "
                + ", ".join(sensitive_params),
                "Move secrets to an Authorization header or a protected request body. Remove them from URLs and "
                "rotate any value that may already have been logged.",
                _query_without_sensitive_values(ctx["url"]),
                scope_key=f"{ctx['origin']}|{parsed.path}|{','.join(sensitive_params)}",
                metadata={"parameters": sensitive_params},
            )
        if ctx["scheme"] == "http" and has_auth_material and not _is_local_host(ctx["host"]):
            self._add(
                findings,
                ctx,
                "AUTH_OVER_HTTP",
                "Authentication flow uses clear-text HTTP",
                "critical" if auth_header.lower().startswith("basic ") else "high",
                "auth",
                "Credentials, session cookies, or authentication responses can be intercepted or modified in transit.",
                "Serve the entire authentication flow over HTTPS, redirect browser entry points, reject direct "
                "clear-text API authentication, and deploy HSTS.",
                f"{ctx['method']} {_query_without_sensitive_values(ctx['url'])}",
                scope_key=ctx["origin"],
            )
        response_contains_token = bool(
            JWT_RE.search(ctx["response_body"]) or SECRET_VALUE_RE.search(ctx["response_body"])
        )
        if response_contains_token and is_auth_path:
            cache_control = ctx["response_headers"].get("cache-control", "").lower()
            pragma = ctx["response_headers"].get("pragma", "").lower()
            if "no-store" not in cache_control and "no-cache" not in pragma:
                self._add(
                    findings,
                    ctx,
                    "AUTH_RESPONSE_CACHEABLE",
                    "Authentication response containing a token may be cached",
                    "medium",
                    "auth",
                    "A token-bearing response does not visibly prohibit storage by browsers and intermediaries.",
                    "Return Cache-Control: no-store (and Pragma: no-cache where legacy support is required) on "
                    "authentication and token responses.",
                    f"Cache-Control: {cache_control or '<absent>'}",
                    scope_key=f"{ctx['origin']}|{parsed.path}",
                )
        jwt_candidates = JWT_RE.findall(
            "\n".join((auth_header, cookie_header, ctx["request_body"], ctx["response_body"]))
        )
        if any(_jwt_algorithm(token) == "none" for token in jwt_candidates):
            self._add(
                findings,
                ctx,
                "JWT_NONE_ALGORITHM",
                "JWT uses the unsecured none algorithm",
                "critical",
                "auth",
                "A captured JWT declares alg=none and therefore has no cryptographic signature.",
                "Reject unsecured JWTs, pin the expected algorithm server-side, and verify issuer, audience, purpose, "
                "signature, and time claims.",
                "JWT header declares alg=none",
                scope_key=f"{ctx['origin']}|jwt-none",
            )
        if re.search(r"/(?:oauth|oidc|authorize)(?:/|$)", parsed.path, re.IGNORECASE):
            response_type = " ".join(params.get("response_type", []))
            if response_type:
                if "token" in response_type.split() or params.get("grant_type") == ["password"]:
                    self._add(
                        findings,
                        ctx,
                        "OAUTH_IMPLICIT_OR_PASSWORD_GRANT",
                        "Deprecated OAuth grant is in use",
                        "high",
                        "auth",
                        "The flow uses the implicit or resource-owner password grant, which ASVS 5.0 disallows.",
                        "Migrate browser clients to Authorization Code with PKCE and remove the password grant.",
                        f"response_type={response_type}; grant_type={params.get('grant_type', [''])[0]}",
                        scope_key=f"{ctx['origin']}|{parsed.path}|deprecated-grant",
                    )
                if "code" in response_type.split():
                    if not params.get("state"):
                        self._add(
                            findings,
                            ctx,
                            "OAUTH_STATE_MISSING",
                            "OAuth authorization request has no state",
                            "high",
                            "auth",
                            "The authorization request lacks a visible state value binding the callback to the "
                            "initiating browser transaction.",
                            "Generate a cryptographically random state value, bind it to the user-agent session, and "
                            "validate it exactly on callback.",
                            _query_without_sensitive_values(ctx["url"]),
                            scope_key=f"{ctx['origin']}|{parsed.path}|state",
                        )
                    if not params.get("code_challenge") or params.get("code_challenge_method") == ["plain"]:
                        self._add(
                            findings,
                            ctx,
                            "OAUTH_PKCE_MISSING",
                            "OAuth code flow lacks strong PKCE",
                            "high",
                            "auth",
                            "The authorization request has no code_challenge or uses the plain method.",
                            "Require PKCE with code_challenge_method=S256 and validate the code_verifier at the token endpoint.",
                            _query_without_sensitive_values(ctx["url"]),
                            scope_key=f"{ctx['origin']}|{parsed.path}|pkce",
                        )
        state_changing = ctx["method"] in {"POST", "PUT", "PATCH", "DELETE"}
        content_type = ctx["request_headers"].get("content-type", "").lower()
        safelisted = any(
            item in content_type
            for item in ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")
        )
        csrf_marker = any(CSRF_NAME_RE.search(key) for key in ctx["request_headers"])
        csrf_marker = csrf_marker or bool(CSRF_NAME_RE.search(ctx["request_body"]))
        if state_changing and cookie_header and not auth_header and safelisted and not csrf_marker:
            self._add(
                findings,
                ctx,
                "POTENTIAL_CSRF",
                "Cookie-authenticated state change has no visible CSRF control",
                "medium",
                "auth",
                "A state-changing request uses ambient cookies and a CORS-safelisted content type without a visible "
                "anti-forgery token or non-safelisted header.",
                "Validate a session-bound anti-forgery token, require a custom header that triggers preflight, and "
                "validate Origin/Sec-Fetch-Site. SameSite is defense in depth.",
                f"{ctx['method']} {parsed.path}; Content-Type: {content_type or '<absent>'}",
                "medium",
                scope_key=f"{ctx['origin']}|{parsed.path}|csrf",
            )

    def _analyze_websocket(
        self,
        ctx: Dict[str, Any],
        findings: List[Dict[str, Any]],
        observations: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        if not ctx["is_websocket"]:
            return
        observations["websocket_flows"].append(
            {
                "flow_id": ctx["flow_id"],
                "url": _query_without_sensitive_values(ctx["url"]),
                "status_code": ctx["status"],
                "message_count": len(ctx["ws_messages"]) if isinstance(ctx["ws_messages"], list) else 0,
            }
        )
        if ctx["scheme"] in {"http", "ws"} and not _is_local_host(ctx["host"]):
            self._add(
                findings,
                ctx,
                "WEBSOCKET_CLEAR_TEXT",
                "WebSocket connection is not protected by TLS",
                "high",
                "websocket",
                "The WebSocket handshake uses clear-text transport and is exposed to interception and modification.",
                "Use wss:// for every WebSocket connection and obtain any channel token through an authenticated "
                "HTTPS session.",
                _query_without_sensitive_values(ctx["url"]),
                scope_key=ctx["origin"],
            )
        if not ctx["request_headers"].get("origin"):
            cookie_auth = bool(ctx["request_headers"].get("cookie"))
            self._add(
                findings,
                ctx,
                "WEBSOCKET_ORIGIN_MISSING",
                "WebSocket handshake has no Origin header",
                "high" if cookie_auth else "medium",
                "websocket",
                "The captured handshake contains no Origin. For browser cookie-authenticated channels this removes "
                "important evidence that the server can use to prevent cross-site WebSocket hijacking.",
                "Require an Origin header for browser clients and validate it against an exact allowlist during the "
                "HTTP upgrade.",
                "Origin request header absent",
                "high",
                scope_key=f"{ctx['origin']}|origin",
            )
        params = parse_qs(urlparse(ctx["url"]).query, keep_blank_values=True)
        sensitive = sorted(key for key in params if _is_sensitive_name(key))
        if sensitive:
            self._add(
                findings,
                ctx,
                "WEBSOCKET_TOKEN_IN_URL",
                "WebSocket authentication token is carried in the URL",
                "high",
                "websocket",
                "WebSocket URLs are commonly logged by proxies and servers; token-like parameters were captured: "
                + ", ".join(sensitive),
                "Use a short-lived dedicated WebSocket token obtained over HTTPS, pass it in a protected handshake "
                "mechanism, and avoid long-lived secrets in the URL.",
                _query_without_sensitive_values(ctx["url"]),
                scope_key=f"{ctx['origin']}|{ctx['path']}|token",
                metadata={"parameters": sensitive},
            )
        for index, message in enumerate(ctx["ws_messages"] if isinstance(ctx["ws_messages"], list) else []):
            content = _as_text(message.get("content") if isinstance(message, dict) else message)
            match = JWT_RE.search(content) or SECRET_VALUE_RE.search(content)
            if match:
                self._add(
                    findings,
                    ctx,
                    "WEBSOCKET_SECRET_EXPOSURE",
                    "Secret-like material appears in a WebSocket message",
                    "high",
                    "websocket",
                    "A captured WebSocket frame contains a JWT or named secret/token value.",
                    "Avoid transmitting reusable secrets in application messages. Use least-privilege, short-lived "
                    "channel credentials and redact sensitive telemetry.",
                    f"message[{index}]: {_evidence(content, match)}",
                    scope_key=f"{ctx['url']}|message-secret",
                )
                break

    def _analyze_graphql(
        self,
        ctx: Dict[str, Any],
        findings: List[Dict[str, Any]],
        observations: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        if not ctx["is_graphql"]:
            return
        query, payload = _extract_graphql_payload(
            ctx["method"], ctx["url"], ctx["request_headers"], ctx["request_body"]
        )
        observations["graphql_flows"].append(
            {
                "flow_id": ctx["flow_id"],
                "method": ctx["method"],
                "url": _query_without_sensitive_values(ctx["url"]),
                "status_code": ctx["status"],
                "operation": (
                    "mutation"
                    if re.search(r"\bmutation\b", query, re.IGNORECASE)
                    else "subscription"
                    if re.search(r"\bsubscription\b", query, re.IGNORECASE)
                    else "query"
                ),
            }
        )
        response = ctx["response_body"]
        introspection = "__schema" in query or "__type" in query
        introspection_result = bool(
            re.search(r'"__schema"\s*:', response)
            or (re.search(r'"queryType"\s*:', response) and re.search(r'"types"\s*:', response))
        )
        if introspection and introspection_result and (ctx["status"] or 0) < 400:
            self._add(
                findings,
                ctx,
                "GRAPHQL_INTROSPECTION_ENABLED",
                "GraphQL introspection is enabled",
                "medium",
                "graphql",
                "The endpoint returned schema metadata to an introspection query.",
                "Disable introspection in production unless third-party schema discovery is a documented requirement. "
                "Enforce authorization independently of obscurity.",
                _evidence(response, re.search(r'"__schema"\s*:', response)),
                scope_key=f"{ctx['origin']}|{ctx['path']}|introspection",
            )
        if ctx["method"] == "GET" and re.search(r"\bmutation\b", query, re.IGNORECASE):
            self._add(
                findings,
                ctx,
                "GRAPHQL_MUTATION_OVER_GET",
                "GraphQL mutation is sent with GET",
                "high",
                "graphql",
                "A state-changing GraphQL operation uses an HTTP safe method, enabling caching, prefetch, and CSRF risks.",
                "Reject mutations over GET and require POST with CSRF defenses appropriate to the authentication model.",
                _query_without_sensitive_values(ctx["url"]),
                scope_key=f"{ctx['origin']}|{ctx['path']}|mutation-get",
            )
        debug_match = re.search(
            r'(?i)"(?:stack|stacktrace|exception|debugMessage)"\s*:\s*(?:\[|{|")',
            response,
        )
        if debug_match and re.search(r'(?i)"errors"\s*:', response):
            self._add(
                findings,
                ctx,
                "GRAPHQL_DEBUG_ERROR",
                "GraphQL error response exposes debugging details",
                "high",
                "graphql",
                "The GraphQL errors payload appears to contain stack, exception, or framework debug fields.",
                "Return stable public error codes and messages. Log stack traces server-side with a correlation ID.",
                _evidence(response, debug_match),
                scope_key=f"{ctx['origin']}|{ctx['path']}|debug",
            )
        depth = self._graphql_depth(query)
        alias_count = len(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s*:\s*[A-Za-z_][A-Za-z0-9_]*", query))
        if depth >= 10 or alias_count >= 20:
            self._add(
                findings,
                ctx,
                "GRAPHQL_COMPLEX_QUERY",
                "High-complexity GraphQL query was accepted",
                "medium",
                "graphql",
                f"A captured query has approximate depth {depth} and {alias_count} aliases. This is evidence to "
                "validate query cost, depth, and amount limits.",
                "Enforce an operation allowlist or server-side depth, amount, and cost limits. Apply rate and "
                "response-size limits per identity.",
                _evidence(query),
                "medium",
                scope_key=f"{ctx['origin']}|{ctx['path']}|complexity",
                metadata={"depth": depth, "alias_count": alias_count},
            )
        if isinstance(payload, list) and isinstance(self._json_or_none(response), list):
            self._add(
                findings,
                ctx,
                "GRAPHQL_BATCHING_ENABLED",
                "GraphQL request batching is enabled",
                "medium",
                "graphql",
                "The endpoint accepted an array of GraphQL operations, which can bypass per-request rate limits.",
                "Disable batching unless required, or apply cost, operation-count, response-size, and per-identity "
                "limits to the complete batch.",
                f"Batch size: {len(payload)}",
                scope_key=f"{ctx['origin']}|{ctx['path']}|batching",
            )
        is_mutation = bool(re.search(r"\bmutation\b", query, re.IGNORECASE))
        cookie_auth = bool(ctx["request_headers"].get("cookie")) and not ctx["request_headers"].get("authorization")
        content_type = ctx["request_headers"].get("content-type", "").lower()
        safelisted = any(
            value in content_type
            for value in ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")
        )
        csrf_marker = bool(CSRF_NAME_RE.search(ctx["request_body"])) or any(
            CSRF_NAME_RE.search(key) for key in ctx["request_headers"]
        )
        if is_mutation and cookie_auth and safelisted and not csrf_marker:
            self._add(
                findings,
                ctx,
                "GRAPHQL_CSRF_SURFACE",
                "Cookie-authenticated GraphQL mutation is CORS-safelisted",
                "high",
                "graphql",
                "The mutation can be submitted with a simple cross-origin request shape and no visible anti-forgery token.",
                "Require application/json or a custom header, reject unexpected Origin/Content-Type values, and "
                "validate a session-bound anti-forgery token.",
                f"Content-Type: {content_type}; operation=mutation",
                "medium",
                scope_key=f"{ctx['origin']}|{ctx['path']}|csrf",
            )

    @staticmethod
    def _json_or_none(value: str) -> Any:
        try:
            return json.loads(value)
        except Exception:
            return None

    @staticmethod
    def _graphql_depth(query: str) -> int:
        depth = 0
        maximum = 0
        in_string = False
        escaped = False
        for char in query:
            if escaped:
                escaped = False
                continue
            if char == "\\" and in_string:
                escaped = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == "{":
                depth += 1
                maximum = max(maximum, depth)
            elif char == "}":
                depth = max(0, depth - 1)
        return maximum

    @staticmethod
    def _deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            key = finding.pop("_dedupe_key")
            if key not in merged:
                merged[key] = finding
                continue
            existing = merged[key]
            existing["flow_ids"] = sorted(set(existing["flow_ids"] + finding["flow_ids"]))
            if SEVERITY_RANK.get(finding["severity"], 0) > SEVERITY_RANK.get(existing["severity"], 0):
                existing["severity"] = finding["severity"]
            existing["metadata"]["affected_count"] = len(existing["flow_ids"])
        return list(merged.values())

    def build_regression_suite(
        self,
        flows: Sequence[Dict[str, Any]],
        report: Optional[Dict[str, Any]] = None,
        name: str = "KittyProxy browser security regression",
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        report = report or self.analyze(flows)
        flow_by_id = {_as_text(flow.get("id")): flow for flow in flows if flow.get("id")}
        findings_by_flow: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for finding in report.get("findings", []):
            for flow_id in finding.get("flow_ids", []):
                findings_by_flow[flow_id].append(finding)
        cases = []
        for flow_id, finding_list in findings_by_flow.items():
            flow = flow_by_id.get(flow_id)
            if not flow:
                continue
            checks = self._checks_for_findings(finding_list)
            if not checks:
                continue
            request = self.prepare_replay(flow, include_sensitive=include_sensitive)
            cases.append(
                {
                    "id": f"flow-{flow_id}",
                    "name": f"{request['method']} {_query_without_sensitive_values(request['url'])}",
                    "flow_id": flow_id,
                    "request": request,
                    "checks": checks,
                    "source_findings": sorted({finding["rule_id"] for finding in finding_list}),
                }
            )
        suite = {
            "schema": "kittyproxy.security-regression/v1",
            "name": name,
            "generated_at": time.time(),
            "asvs_version": ASVS_VERSION,
            "include_sensitive": include_sensitive,
            "environment_placeholders": not include_sensitive,
            "cases": cases,
        }
        placeholder_source = json.dumps(cases)
        for case in cases:
            try:
                placeholder_source += base64.b64decode(
                    case["request"].get("body_b64") or ""
                ).decode("utf-8")
            except Exception:
                pass
        suite["required_environment"] = sorted(
            set(re.findall(r"\$\{([A-Z0-9_]+)\}", placeholder_source))
        )
        suite["python"] = self.render_python_suite(suite)
        return suite

    def prepare_replay(self, flow: Dict[str, Any], include_sensitive: bool = True) -> Dict[str, Any]:
        request = flow.get("request") if isinstance(flow.get("request"), dict) else {}
        headers = _headers_dict(request.get("headers"))
        for name in ("host", "content-length", "connection", "proxy-connection", "transfer-encoding"):
            headers.pop(name, None)
        if not include_sensitive:
            headers = self._placeholder_headers(headers)
        body_b64 = _as_text(request.get("content_bs64") or request.get("body_b64"))
        if not include_sensitive and body_b64:
            body_b64 = self._placeholder_body(body_b64, headers.get("content-type", ""))
        return {
            "method": _as_text(flow.get("method") or request.get("method") or "GET").upper(),
            "url": (
                _as_text(flow.get("url") or request.get("url"))
                if include_sensitive
                else self._placeholder_url(_as_text(flow.get("url") or request.get("url")))
            ),
            "headers": headers,
            "body_b64": body_b64,
        }

    @staticmethod
    def _placeholder_url(url: str) -> str:
        parsed = urlparse(url)
        pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if _is_sensitive_name(key):
                env = "KITTYPROXY_QUERY_" + re.sub(r"[^A-Z0-9]+", "_", key.upper()).strip("_")
                value = "${" + env + "}"
                pairs.append(f"{quote_plus(key)}={value}")
            else:
                pairs.append(f"{quote_plus(key)}={quote_plus(value)}")
        return urlunparse(parsed._replace(query="&".join(pairs)))

    @staticmethod
    def _placeholder_headers(headers: Dict[str, str]) -> Dict[str, str]:
        output = dict(headers)
        for name in list(output):
            if name in {"authorization", "cookie", "proxy-authorization", "x-api-key", "api-key"}:
                env_name = "KITTYPROXY_" + re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")
                output[name] = "${" + env_name + "}"
        return output

    @staticmethod
    def _placeholder_body(body_b64: str, content_type: str) -> str:
        try:
            raw = base64.b64decode(body_b64)
            text = raw.decode("utf-8")
        except Exception:
            return body_b64
        if "json" in content_type.lower():
            try:
                data = json.loads(text)
            except Exception:
                return body_b64

            def replace(value: Any, key: str = "") -> Any:
                if key and _is_sensitive_name(key):
                    env = "KITTYPROXY_" + re.sub(r"[^A-Z0-9]+", "_", key.upper()).strip("_")
                    return "${" + env + "}"
                if isinstance(value, dict):
                    return {item_key: replace(item_value, item_key) for item_key, item_value in value.items()}
                if isinstance(value, list):
                    return [replace(item, key) for item in value]
                return value

            return base64.b64encode(json.dumps(replace(data)).encode("utf-8")).decode("ascii")
        if "application/x-www-form-urlencoded" in content_type.lower():
            parsed = parse_qs(text, keep_blank_values=True)
            pairs = []
            for key, values in parsed.items():
                for value in values:
                    if _is_sensitive_name(key):
                        env = "KITTYPROXY_" + re.sub(r"[^A-Z0-9]+", "_", key.upper()).strip("_")
                        value = "${" + env + "}"
                    pairs.append((key, value))
            return base64.b64encode(urlencode(pairs).encode("utf-8")).decode("ascii")
        if JWT_RE.search(text) or SECRET_VALUE_RE.search(text) or re.search(
            r"(?i)(?:password|secret|token|api[_-]?key)\s*=", text
        ):
            return base64.b64encode(b"${KITTYPROXY_REQUEST_BODY}").decode("ascii")
        return body_b64

    def _checks_for_findings(self, findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        checks: List[Dict[str, Any]] = [{"type": "status_not_5xx"}]
        seen = {"status_not_5xx"}
        for finding in findings:
            rule = finding["rule_id"]
            check: Optional[Dict[str, Any]] = None
            if rule in {"CSP_MISSING", "CSP_REPORT_ONLY"}:
                check = {"type": "header_present", "header": "content-security-policy"}
            elif rule == "CSP_UNSAFE_SCRIPT":
                check = {
                    "type": "header_not_contains_any",
                    "header": "content-security-policy",
                    "values": finding.get("metadata", {}).get("unsafe_tokens", []),
                }
            elif rule == "CSP_WEAK_BASELINE":
                check = {
                    "type": "header_contains_all",
                    "header": "content-security-policy",
                    "values": ["object-src 'none'", "base-uri 'none'", "frame-ancestors"],
                }
            elif rule == "HSTS_MISSING":
                check = {"type": "hsts_min_age", "seconds": 31_536_000}
            elif rule == "HSTS_WEAK":
                check = {"type": "hsts_min_age", "seconds": 31_536_000}
            elif rule == "NOSNIFF_MISSING":
                check = {"type": "header_equals", "header": "x-content-type-options", "value": "nosniff"}
            elif rule == "FRAME_ANCESTORS_MISSING":
                check = {"type": "header_contains", "header": "content-security-policy", "value": "frame-ancestors"}
            elif rule == "REFERRER_POLICY_MISSING":
                check = {"type": "header_present", "header": "referrer-policy"}
            elif rule == "COOP_MISSING":
                check = {"type": "header_present", "header": "cross-origin-opener-policy"}
            elif rule == "CORS_WILDCARD_CREDENTIALS":
                check = {"type": "cors_no_wildcard_credentials"}
            elif rule == "COOKIE_PREFIX_INVALID":
                check = {
                    "type": "cookie_prefix_valid",
                    "cookie": finding.get("metadata", {}).get("cookie_name"),
                }
            elif rule.startswith("COOKIE_"):
                cookie_name = finding.get("metadata", {}).get("cookie_name")
                required = []
                if rule in {"COOKIE_SECURE_MISSING", "COOKIE_SAMESITE_NONE_INSECURE"}:
                    required.append("secure")
                if rule == "COOKIE_HTTPONLY_MISSING":
                    required.append("httponly")
                if rule == "COOKIE_SAMESITE_MISSING":
                    required.append("samesite")
                check = {"type": "cookie_attributes", "cookie": cookie_name, "required": required}
            elif rule == "GRAPHQL_INTROSPECTION_ENABLED":
                check = {"type": "body_not_regex", "pattern": r'"__schema"\s*:'}
            elif rule == "GRAPHQL_DEBUG_ERROR":
                check = {
                    "type": "body_not_regex",
                    "pattern": r'(?i)"(?:stack|stacktrace|exception|debugMessage)"\s*:',
                }
            else:
                check = {
                    "type": "manual",
                    "rule_id": rule,
                    "instruction": finding["remediation"],
                }
            signature = json.dumps(check, sort_keys=True)
            if signature not in seen:
                seen.add(signature)
                checks.append(check)
        return checks

    def evaluate_response(self, checks: Sequence[Dict[str, Any]], response: Dict[str, Any]) -> Dict[str, Any]:
        headers = _headers_dict(response.get("headers"))
        status = int(response.get("status_code") or 0)
        body = _as_text(response.get("body"))
        set_cookies = response.get("set_cookie_headers") or []
        results = []
        for check in checks:
            check_type = check.get("type")
            passed = True
            detail = ""
            if check_type == "status_not_5xx":
                passed = status < 500
                detail = f"status={status}"
            elif check_type == "header_present":
                passed = bool(headers.get(check["header"].lower()))
            elif check_type == "header_equals":
                actual = headers.get(check["header"].lower(), "")
                passed = actual.lower() == _as_text(check.get("value")).lower()
                detail = f"actual={actual or '<absent>'}"
            elif check_type == "header_contains":
                actual = headers.get(check["header"].lower(), "")
                passed = _as_text(check.get("value")).lower() in actual.lower()
            elif check_type == "header_contains_all":
                actual = headers.get(check["header"].lower(), "").lower()
                passed = all(_as_text(value).lower() in actual for value in check.get("values", []))
            elif check_type == "header_not_contains_any":
                actual = headers.get(check["header"].lower(), "").lower()
                passed = all(_as_text(value).lower() not in actual for value in check.get("values", []))
            elif check_type == "header_regex":
                actual = headers.get(check["header"].lower(), "")
                passed = bool(re.search(check.get("pattern", ""), actual, re.IGNORECASE))
            elif check_type == "hsts_min_age":
                actual = headers.get("strict-transport-security", "")
                match = re.search(r"max-age\s*=\s*(\d+)", actual, re.IGNORECASE)
                passed = bool(match and int(match.group(1)) >= int(check.get("seconds", 0)))
            elif check_type == "cors_no_wildcard_credentials":
                passed = not (
                    headers.get("access-control-allow-origin") == "*"
                    and headers.get("access-control-allow-credentials", "").lower() == "true"
                )
            elif check_type == "cookie_attributes":
                required = {item.lower() for item in check.get("required", [])}
                parsed_cookies = [_parse_cookie(value) for value in set_cookies]
                matching = [
                    cookie for cookie in parsed_cookies
                    if cookie and cookie.get("name") == check.get("cookie")
                ]
                passed = bool(matching) and all(
                    required.issubset(set(cookie["attributes"])) for cookie in matching if cookie
                )
            elif check_type == "cookie_prefix_valid":
                parsed_cookies = [_parse_cookie(value) for value in set_cookies]
                matching = [
                    cookie for cookie in parsed_cookies
                    if cookie and cookie.get("name") == check.get("cookie")
                ]
                passed = bool(matching)
                for cookie in matching:
                    attrs = cookie["attributes"]
                    name = cookie["name"]
                    if name.startswith("__Host-"):
                        passed = passed and "secure" in attrs and "domain" not in attrs and attrs.get("path") == "/"
                    elif name.startswith("__Secure-"):
                        passed = passed and "secure" in attrs
            elif check_type == "body_not_regex":
                passed = not bool(re.search(check.get("pattern", ""), body))
            elif check_type == "manual":
                passed = True
                detail = "manual verification required"
            results.append({"check": check, "passed": passed, "detail": detail})
        return {
            "passed": all(item["passed"] for item in results if item["check"].get("type") != "manual"),
            "results": results,
        }

    @staticmethod
    def render_python_suite(suite: Dict[str, Any]) -> str:
        serializable = {key: value for key, value in suite.items() if key != "python"}
        suite_json = json.dumps(serializable, indent=2, sort_keys=True)
        return f'''#!/usr/bin/env python3
"""Generated by KittyProxy Browser Security Workbench."""
import base64
import json
import os
import re
import requests

SUITE = json.loads(r"""{suite_json}""")

def expand(value):
    if isinstance(value, str):
        return re.sub(r"\\$\\{{([A-Z0-9_]+)\\}}", lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {{key: expand(item) for key, item in value.items()}}
    if isinstance(value, list):
        return [expand(item) for item in value]
    return value

def set_cookie_headers(response):
    raw = response.raw.headers
    if hasattr(raw, "getlist"):
        return raw.getlist("Set-Cookie")
    value = response.headers.get("Set-Cookie")
    return [value] if value else []

def check_response(check, response):
    headers = {{key.lower(): value for key, value in response.headers.items()}}
    kind = check["type"]
    if kind == "status_not_5xx":
        return response.status_code < 500
    if kind == "header_present":
        return bool(headers.get(check["header"].lower()))
    if kind == "header_equals":
        return headers.get(check["header"].lower(), "").lower() == check["value"].lower()
    if kind == "header_contains":
        return check["value"].lower() in headers.get(check["header"].lower(), "").lower()
    if kind == "header_contains_all":
        actual = headers.get(check["header"].lower(), "").lower()
        return all(value.lower() in actual for value in check["values"])
    if kind == "header_not_contains_any":
        actual = headers.get(check["header"].lower(), "").lower()
        return all(value.lower() not in actual for value in check["values"])
    if kind == "header_regex":
        return bool(re.search(check["pattern"], headers.get(check["header"].lower(), ""), re.I))
    if kind == "hsts_min_age":
        match = re.search(r"max-age\\s*=\\s*(\\d+)", headers.get("strict-transport-security", ""), re.I)
        return bool(match and int(match.group(1)) >= check["seconds"])
    if kind == "cors_no_wildcard_credentials":
        return not (headers.get("access-control-allow-origin") == "*" and headers.get("access-control-allow-credentials", "").lower() == "true")
    if kind == "body_not_regex":
        return not bool(re.search(check["pattern"], response.text))
    if kind == "cookie_attributes":
        required = {{item.lower() for item in check["required"]}}
        matches = [value for value in set_cookie_headers(response) if value.split("=", 1)[0].strip() == check["cookie"]]
        return bool(matches) and all(required.issubset({{part.strip().split("=", 1)[0].lower() for part in value.split(";")[1:]}}) for value in matches)
    if kind == "cookie_prefix_valid":
        matches = [value for value in set_cookie_headers(response) if value.split("=", 1)[0].strip() == check["cookie"]]
        if not matches:
            return False
        for value in matches:
            name = value.split("=", 1)[0].strip()
            attrs = {{}}
            for part in value.split(";")[1:]:
                key, _, attr_value = part.strip().partition("=")
                attrs[key.lower()] = attr_value
            if name.startswith("__Host-") and not ("secure" in attrs and "domain" not in attrs and attrs.get("path") == "/"):
                return False
            if name.startswith("__Secure-") and "secure" not in attrs:
                return False
        return True
    return True

def main():
    proxy = os.environ.get("KITTYPROXY_TEST_PROXY")
    proxies = {{"http": proxy, "https": proxy}} if proxy else None
    verify_tls = os.environ.get("KITTYPROXY_VERIFY_TLS", "1").lower() not in {{"0", "false", "no"}}
    failures = []
    for case in SUITE["cases"]:
        request = expand(case["request"])
        request_body = base64.b64decode(request.get("body_b64") or "")
        try:
            request_body = expand(request_body.decode("utf-8")).encode("utf-8")
        except UnicodeDecodeError:
            pass
        response = requests.request(
            request["method"],
            request["url"],
            headers=request.get("headers") or {{}},
            data=request_body,
            proxies=proxies,
            verify=verify_tls,
            timeout=20,
            allow_redirects=False,
        )
        for check in case["checks"]:
            if check["type"] == "manual":
                print(f"MANUAL {{case['name']}}: {{check['instruction']}}")
                continue
            if not check_response(check, response):
                failures.append(f"{{case['name']}} :: {{check}}")
    if failures:
        raise AssertionError("\\n".join(failures))
    print(f"{{len(SUITE['cases'])}} security regression case(s) passed")

if __name__ == "__main__":
    main()
'''


security_workbench = SecurityWorkbench()
