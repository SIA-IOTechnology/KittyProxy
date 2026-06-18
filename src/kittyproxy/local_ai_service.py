"""
Local AI service for flow security analysis via Ollama or any OpenAI-compatible API.
"""
import json
import os
import re
from typing import Any, Dict, List, Optional

import requests

from ._paths import framework_root

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2"
DEFAULT_MAX_RESPONSE_CHARS = 8000

SYSTEM_PROMPT = """You are a web application security expert assisting penetration testers.
Analyze the HTTP request/response and return ONLY valid JSON (no markdown, no commentary) with this exact structure:
{
  "summary": "brief security assessment",
  "suggestions": [
    {
      "technique": "vulnerability name",
      "description": "why this is relevant",
      "confidence": 0.0,
      "target_param": "parameter name or empty string",
      "payloads": [{"value": "payload", "description": "what it tests"}]
    }
  ],
  "tech_stack": {"category": ["item"]},
  "next_steps": ["actionable step"]
}
Rules:
- confidence is a float between 0 and 1
- suggest 1-5 realistic techniques based on the data provided
- include concrete test payloads when applicable
- tech_stack keys are categories (framework, server, language, etc.)
- respond in the same language as the target application when obvious, otherwise English"""


def _load_toml_config() -> Dict[str, Any]:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return {}

    try:
        candidate = os.path.join(str(framework_root()), "config.toml")
        if os.path.exists(candidate):
            with open(candidate, "rb") as f:
                return tomllib.load(f)
    except Exception:
        pass
    return {}


def load_ai_config() -> Dict[str, Any]:
    """Load AI settings from environment variables and config.toml [AI] section."""
    toml_data = _load_toml_config()
    ai_cfg = toml_data.get("AI") or toml_data.get("ai") or {}

    def _env_bool(name: str, default: bool) -> bool:
        val = os.getenv(name)
        if val is None:
            return default
        return val.strip().lower() in ("1", "true", "yes", "on")

    enabled = _env_bool("AI_ENABLED", ai_cfg.get("enabled", True))
    base_url = (os.getenv("AI_BASE_URL") or ai_cfg.get("base_url") or DEFAULT_BASE_URL).rstrip("/")
    model = os.getenv("AI_MODEL") or ai_cfg.get("model") or DEFAULT_MODEL
    api_key = (os.getenv("AI_API_KEY") or ai_cfg.get("api_key") or "").strip()
    provider = os.getenv("AI_PROVIDER") or ai_cfg.get("provider") or "openai_compatible"
    max_chars = ai_cfg.get("max_response_chars", DEFAULT_MAX_RESPONSE_CHARS)
    try:
        max_chars = int(os.getenv("AI_MAX_RESPONSE_CHARS") or max_chars)
    except (TypeError, ValueError):
        max_chars = DEFAULT_MAX_RESPONSE_CHARS

    return {
        "enabled": enabled,
        "base_url": base_url,
        "model": model,
        "api_key": api_key,
        "provider": provider,
        "max_response_chars": max(500, max_chars),
    }


def _truncate(text: str, limit: int) -> str:
    if not text or len(text) <= limit:
        return text or ""
    return text[:limit] + f"\n... [truncated, {len(text) - limit} chars omitted]"


def _build_user_prompt(payload: Dict[str, Any], max_chars: int) -> str:
    response = payload.get("response") or {}
    response_content = _truncate(str(response.get("content") or ""), max_chars)
    body = _truncate(str(payload.get("body") or ""), max_chars // 2)

    parts = [
        f"HTTP Request: {payload.get('method', 'GET')} {payload.get('url', '')}",
        f"Request headers: {json.dumps(payload.get('headers') or {}, ensure_ascii=False)}",
        f"Request body: {body}",
        f"Response status: {response.get('status', 'N/A')}",
        f"Response headers: {json.dumps(response.get('headers') or {}, ensure_ascii=False)}",
        f"Response body:\n{response_content}",
        f"Detected technologies: {json.dumps(payload.get('technologies') or {}, ensure_ascii=False)}",
        f"Query parameters: {json.dumps((payload.get('parameters') or {}).get('query') or {}, ensure_ascii=False)}",
        f"Body parameters: {json.dumps((payload.get('parameters') or {}).get('body') or {}, ensure_ascii=False)}",
        f"Discovered endpoints: {json.dumps(payload.get('endpoints') or {}, ensure_ascii=False)}",
    ]
    return "\n\n".join(parts)


def _extract_json(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise ValueError("Empty LLM response")

    fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if fence:
        text = fence.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def _normalize_result(data: Dict[str, Any]) -> Dict[str, Any]:
    suggestions = data.get("suggestions") or []
    normalized_suggestions: List[Dict[str, Any]] = []
    for item in suggestions:
        if not isinstance(item, dict):
            continue
        confidence = item.get("confidence", 0.5)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        payloads = item.get("payloads") or []
        norm_payloads = []
        for p in payloads:
            if isinstance(p, str):
                norm_payloads.append({"value": p, "description": ""})
            elif isinstance(p, dict):
                norm_payloads.append({
                    "value": p.get("value", ""),
                    "description": p.get("description", ""),
                    "encoded": p.get("encoded", ""),
                })

        normalized_suggestions.append({
            "technique": str(item.get("technique") or "Unknown"),
            "description": str(item.get("description") or ""),
            "confidence": confidence,
            "target_param": str(item.get("target_param") or ""),
            "payloads": norm_payloads,
        })

    tech_stack = data.get("tech_stack") or {}
    if not isinstance(tech_stack, dict):
        tech_stack = {}

    next_steps = data.get("next_steps") or []
    if not isinstance(next_steps, list):
        next_steps = [str(next_steps)] if next_steps else []

    return {
        "summary": str(data.get("summary") or ""),
        "suggestions": normalized_suggestions,
        "tech_stack": tech_stack,
        "next_steps": [str(s) for s in next_steps],
        "source": "local",
    }


def check_availability(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Ping the configured LLM provider and return status."""
    cfg = config or load_ai_config()
    result = {
        "available": False,
        "enabled": cfg["enabled"],
        "provider": cfg["provider"],
        "base_url": cfg["base_url"],
        "model": cfg["model"],
        "message": "",
    }

    if not cfg["enabled"]:
        result["message"] = "Local AI is disabled. Set [AI] enabled = true in config.toml."
        return result

    headers = {"Content-Type": "application/json"}
    if cfg["api_key"]:
        headers["Authorization"] = f"Bearer {cfg['api_key']}"

    # Ollama native health endpoint
    if "11434" in cfg["base_url"] or cfg["provider"] == "ollama":
        try:
            resp = requests.get(f"{cfg['base_url']}/api/tags", timeout=3)
            if resp.status_code == 200:
                tags = resp.json().get("models") or []
                model_names = [m.get("name", "") for m in tags]
                if cfg["model"] not in model_names and model_names:
                    result["message"] = (
                        f"Ollama is running but model '{cfg['model']}' not found. "
                        f"Available: {', '.join(model_names[:5])}"
                    )
                else:
                    result["available"] = True
                    result["message"] = "Ollama is ready"
                return result
        except requests.RequestException as e:
            result["message"] = f"Cannot reach Ollama at {cfg['base_url']}: {e}"
            return result

    # Generic OpenAI-compatible: list models or minimal completion
    try:
        resp = requests.get(f"{cfg['base_url']}/v1/models", headers=headers, timeout=5)
        if resp.status_code == 200:
            result["available"] = True
            result["message"] = "LLM endpoint is reachable"
            return result
    except requests.RequestException:
        pass

    try:
        resp = requests.post(
            f"{cfg['base_url']}/v1/chat/completions",
            headers=headers,
            json={
                "model": cfg["model"],
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5,
                "stream": False,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            result["available"] = True
            result["message"] = "LLM endpoint is ready"
        else:
            result["message"] = f"LLM returned HTTP {resp.status_code}"
    except requests.RequestException as e:
        result["message"] = f"Cannot reach LLM at {cfg['base_url']}: {e}"

    return result


def analyze_flow(payload: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Analyze an HTTP flow using the local LLM."""
    cfg = config or load_ai_config()
    status = check_availability(cfg)
    if not status["available"]:
        raise RuntimeError(status["message"] or "Local AI is not available")

    headers = {"Content-Type": "application/json"}
    if cfg["api_key"]:
        headers["Authorization"] = f"Bearer {cfg['api_key']}"

    user_prompt = _build_user_prompt(payload, cfg["max_response_chars"])
    body = {
        "model": cfg["model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.3,
        "stream": False,
    }

    # Ollama supports format=json on native API; use OpenAI-compatible route for portability
    resp = requests.post(
        f"{cfg['base_url']}/v1/chat/completions",
        headers=headers,
        json=body,
        timeout=120,
    )
    if resp.status_code != 200:
        detail = resp.text[:300]
        raise RuntimeError(f"LLM request failed (HTTP {resp.status_code}): {detail}")

    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("LLM returned no choices")

    content = (choices[0].get("message") or {}).get("content") or ""
    parsed = _extract_json(content)
    return _normalize_result(parsed)
