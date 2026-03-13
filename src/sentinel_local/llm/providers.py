"""HTTP providers for local model runtimes."""

from __future__ import annotations

import json

import httpx


def invoke_ollama(
    *,
    base_url: str,
    model: str,
    system_prompt: str,
    prompt: str,
    timeout_seconds: int,
    client: httpx.Client | None = None,
) -> str:
    """Invoke an Ollama chat endpoint and return the response content."""
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "format": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "verdict_rationale": {"type": "string"},
                "recommended_actions": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary", "verdict_rationale", "recommended_actions"],
        },
    }
    close_client = client is None
    # Separate connect vs read timeout — local models need long read time to generate.
    client = client or httpx.Client(timeout=httpx.Timeout(connect=5.0, read=timeout_seconds, write=10.0, pool=5.0))
    try:
        response = client.post(f"{base_url.rstrip('/')}/api/chat", json=payload)
        response.raise_for_status()
        data = response.json()
        return data["message"]["content"]
    finally:
        if close_client:
            client.close()


def invoke_openai_compatible(
    *,
    base_url: str,
    model: str,
    system_prompt: str,
    prompt: str,
    timeout_seconds: int,
    client: httpx.Client | None = None,
) -> str:
    """Invoke an OpenAI-compatible local chat endpoint such as LM Studio."""
    payload = {
        "model": model,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    }
    close_client = client is None
    client = client or httpx.Client(timeout=httpx.Timeout(connect=5.0, read=timeout_seconds, write=10.0, pool=5.0))
    try:
        response = client.post(f"{base_url.rstrip('/')}/v1/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]
    finally:
        if close_client:
            client.close()


def parse_json_response(raw_content: str) -> dict:
    """Parse a provider JSON payload into a dictionary."""
    return json.loads(raw_content)
