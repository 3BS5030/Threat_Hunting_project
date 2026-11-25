"""Minimal OpenAI-compatible LLM client; optional and stdlib-only."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.request import Request, urlopen


class NoClientConfigured(RuntimeError):
    """Raised when no API key is available for remote inference."""


class LLMClient:
    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: int = 30,
    ) -> None:
        self.base_url = (base_url or os.getenv("AI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or os.getenv("AI_API_KEY", "")
        self.model = model or os.getenv("AI_MODEL", "gpt-4o-mini")
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def complete(self, prompt: str, system: str = "You are a threat hunting assistant.") -> str:
        if not self.configured:
            raise NoClientConfigured("AI_API_KEY is not set")
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        request = Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urlopen(request, timeout=self.timeout) as response:
            body = json.load(response)
        return body["choices"][0]["message"]["content"].strip()
