"""External model via the Anthropic API (Claude Sonnet / Opus).

Used only for complex correlation and demanding security judgement, and only when
explicitly enabled in config (`ai.allow_external: true`) and an API key is set.
By default the agent runs fully offline on Ollama.

The `anthropic` SDK is optional; without it (or without a key) `available()` is
False and the router falls back to the local model. Before any data leaves the
box, the engine redacts hostnames/IPs if configured (see engine.redact).
"""
from __future__ import annotations

import os


class ClaudeError(Exception):
    pass


class ClaudeBackend:
    def __init__(self, model: str = "claude-sonnet-5-5",
                 api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._client = None
        try:
            import anthropic
            self._anthropic = anthropic
            self._have_sdk = True
        except Exception:
            self._anthropic = None
            self._have_sdk = False

    def available(self) -> tuple[bool, str]:
        if not self._have_sdk:
            return False, "anthropic SDK not installed"
        if not self.api_key:
            return False, "ANTHROPIC_API_KEY not set"
        return True, self.model

    def _client_lazy(self):
        if self._client is None:
            self._client = self._anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def chat(self, system: str, user: str, max_tokens: int = 2048,
             timeout: int = 120) -> str:
        ok, msg = self.available()
        if not ok:
            raise ClaudeError(msg)
        try:
            resp = self._client_lazy().messages.create(
                model=self.model, max_tokens=max_tokens, system=system,
                messages=[{"role": "user", "content": user}], timeout=timeout)
            parts = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
            return "\n".join(parts)
        except Exception as e:  # pragma: no cover - needs network + SDK
            raise ClaudeError(str(e))

    @staticmethod
    def estimate_tokens(text: str) -> int:
        return max(1, len(text) // 4)
