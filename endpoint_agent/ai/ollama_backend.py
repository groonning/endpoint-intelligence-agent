"""Local LLM via Ollama — stdlib only (mirrors Agent 1's wifi_agent.llm).

Reused deliberately so Agent 1 and Agent 2 share one local-model convention and
the same running Ollama instance on the Kali box.
"""
from __future__ import annotations

import json
import os
import urllib.request


class OllamaError(Exception):
    pass


class OllamaBackend:
    def __init__(self, url: str | None = None, model: str | None = None):
        self.url = url or os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
        self.model = model or os.environ.get("OLLAMA_MODEL", "qwen3:30b-a3b")

    def available(self) -> tuple[bool, str]:
        try:
            with urllib.request.urlopen(self.url + "/api/tags", timeout=3) as r:
                tags = json.loads(r.read())
            names = [m.get("name", "") for m in tags.get("models", [])]
            if self.model in names:
                return True, self.model
            if any(n.split(":")[0] == self.model.split(":")[0] for n in names):
                return True, self.model + " (variant present)"
            if names:
                return False, f"model '{self.model}' not pulled; have: " + ", ".join(names)
            return False, "no models pulled — run: ollama pull " + self.model
        except Exception as e:
            return False, f"Ollama unavailable at {self.url}: {e}"

    def chat(self, system: str, user: str, as_json: bool = False,
             timeout: int = 300) -> str:
        body = {"model": self.model, "stream": False,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        if as_json:
            body["format"] = "json"
        req = urllib.request.Request(
            self.url + "/api/chat", data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read())
            return data.get("message", {}).get("content", "")
        except Exception as e:
            raise OllamaError(str(e))

    # rough token estimate for routing/accounting (4 chars/token heuristic)
    @staticmethod
    def estimate_tokens(text: str) -> int:
        return max(1, len(text) // 4)
