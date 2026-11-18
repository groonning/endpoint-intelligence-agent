"""Model router.

Chooses which model handles a task from three inputs, exactly as the brief asks:
complexity, risk, and token cost.

  * Simple, low-risk, small tasks  -> local Ollama (free, offline, private).
  * Complex correlation / code analysis -> Claude Sonnet (if external allowed).
  * High-risk, high-stakes judgement    -> Claude Opus (if external allowed).

If external models are disallowed or unavailable, everything routes to Ollama and
the route is marked `downgraded=True` so the reporter can note that a complex task
was handled locally.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TaskKind(str, Enum):
    CLASSIFY = "classify"          # label/triage a finding — trivial
    SUMMARIZE = "summarize"        # write a report section — easy
    CORRELATE = "correlate"        # link findings across hosts — complex
    CODE_ANALYSIS = "code"         # analyse a script/binary behaviour — complex
    RISK_JUDGEMENT = "risk"        # exploitability / blast-radius call — critical


# Base complexity weight per task kind (0..1).
_COMPLEXITY = {
    TaskKind.CLASSIFY: 0.1,
    TaskKind.SUMMARIZE: 0.3,
    TaskKind.CORRELATE: 0.7,
    TaskKind.CODE_ANALYSIS: 0.8,
    TaskKind.RISK_JUDGEMENT: 0.95,
}


@dataclass
class Route:
    backend: str          # "ollama" | "claude"
    model: str
    reason: str
    downgraded: bool = False
    est_tokens: int = 0


class ModelRouter:
    def __init__(self, ollama_model: str, sonnet_model: str, opus_model: str,
                 allow_external: bool, external_available: bool,
                 max_external_tokens: int = 200_000,
                 complex_threshold: float = 0.6,
                 critical_threshold: float = 0.9):
        self.ollama_model = ollama_model
        self.sonnet_model = sonnet_model
        self.opus_model = opus_model
        self.allow_external = allow_external
        self.external_available = external_available
        self.max_external_tokens = max_external_tokens
        self.complex_threshold = complex_threshold
        self.critical_threshold = critical_threshold

    def route(self, kind: TaskKind, est_tokens: int = 0,
              risk: float = 0.0) -> Route:
        """risk: 0..1 extra weight from how sensitive the finding is."""
        score = min(1.0, _COMPLEXITY[kind] + 0.35 * risk)
        wants_external = score >= self.complex_threshold
        external_ok = self.allow_external and self.external_available

        if not wants_external:
            return Route("ollama", self.ollama_model,
                         f"low complexity ({score:.2f}) — local model", False,
                         est_tokens)
        if not external_ok:
            return Route("ollama", self.ollama_model,
                         f"complex ({score:.2f}) but external models disabled/"
                         "unavailable — handled locally", True, est_tokens)
        if est_tokens > self.max_external_tokens:
            return Route("ollama", self.ollama_model,
                         f"complex but {est_tokens} tokens over external budget "
                         f"({self.max_external_tokens}) — local to control cost",
                         True, est_tokens)
        if score >= self.critical_threshold:
            return Route("claude", self.opus_model,
                         f"critical judgement ({score:.2f}) — Opus", False,
                         est_tokens)
        return Route("claude", self.sonnet_model,
                     f"complex ({score:.2f}) — Sonnet", False, est_tokens)
