"""AI Analysis Engine.

Ties the router to the two backends and enforces the data-handling policy:

  * The ground truth is the deterministic analyzer findings. The AI only
    *describes*, *summarises* and *hypothesises*; it never decides what to attack
    (there is nothing to attack — the agent is read-only) and its output is
    clearly tagged as hypothesis, kept apart from confirmed findings.
  * Before anything is sent to an external model, host identifiers are redacted
    if config.ai.redact_before_external is on.
  * External calls need the `ai.external` capability and count against one
    token budget for the whole run; once it is spent, work falls back to the
    local model.
  * Every model call is audit-logged (backend, model, task kind, token estimate,
    and whether data left the box) — never the content.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from .router import ModelRouter, TaskKind, Route
from .ollama_backend import OllamaBackend, OllamaError
from .claude_backend import ClaudeBackend, ClaudeError
from ..core.audit import AuditLog
from ..analyzer.analyzer import Finding


@dataclass
class AIResult:
    ok: bool
    text: str = ""
    route: Route | None = None
    error: str = ""
    hypothesis: bool = True          # AI output is always treated as hypothesis

    def dict(self) -> dict:
        return {"ok": self.ok, "text": self.text, "error": self.error,
                "hypothesis": self.hypothesis,
                "route": None if not self.route else {
                    "backend": self.route.backend, "model": self.route.model,
                    "reason": self.route.reason, "downgraded": self.route.downgraded,
                    "est_tokens": self.route.est_tokens}}


_SYSTEM = (
    "Du er en sikkerhetsanalytiker. Du skriver korte, konkrete rapporter på "
    "norsk om endepunkt-sikkerhet, basert KUN på dataene du får. Ikke finn på "
    "funn. Skill tydelig mellom bekreftede observasjoner og hypoteser. Dette "
    "gjelder maskiner brukeren selv har tillatelse til å undersøke.")

_OUTPUT_RESERVE = 2048        # tokens reserved for the model's reply

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


class AIAnalysisEngine:
    def __init__(self, router: ModelRouter, ollama: OllamaBackend,
                 claude: ClaudeBackend | None = None,
                 audit: AuditLog | None = None, actor: str = "agent2",
                 redact_external: bool = True, rbac=None, role: str = "operator",
                 max_external_tokens_per_run: int | None = None):
        self.rbac = rbac
        self.role = role
        self.max_external = max_external_tokens_per_run
        self._external_used = 0
        self._budget_lock = threading.Lock()
        self.router = router
        self.ollama = ollama
        self.claude = claude
        self.audit = audit
        self.actor = actor
        self.redact_external = redact_external

    # -------------------------------------------------------------- public
    def run(self, kind: TaskKind, prompt: str, risk: float = 0.0,
            system: str = _SYSTEM) -> AIResult:
        est = OllamaBackend.estimate_tokens(prompt)
        if self.rbac is not None and not (self.rbac.allows(self.role, "ai.local")
                                          or self.rbac.allows(self.role, "ai.external")):
            if self.audit:
                self.audit.record(self.actor, "ai.call", "-", "denied",
                                  {"kind": kind.value, "role": self.role})
            return AIResult(ok=False, error=f"role {self.role!r} may not use AI analysis")
        route = self.router.route(kind, est_tokens=est, risk=risk)
        if route.backend == "claude":
            blocked = self._external_blocked(est)
            if blocked:
                route = Route("ollama", self.ollama.model,
                              f"{blocked} — handled locally", True, est)
        payload = prompt
        left_box = route.backend == "claude"
        if left_box and self.redact_external:
            payload = self._redact(prompt)
        if self.audit:
            self.audit.record(self.actor, "ai.call", route.model,
                              "start", {"kind": kind.value, "backend": route.backend,
                                        "est_tokens": est, "left_box": left_box,
                                        "redacted": left_box and self.redact_external})
        try:
            if route.backend == "claude" and self.claude is not None:
                text = self.claude.chat(system, payload)
            else:
                text = self.ollama.chat(system, payload)
            if self.audit:
                self.audit.record(self.actor, "ai.call", route.model, "ok",
                                  {"kind": kind.value, "backend": route.backend})
            return AIResult(ok=True, text=text, route=route)
        except (OllamaError, ClaudeError) as e:
            if self.audit:
                self.audit.record(self.actor, "ai.call", route.model, "error",
                                  {"kind": kind.value, "error": str(e)})
            return AIResult(ok=False, error=str(e), route=route)

    # ------------------------------------------------- external-call gating
    def _external_blocked(self, est_tokens: int) -> str:
        """Empty string if an external call may go ahead (and reserve its
        tokens), otherwise the reason it may not."""
        if self.rbac is not None and not self.rbac.allows(self.role, "ai.external"):
            return f"role {self.role!r} lacks ai.external"
        if self.max_external is None:
            return ""
        cost = est_tokens + _OUTPUT_RESERVE
        with self._budget_lock:
            if self._external_used + cost > self.max_external:
                return (f"external token budget for this run is spent "
                        f"({self._external_used}/{self.max_external})")
            self._external_used += cost
        return ""

    def reset_budget(self) -> None:
        with self._budget_lock:
            self._external_used = 0

    @property
    def external_tokens_used(self) -> int:
        return self._external_used

    def summarize_findings(self, host: str, findings: list[Finding]) -> AIResult:
        risk = min(1.0, max((int(f.severity) for f in findings), default=0) / 4)
        kind = TaskKind.RISK_JUDGEMENT if risk >= 0.75 else TaskKind.SUMMARIZE
        lines = [f"- [{f.severity.label}] {f.title}: {f.detail}" for f in findings]
        prompt = (f"Vert: {host}\nBekreftede funn:\n" + "\n".join(lines) +
                  "\n\nSkriv ## Sammendrag og ## Prioriterte tiltak. Marker "
                  "eventuelle antakelser tydelig som hypotese.")
        return self.run(kind, prompt, risk=risk)

    def correlate(self, per_host: dict[str, list[Finding]]) -> AIResult:
        blocks = []
        for host, fs in per_host.items():
            blocks.append(f"### {host}\n" +
                          "\n".join(f"- [{f.severity.label}] {f.title}" for f in fs))
        prompt = ("Korreler funn på tvers av verter. Pek på mønstre (felles "
                  "svakhet, mulig lateral bevegelse). Skill hypotese fra "
                  "bekreftet.\n\n" + "\n\n".join(blocks))
        risk = 0.6
        return self.run(TaskKind.CORRELATE, prompt, risk=risk)

    # ------------------------------------------------------------- redaction
    @staticmethod
    def _redact(text: str) -> str:
        text = _IP_RE.sub("<ip>", text)
        text = _HOST_RE.sub("<host>", text)
        return text
