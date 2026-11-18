"""AI analysis engine (model routing: local Ollama + external Claude)."""
from __future__ import annotations

from .engine import AIAnalysisEngine, AIResult
from .router import ModelRouter, TaskKind, Route
from .ollama_backend import OllamaBackend, OllamaError
from .claude_backend import ClaudeBackend, ClaudeError

__all__ = [
    "AIAnalysisEngine", "AIResult",
    "ModelRouter", "TaskKind", "Route",
    "OllamaBackend", "OllamaError",
    "ClaudeBackend", "ClaudeError",
]
