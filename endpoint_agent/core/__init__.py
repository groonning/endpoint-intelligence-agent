"""Core safety + infrastructure layer for Agent 2.

Nothing in the discovery/collector/analyzer/ai/reporting layers is allowed to
act against a remote host without going through these primitives:

    scope        -- authorised-host allowlist (hard gate)
    rbac         -- role -> allowed-action mapping
    credentials  -- encrypted credential vault (Fernet)
    audit        -- append-only, hash-chained audit log
    ratelimit    -- token-bucket rate + concurrency limits
    killswitch   -- global abort
    runner       -- uniform, logged subprocess execution (sync + async)
    config       -- typed settings loader
"""
from __future__ import annotations

from .scope import Scope, ScopeError, Endpoint
from .rbac import RBAC, Role, AccessDenied
from .credentials import CredentialVault, Credential, VaultError
from .audit import AuditLog, AuditEvent
from .ratelimit import RateLimiter, RateLimitExceeded
from .killswitch import KillSwitch, KillSwitchEngaged
from .runner import run, arun, tool_available, RunResult
from .config import AgentConfig, load_config
from .hostkeys import HostKeyStore, HostKeyError
from .approvals import ApprovalQueue, ApprovalRequest

__all__ = [
    "Scope", "ScopeError", "Endpoint",
    "RBAC", "Role", "AccessDenied",
    "CredentialVault", "Credential", "VaultError",
    "AuditLog", "AuditEvent",
    "RateLimiter", "RateLimitExceeded",
    "KillSwitch", "KillSwitchEngaged",
    "run", "arun", "tool_available", "RunResult",
    "AgentConfig", "load_config",
    "HostKeyStore", "HostKeyError", "ApprovalQueue", "ApprovalRequest",
]
