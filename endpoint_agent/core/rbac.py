"""Minimal role-based access control.

Actions are coarse capability names the modules ask for before doing work, e.g.
`discovery.sweep`, `collect.read`, `scan.active`, `scope.modify`, `ai.external`,
`killswitch.engage`. A role maps to a set of allowed actions; `*` grants all.

This is an *authorisation policy*, not an authentication system — the operator's
identity is established out of band (who holds the box / the API token). RBAC
decides what that identity may ask the agent to do, and every denial is a
first-class, audit-logged event.

Default roles (override in config/roles.yaml):
  * viewer     -- discovery + read-only collection + reporting, nothing active
  * operator   -- viewer + active scans + scope changes (confirmed at the CLI)
  * admin      -- everything, including external models (`ai.external`),
                  approving access requests (`approval.grant`) and the killswitch
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


class AccessDenied(Exception):
    """Raised when a role lacks the capability for a requested action."""


# Sensible, least-privilege defaults. Everyone may STOP the agent (stopping is
# always safe); re-arming it needs killswitch.reset. Active + external-model + destructive
# capabilities are NOT granted to viewer.
DEFAULT_ROLES: dict[str, list[str]] = {
    "viewer": [
        "discovery.sweep", "collect.read", "analyze.run",
        "report.read", "report.write", "killswitch.engage",
    ],
    "operator": [
        "discovery.sweep", "collect.read", "analyze.run", "scan.active",
        "scope.modify", "report.read", "report.write", "ai.local",
        "baseline.accept", "hostkeys.modify",
        "killswitch.engage", "killswitch.reset",
    ],
    "admin": ["*"],
}


@dataclass(frozen=True)
class Role:
    name: str
    actions: frozenset[str] = field(default_factory=frozenset)

    def allows(self, action: str) -> bool:
        if "*" in self.actions:
            return True
        if action in self.actions:
            return True
        # wildcard prefixes, e.g. "collect.*"
        for a in self.actions:
            if a.endswith(".*") and action.startswith(a[:-1]):
                return True
        return False


class RBAC:
    def __init__(self, roles: dict[str, list[str]] | None = None):
        src = roles if roles is not None else DEFAULT_ROLES
        self._roles = {name: Role(name, frozenset(acts))
                       for name, acts in src.items()}

    @classmethod
    def load(cls, path: str | Path) -> "RBAC":
        path = Path(path)
        if not path.exists():
            return cls()
        data = yaml.safe_load(path.read_text()) or {}
        return cls(data.get("roles") or DEFAULT_ROLES)

    def role(self, name: str) -> Role:
        r = self._roles.get(name)
        if r is None:
            raise AccessDenied(f"unknown role: {name!r}")
        return r

    def check(self, role_name: str, action: str) -> None:
        """Raise AccessDenied if `role_name` may not perform `action`."""
        if not self.role(role_name).allows(action):
            raise AccessDenied(
                f"role {role_name!r} is not permitted to perform {action!r}")

    def allows(self, role_name: str, action: str) -> bool:
        try:
            self.check(role_name, action)
            return True
        except AccessDenied:
            return False

    def roles(self) -> list[str]:
        return list(self._roles)
