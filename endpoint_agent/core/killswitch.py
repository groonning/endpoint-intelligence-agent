"""Global kill switch.

Any long-running loop (discovery sweep, collection fan-out, autopilot) must call
`check()` between units of work. When the switch is engaged — from the CLI, the
API, a signal, or the Orchestrator — `check()` raises KillSwitchEngaged and the
operation unwinds cleanly.

The switch is also file-backed (`.run/killswitch`) so a *separate* process (a
shell one-liner, a cron job, the Orchestrator) can trip it even if the agent is
mid-run and not reading stdin:

    touch .run/killswitch      # engage from anywhere
    rm .run/killswitch         # (does NOT re-arm; use reset())
"""
from __future__ import annotations

import threading
import time
from pathlib import Path


class KillSwitchEngaged(Exception):
    """Raised by KillSwitch.check() when the switch has been engaged."""


class KillSwitch:
    def __init__(self, flag_path: str | Path = ".run/killswitch"):
        self._engaged = threading.Event()
        self._reason = ""
        self._engaged_at: float | None = None
        self._flag = Path(flag_path)
        self._flag.parent.mkdir(parents=True, exist_ok=True)
        # A leftover flag file from a previous run counts as engaged.
        if self._flag.exists():
            self.engage("pre-existing killswitch flag on startup")

    def engage(self, reason: str = "manual") -> None:
        if self._engaged.is_set():
            return
        self._reason = reason
        self._engaged_at = time.time()
        self._engaged.set()
        try:
            self._flag.write_text(f"{reason}\n")
        except OSError:
            pass

    def reset(self) -> None:
        """Re-arm the switch (clears state and the flag file)."""
        self._engaged.clear()
        self._reason = ""
        self._engaged_at = None
        try:
            self._flag.unlink()
        except FileNotFoundError:
            pass

    @property
    def engaged(self) -> bool:
        # An out-of-band `touch` of the flag file engages us too.
        if not self._engaged.is_set() and self._flag.exists():
            self.engage("killswitch flag file created")
        return self._engaged.is_set()

    @property
    def reason(self) -> str:
        return self._reason

    def check(self) -> None:
        """Raise if engaged — call this between units of work."""
        if self.engaged:
            raise KillSwitchEngaged(self._reason or "killswitch engaged")

    def status(self) -> dict:
        return {"engaged": self.engaged, "reason": self._reason,
                "engaged_at": self._engaged_at}
