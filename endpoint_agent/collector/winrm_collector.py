"""WinRM collector for Windows endpoints (pywinrm).

Runs the read-only Windows PowerShell catalog over WinRM. pywinrm is optional;
without it the collector raises a clear error on construction.
"""
from __future__ import annotations

from .base import EndpointCollector, CollectionError
from ..core.credentials import Credential

try:
    import winrm
    _HAVE_WINRM = True
except Exception:  # pragma: no cover
    _HAVE_WINRM = False


class WinRMCollector(EndpointCollector):
    transport = "winrm"

    def __init__(self, *a, scheme: str = "http", port: int = 5985,
                 transport_auth: str = "ntlm", **kw):
        if not _HAVE_WINRM:
            raise CollectionError(
                "pywinrm is required for WinRMCollector (pip install pywinrm)")
        super().__init__(*a, **kw)
        self.scheme = scheme
        self.port = port
        self.transport_auth = transport_auth
        self._session = None

    def _connect(self, host: str, credential: Credential | None = None,
                 scheme: str | None = None, port: int | None = None, **kw) -> None:
        if credential is None:
            raise CollectionError("WinRMCollector requires a credential")
        endpoint = f"{scheme or self.scheme}://{host}:{port or self.port}/wsman"
        self._session = winrm.Session(
            endpoint, auth=(credential.username, credential.secret),
            transport=self.transport_auth,
            server_cert_validation="validate" if (scheme or self.scheme) == "https"
            else "ignore")

    def _exec_raw(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        if self._session is None:
            raise CollectionError("not connected")
        # Catalog Windows argv are: powershell -NonInteractive -NoProfile -Command <ps>
        if len(argv) >= 5 and argv[0] == "powershell":
            ps = argv[-1]
            r = self._session.run_ps(ps)
        else:
            r = self._session.run_cmd(argv[0], argv[1:])
        out = r.std_out.decode(errors="ignore") if isinstance(r.std_out, bytes) else r.std_out
        err = r.std_err.decode(errors="ignore") if isinstance(r.std_err, bytes) else r.std_err
        return r.status_code, out, err

    def _close(self) -> None:
        self._session = None
