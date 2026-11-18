"""YARA-X file analysis.

YARA-X (VirusTotal, BSD-3-Clause, Rust with official `yara-x` Python bindings) is
the current, maintained successor to classic YARA. This engine compiles the
operator's rules once and scans the contents of files the collector read from
explicitly approved directories (see collector.files).

Optional dependency: without `yara-x` installed, `available` is False and
`scan()` returns no findings (it never raises). Rules live under
config.yara_rules_dir (*.yar / *.yara).
"""
from __future__ import annotations

import glob
import os

from .analyzer import Finding, Severity
from ..collector.base import CollectionResult

try:
    import yara_x
    _HAVE_YARAX = True
except Exception:
    _HAVE_YARAX = False


class YaraEngine:
    def __init__(self, rules_dir: str = "rules/yara"):
        self.rules_dir = rules_dir
        self.available = _HAVE_YARAX
        self._rules = None
        self.load_error = ""
        if self.available:
            self._compile()

    def _compile(self) -> None:
        sources = []
        for path in glob.glob(os.path.join(self.rules_dir, "**", "*.yar*"),
                              recursive=True):
            try:
                sources.append(open(path, encoding="utf-8").read())
            except Exception as e:
                self.load_error += f"{path}: {e}; "
        if not sources:
            self._rules = None
            return
        try:
            compiler = yara_x.Compiler()
            for src in sources:
                compiler.add_source(src)
            self._rules = compiler.build()
        except Exception as e:  # pragma: no cover - needs yara_x
            self.load_error += f"compile: {e}"
            self._rules = None

    def scan_bytes(self, data: bytes, origin: str = "") -> list[str]:
        """Return the names of rules that match `data`."""
        if not self.available or self._rules is None:
            return []
        scanner = yara_x.Scanner(self._rules)
        res = scanner.scan(data)
        return [r.identifier for r in res.matching_rules]

    def scan(self, result: CollectionResult) -> list[Finding]:
        """Scan the contents of files collected from approved directories. The
        matching rule names are also recorded on each FileSample."""
        if not self.available or self._rules is None:
            return []
        findings: list[Finding] = []
        samples = {f.path: f for f in result.files}
        for path, data in result.file_bytes.items():
            names = self.scan_bytes(data, origin=path)
            if not names:
                continue
            if path in samples:
                samples[path].yara = names
            sha = samples[path].sha256 if path in samples else ""
            findings.append(Finding(
                host=result.host, severity=Severity.HIGH,
                title=f"YARA-X treff i {path}",
                detail="Regel(er) som traff: " + ", ".join(names),
                category="malware", source="yara", evidence=f"sha256 {sha}",
                recommendation="Isoler verten og undersøk filen manuelt."))
        return findings
