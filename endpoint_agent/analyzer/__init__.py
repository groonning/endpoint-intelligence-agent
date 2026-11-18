"""Security analysis module."""
from __future__ import annotations

from .analyzer import SecurityAnalyzer, Finding, Severity
from .sigma_engine import SigmaEngine
from .yara_engine import YaraEngine

__all__ = ["SecurityAnalyzer", "Finding", "Severity", "SigmaEngine", "YaraEngine"]
from .baseline import BaselineStore, snapshot, compare
from .vuln import OSVClient, vuln_findings
from .lynis import lynis_findings

__all__ += ["BaselineStore", "snapshot", "compare", "OSVClient", "vuln_findings",
            "lynis_findings"]
