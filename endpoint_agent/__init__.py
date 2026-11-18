"""Endpoint Intelligence Agent (Agent 2).

A modular, read-only endpoint security-intelligence agent for authorised test
environments. Discovers hosts, collects system facts over authenticated SSH /
WinRM, analyses them for misconfigurations and known-vulnerability indicators
(Sigma / YARA-X), and writes structured reports.

Design rules (see ARCHITECTURE.md):
  * Every active operation passes a hard scope gate (authorised hosts only).
  * Collection is strictly read-only — no privilege escalation, no credential
    extraction, no exfiltration of private files.
  * Every tool invocation is written to an append-only, hash-chained audit log.
  * A kill switch aborts all in-flight and future work immediately.

This package is self-contained and does NOT modify Agent 1 (the WiFi agent). It
talks to the Security Orchestrator through a small, explicit bus interface
(endpoint_agent.orchestrator.bus).
"""
from __future__ import annotations

__version__ = "0.2.0"
__agent_name__ = "endpoint-intelligence-agent"
__agent_id__ = "agent2"
