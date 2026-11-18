"""Typed configuration loader for Agent 2.

Reads config/agent2.yaml (see config/agent2.example.yaml) and overlays a few
environment variables. Unknown keys are rejected so a typo cannot silently
leave a safety setting at its default.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict, fields, is_dataclass
from pathlib import Path

import yaml


@dataclass
class AIConfig:
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:30b-a3b"
    allow_external: bool = False            # must be explicitly enabled
    anthropic_model_complex: str = "claude-sonnet-5-5"
    anthropic_model_critical: str = "claude-opus-5-5"
    max_external_tokens_per_run: int = 200_000   # hard cap for one sweep
    redact_before_external: bool = True     # strip hostnames/IPs before sending out


@dataclass
class LimitsConfig:
    rate_per_sec: float = 5.0
    burst: int = 10
    max_concurrency: int = 8                # hosts collected in parallel
    connect_timeout_s: int = 15
    command_timeout_s: int = 60


@dataclass
class FilesConfig:
    """File-content collection. Off unless directories are listed here."""
    enabled: bool = False
    linux_paths: list[str] = field(default_factory=list)
    windows_paths: list[str] = field(default_factory=list)
    max_file_bytes: int = 1_048_576
    max_files: int = 200
    max_depth: int = 3


@dataclass
class LogsConfig:
    enabled: bool = True                    # auth log / journal / Windows event log


@dataclass
class VulnConfig:
    """Known-vulnerability lookup against OSV. Sends package names + versions
    (nothing else) to the OSV API, so it is off by default."""
    enabled: bool = False
    osv_url: str = "https://api.osv.dev"
    cache_ttl_hours: int = 24
    kali_as_debian: str = ""                # e.g. "13": treat Kali as that Debian release
    max_findings: int = 25


@dataclass
class LynisConfig:
    enabled: bool = False                   # runs `lynis audit system` on Linux hosts


@dataclass
class Agent1Config:
    url: str = "http://127.0.0.1:8777"      # Agent 1 dashboard API


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 8778


@dataclass
class AgentConfig:
    scope_path: str = "config/authorized_endpoints.yaml"
    roles_path: str = "config/roles.yaml"
    vault_path: str = "config/credentials.vault"
    known_hosts_path: str = "config/known_hosts.json"
    ssh_strict_host_keys: bool = False      # true: refuse hosts that are not pinned
    audit_path: str = "audit/agent2-audit.jsonl"
    killswitch_path: str = ".run/killswitch"
    approvals_path: str = ".run/approvals.json"
    bus_dir: str = ".run/orchestrator"
    state_dir: str = "state"                # baselines + caches
    reports_dir: str = "reports"
    sigma_rules_dir: str = "rules/sigma"
    yara_rules_dir: str = "rules/yara"
    default_role: str = "operator"
    credentials_map: dict[str, str] = field(default_factory=dict)  # ip/cidr/host -> cred id
    ai: AIConfig = field(default_factory=AIConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    files: FilesConfig = field(default_factory=FilesConfig)
    logs: LogsConfig = field(default_factory=LogsConfig)
    vuln: VulnConfig = field(default_factory=VulnConfig)
    lynis: LynisConfig = field(default_factory=LynisConfig)
    agent1: Agent1Config = field(default_factory=Agent1Config)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)

    def dict(self) -> dict:
        return asdict(self)


def _build(cls, data: dict, where: str):
    known = {f.name: f for f in fields(cls)}
    unknown = set(data) - set(known)
    if unknown:
        raise ValueError(f"unknown config key(s) in {where}: {', '.join(sorted(unknown))}")
    kwargs = {}
    for name, value in data.items():
        default = getattr(cls(), name)
        if is_dataclass(default):
            kwargs[name] = _build(type(default), value or {}, f"{where}.{name}")
        else:
            kwargs[name] = value
    return cls(**kwargs)


def load_config(path: str | Path = "config/agent2.yaml") -> AgentConfig:
    path = Path(path)
    data: dict = {}
    if path.exists():
        data = yaml.safe_load(path.read_text()) or {}
    cfg = _build(AgentConfig, data, str(path))
    if os.environ.get("OLLAMA_URL"):
        cfg.ai.ollama_url = os.environ["OLLAMA_URL"]
    if os.environ.get("OLLAMA_MODEL"):
        cfg.ai.ollama_model = os.environ["OLLAMA_MODEL"]
    if os.environ.get("AGENT2_ALLOW_EXTERNAL") == "1":
        cfg.ai.allow_external = True
    return cfg
