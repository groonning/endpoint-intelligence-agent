"""Catalog of read-only collection commands.

Every command here is non-destructive and non-privilege-escalating: it reads
system state only. The collector will ONLY run commands from this catalog — an
allowlist, exactly like the scope gate but for actions instead of hosts. A
caller cannot ask the collector to run an arbitrary command.

Each CommandSpec declares:
  os        -- "linux" | "windows"
  key       -- stable result key (e.g. "processes")
  argv      -- the command as an argv list (no shell)
  parser    -- optional name of a parser in collector.parsers
  category  -- grouping for the report (system/users/processes/services/network/files/security)
  redactable-- whether output may contain values to strip before external AI

Explicitly excluded (never in this catalog, by policy):
  * anything that reads private key material or shadow/SAM hashes
  * anything that changes state (install, kill, write, modify config)
  * anything that escalates privilege (sudo -s, runas) beyond the single
    read commands the connecting account is already allowed to run
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CommandSpec:
    os: str
    key: str
    argv: list[str]
    category: str = "system"
    description: str = ""
    requires_root: bool = False     # informational; agent never auto-escalates
    redactable: bool = False


# --- Linux (POSIX) read-only commands -------------------------------------
_LINUX: list[CommandSpec] = [
    CommandSpec("linux", "os_release", ["cat", "/etc/os-release"], "system",
                "distribution + version"),
    CommandSpec("linux", "kernel", ["uname", "-a"], "system", "kernel + arch"),
    CommandSpec("linux", "uptime", ["uptime"], "system", "uptime + load"),
    CommandSpec("linux", "hostname", ["hostname", "-f"], "system", "FQDN"),
    CommandSpec("linux", "users", ["getent", "passwd"], "users",
                "local accounts", redactable=True),
    CommandSpec("linux", "logged_in", ["who"], "users", "active sessions"),
    CommandSpec("linux", "sudoers_who", ["getent", "group", "sudo"], "users",
                "members of the sudo group"),
    CommandSpec("linux", "processes", ["ps", "-eo", "pid,ppid,user,comm,args"],
                "processes", "running processes", redactable=True),
    CommandSpec("linux", "listening", ["ss", "-tulpn"], "network",
                "listening sockets", redactable=True),
    CommandSpec("linux", "connections", ["ss", "-tunp"], "network",
                "established connections", redactable=True),
    CommandSpec("linux", "routes", ["ip", "route"], "network", "routing table"),
    CommandSpec("linux", "interfaces", ["ip", "-o", "addr"], "network",
                "interfaces + addresses", redactable=True),
    CommandSpec("linux", "services_systemd",
                ["systemctl", "list-units", "--type=service", "--state=running",
                 "--no-pager", "--no-legend"], "services", "running services"),
    CommandSpec("linux", "listening_units",
                ["systemctl", "list-units", "--type=socket", "--no-pager",
                 "--no-legend"], "services", "socket units"),
    CommandSpec("linux", "packages_dpkg", ["dpkg", "-l"], "system",
                "installed packages (Debian/Kali)"),
    CommandSpec("linux", "cron_system", ["ls", "-la", "/etc/cron.d"], "security",
                "system cron entries"),
    CommandSpec("linux", "world_writable",
                ["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002",
                 "-maxdepth", "3"], "files",
                "world-writable files under /etc"),
    CommandSpec("linux", "suid_binaries",
                ["find", "/usr/bin", "/usr/sbin", "-xdev", "-perm", "-4000",
                 "-type", "f"], "security", "SUID binaries"),
    CommandSpec("linux", "ssh_config", ["cat", "/etc/ssh/sshd_config"],
                "security", "sshd configuration"),
    CommandSpec("linux", "firewall_nft", ["nft", "list", "ruleset"], "security",
                "nftables ruleset", requires_root=True),
    CommandSpec("linux", "packages_src",
                ["dpkg-query", "-W", "-f",
                 "${source:Package}\\t${source:Version}\\t${Package}\\n"],
                "system", "source package + version (for vulnerability lookup)"),
    # --- logs (for Sigma detection); skipped when logs are disabled ---------
    CommandSpec("linux", "auth_log", ["tail", "-n", "2000", "/var/log/auth.log"],
                "logs", "authentication log (tail)", redactable=True),
    CommandSpec("linux", "journal",
                ["journalctl", "-n", "2000", "--no-pager", "-o", "short-iso"],
                "logs", "systemd journal (tail)", redactable=True),
]

# --- Windows (PowerShell) read-only commands ------------------------------
# All run through: powershell -NonInteractive -NoProfile -Command "<ps>"
def _ps(cmd: str) -> list[str]:
    return ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd]


_WINDOWS: list[CommandSpec] = [
    CommandSpec("windows", "os_info",
                _ps("Get-CimInstance Win32_OperatingSystem | "
                    "Select-Object Caption,Version,BuildNumber,OSArchitecture | "
                    "ConvertTo-Json"), "system", "OS caption + build"),
    CommandSpec("windows", "hotfixes",
                _ps("Get-HotFix | Select-Object HotFixID,InstalledOn | "
                    "ConvertTo-Json"), "system", "installed patches"),
    CommandSpec("windows", "users",
                _ps("Get-LocalUser | Select-Object Name,Enabled,LastLogon | "
                    "ConvertTo-Json"), "users", "local accounts", redactable=True),
    CommandSpec("windows", "admins",
                _ps("Get-LocalGroupMember -Group Administrators | "
                    "Select-Object Name,PrincipalSource | ConvertTo-Json"),
                "users", "local administrators"),
    CommandSpec("windows", "processes",
                _ps("Get-Process | Select-Object Id,ProcessName,Path | "
                    "ConvertTo-Json"), "processes", "running processes",
                redactable=True),
    CommandSpec("windows", "services",
                _ps("Get-Service | Where-Object {$_.Status -eq 'Running'} | "
                    "Select-Object Name,DisplayName,StartType | ConvertTo-Json"),
                "services", "running services"),
    CommandSpec("windows", "listening",
                _ps("Get-NetTCPConnection -State Listen | "
                    "Select-Object LocalAddress,LocalPort,OwningProcess | "
                    "ConvertTo-Json"), "network", "listening sockets",
                redactable=True),
    CommandSpec("windows", "connections",
                _ps("Get-NetTCPConnection -State Established | "
                    "Select-Object LocalPort,RemoteAddress,RemotePort,OwningProcess | "
                    "ConvertTo-Json"), "network", "established connections",
                redactable=True),
    CommandSpec("windows", "firewall",
                _ps("Get-NetFirewallProfile | "
                    "Select-Object Name,Enabled | ConvertTo-Json"),
                "security", "firewall profile state"),
    CommandSpec("windows", "smb_shares",
                _ps("Get-SmbShare | Select-Object Name,Path,Description | "
                    "ConvertTo-Json"), "security", "SMB shares", redactable=True),
    CommandSpec("windows", "defender",
                _ps("Get-MpComputerStatus | "
                    "Select-Object AMServiceEnabled,RealTimeProtectionEnabled,"
                    "AntivirusSignatureLastUpdated | ConvertTo-Json"),
                "security", "Defender status"),
]

def _winevents(log: str, ids: str, n: int = 300) -> list[str]:
    return _ps(f"Get-WinEvent -FilterHashtable @{{LogName='{log}';Id={ids}}} "
               f"-MaxEvents {n} -ErrorAction SilentlyContinue | "
               "ForEach-Object { $_.ToXml() }")


_WINDOWS += [
    CommandSpec("windows", "events_security",
                _winevents("Security", "4624,4625,4648,4672,4688,4697,4720,4726,4732,1102"),
                "logs", "Security event log (logons, process creation, accounts)",
                requires_root=True, redactable=True),
    CommandSpec("windows", "events_system", _winevents("System", "7045,104"),
                "logs", "System event log (service installs, log clears)",
                redactable=True),
    CommandSpec("windows", "events_powershell",
                _winevents("Microsoft-Windows-PowerShell/Operational", "4104"),
                "logs", "PowerShell script-block log", redactable=True),
]

COMMANDS: dict[str, list[CommandSpec]] = {"linux": _LINUX, "windows": _WINDOWS}

# Opt-in commands that are not part of the default sweep. Lynis is an auditing
# tool that only reports, but it does write a PID/temp file on the endpoint
# while it runs, so it is enabled explicitly (config: lynis.enabled).
EXTRAS: dict[str, list[CommandSpec]] = {
    "linux": [
        CommandSpec("linux", "lynis",
                    ["lynis", "audit", "system", "--pentest", "--quick", "--quiet",
                     "--no-colors", "--no-log", "--report-file", "/dev/stdout"],
                    "security", "Lynis host audit (unprivileged mode)"),
    ],
    "windows": [],
}


def read_only_catalog(os_name: str, include_logs: bool = True,
                      extras: list[str] | None = None) -> list[CommandSpec]:
    cat = [c for c in COMMANDS.get(os_name, [])
           if include_logs or c.category != "logs"]
    wanted = set(extras or [])
    cat += [c for c in EXTRAS.get(os_name, []) if c.key in wanted]
    return cat


def spec_for(os_name: str, key: str) -> CommandSpec | None:
    for spec in COMMANDS.get(os_name, []):
        if spec.key == key:
            return spec
    return None
