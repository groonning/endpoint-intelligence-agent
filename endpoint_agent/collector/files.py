"""File-content collection, restricted to explicitly approved directories.

File *contents* are only ever read from directories the operator listed in the
config (files.linux_paths / files.windows_paths). On top of that allowlist a
deny-list blocks credential and key material even inside an approved directory,
and size / count / depth limits keep the collection small.

Contents are held in memory for hashing and YARA-X scanning only. Reports and
baselines store metadata (path, size, mtime, SHA-256, rule matches), never the
content, so nothing private is copied off the endpoint into a file.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import posixpath
import re
from dataclasses import dataclass, field, asdict

# Never read these, even inside an approved directory.
_DENY = [re.compile(p, re.I) for p in (
    r"(^|[\\/])\.ssh([\\/]|$)", r"(^|[\\/])\.gnupg([\\/]|$)",
    r"(^|[\\/])\.aws([\\/]|$)", r"(^|[\\/])\.kube([\\/]|$)",
    r"(^|[\\/])g?shadow-?$", r"(^|[\\/])id_(rsa|dsa|ecdsa|ed25519)",
    r"\.(pem|key|pfx|p12|kdbx|ppk|jks)$", r"(^|[\\/])(sam|security|ntds\.dit)$",
    r"wallet", r"(^|[\\/])\.?(netrc|pgpass|htpasswd)$",
    r"(^|[\\/])(login data|cookies|key[34]\.db|logins\.json)$",
    r"credential", r"secret", r"(^|[\\/])\.env(\.|$)",
)]

# Directories that may never be approved wholesale.
_FORBIDDEN_ROOTS = {"/", "/root", "/home", "/etc/ssh", "/proc", "/sys", "/dev"}


class FilePolicyError(Exception):
    pass


def denied(path: str) -> bool:
    return any(rx.search(path) for rx in _DENY)


@dataclass
class FileSample:
    path: str
    size: int
    mtime: float
    sha256: str = ""
    yara: list[str] = field(default_factory=list)
    error: str = ""

    def dict(self) -> dict:
        return asdict(self)


@dataclass
class FilePolicy:
    linux_paths: list[str] = field(default_factory=list)
    windows_paths: list[str] = field(default_factory=list)
    max_file_bytes: int = 1_048_576
    max_files: int = 200
    max_depth: int = 3

    def __post_init__(self) -> None:
        for d in self.linux_paths:
            norm = posixpath.normpath(d)
            if (not d.startswith("/") or ".." in d.split("/") or "\n" in d
                    or norm in _FORBIDDEN_ROOTS or denied(norm)):
                raise FilePolicyError(f"directory may not be approved: {d!r}")
        for d in self.windows_paths:
            bare = d.rstrip("\\/")
            if (not re.match(r"^[A-Za-z]:[\\/].+", d) or ".." in re.split(r"[\\/]", d)
                    or re.search(r"[\n'`$;|&]", d) or denied(bare)
                    or re.match(r"^[A-Za-z]:[\\/](windows|users)?$", bare, re.I)):
                raise FilePolicyError(f"directory may not be approved: {d!r}")

    def paths(self, os_name: str) -> list[str]:
        return self.linux_paths if os_name == "linux" else self.windows_paths

    # ---- command builders (fixed templates; only the approved dir varies) ----
    def list_argv(self, os_name: str, directory: str) -> list[str]:
        if os_name == "linux":
            kib = self.max_file_bytes // 1024 + 1
            return ["find", directory, "-xdev", "-maxdepth", str(self.max_depth),
                    "-type", "f", "-size", f"-{kib}k",
                    "-printf", "%s\\t%T@\\t%p\\n"]
        d = directory.replace("'", "''")
        return ["powershell", "-NonInteractive", "-NoProfile", "-Command",
                f"Get-ChildItem -LiteralPath '{d}' -File -Recurse "
                f"-Depth {self.max_depth - 1} -ErrorAction SilentlyContinue | "
                f"Where-Object {{$_.Length -le {self.max_file_bytes}}} | "
                "ForEach-Object { \"{0}`t{1}`t{2}\" -f $_.Length,"
                "([DateTimeOffset]$_.LastWriteTimeUtc).ToUnixTimeSeconds(),$_.FullName }"]

    def read_argv(self, os_name: str, path: str) -> list[str]:
        if os_name == "linux":
            return ["base64", "--", path]
        p = path.replace("'", "''")
        return ["powershell", "-NonInteractive", "-NoProfile", "-Command",
                f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{p}'))"]

    # ---- validation of what the endpoint reported ---------------------------
    def inside(self, os_name: str, directory: str, path: str) -> bool:
        """True only if `path` (as reported by the endpoint) really is inside the
        approved directory and is not on the deny-list."""
        if "\n" in path or "\r" in path or denied(path):
            return False
        if os_name == "linux":
            root = posixpath.normpath(directory)
            return posixpath.normpath(path).startswith(root.rstrip("/") + "/")
        root = directory.rstrip("\\/").lower()
        norm = path.replace("/", "\\").lower()
        return ".." not in norm.split("\\") and norm.startswith(root + "\\")

    def parse_listing(self, os_name: str, directory: str, out: str) -> list[FileSample]:
        samples = []
        for line in out.splitlines():
            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue
            try:
                size, mtime = int(parts[0]), float(parts[1])
            except ValueError:
                continue
            path = parts[2].strip("\r")
            if size > self.max_file_bytes or not self.inside(os_name, directory, path):
                continue
            samples.append(FileSample(path=path, size=size, mtime=mtime))
        return samples


def decode_content(b64_text: str) -> bytes:
    try:
        return base64.b64decode("".join(b64_text.split()), validate=True)
    except (binascii.Error, ValueError) as e:
        raise FilePolicyError(f"endpoint returned invalid base64: {e}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
