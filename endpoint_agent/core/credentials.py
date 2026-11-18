"""Encrypted credential vault.

Credentials for authenticated collection (SSH keys/passwords, WinRM passwords,
scanner-API tokens) are stored encrypted at rest with Fernet (AES-128-CBC +
HMAC-SHA256, from `cryptography`). The symmetric key is derived from a master
passphrase via scrypt, or supplied directly via the AGENT2_VAULT_KEY env var.

Guarantees:
  * Secrets are never written to disk in cleartext and never printed.
  * Secrets are never placed in the audit log — callers log the credential *id*.
  * `Credential.__repr__` redacts the secret, so an accidental log/print is safe.

The on-disk file is JSON: a salt + a map of id -> Fernet token. Only the vault
holds the key material in memory, and only for the lifetime of the process.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - exercised only when dep missing
    _HAVE_CRYPTO = False


class VaultError(Exception):
    pass


@dataclass
class Credential:
    """A decrypted credential, held only transiently in memory."""
    id: str
    kind: str                    # "ssh_password" | "ssh_key" | "winrm_password" | "api_token"
    username: str = ""
    secret: str = ""             # password, private-key PEM, or token
    extra: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:   # never leak the secret via repr/log
        return (f"Credential(id={self.id!r}, kind={self.kind!r}, "
                f"username={self.username!r}, secret=<redacted>)")

    def redacted(self) -> dict:
        return {"id": self.id, "kind": self.kind, "username": self.username,
                "secret_set": bool(self.secret)}


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


class CredentialVault:
    """Fernet-encrypted credential store.

    Open with either a passphrase (derives a key via scrypt using the stored
    salt) or a raw Fernet key via AGENT2_VAULT_KEY. New vaults need a passphrase
    or key to create the salt/key.
    """

    def __init__(self, path: str | Path = "config/credentials.vault",
                 passphrase: str | None = None, key: bytes | None = None):
        if not _HAVE_CRYPTO:
            raise VaultError(
                "the 'cryptography' package is required for the credential vault")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._store: dict[str, str] = {}
        self._salt: bytes
        self._fernet: Fernet
        # Explicit passphrase takes priority over env key — the caller chose it.
        env_key = os.environ.get("AGENT2_VAULT_KEY")
        effective_key = key or (env_key.encode() if env_key and not passphrase else None)
        if self.path.exists():
            self._load(passphrase, effective_key)
        else:
            self._create(passphrase, effective_key)

    # ------------------------------------------------------------- lifecycle
    def _create(self, passphrase: str | None, key: bytes | None) -> None:
        if key:
            self._fernet = Fernet(key)
            self._salt = b""
        elif passphrase:
            self._salt = os.urandom(16)
            self._fernet = Fernet(_derive_key(passphrase, self._salt))
        else:
            raise VaultError("a passphrase or key is required to create a vault")
        self._flush()

    def _load(self, passphrase: str | None, key: bytes | None) -> None:
        data = json.loads(self.path.read_text())
        self._salt = base64.b64decode(data.get("salt", "")) if data.get("salt") else b""
        self._store = data.get("store", {})
        if key:
            self._fernet = Fernet(key)
        elif passphrase:
            if not self._salt:
                raise VaultError("vault has no salt but a passphrase was given")
            self._fernet = Fernet(_derive_key(passphrase, self._salt))
        else:
            raise VaultError("a passphrase or AGENT2_VAULT_KEY is required to open the vault")
        # Validate the key against one entry, if any exist.
        for tok in self._store.values():
            try:
                self._fernet.decrypt(tok.encode())
            except InvalidToken:
                raise VaultError("wrong passphrase/key for this vault")
            break

    def _flush(self) -> None:
        data = {"salt": base64.b64encode(self._salt).decode() if self._salt else "",
                "store": self._store}
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def generate_key() -> bytes:
        if not _HAVE_CRYPTO:
            raise VaultError("cryptography not available")
        return Fernet.generate_key()

    # --------------------------------------------------------------- access
    def put(self, cred: Credential) -> None:
        payload = json.dumps({"kind": cred.kind, "username": cred.username,
                              "secret": cred.secret, "extra": cred.extra}).encode()
        self._store[cred.id] = self._fernet.encrypt(payload).decode()
        self._flush()

    def get(self, cred_id: str) -> Credential:
        tok = self._store.get(cred_id)
        if tok is None:
            raise VaultError(f"no credential with id {cred_id!r}")
        try:
            raw = self._fernet.decrypt(tok.encode())
        except InvalidToken as e:
            raise VaultError(f"cannot decrypt credential {cred_id!r}") from e
        d = json.loads(raw)
        return Credential(id=cred_id, kind=d["kind"], username=d.get("username", ""),
                          secret=d.get("secret", ""), extra=d.get("extra", {}))

    def delete(self, cred_id: str) -> None:
        if self._store.pop(cred_id, None) is not None:
            self._flush()

    def ids(self) -> list[str]:
        return list(self._store)
