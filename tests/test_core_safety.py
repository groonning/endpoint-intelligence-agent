"""Credential vault, audit chain, rate limiter, kill switch, RBAC."""
import pytest

from endpoint_agent.core.credentials import CredentialVault, Credential, VaultError
from endpoint_agent.core.audit import AuditLog
from endpoint_agent.core.ratelimit import RateLimiter, RateLimitExceeded
from endpoint_agent.core.killswitch import KillSwitch, KillSwitchEngaged
from endpoint_agent.core.rbac import RBAC, AccessDenied


# --- credentials ----------------------------------------------------------
def test_vault_roundtrip_passphrase(tmp_path):
    v = CredentialVault(tmp_path / "v.vault", passphrase="correct horse")
    v.put(Credential("lab", "ssh_password", "kali", "s3cret"))
    v2 = CredentialVault(tmp_path / "v.vault", passphrase="correct horse")
    got = v2.get("lab")
    assert got.username == "kali" and got.secret == "s3cret"


def test_vault_wrong_passphrase(tmp_path):
    v = CredentialVault(tmp_path / "v.vault", passphrase="right")
    v.put(Credential("lab", "ssh_password", "kali", "s3cret"))
    with pytest.raises(VaultError):
        CredentialVault(tmp_path / "v.vault", passphrase="wrong")


def test_vault_secret_never_in_repr(tmp_path):
    c = Credential("lab", "ssh_password", "kali", "TOPSECRET")
    assert "TOPSECRET" not in repr(c)
    assert "redacted" in repr(c)


def test_vault_file_has_no_cleartext(tmp_path):
    p = tmp_path / "v.vault"
    v = CredentialVault(p, passphrase="pw")
    v.put(Credential("lab", "ssh_password", "kali", "PLAINTEXTSECRET"))
    assert "PLAINTEXTSECRET" not in p.read_text()


def test_vault_key_mode(tmp_path):
    key = CredentialVault.generate_key()
    v = CredentialVault(tmp_path / "k.vault", key=key)
    v.put(Credential("t", "api_token", secret="abc"))
    v2 = CredentialVault(tmp_path / "k.vault", key=key)
    assert v2.get("t").secret == "abc"


# --- audit chain ----------------------------------------------------------
def test_audit_chain_intact(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.record("agent2", "test", f"h{i}", "ok")
    ok, msg = log.verify()
    assert ok, msg


def test_audit_tamper_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.record("agent2", "a", "h", "ok")
    log.record("agent2", "b", "h", "ok")
    lines = p.read_text().splitlines()
    lines[0] = lines[0].replace('"outcome": "ok"', '"outcome": "tampered"')
    p.write_text("\n".join(lines) + "\n")
    log2 = AuditLog(p)
    ok, msg = log2.verify()
    assert not ok and "chain break" in msg


def test_audit_never_logs_secret(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.record("agent2", "collect.ssh", "h", "start", {"cred_id": "lab"})
    assert "lab" in p.read_text()           # id ok
    # (the caller never passes the secret; this documents the contract)


# --- rate limiter ---------------------------------------------------------
def test_rate_limiter_burst_then_block():
    rl = RateLimiter(rate_per_sec=5, burst=3)
    assert rl.try_acquire() and rl.try_acquire() and rl.try_acquire()
    assert not rl.try_acquire()             # burst exhausted


def test_rate_limiter_timeout():
    rl = RateLimiter(rate_per_sec=1, burst=1)
    rl.acquire()
    with pytest.raises(RateLimitExceeded):
        rl.acquire(timeout=0.05)


# --- kill switch ----------------------------------------------------------
def test_killswitch_blocks(tmp_path):
    ks = KillSwitch(tmp_path / "ks")
    ks.check()                              # fine
    ks.engage("test")
    with pytest.raises(KillSwitchEngaged):
        ks.check()
    ks.reset()
    ks.check()                              # fine again


def test_killswitch_file_trips_out_of_band(tmp_path):
    flag = tmp_path / "ks"
    ks = KillSwitch(flag)
    flag.write_text("stop")                 # another process trips it
    assert ks.engaged
    with pytest.raises(KillSwitchEngaged):
        ks.check()


# --- RBAC -----------------------------------------------------------------
def test_rbac_viewer_cannot_scan():
    r = RBAC()
    r.check("viewer", "collect.read")       # allowed
    with pytest.raises(AccessDenied):
        r.check("viewer", "scan.active")


def test_rbac_admin_wildcard():
    r = RBAC()
    r.check("admin", "anything.at.all")


def test_rbac_wildcard_prefix():
    r = RBAC({"x": ["collect.*"]})
    assert r.allows("x", "collect.read")
    assert not r.allows("x", "scan.active")
