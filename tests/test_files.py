"""File-content collection: approved directories only, deny-list, limits."""
import hashlib

import pytest

from endpoint_agent.collector.files import FilePolicy, FilePolicyError, denied
from endpoint_agent.collector.local_collector import LocalCollector
from endpoint_agent.analyzer.baseline import snapshot


@pytest.mark.parametrize("bad", ["/", "/root", "/home", "relative/dir", "/opt/../etc",
                                 "/home/kali/.ssh", "/etc/ssh"])
def test_dangerous_directories_cannot_be_approved(bad):
    with pytest.raises(FilePolicyError):
        FilePolicy(linux_paths=[bad])


@pytest.mark.parametrize("bad", ["C:\\", "C:\\Windows", "C:\\Users", "data", "C:\\a';rm"])
def test_dangerous_windows_directories_cannot_be_approved(bad):
    with pytest.raises(FilePolicyError):
        FilePolicy(windows_paths=[bad])


@pytest.mark.parametrize("path", ["/opt/app/id_rsa", "/opt/app/server.key", "/opt/app/.env",
                                  "/opt/app/tls/cert.pem", "/opt/app/.ssh/config",
                                  "C:\\app\\secrets.txt"])
def test_key_material_is_denied_even_inside_approved_dir(path):
    assert denied(path)


def test_listing_drops_paths_outside_the_approved_dir():
    pol = FilePolicy(linux_paths=["/opt/app"])
    listing = ("10\t1.0\t/opt/app/ok.conf\n"
               "10\t1.0\t/opt/app/../../etc/shadow\n"      # traversal
               "10\t1.0\t/etc/passwd\n"                     # outside
               "10\t1.0\t/opt/application/x\n"              # prefix trick
               "10\t1.0\t/opt/app/id_rsa\n"                 # denied
               "99999999\t1.0\t/opt/app/huge.bin\n")        # too big
    assert [s.path for s in pol.parse_listing("linux", "/opt/app", listing)] == ["/opt/app/ok.conf"]


def test_local_collection_hashes_only_approved_files(scope, rbac, audit, rate, kill, tmp_path):
    approved = tmp_path / "approved"
    (approved / "sub").mkdir(parents=True)
    (approved / "app.conf").write_bytes(b"port=8080\n")
    (approved / "sub" / "blob.bin").write_bytes(bytes(range(256)))
    (approved / "server.key").write_text("PRIVATE KEY")
    (approved / "big.log").write_bytes(b"x" * 5000)
    (tmp_path / "outside.txt").write_text("not approved")
    pol = FilePolicy(linux_paths=[str(approved)], max_file_bytes=2048)
    col = LocalCollector(scope, rbac, audit, rate, kill, role="operator", file_policy=pol)
    res = col.collect("127.0.0.1", "linux")

    got = {f.path.rsplit("/", 1)[-1]: f for f in res.files}
    assert set(got) == {"app.conf", "blob.bin"}
    assert got["blob.bin"].sha256 == hashlib.sha256(bytes(range(256))).hexdigest()
    assert res.file_bytes[str(approved / "app.conf")] == b"port=8080\n"
    # contents never reach anything that is written to disk
    assert "port=8080" not in str(res.dict()["files"]) and "file_bytes" not in res.dict()
    assert "port=8080" not in str(snapshot(res))
    assert any(e.action == "collect.files" for e in audit.events())


def test_no_file_reads_without_a_policy(scope, rbac, audit, rate, kill):
    res = LocalCollector(scope, rbac, audit, rate, kill, role="operator").collect(
        "127.0.0.1", "linux", only=["kernel"])
    assert res.files == [] and res.file_bytes == {}


def test_max_files_is_enforced(scope, rbac, audit, rate, kill, tmp_path):
    d = tmp_path / "many"
    d.mkdir()
    for i in range(10):
        (d / f"f{i}.txt").write_text(str(i))
    pol = FilePolicy(linux_paths=[str(d)], max_files=3)
    res = LocalCollector(scope, rbac, audit, rate, kill, role="operator",
                         file_policy=pol).collect("127.0.0.1", "linux")
    assert len(res.files) == 3
