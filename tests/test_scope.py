"""Scope gate: the core authorisation control."""
import pytest

from endpoint_agent.core.scope import Scope, Endpoint, ScopeError


def test_exact_ip_authorised(scope):
    assert scope.is_authorised("127.0.0.1")
    assert scope.require("127.0.0.1").note == "self"


def test_cidr_membership(scope):
    assert scope.is_authorised("192.168.56.10")
    assert scope.require("192.168.56.254") is not None


def test_outside_scope_denied(scope):
    assert not scope.is_authorised("8.8.8.8")
    with pytest.raises(ScopeError):
        scope.require("8.8.8.8")


def test_adjacent_range_denied(scope):
    # .57.x is outside the authorised .56.0/24
    assert not scope.is_authorised("192.168.57.1")


def test_hostname_match_case_insensitive():
    s = Scope([Endpoint("lab-host.local", "h")])
    assert s.is_authorised("LAB-HOST.LOCAL")
    assert not s.is_authorised("other.local")


def test_allow_all_rejected():
    with pytest.raises(ScopeError):
        Scope([Endpoint("0.0.0.0/0")])


def test_invalid_identifier_rejected():
    with pytest.raises(ValueError):
        Endpoint("not a host!!")


def test_persist_roundtrip(tmp_path):
    p = tmp_path / "scope.yaml"
    s = Scope.load(p)
    s.add("192.168.56.0/24", "lab")
    s2 = Scope.load(p)
    assert s2.is_authorised("192.168.56.9")


def test_remove(tmp_path):
    p = tmp_path / "scope.yaml"
    s = Scope.load(p)
    s.add("10.0.0.1", "x")
    assert s.is_authorised("10.0.0.1")
    s.remove("10.0.0.1")
    assert not s.is_authorised("10.0.0.1")
