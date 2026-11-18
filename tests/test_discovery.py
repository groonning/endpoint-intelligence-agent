"""Discovery: scope-bounded target expansion + TCP probing (local)."""
import asyncio

import pytest

from endpoint_agent.core.scope import Scope, Endpoint, ScopeError
from endpoint_agent.discovery.discovery import EndpointDiscovery, DiscoveredHost


def test_expand_targets_bounded():
    s = Scope([Endpoint("192.168.56.0/30", "lab")])   # 2 usable hosts
    d = EndpointDiscovery(s)
    targets = d._expand_targets()
    assert set(targets) == {"192.168.56.1", "192.168.56.2"}


def test_expand_rejects_huge_range():
    s = Scope([Endpoint("10.0.0.0/8", "too big")])
    d = EndpointDiscovery(s)
    with pytest.raises(ScopeError):
        d._expand_targets(max_hosts=1024)


def test_probe_tcp_detects_open_port(scope, kill):
    async def _run():
        # Start a throwaway server on localhost and discover it.
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        # Teach discovery to look at that port by monkeypatching MGMT_PORTS copy.
        d = EndpointDiscovery(scope, kill=kill)
        from endpoint_agent.discovery import discovery as mod
        saved = mod.MGMT_PORTS.copy()
        mod.MGMT_PORTS.clear(); mod.MGMT_PORTS[port] = "test"
        try:
            host = await d._probe_tcp("127.0.0.1")
        finally:
            mod.MGMT_PORTS.clear(); mod.MGMT_PORTS.update(saved)
            server.close()
            await server.wait_closed()
        return host
    host = asyncio.run(_run())
    assert host.alive and host.open_mgmt_ports


def test_probe_rechecks_scope(scope, kill):
    d = EndpointDiscovery(scope, kill=kill)
    with pytest.raises(ScopeError):
        asyncio.run(d._probe_tcp("1.2.3.4"))


def test_os_guess_from_ports():
    d = EndpointDiscovery.__new__(EndpointDiscovery)
    assert d._os_from_ports([5985]) == "windows"
    assert d._os_from_ports([22]) == "linux"
    assert d._os_from_ports([]) == ""
