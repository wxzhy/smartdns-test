"""上游配置与调用方预算的共同约束。"""

import asyncio
from time import monotonic
from typing import TYPE_CHECKING, cast

import dns.exception
import dns.message
import pytest
from anyio import fail_after

from smartdns.models.nameserver import UDPNameserverConfig
from smartdns.nameservers.base import query_deadline
from smartdns.nameservers.udp import UDPNameserver

if TYPE_CHECKING:
    from dns.asyncbackend import Backend


@pytest.mark.parametrize(
    ("requested", "configured", "effective"),
    [(None, 1, 1), (0.1, 1, 0.1), (1, 0.1, 0.1)],
)
def test_deadline_uses_smaller_query_budget(
    requested: float | None, configured: float, effective: float
) -> None:
    start = monotonic()
    deadline = query_deadline(requested, configured)
    assert start + effective <= deadline <= monotonic() + effective


async def test_configured_udp_timeout_cannot_be_overridden_by_longer_budget() -> None:
    class Server(asyncio.DatagramProtocol):
        def connection_made(self, transport) -> None:
            self.transport = transport
            self.handles = []

        def datagram_received(self, data, addr) -> None:
            response = dns.message.make_response(dns.message.from_wire(data)).to_wire()
            self.handles.append(
                asyncio.get_running_loop().call_later(
                    0.16, self.transport.sendto, response, addr
                )
            )

        def connection_lost(self, exc) -> None:
            for handle in self.handles:
                handle.cancel()

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        Server, local_addr=("127.0.0.1", 0)
    )
    port = transport.get_extra_info("sockname")[1]
    nameserver = UDPNameserver(
        UDPNameserverConfig(
            name="up", type="udp", address="127.0.0.1", port=port, timeout=0.1
        )
    )
    try:
        with fail_after(1):
            with pytest.raises(dns.exception.Timeout):
                await nameserver.async_query(
                    dns.message.make_query("example.com.", "A"),
                    0.5,
                    None,
                    0,
                    False,
                    cast("Backend", None),
                )
    finally:
        transport.close()
