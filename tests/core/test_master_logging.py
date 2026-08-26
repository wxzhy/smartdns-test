"""Master 错误应答日志级别回归测试。"""

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import dns.message
from dns.rcode import Rcode

import smartdns.core.master as master_module
from smartdns.core.master import Master
from smartdns.models.context import Request, Response

if TYPE_CHECKING:
    from anyio.from_thread import BlockingPortal

    from smartdns.core.worker import Worker
    from smartdns.models.config import Config


class _Portal:
    def __init__(self, response: Response) -> None:
        self.response = response

    def start_task_soon(self, *args: object) -> Response:
        return self.response


class _Worker:
    async def handle(self, request: Request) -> Response:
        raise AssertionError("portal stub should provide the response")


class _LogCapture:
    def __init__(self) -> None:
        self.debug_calls: list[tuple[object, ...]] = []
        self.warning_calls: list[tuple[object, ...]] = []
        self.exception_calls: list[tuple[object, ...]] = []

    def debug(self, *args: object, **kwargs: object) -> None:
        self.debug_calls.append(args)

    def warning(self, *args: object, **kwargs: object) -> None:
        self.warning_calls.append(args)

    def exception(self, *args: object, **kwargs: object) -> None:
        self.exception_calls.append(args)


def _request() -> Request:
    return Request.from_message(dns.message.make_query("example.com.", "A"), "test")


async def _query_with_response(monkeypatch, response: Response, capture: _LogCapture):
    config = SimpleNamespace(worker_count=1, cache_size=0)
    master = Master(cast("Config", config))
    master.worker_count = 1
    master.workers = [cast("Worker", _Worker())]
    master.portals = [cast("BlockingPortal", _Portal(response))]

    async def fake_wrap_future(value: Any) -> Response:
        assert isinstance(value, Response)
        return value

    monkeypatch.setattr(master_module, "wrap_future", fake_wrap_future)
    monkeypatch.setattr(master_module, "logger", capture)
    # `_query_worker` invokes the module logger; retain the capture object for
    # assertions while avoiding any dependency on Loguru's sink internals.
    return await master._query_worker(_request())


async def test_nxdomain_is_debug_but_servfail_is_warning(monkeypatch) -> None:
    capture = _LogCapture()
    await _query_with_response(
        monkeypatch, Response.from_rcode(Rcode.NXDOMAIN, upstream="upstream"), capture
    )
    assert len(capture.warning_calls) == 0
    assert len(capture.debug_calls) == 1
    assert capture.warning_calls == []

    capture = _LogCapture()
    await _query_with_response(
        monkeypatch, Response.from_rcode(Rcode.SERVFAIL, upstream="upstream"), capture
    )
    assert len(capture.warning_calls) == 1
    assert capture.debug_calls == []

    capture = _LogCapture()
    await _query_with_response(
        monkeypatch, Response.from_rcode(Rcode.REFUSED, upstream="upstream"), capture
    )
    assert len(capture.warning_calls) == 1
    assert capture.debug_calls == []
