"""复用数量受限的 c-ares 通道；每个租用通道只执行一个原生查询。"""

from asyncio import Semaphore
from typing import TYPE_CHECKING

from anyio import CancelScope

if TYPE_CHECKING:
    from collections.abc import Callable

    from aiodns import DNSResolver
    from pycares import DNSResult


class AioDNSPool:
    def __init__(self, factory: Callable[[], DNSResolver], max_queries: int) -> None:
        self._factory = factory
        self._slots = Semaphore(max_queries)
        first = factory()
        self._idle = [first]
        self._channels = {first}
        self._closed = False

    async def query_dns(self, name: str, qtype: str, qclass: str) -> DNSResult:
        async with self._slots:
            if self._closed:
                raise RuntimeError("aiodns 通道池已停止")
            if self._idle:
                resolver = self._idle.pop()
            else:
                resolver = self._factory()
                self._channels.add(resolver)
            try:
                return await resolver.query_dns(name, qtype, qclass)
            except BaseException:
                if not self._closed:
                    # cancel() 会取消此通道的全部查询；独占租用保证不影响其他请求。
                    resolver.cancel()
                raise
            finally:
                if not self._closed:
                    self._idle.append(resolver)

    async def close(self) -> None:
        self._closed = True
        channels = tuple(self._channels)
        self._channels.clear()
        self._idle.clear()
        with CancelScope(shield=True):
            for resolver in channels:
                await resolver.close()
