from time import monotonic
from typing import TYPE_CHECKING

from dns.exception import Timeout
from dns.nameserver import AddressAndPortNameserver, Nameserver

if TYPE_CHECKING:
    import dns.asyncbackend
    import dns.message

    from smartdns.models.nameserver import (
        AddressNameserverConfig,
        BaseNameserverConfig,
    )


def query_deadline(timeout: float | None, default: float) -> float:
    """建立单次上游查询的绝对截止时刻。"""
    effective = default if timeout is None else timeout
    if effective <= 0:
        raise Timeout(timeout=effective)
    return monotonic() + effective


def remaining_timeout(deadline: float) -> float:
    """返回截止时刻前的严格正剩余时间，耗尽时立即超时。"""
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise Timeout(timeout=0)
    return remaining


class BaseNameserver(Nameserver):
    def __init__(self, config: BaseNameserverConfig):
        self.config = config
        self.name = config.name
        self.timeout = config.timeout

    def kind(self) -> str:
        raise NotImplementedError

    def __str__(self):
        ns_kind = self.kind()
        return f"{ns_kind}:{self.config.name}"

    async def start(self) -> None:
        """启动Nameserver服务"""
        raise NotImplementedError

    async def stop(self) -> None:
        """停止Nameserver服务；默认无操作，持有资源的子类覆写以释放资源。"""

    async def async_query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        backend: dns.asyncbackend.Backend,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        raise NotImplementedError


class BaseAddressNameserver(BaseNameserver, AddressAndPortNameserver):
    def __init__(self, config: AddressNameserverConfig):
        # 两个基类的 __init__ 签名不同，需分别显式初始化：
        # BaseNameserver 存 config/name/timeout；后者存 address/port。
        BaseNameserver.__init__(self, config)
        AddressAndPortNameserver.__init__(self, str(config.address), config.port)
