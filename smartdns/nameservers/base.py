import dns.message
from dns.nameserver import AddressAndPortNameserver

from smartdns.models.nameserver import NameserverConfig


class BaseNameserver(AddressAndPortNameserver):
    def __init__(self, config: NameserverConfig):
        super().__init__(str(config.address), config.port)
        self.config = config
        self.name = config.name
        self.timeout = config.timeout

    def kind(self) -> str:
        raise NotImplementedError

    def is_always_max_size(self) -> bool:
        return False

    def __str__(self):
        ns_kind = self.kind()
        return f"{ns_kind}:{self.address}@{self.port}"

    def answer_nameserver(self) -> str:
        return self.address

    def answer_port(self) -> int:
        return self.port

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        raise NotImplementedError

    async def start(self) -> None:
        """启动Nameserver服务"""
        raise NotImplementedError

    async def stop(self) -> None:
        """停止Nameserver服务"""
        raise NotImplementedError

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
