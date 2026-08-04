from itertools import chain
from time import time
from typing import TYPE_CHECKING

from dns.resolver import CacheKey, LRUCache

if TYPE_CHECKING:
    from dns.resolver import Answer

    from smartdns.models.context import Request


class TTLCache(LRUCache):
    """自动更新 TTL 的缓存，继承自 dns.resolver.LRUCache。

    注意：缓存键仅为 (qname, rdtype, rdclass)，不含客户端身份/ECS；按客户端 geo 路由
    改写的应答会被跨客户端复用。此为已知限制，本次重构保留现状。
    """

    def __init__(self, max_size: int = 10000):
        super().__init__(max_size)

    def get(self, key: CacheKey) -> Answer | None:
        """获取缓存并按剩余存活时间刷新各段 rrset 的 TTL。"""
        answer = super().get(key)
        if answer is not None:
            ttl = max(0, int(answer.expiration - time()))
            for rrset in chain(
                answer.response.answer,
                answer.response.authority,
                answer.response.additional,
            ):
                rrset.update_ttl(ttl)
        return answer

    def cache_get(self, request: Request) -> Answer | None:
        """根据请求获取缓存的 Answer 对象。"""
        return self.get((request.qname, request.rdtype, request.rdclass))

    def cache_set(self, request: Request, answer: Answer) -> None:
        """根据请求写入缓存的 Answer 对象。"""
        self.put((request.qname, request.rdtype, request.rdclass), answer)
