from time import time
from typing import TYPE_CHECKING

from dns.resolver import CacheKey, LRUCache

if TYPE_CHECKING:
    from dns.resolver import Answer

    from smartdns.models.context import Request


class TTLCache(LRUCache):
    """自动更新TTL的缓存类，继承自dns.resolver.LRUCache"""

    def __init__(self, maxsize: int = 10000):
        super().__init__(maxsize)

    def get(self, key: CacheKey) -> Answer | None:
        """重写get方法，获取缓存时自动更新TTL"""
        answer = super().get(key)
        if answer is not None:
            # 更新TTL
            ttl = int(answer.expiration - time())
            for rrset in answer.response.answer:
                rrset.update_ttl(ttl)
            for rrset in answer.response.authority:
                rrset.update_ttl(ttl)
            for rrset in answer.response.additional:
                rrset.update_ttl(ttl)
        return answer

    def cache_get(self, request: Request) -> Answer | None:
        """根据请求获取缓存的Answer对象"""
        key = (request.qname, request.rdtype, request.rdclass)
        return self.get(key)

    def cache_set(self, request: Request, answer: Answer) -> None:
        """根据请求设置缓存的Answer对象"""
        key = (request.qname, request.rdtype, request.rdclass)
        super().put(key, answer)


# class CacheManager:
#     # 按照resolver名称的缓存
#     caches: dict[str, TTLCache] = {}
#     def __init__(self,config:ResolverConfig)
