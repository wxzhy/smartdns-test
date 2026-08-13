from collections import OrderedDict
from threading import Lock
from time import time
from typing import TYPE_CHECKING

from smartdns.actions._helper import clone_answer

if TYPE_CHECKING:
    from dns.name import Name
    from dns.rdataclass import RdataClass
    from dns.rdatatype import RdataType
    from dns.resolver import Answer

    from smartdns.models.context import Request

type CacheKey = tuple[
    Name,
    RdataType,
    RdataClass,
    str,
    str | None,
    str | None,
]


class TTLCache:
    """按客户端上下文隔离、线程安全且 copy-on-write 的 Answer LRU 缓存。"""

    def __init__(self, max_size: int = 10000) -> None:
        self.max_size = max_size
        self._data: OrderedDict[CacheKey, Answer] = OrderedDict()
        self._lock = Lock()

    def get(self, key: CacheKey) -> Answer | None:
        with self._lock:
            answer = self._data.get(key)
            if answer is None:
                return None
            if answer.expiration <= time():
                del self._data[key]
                return None
            self._data.move_to_end(key)
            ttl = max(0, int(answer.expiration - time()))
            return clone_answer(answer, remaining_ttl=ttl)

    def put(self, key: CacheKey, answer: Answer) -> None:
        copied = clone_answer(answer)
        with self._lock:
            self._data[key] = copied
            self._data.move_to_end(key)
            while len(self._data) > self.max_size:
                self._data.popitem(last=False)

    def cache_get(self, request: Request) -> Answer | None:
        return self.get(self._key(request))

    def cache_set(self, request: Request, answer: Answer) -> None:
        self.put(self._key(request), answer)

    @staticmethod
    def _key(request: Request) -> CacheKey:
        return (
            request.qname,
            request.rdtype,
            request.rdclass,
            request.listener,
            str(request.remote_address) if request.remote_address is not None else None,
            str(request.ecs) if request.ecs is not None else None,
        )
