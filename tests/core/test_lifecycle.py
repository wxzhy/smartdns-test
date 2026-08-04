"""Phase 8：Worker 停机路径回归测试。

修复前：Worker 无 stop()，各 manager 的 stop_all 与 client.stop 从不被调用，
长驻服务退出/重载时 HTTP 客户端与上游连接泄漏。修复后：Worker.stop() 按依赖逆序
停止各管理器并释放客户端。
"""

from typing import cast

from smartdns.actions.manager import ActionManager
from smartdns.core.worker import Worker
from smartdns.nameservers.client import HTTPClient
from smartdns.nameservers.manager import NameserverManager
from smartdns.resolvers.manager import ResolverManager


class _Spy:
    def __init__(self) -> None:
        self.called = False

    async def stop_all(self) -> None:
        self.called = True

    async def stop(self) -> None:
        self.called = True


async def test_worker_stop_stops_all_components() -> None:
    worker = Worker.__new__(Worker)  # 绕过需要 Config 的 __init__
    worker.worker_id = 0
    resolvers, nameservers, actions, client = _Spy(), _Spy(), _Spy(), _Spy()
    worker._resolvers = cast(ResolverManager, resolvers)
    worker._nameservers = cast(NameserverManager, nameservers)
    worker._actions = cast(ActionManager, actions)
    worker._client = cast(HTTPClient, client)

    await worker.stop()

    assert resolvers.called
    assert nameservers.called
    assert actions.called
    assert client.called


async def test_worker_stop_tolerates_partial_init() -> None:
    # 部分初始化（如 start 中途失败）时，None 组件应被跳过而不抛错。
    worker = Worker.__new__(Worker)
    worker.worker_id = 0
    worker._resolvers = None
    worker._nameservers = None
    worker._actions = None
    worker._client = None
    await worker.stop()  # 不应抛异常
