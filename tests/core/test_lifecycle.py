"""Worker 与组件管理器的部分启动失败清理回归测试。"""

from typing import TYPE_CHECKING, cast

import pytest
from anyio import Event, create_task_group, sleep
from pydantic import TypeAdapter

from smartdns.actions.manager import ActionManager
from smartdns.core.worker import Worker
from smartdns.listeners.manager import ListenerManager
from smartdns.models.action import ActionConfig
from smartdns.models.listener import ListenerConfig
from smartdns.models.nameserver import NameserverConfig
from smartdns.models.resolver import ResolverConfig
from smartdns.nameservers.manager import NameserverManager
from smartdns.resolvers.manager import ResolverManager

if TYPE_CHECKING:
    from smartdns.nameservers.client import HTTPClient


class _Spy:
    def __init__(self) -> None:
        self.called = False

    async def stop_all(self) -> None:
        self.called = True

    async def stop(self) -> None:
        self.called = True


class _FailingComponent:
    def __init__(self, name: str = "failing") -> None:
        self.name = name
        self.stopped = False

    async def start(self, *args: object) -> None:
        raise RuntimeError("partial startup failure")

    async def stop(self) -> None:
        self.stopped = True


class _CancellableComponent(_FailingComponent):
    def __init__(self, start_entered: Event) -> None:
        super().__init__()
        self._start_entered = start_entered

    async def start(self, *args: object) -> None:
        self._start_entered.set()
        await sleep(10)


class _Client:
    pass


async def test_worker_stop_stops_all_components() -> None:
    worker = Worker.__new__(Worker)
    worker.worker_id = 0
    resolvers, nameservers, actions, client = _Spy(), _Spy(), _Spy(), _Spy()
    worker._resolvers = cast("ResolverManager", resolvers)
    worker._nameservers = cast("NameserverManager", nameservers)
    worker._actions = cast("ActionManager", actions)
    worker._client = cast("HTTPClient", client)

    await worker.stop()

    assert resolvers.called
    assert nameservers.called
    assert actions.called
    assert client.called


async def test_worker_stop_tolerates_partial_init() -> None:
    worker = Worker.__new__(Worker)
    worker.worker_id = 0
    worker._resolvers = None
    worker._nameservers = None
    worker._actions = None
    worker._client = None
    await worker.stop()


async def test_nameserver_manager_stops_component_whose_start_fails(
    monkeypatch,
) -> None:
    component = _FailingComponent()
    monkeypatch.setattr(
        "smartdns.nameservers.manager.UDPNameserver",
        lambda config: component,
    )
    config = TypeAdapter(NameserverConfig).validate_python(
        {
            "name": "failing",
            "type": "udp",
            "address": "127.0.0.1",
            "port": 53,
        }
    )
    manager = NameserverManager([config], cast("HTTPClient", _Client()))

    with pytest.raises(RuntimeError, match="partial startup failure"):
        await manager.start_all()

    assert component.stopped
    assert manager.nameservers == {}


async def test_action_manager_stops_component_whose_start_fails(monkeypatch) -> None:
    component = _FailingComponent()
    monkeypatch.setattr(
        "smartdns.actions.manager.LogAction",
        lambda config: component,
    )
    config = TypeAdapter(ActionConfig).validate_python(
        {
            "name": "failing",
            "type": "log",
            "text": "x",
        }
    )
    manager = ActionManager([config], cast("HTTPClient", _Client()))

    with pytest.raises(RuntimeError, match="partial startup failure"):
        await manager.start_all()

    assert component.stopped
    assert manager.actions == {}


async def test_resolver_manager_stops_component_whose_start_fails(
    monkeypatch,
) -> None:
    component = _FailingComponent()
    monkeypatch.setattr(
        "smartdns.resolvers.manager.AioDNSResolver",
        lambda config: component,
    )
    config = TypeAdapter(ResolverConfig).validate_python(
        {
            "name": "failing",
            "type": "aiodns",
            "nameservers": ["127.0.0.1"],
        }
    )
    manager = ResolverManager([config])

    with pytest.raises(RuntimeError, match="partial startup failure"):
        await manager.start_all(
            cast("NameserverManager", object()), cast("ActionManager", object())
        )

    assert component.stopped
    assert manager.resolvers == {}


async def test_listener_manager_stops_listener_whose_start_fails(monkeypatch) -> None:
    component = _FailingComponent()
    monkeypatch.setattr(
        "smartdns.listeners.manager.UDPListener", lambda config: component
    )
    config = TypeAdapter(ListenerConfig).validate_python(
        {
            "name": "failing",
            "type": "udp",
            "host": "127.0.0.1",
            "port": 5353,
        }
    )
    manager = ListenerManager([config])

    async def handler(request: object) -> None:
        return None

    with pytest.raises(ExceptionGroup) as error:
        await manager.start_all(handler)

    assert any(
        isinstance(item, RuntimeError) and str(item) == "partial startup failure"
        for item in error.value.exceptions
    )
    assert component.stopped
    assert manager.listeners == []


async def test_action_manager_cleanup_is_shielded_from_cancellation(
    monkeypatch,
) -> None:
    start_entered = Event()
    component = _CancellableComponent(start_entered)
    monkeypatch.setattr(
        "smartdns.actions.manager.LogAction",
        lambda config: component,
    )
    config = TypeAdapter(ActionConfig).validate_python(
        {
            "name": "failing",
            "type": "log",
            "text": "x",
        }
    )
    manager = ActionManager([config], cast("HTTPClient", _Client()))

    async with create_task_group() as tg:
        tg.start_soon(manager.start_all)
        await start_entered.wait()
        tg.cancel_scope.cancel()

    assert component.stopped
    assert manager.actions == {}
