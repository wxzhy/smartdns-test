"""真实连接池在获取、检查和归还时取消后，容量与连接所有权须恢复。"""

import asyncio
from importlib.metadata import version
from typing import TYPE_CHECKING, cast

import anyio.lowlevel
import dns.message
import pytest
from anyio import CancelScope, Event, create_task_group, fail_after, sleep
from generic_connection_pool.asyncio import BaseConnectionManager

from smartdns.models.nameserver import TCPNameserverConfig, TLSNameserverConfig
from smartdns.nameservers._pool_compat import (
    SUPPORTED_POOL_VERSION,
    CancellationSafeConnectionPool,
)
from smartdns.nameservers.tcp import TCPNameserver
from smartdns.nameservers.tls import TLSNameserver

if TYPE_CHECKING:
    from dns.asyncbackend import Backend


class _Connection:
    healthy = True


class _Manager(BaseConnectionManager[str, _Connection]):
    def __init__(self) -> None:
        self.entered = Event()
        self.block_create = False
        self.block_check = False
        self.block_hook = False
        self.created: list[_Connection] = []
        self.disposed: list[_Connection] = []

    async def create(self, endpoint: str) -> _Connection:
        self.entered.set()
        if self.block_create:
            await sleep(10)
        conn = _Connection()
        self.created.append(conn)
        return conn

    async def check_aliveness(self, endpoint: str, conn: _Connection) -> bool:
        if self.block_check:
            self.entered.set()
            await sleep(10)
        return conn.healthy

    async def on_acquire(self, endpoint: str, conn: _Connection) -> None:
        if self.block_hook:
            self.entered.set()
            await sleep(10)

    async def on_release(self, endpoint: str, conn: _Connection) -> None:
        await anyio.lowlevel.checkpoint()

    async def dispose(self, endpoint: str, conn: _Connection) -> None:
        await anyio.lowlevel.checkpoint()
        self.disposed.append(conn)


def _pool(manager: _Manager) -> CancellationSafeConnectionPool[str, _Connection]:
    return CancellationSafeConnectionPool(
        manager, min_idle=1, max_size=1, total_max_size=1
    )


@pytest.mark.parametrize(
    "cancellation", ["asyncio", "anyio", "timeout", "pool-timeout"]
)
async def test_cancelled_creation_rolls_back_all_capacity(cancellation: str) -> None:
    manager = _Manager()
    manager.block_create = True
    pool = _pool(manager)
    if cancellation == "asyncio":
        task = asyncio.create_task(pool.acquire("upstream", timeout=1))
        await manager.entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    elif cancellation == "anyio":
        async with create_task_group() as tg:
            tg.start_soon(pool.acquire, "upstream", 1)
            await manager.entered.wait()
            tg.cancel_scope.cancel()
    elif cancellation == "timeout":
        with pytest.raises(TimeoutError):
            with fail_after(0.05):
                await pool.acquire("upstream", timeout=1)
    else:
        with pytest.raises(TimeoutError):
            await pool.acquire("upstream", timeout=0.05)
    assert pool._pool_size == 0
    assert pool._pools.get_size() == 0
    manager.block_create = False
    with fail_after(1):
        async with pool.connection("upstream", timeout=0.5):
            pass
        await pool.close()
    assert manager.disposed == manager.created


@pytest.mark.parametrize("stage", ["health", "hook"])
@pytest.mark.parametrize("cancellation", ["asyncio", "anyio", "timeout"])
async def test_cancelled_check_returns_borrowed_connection(
    stage: str, cancellation: str
) -> None:
    manager = _Manager()
    pool = _pool(manager)
    async with pool.connection("upstream", timeout=0.5) as original:
        pass
    manager.entered = Event()
    manager.block_check = stage == "health"
    manager.block_hook = stage == "hook"
    if cancellation == "asyncio":
        task = asyncio.create_task(pool.acquire("upstream", timeout=1))
        await manager.entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    elif cancellation == "anyio":
        async with create_task_group() as tg:
            tg.start_soon(pool.acquire, "upstream", 1)
            await manager.entered.wait()
            tg.cancel_scope.cancel()
    else:
        with pytest.raises(TimeoutError):
            with fail_after(0.05):
                await pool.acquire("upstream", timeout=1)
    manager.block_check = manager.block_hook = False
    with fail_after(1):
        async with pool.connection("upstream", timeout=0.5) as recovered:
            assert recovered is original
        await pool.close()
    assert manager.disposed == [original]


async def test_cancelled_exchange_returns_connection_under_anyio_scope() -> None:
    manager = _Manager()
    pool = _pool(manager)
    with CancelScope() as scope:
        async with pool.connection("upstream", timeout=0.5):
            scope.cancel()
            await anyio.lowlevel.checkpoint()
    with fail_after(1):
        async with pool.connection("upstream", timeout=0.5):
            pass
        await pool.close()
    assert len(manager.created) == 1
    assert manager.disposed == manager.created


async def test_waiting_request_cancellation_keeps_existing_lease() -> None:
    manager = _Manager()
    pool = _pool(manager)
    conn = await pool.acquire("upstream", timeout=0.5)
    async with create_task_group() as tg:
        tg.start_soon(pool.acquire, "upstream", 1)
        await sleep(0.01)
        tg.cancel_scope.cancel()
    await pool.release(conn, "upstream")
    with fail_after(1):
        async with pool.connection("upstream", timeout=0.5) as recovered:
            assert recovered is conn
        await pool.close()


async def test_global_capacity_wait_cancellation_rolls_back_endpoint(
    monkeypatch,
) -> None:
    manager = _Manager()
    pool = _pool(manager)
    conn = await pool.acquire("first", timeout=0.5)
    waiting = Event()
    original = pool._try_free_slot

    async def wait_for_slot(timeout):
        waiting.set()
        return await original(timeout)

    monkeypatch.setattr(pool, "_try_free_slot", wait_for_slot)
    async with create_task_group() as tg:
        tg.start_soon(pool.acquire, "second", 1)
        await waiting.wait()
        tg.cancel_scope.cancel()
    assert pool._pool_size == 1
    assert pool._pools.get_size() == 1
    assert await pool.get_endpoint_pool_size("second") == 0
    await pool.release(conn, "first")
    with fail_after(1):
        async with pool.connection("second", timeout=0.5):
            pass
        await pool.close()
    assert manager.disposed == manager.created


async def test_cancelled_attach_closes_new_connection_and_rolls_back(
    monkeypatch,
) -> None:
    manager = _Manager()
    pool = _pool(manager)
    async with pool._pools.acquired("upstream", setdefault=True) as endpoint_pool:
        pass
    attaching = Event()
    original_create = manager.create
    original_attach = endpoint_pool.attach_and_unreserve

    async def create(endpoint):
        conn = await original_create(endpoint)
        await endpoint_pool._condvar.acquire()
        return conn

    async def attach(info, acquired=False):
        attaching.set()
        await original_attach(info, acquired)

    monkeypatch.setattr(manager, "create", create)
    monkeypatch.setattr(endpoint_pool, "attach_and_unreserve", attach)
    task = asyncio.create_task(pool.acquire("upstream", timeout=1))
    await attaching.wait()
    task.cancel()
    await anyio.lowlevel.checkpoint()
    endpoint_pool._condvar.release()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert pool._pool_size == 0
    assert pool._pools.get_size() == 0
    assert manager.disposed == manager.created
    monkeypatch.setattr(manager, "create", original_create)
    with fail_after(1):
        async with pool.connection("upstream", timeout=0.5):
            pass
        await pool.close()


async def test_unhealthy_connection_is_closed_before_replacement() -> None:
    manager = _Manager()
    pool = _pool(manager)
    async with pool.connection("upstream", timeout=0.5) as broken:
        broken.healthy = False
    async with pool.connection("upstream", timeout=0.5) as replacement:
        assert replacement is not broken
        assert manager.disposed == [broken]
    await pool.close()
    assert manager.disposed == [broken, replacement]


@pytest.mark.parametrize("kind", ["tcp", "tls"])
async def test_nameserver_recovers_after_cancelled_creation(
    kind: str, monkeypatch
) -> None:
    if kind == "tcp":
        ns = TCPNameserver(
            TCPNameserverConfig(
                name="test", type="tcp", address="127.0.0.1", port=53, pool_size=1
            )
        )
    else:
        ns = TLSNameserver(
            TLSNameserverConfig(
                name="test",
                type="tls",
                address="127.0.0.1",
                verify=False,
                fingerprint=None,
                pool_size=1,
            )
        )
    await ns.start()
    manager = _Manager()
    manager.block_create = True
    assert ns._pool is not None
    monkeypatch.setattr(ns._pool, "_connection_manager", manager)
    query = dns.message.make_query("example.com.", "A")
    backend = cast("Backend", object())
    task = asyncio.create_task(ns.async_query(query, 1, None, 0, False, backend))
    await manager.entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert ns._pool._pool_size == 0
    manager.block_create = False

    async def exchange(*args, **kwargs):
        return dns.message.make_response(query)

    monkeypatch.setattr(ns, "_query_on_stream", exchange)
    with fail_after(1):
        result = await ns.async_query(query, 0.5, None, 0, False, backend)
        assert query.is_response(result)
        await ns.stop()
    assert manager.disposed == manager.created


def test_installed_pool_matches_compat_layer_version() -> None:
    """兼容层依赖私有实现；升级依赖时须先重新核对再更新此版本号。"""
    assert version("generic-connection-pool") == SUPPORTED_POOL_VERSION
