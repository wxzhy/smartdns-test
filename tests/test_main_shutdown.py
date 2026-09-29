"""主入口收到 Unix SIGTERM 时应清理服务并退出。"""

from signal import SIGTERM
from typing import TYPE_CHECKING, cast

from anyio import Event, create_task_group, fail_after, sleep_forever

from smartdns import main

if TYPE_CHECKING:
    from smartdns.models.config import Config


class _SignalReceiver:
    def __init__(self) -> None:
        self.trigger = Event()
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True

    async def __aiter__(self):
        await self.trigger.wait()
        yield SIGTERM


class _RunningMaster:
    def __init__(self) -> None:
        self.started = Event()
        self.stopped = Event()

    async def start(self) -> None:
        self.started.set()
        try:
            await sleep_forever()
        finally:
            self.stopped.set()


async def test_sigterm_cancels_master_and_closes_receiver(monkeypatch) -> None:
    master = _RunningMaster()
    receiver = _SignalReceiver()
    selected_signals: list[object] = []

    def open_receiver(*signals: object) -> _SignalReceiver:
        selected_signals.extend(signals)
        return receiver

    monkeypatch.setattr(main, "platform", "linux")
    monkeypatch.setattr(main, "Master", lambda config: master)
    monkeypatch.setattr(main, "open_signal_receiver", open_receiver)

    with fail_after(2):
        async with create_task_group() as tg:
            tg.start_soon(main._serve, cast("Config", object()))
            await master.started.wait()
            receiver.trigger.set()
            await master.stopped.wait()

    assert selected_signals == [SIGTERM]
    assert receiver.closed


async def test_master_normal_exit_cancels_signal_watcher(monkeypatch) -> None:
    receiver = _SignalReceiver()

    class _FinishedMaster:
        async def start(self) -> None:
            return

    monkeypatch.setattr(main, "platform", "linux")
    monkeypatch.setattr(main, "Master", lambda config: _FinishedMaster())
    monkeypatch.setattr(main, "open_signal_receiver", lambda *signals: receiver)

    with fail_after(2):
        await main._serve(cast("Config", object()))

    assert receiver.closed


async def test_windows_start_does_not_install_unix_signal_handler(monkeypatch) -> None:
    class _FinishedMaster:
        def __init__(self) -> None:
            self.started = False

        async def start(self) -> None:
            self.started = True

    master = _FinishedMaster()
    monkeypatch.setattr(main, "platform", "win32")
    monkeypatch.setattr(main, "Master", lambda config: master)

    def fail_on_signal_receiver(*signals: object) -> None:
        raise AssertionError("Windows must not install a Unix signal handler")

    monkeypatch.setattr(main, "open_signal_receiver", fail_on_signal_receiver)

    await main._serve(cast("Config", object()))

    assert master.started
