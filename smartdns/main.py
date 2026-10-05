from pathlib import Path
from signal import SIGTERM
from sys import platform, stderr
from typing import Annotated

import typer
from anyio import create_task_group, open_signal_receiver, run
from loguru import logger
from typer import Typer

from smartdns.core.master import Master
from smartdns.models.config import Config

app = Typer(name="SmartDNS", help="SmartDNS CLI 工具")


async def _serve(config: Config) -> None:
    """启动 Master 主服务并阻塞运行。"""
    master = Master(config)
    if platform == "win32":
        await master.start()
        return

    # ujail 中的服务可能是 PID 命名空间的 PID 1；默认 SIGTERM 动作不会
    # 终止它。显式接收信号并取消主服务，让 Master 的 finally 清理资源。
    with open_signal_receiver(SIGTERM) as signals:
        async with create_task_group() as tg:

            async def stop_on_sigterm() -> None:
                async for _ in signals:
                    logger.info("收到 SIGTERM，停止 SmartDNS 服务")
                    tg.cancel_scope.cancel()
                    return

            tg.start_soon(stop_on_sigterm)
            try:
                await master.start()
            finally:
                tg.cancel_scope.cancel()


@app.command()
def start(
    config: Annotated[Path, typer.Option(exists=True, help="配置文件路径")] = Path(
        "config.yaml"
    ),
) -> None:
    """启动 SmartDNS 服务"""
    logger.info("启动 SmartDNS 服务")
    Config.set_config_file(config)
    try:
        cfg = Config()
    except Exception:
        logger.exception("配置文件加载失败")
        raise typer.Exit(1) from None
    # 默认只输出 INFO 及以上，异步写入避免 stderr 阻塞 DNS 事件循环。
    logger.remove()
    logger.add(stderr, level=cfg.log_level, enqueue=True, diagnose=False)
    logger.info(
        "配置加载成功：{} 监听器 / {} 上游 / {} 解析器 / {} 路由",
        len(cfg.listeners),
        len(cfg.nameservers),
        len(cfg.resolvers),
        len(cfg.routing),
    )
    run(_serve, cfg, backend_options={"use_uvloop": True})


if __name__ == "__main__":
    app()
