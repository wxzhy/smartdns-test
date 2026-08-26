from pathlib import Path
from typing import Annotated

import typer
from anyio import run
from loguru import logger
from typer import Typer

from smartdns.core.master import Master
from smartdns.models.config import Config

app = Typer(name="SmartDNS", help="SmartDNS CLI 工具")


async def _serve(config: Config) -> None:
    """启动 Master 主服务并阻塞运行。"""
    master = Master(config)
    await master.start()


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
