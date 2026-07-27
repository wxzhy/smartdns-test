from anyio import run
from loguru import logger
from typer import Typer

from .core.master import Master
from .models.config import Config


async def main():
    """启动 SmartDNS 主服务"""
    logger.info("加载配置")
    try:
        config = Config()
        logger.debug(f"配置文件加载成功: {config}")
    except Exception as e:
        logger.error(f"配置文件加载失败: {e}")
        return
    master = Master(config)
    await master.start()


app = Typer(name="SmartDNS", help="SmartDNS CLI 工具")


@app.command()
def start(config: str = "config.yaml"):
    """启动 SmartDNS 服务"""
    logger.info("启动 SmartDNS 服务")
    Config.set_config_file(config)
    run(main, backend_options={"use_uvloop": True})


if __name__ == "__main__":
    app()
