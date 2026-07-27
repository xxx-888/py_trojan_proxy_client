"""程序入口：装配配置、TrojanClient 与 SOCKS5Server 并启动服务。"""
import asyncio
import os

from .config import load_config, PROJECT_ROOT
from .logger import logger
from .trojan import TrojanClient
from .socks5 import SOCKS5Server


async def main():
    try:
        config = load_config(os.path.join(PROJECT_ROOT, 'config.json'))
        trojan_client = TrojanClient(config)
        socks5_server = SOCKS5Server(trojan_client, config)
        # 启动连接池清理任务
        asyncio.create_task(trojan_client.cleanup_connection_pool())
        await socks5_server.start()
    except KeyboardInterrupt:
        logger.info("正在关闭服务器")
    except Exception as e:
        logger.error(f"主循环错误: {type(e).__name__}: {e}")
