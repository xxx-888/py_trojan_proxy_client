"""程序入口：装配配置、TrojanClient 与 SOCKS5Server 并启动服务。"""
import argparse
import asyncio
import sys

from loguru import logger

from . import __version__
from .config import DEFAULT_CONFIG_NAME, PROJECT_ROOT, find_config, load_config
from .logger import setup_logger
from .trojan import TrojanClient
from .socks5 import SOCKS5Server


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='trojan-client',
        description='本地 SOCKS5 代理服务器，通过 Trojan 协议将流量转发到远端服务器',
    )
    parser.add_argument(
        '-c', '--config', default=None, metavar='PATH',
        help=f'配置文件路径（默认按 当前目录 → 程序目录 查找 {DEFAULT_CONFIG_NAME}）',
    )
    parser.add_argument('-V', '--version', action='version', version=f'%(prog)s {__version__}')
    return parser.parse_args(argv)


async def serve(config_path: str) -> None:
    """加载配置并启动代理服务，直到被取消或出错。"""
    config = load_config(config_path)
    setup_logger(level=config['log_level'])

    trojan_client = TrojanClient(config)
    socks5_server = SOCKS5Server(trojan_client, config)
    stats_task = asyncio.create_task(
        trojan_client.log_stats(config.get('stats_interval', 60))
    )
    try:
        await socks5_server.start()
        await socks5_server.run_forever()
    finally:
        stats_task.cancel()


def main(argv=None) -> None:
    """同步入口：解析参数、定位配置文件并运行事件循环。"""
    args = parse_args(argv)
    config_path = find_config(args.config)
    if config_path is None:
        searched = '当前目录 / 程序根目录'
        print(
            f"错误: 未找到配置文件 {DEFAULT_CONFIG_NAME}（已尝试 {searched}）。\n"
            f"请复制 config.example.json 为 {DEFAULT_CONFIG_NAME} 并填写你的服务器信息，\n"
            f"或使用 --config 指定路径。程序根目录: {PROJECT_ROOT}",
            file=sys.stderr,
        )
        sys.exit(2)

    exit_code = 0
    try:
        asyncio.run(serve(config_path))
    except KeyboardInterrupt:
        logger.info("收到 Ctrl+C，服务已停止")
    except (ValueError, FileNotFoundError) as e:
        logger.error(f"启动失败: {e}")
        exit_code = 2
    except Exception as e:
        logger.exception(f"主循环错误: {type(e).__name__}: {e}")
        exit_code = 1
    finally:
        sys.exit(exit_code)


if __name__ == '__main__':
    main()
