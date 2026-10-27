"""程序入口：装配配置、TrojanClient 与 SOCKS5Server 并启动服务。"""
import argparse
import asyncio
import sys
from typing import Dict

from loguru import logger

from . import __version__
from .config import DEFAULT_CONFIG_NAME, PROJECT_ROOT, find_config, load_config
from .logger import setup_logger
from .trojan import TrojanClient
from .socks5 import SOCKS5Server


def _loop_exception_handler(loop: asyncio.AbstractEventLoop, context: Dict) -> None:
    """过滤事件循环回调中良性的连接中断噪声，其余交给默认处理器。

    Windows ProactorEventLoop 在对端异常断开（RST, WinError 10054 /
    连接中止 1236）时，会在 _call_connection_lost 等内部收尾回调里抛出
    ConnectionResetError/ConnectionAbortedError——这是 asyncio 内部噪声，
    对端粗暴断开在代理场景（广告/爬虫类目标很常见）属正常网络行为；
    业务侧各转发泵已妥善处理连接错误，此处降级为 DEBUG 避免刷屏。
    """
    exception = context.get('exception')
    if isinstance(exception, (ConnectionResetError, ConnectionAbortedError)):
        logger.debug(f"忽略事件循环中的连接中断噪声: {context.get('message', '')} {exception!r}")
        return
    loop.default_exception_handler(context)


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
    asyncio.get_running_loop().set_exception_handler(_loop_exception_handler)
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
