"""日志初始化。

集中配置 loguru：滚动文件日志 + 控制台彩色输出。
导入本模块即完成一次配置（幂等：先 remove 再 add）。
"""
import os
from loguru import logger

from .config import PROJECT_ROOT

LOG_FILE = os.path.join(PROJECT_ROOT, "trojan_client.log")


def setup_logger() -> None:
    """配置 loguru 处理器：文件(INFO, 滚动) + 控制台(DEBUG)。"""
    logger.remove()
    logger.add(
        LOG_FILE,
        rotation="10MB",
        retention="7 days",
        level="INFO",
        backtrace=True,
        diagnose=True,
    )
    logger.add(lambda msg: print(msg, end=""), colorize=True, level="DEBUG")


# 模块导入时即完成配置
setup_logger()
