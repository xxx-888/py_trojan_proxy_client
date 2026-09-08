"""日志初始化。

集中配置 loguru：滚动文件日志 + 控制台彩色输出。
导入本模块即完成一次默认配置；main 启动后会依据配置中的
log_level 重新调用 setup_logger（幂等：先 remove 再 add）。
"""
import os
import sys
from loguru import logger

from .config import PROJECT_ROOT

LOG_FILE = os.path.join(PROJECT_ROOT, "trojan_client.log")

VALID_LEVELS = {"TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"}


def setup_logger(level: str = "INFO", log_file: str = None) -> None:
    """配置 loguru 处理器：文件(滚动, enqueue 后台写入) + 控制台(彩色)。"""
    level = str(level or "INFO").upper()
    if level not in VALID_LEVELS:
        level = "INFO"
    logger.remove()
    logger.add(
        log_file or LOG_FILE,
        rotation="10MB",
        retention="7 days",
        level=level,
        backtrace=True,
        diagnose=False,  # 不输出局部变量，避免日志泄露本机路径等环境信息
        enqueue=True,    # 后台线程写文件，降低高频日志对转发性能的影响
    )
    logger.add(sys.stderr, colorize=True, level=level)


# 模块导入时即完成默认配置（main 中会按配置重新初始化）
setup_logger()
