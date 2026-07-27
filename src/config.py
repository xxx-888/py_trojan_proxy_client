"""配置加载与校验。

负责定位项目根目录、读取并校验 Trojan 客户端的 JSON 配置文件，
缺失字段时抛出清晰错误，并为可选字段填充默认值。
"""
import os
import json
from typing import Dict, Any

from loguru import logger

# 项目根目录：src/ 的上一级
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 配置文件必须的字段
REQUIRED_FIELDS = ['trojan_host', 'trojan_port', 'trojan_password', 'listen_host', 'listen_port']

# 可选字段的默认值
DEFAULTS: Dict[str, Any] = {
    'timeout': 60,
    'max_retries': 3,
    'buffer_size': 16384,
    'pool_cleanup_interval': 30,
    'users': {},
}


def load_config(config_path: str) -> Dict[str, Any]:
    """加载并校验 JSON 配置文件，填充默认值后返回。"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        for field in REQUIRED_FIELDS:
            if field not in config:
                logger.error(f"配置文件缺少必要字段: {field}")
                raise ValueError(f"配置文件缺少必要字段: {field}")
        for key, value in DEFAULTS.items():
            config.setdefault(key, value)
        logger.info(f"成功加载配置文件: {config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"配置文件未找到: {config_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"配置文件格式错误: {e}")
        raise
    except Exception as e:
        logger.error(f"加载配置文件时发生意外错误: {type(e).__name__}: {e}")
        raise
