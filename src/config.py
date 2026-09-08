"""配置加载与校验。

负责定位项目根目录（兼容 PyInstaller 打包后的 exe）、查找并读取
Trojan 客户端的 JSON 配置文件，缺失字段时抛出清晰错误，并为可选
字段填充默认值、做基本的类型与取值校验。
"""
import os
import sys
import json
from typing import Any, Dict, Optional

from loguru import logger

# PyInstaller 打包后 __file__ 指向临时解包目录，须以 exe 所在目录为根，
# 这样 config.json / 日志文件始终与用户可见的可执行文件在一起。
if getattr(sys, 'frozen', False):
    PROJECT_ROOT = os.path.dirname(os.path.abspath(sys.executable))
else:
    # 项目根目录：src/ 的上一级
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_CONFIG_NAME = 'config.json'

# 配置文件必须的字段
REQUIRED_FIELDS = ['trojan_host', 'trojan_port', 'trojan_password', 'listen_host', 'listen_port']

# 可选字段的默认值
DEFAULTS: Dict[str, Any] = {
    'timeout': 10,           # 与 Trojan 服务器建立连接的超时（秒）
    'idle_timeout': 300,     # 转发空闲超时（秒），0 表示不超时
    'buffer_size': 65536,    # 收发缓冲区大小（字节）
    'stats_interval': 60,    # 活跃连接数统计输出间隔（秒）
    'users': {},             # SOCKS5 用户名/密码认证表，为空则关闭认证
    'ssl_verify': False,     # 是否校验 Trojan 服务器证书
    'ssl_sni': '',           # TLS SNI，默认使用 trojan_host
    'log_level': 'INFO',     # 日志级别：TRACE/DEBUG/INFO/WARNING/ERROR
}

VALID_LOG_LEVELS = {'TRACE', 'DEBUG', 'INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL'}


def find_config(explicit_path: Optional[str] = None) -> Optional[str]:
    """按优先级查找配置文件：显式路径 > 环境变量 > 当前目录 > 程序根目录。

    显式路径是权威指定：存在则直接使用，不存在则返回 None（由调用方
    报出准确的错误），不再静默回退到其他候选位置。
    """
    if explicit_path:
        return explicit_path if os.path.isfile(explicit_path) else None
    candidates = []
    env_path = os.environ.get('TROJAN_CONFIG')
    if env_path:
        candidates.append(env_path)
    candidates.append(os.path.join(os.getcwd(), DEFAULT_CONFIG_NAME))
    candidates.append(os.path.join(PROJECT_ROOT, DEFAULT_CONFIG_NAME))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _validate(config: Dict[str, Any], config_path: str) -> None:
    """对关键字段做类型与取值校验，错误信息指向具体字段。"""
    def fail(field: str, reason: str):
        raise ValueError(f"配置文件 {config_path} 字段 {field} {reason}")

    for field in ('trojan_port', 'listen_port'):
        port = config[field]
        if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
            fail(field, f"必须是 1-65535 的整数，当前为 {port!r}")

    if not config['trojan_host']:
        fail('trojan_host', '不能为空')
    if not config['trojan_password']:
        fail('trojan_password', '不能为空')
    if not config['listen_host']:
        fail('listen_host', '不能为空')

    for field in ('timeout', 'buffer_size', 'stats_interval'):
        value = config[field]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            fail(field, f"必须是正整数，当前为 {value!r}")

    idle_timeout = config['idle_timeout']
    if not isinstance(idle_timeout, int) or isinstance(idle_timeout, bool) or idle_timeout < 0:
        fail('idle_timeout', f"必须是不小于 0 的整数，当前为 {idle_timeout!r}")

    users = config['users']
    if not isinstance(users, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in users.items()
    ):
        fail('users', '必须是 {用户名: 密码} 的字符串映射')

    config['log_level'] = str(config['log_level']).upper()
    if config['log_level'] not in VALID_LOG_LEVELS:
        fail('log_level', f"必须是 {sorted(VALID_LOG_LEVELS)} 之一，当前为 {config['log_level']!r}")


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
        _validate(config, config_path)
        logger.info(f"成功加载配置文件: {config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"配置文件未找到: {config_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"配置文件格式错误: {e}")
        raise
    except ValueError:
        raise
    except Exception as e:
        logger.error(f"加载配置文件时发生意外错误: {type(e).__name__}: {e}")
        raise
