"""根目录启动器：允许 `python run.py` 直接运行 Trojan 代理客户端。

包内部使用相对导入（from .config import ...），必须以「包/模块」方式加载，
因此不能直接 `python src/main.py`（会丢失包上下文）。

推荐两种方式（效果相同）：
    python -m src        # 以模块方式运行（src/__main__.py）
    python run.py        # 通过本启动器运行
"""

import asyncio

from src.main import main

if __name__ == "__main__":
    asyncio.run(main())
