"""支持 `python -m src` 方式运行。"""
import asyncio

from .main import main

if __name__ == '__main__':
    asyncio.run(main())
