"""main 模块的事件循环异常处理器测试。"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main import _loop_exception_handler  # noqa: E402


def make_loop():
    """构造一个记录 default_exception_handler 调用的假事件循环。"""
    delegated = []
    loop = types.SimpleNamespace(default_exception_handler=delegated.append)
    return loop, delegated


class TestLoopExceptionHandler(unittest.TestCase):

    def test_connection_reset_ignored(self):
        # 对端 RST (WinError 10054)：吞掉，不交给默认处理器
        loop, delegated = make_loop()
        _loop_exception_handler(
            loop,
            {'exception': ConnectionResetError(10054, '远程主机强迫关闭了一个现有的连接。'),
             'message': 'Exception in callback _ProactorBasePipeTransport._call_connection_lost()'},
        )
        self.assertEqual(delegated, [])

    def test_connection_aborted_ignored(self):
        # 连接中止 (WinError 1236)：同样吞掉
        loop, delegated = make_loop()
        _loop_exception_handler(loop, {'exception': ConnectionAbortedError(1236, '连接中止')})
        self.assertEqual(delegated, [])

    def test_other_exception_delegated(self):
        # 其他异常：必须交给默认处理器完整报告
        loop, delegated = make_loop()
        context = {'exception': ValueError('boom'), 'message': 'Exception in callback foo()'}
        _loop_exception_handler(loop, context)
        self.assertEqual(delegated, [context])

    def test_no_exception_delegated(self):
        # 无异常对象的上下文（如任务结果未取回）：同样交给默认处理器
        loop, delegated = make_loop()
        context = {'message': 'Task was destroyed but it is pending!'}
        _loop_exception_handler(loop, context)
        self.assertEqual(delegated, [context])


if __name__ == '__main__':
    unittest.main()
