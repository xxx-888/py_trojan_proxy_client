"""SOCKS5 + TrojanClient 全链路集成测试（本地回环，不依赖外网与真实服务器）。

通过本地 Mock Trojan 服务器（真实 TLS + Trojan 协议）验证：
- SOCKS5 握手 / 用户名密码认证（成功与失败）
- CONNECT 双向转发（域名透传到远端解析）
- UDP ASSOCIATE 数据报往返（含并发多目标）
- 协议纯函数部分由 test_protocol.py 覆盖
"""
import asyncio
import hashlib
import os
import socket
import ssl
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.protocol import (  # noqa: E402
    encode_address,
    parse_socks5_udp_datagram,
    parse_trojan_udp_stream,
)
from src.socks5 import SOCKS5Server  # noqa: E402
from src.trojan import TrojanClient  # noqa: E402
from tests.certs import CERT_PEM, KEY_PEM  # noqa: E402

TEST_PASSWORD = 'integration-test-password'


class MockTrojanServer:
    """本地 Trojan 服务器：校验密码后回显 CONNECT 数据 / 回显 UDP 数据报。"""

    def __init__(self, password: str = TEST_PASSWORD):
        self.hashed = hashlib.sha224(password.encode()).hexdigest()
        self._server = None

    async def start(self) -> 'MockTrojanServer':
        with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False, encoding='ascii') as f:
            f.write(CERT_PEM.strip() + '\n' + KEY_PEM.strip())
            certfile = f.name
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile)
        finally:
            os.unlink(certfile)
        self._server = await asyncio.start_server(self._handle, '127.0.0.1', 0, ssl=ctx)
        return self

    @property
    def port(self) -> int:
        return self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            if line.decode(errors='replace').strip() != self.hashed:
                return  # 密码错误：直接断开
            head = await reader.readexactly(2)  # CMD + ATYP
            atyp = head[1]
            if atyp == 1:
                head += await reader.readexactly(6)
            elif atyp == 3:
                n = (await reader.readexactly(1))[0]
                head += bytes([n]) + await reader.readexactly(n + 2)
            elif atyp == 4:
                head += await reader.readexactly(18)
            await reader.readexactly(2)  # CRLF

            if head[0] == 1:  # CONNECT：回显全部数据
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            else:  # UDP ASSOCIATE：按 Trojan UDP 帧回显
                buf = b''
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    buf += data
                    packets, consumed = parse_trojan_udp_stream(buf)
                    buf = buf[consumed:]
                    for addr, port, payload in packets:
                        writer.write(
                            encode_address(addr, port)
                            + struct.pack('>H', len(payload)) + b'\r\n' + payload
                        )
                        await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


class ProxyIntegrationTestCase(unittest.TestCase):
    """公共装置：启动 Mock Trojan + SOCKS5 服务（随机端口）。"""

    def _setup_proxy(self, users=None) -> tuple:
        """同步初始化（在 asyncio.run 内调用）。"""
        raise NotImplementedError

    async def _start_proxy(self, users=None):
        mock = await MockTrojanServer().start()
        config = {
            'trojan_host': '127.0.0.1',
            'trojan_port': mock.port,
            'trojan_password': TEST_PASSWORD,
            'listen_host': '127.0.0.1',
            'listen_port': 0,  # 随机端口
            'users': users or {},
            'timeout': 5,
            'idle_timeout': 5,
            'buffer_size': 65536,
        }
        client = TrojanClient(config)
        server = SOCKS5Server(client, config)
        await server.start()
        return mock, server

    async def _socks_connect(self, port: int, user: str = None, password: str = None):
        """完成到 SOCKS5 服务器的握手，返回 (reader, writer)。"""
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        if user is not None:
            writer.write(b'\x05\x01\x02')
        else:
            writer.write(b'\x05\x01\x00')
        await writer.drain()
        choice = await reader.readexactly(2)
        assert choice == (b'\x05\x02' if user is not None else b'\x05\x00'), choice
        if user is not None:
            writer.write(
                b'\x01' + bytes([len(user)]) + user.encode()
                + bytes([len(password)]) + password.encode()
            )
            await writer.drain()
            status = await reader.readexactly(2)
            if status != b'\x01\x00':
                writer.close()
                raise PermissionError('认证失败')
        return reader, writer

    async def _request_connect(self, writer, addr: str, port: int):
        host = addr.encode()
        writer.write(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + struct.pack('>H', port))
        await writer.drain()

    async def _request_udp(self, writer):
        writer.write(
            b'\x05\x03\x00\x01' + socket.inet_pton(socket.AF_INET, '127.0.0.1') + struct.pack('>H', 0)
        )
        await writer.drain()


class TestConnect(ProxyIntegrationTestCase):

    def test_connect_relay_echo(self):
        asyncio.run(self._scenario())

    async def _scenario(self):
        mock, server = await self._start_proxy()
        try:
            reader, writer = await self._socks_connect(server.bound_port)
            await self._request_connect(writer, 'example.com', 80)
            reply = await asyncio.wait_for(reader.readexactly(10), timeout=5)
            self.assertEqual(reply[1], 0x00, f'CONNECT 应答失败: {reply.hex()}')

            writer.write(b'hello trojan')
            await writer.drain()
            data = await asyncio.wait_for(reader.read(64), timeout=5)
            self.assertEqual(data, b'hello trojan')

            # 大块数据双向转发（超过单个缓冲区）
            blob = os.urandom(300_000)
            writer.write(blob)
            await writer.drain()
            got = b''
            while len(got) < len(blob):
                chunk = await asyncio.wait_for(reader.read(65536), timeout=10)
                self.assertTrue(chunk)
                got += chunk
            self.assertEqual(got, blob)
            writer.close()
        finally:
            await mock.close()
            await server.stop()


class TestAuth(ProxyIntegrationTestCase):

    def test_auth_success_and_failure(self):
        asyncio.run(self._scenario())

    async def _scenario(self):
        mock, server = await self._start_proxy(users={'alice': 'wonderland'})
        try:
            # 正确密码：认证成功并可完成 CONNECT
            reader, writer = await self._socks_connect(
                server.bound_port, user='alice', password='wonderland'
            )
            await self._request_connect(writer, 'example.com', 80)
            reply = await asyncio.wait_for(reader.readexactly(10), timeout=5)
            self.assertEqual(reply[1], 0x00)
            writer.close()

            # 错误密码：认证失败
            with self.assertRaises(PermissionError):
                await self._socks_connect(server.bound_port, user='alice', password='wrong')

            # 未提供认证方法：被拒绝
            reader, writer = await asyncio.open_connection('127.0.0.1', server.bound_port)
            writer.write(b'\x05\x01\x00')  # 只声明无认证
            await writer.drain()
            choice = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            self.assertEqual(choice, b'\x05\xFF')
            writer.close()
        finally:
            await mock.close()
            await server.stop()


class TestUdpAssociate(ProxyIntegrationTestCase):

    def test_udp_roundtrip(self):
        asyncio.run(self._scenario())

    async def _scenario(self):
        mock, server = await self._start_proxy()
        loop = asyncio.get_running_loop()
        try:
            reader, writer = await self._socks_connect(server.bound_port)
            await self._request_udp(writer)
            reply = await asyncio.wait_for(reader.readexactly(10), timeout=5)
            self.assertEqual(reply[1], 0x00, f'UDP ASSOCIATE 应答失败: {reply.hex()}')
            self.assertEqual(reply[3], 0x01)
            relay_port = struct.unpack('>H', reply[8:10])[0]

            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setblocking(False)
            try:
                # 并发向两个不同目标发送（验证全双工与响应归属）
                for target, payload in [('8.8.8.8', b'dns-query-a'), ('1.1.1.1', b'dns-query-b')]:
                    packet = b'\x00\x00\x00' + encode_address(target, 53) + payload
                    await loop.sock_sendto(udp, packet, ('127.0.0.1', relay_port))

                responses = {}
                for _ in range(2):
                    data, _ = await asyncio.wait_for(loop.sock_recvfrom(udp, 65536), timeout=5)
                    _, src, _, payload = parse_socks5_udp_datagram(data)
                    responses[src] = payload
                self.assertEqual(responses, {'8.8.8.8': b'dns-query-a', '1.1.1.1': b'dns-query-b'})
            finally:
                udp.close()

            # 客户端 TCP 断开 → UDP 会话应正常收尾（不抛错即通过）
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=5)
            except (ConnectionError, OSError):
                pass
            await asyncio.sleep(0.2)
        finally:
            await mock.close()
            await server.stop()


class TestTrojanUdpStreamFraming(unittest.TestCase):
    """验证 TCP 粘包/拆包场景下的流式分帧。"""

    def test_split_and_coalesced_packets(self):
        from src.protocol import build_trojan_udp_packet
        p1 = build_trojan_udp_packet('8.8.8.8', 53, b'aaaa')
        p2 = build_trojan_udp_packet('example.com', 80, b'bbbbbbbb')
        p3 = build_trojan_udp_packet('::1', 443, b'cc')

        # 全部粘在一起
        packets, consumed = parse_trojan_udp_stream(p1 + p2 + p3)
        self.assertEqual(consumed, len(p1) + len(p2) + len(p3))
        self.assertEqual(
            packets,
            [('8.8.8.8', 53, b'aaaa'), ('example.com', 80, b'bbbbbbbb'), ('::1', 443, b'cc')],
        )

        # p2 被截断一半：只应解析出 p1，剩余保留
        stream = p1 + p2[:5]
        packets, consumed = parse_trojan_udp_stream(stream)
        self.assertEqual(packets, [('8.8.8.8', 53, b'aaaa')])
        self.assertEqual(consumed, len(p1))

        # 纯垃圾数据：不消费任何字节
        packets, consumed = parse_trojan_udp_stream(b'\xff\xff\xff\xff')
        self.assertEqual(packets, [])
        self.assertEqual(consumed, 0)


if __name__ == '__main__':
    unittest.main()
