"""本地 SOCKS5 服务端：完成握手/认证、解析请求并路由到 TrojanClient。

对外暴露 SOCKS5Server，接收本地应用的 SOCKS5 连接（支持 CONNECT 与
UDP ASSOCIATE，可选用户名/密码认证），解析目标地址后交给 TrojanClient
完成实际的 Trojan 协议转发。

设计说明（稳定性关键点）：
- 每个连接的全部状态都是局部变量，绝无跨连接共享（并发安全）。
- 目标域名不做本地 DNS 解析，原样透传给 Trojan 服务器解析：
  既避免 DNS 泄露/污染，也免除本地解析失败导致的错误。
- 认证密码比较使用 hmac.compare_digest（常数时间）。
- UDP 套接字优先绑定到客户端来源地址，绑定失败再退回通配地址。
"""
import hmac
import socket
import struct
import asyncio
import uuid
from asyncio import StreamReader, StreamWriter
from typing import Dict, Optional, Tuple

from loguru import logger
from .trojan import TrojanClient

# 常用 SOCKS5 应答（VER + REP + RSV + ATYP=IPv4 + 全零地址/端口）
_REPLY_OK = b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
_REPLY_FAIL = b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00'
_REPLY_HOST_UNREACHABLE = b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00'
_REPLY_REFUSED = b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
_REPLY_CMD_NOT_SUPPORTED = b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00'
_REPLY_ATYP_NOT_SUPPORTED = b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00'


class Socks5Error(Exception):
    """SOCKS5 协议层错误：携带应答码，由 handle_socks5 统一回复。"""

    def __init__(self, reply: bytes, message: str):
        super().__init__(message)
        self.reply = reply


class SOCKS5Server:
    def __init__(self, trojan_client: TrojanClient, config: Dict):
        self.trojan_client = trojan_client
        self.listen_host = config['listen_host']
        self.listen_port = config['listen_port']
        self.users: Dict[str, str] = config.get('users') or {}
        self.timeout = config.get('timeout', 60)
        self.handshake_timeout = max(3, self.timeout // 6)
        self.buffer_size = config.get('buffer_size', 16384)
        self._server: Optional[asyncio.AbstractServer] = None

    @property
    def bound_port(self) -> int:
        """实际绑定的端口（listen_port 为 0 时可取得随机分配的端口）。"""
        if self._server is None:
            raise RuntimeError("服务器尚未启动")
        return self._server.sockets[0].getsockname()[1]

    async def start(self) -> None:
        """绑定监听地址并开始接受连接（不阻塞）。"""
        self._server = await asyncio.start_server(
            self.handle_socks5,
            self.listen_host,
            self.listen_port,
            limit=max(self.buffer_size * 4, 262144),
        )
        logger.info(f"SOCKS5 服务器运行在 {self.listen_host}:{self.bound_port}")

    async def run_forever(self) -> None:
        """持续服务，直到任务被取消或出错。"""
        try:
            async with self._server:
                await self._server.serve_forever()
        finally:
            logger.info("SOCKS5 服务器已停止")

    async def stop(self) -> None:
        """停止接受新连接并关闭监听套接字。"""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def safe_close(self, writer: Optional[StreamWriter]) -> None:
        """安全关闭 TCP 连接"""
        if writer and not writer.is_closing():
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=5)
            except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                logger.debug(f"关闭 TCP 连接时发生错误: {type(e).__name__}: {e}")

    @staticmethod
    async def _reply(writer: StreamWriter, data: bytes) -> None:
        """尽力发送应答；连接已断开时忽略错误，避免二次异常。"""
        try:
            writer.write(data)
            await writer.drain()
        except (ConnectionError, OSError):
            pass

    async def handle_socks5(self, reader: StreamReader, writer: StreamWriter) -> None:
        """处理单个 SOCKS5 客户端连接（所有状态均为局部变量）。"""
        request_id = str(uuid.uuid4())[:8]
        try:
            peername = writer.get_extra_info('peername')
            client_addr = peername[0] if peername else None
            logger.debug(f"[{request_id}] 客户端连接: {peername}")

            ok = await asyncio.wait_for(self._negotiate(reader, writer), timeout=self.handshake_timeout)
            if not ok:
                return

            cmd, dst_addr, dst_port = await asyncio.wait_for(
                self._read_request(reader), timeout=self.handshake_timeout
            )
            logger.debug(f"[{request_id}] 请求: cmd={cmd}, 目标={dst_addr}:{dst_port}")

            if cmd == 1:  # CONNECT
                if dst_addr == self.listen_host and dst_port == self.listen_port:
                    logger.warning(f"[{request_id}] 拒绝连接到代理服务器本身: {dst_addr}:{dst_port}")
                    await self._reply(writer, _REPLY_FAIL)
                    return
                await self.trojan_client.handle_connect(dst_addr, dst_port, reader, writer, request_id)
                return
            # cmd == 3: UDP ASSOCIATE
            await self._handle_udp_associate(reader, writer, client_addr, request_id)
        except Socks5Error as e:
            logger.warning(f"[{request_id}] {e}")
            await self._reply(writer, e.reply)
        except asyncio.IncompleteReadError:
            logger.warning(f"[{request_id}] 客户端提前断开连接")
            await self._reply(writer, _REPLY_FAIL)
        except asyncio.TimeoutError:
            logger.warning(f"[{request_id}] 握手或请求超时")
            await self._reply(writer, _REPLY_FAIL)
        except (ConnectionError, OSError) as e:
            logger.warning(f"[{request_id}] SOCKS5 请求处理失败: {type(e).__name__}: {e}")
            await self._reply(writer, _REPLY_FAIL)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.exception(f"[{request_id}] 意外的 SOCKS5 请求错误: {type(e).__name__}: {e}")
            await self._reply(writer, _REPLY_FAIL)
        finally:
            await self.safe_close(writer)

    async def _negotiate(self, reader: StreamReader, writer: StreamWriter) -> bool:
        """SOCKS5 方法协商与可选的用户名/密码认证，成功返回 True。"""
        ver, nmethods = await reader.readexactly(2)
        if ver != 5:
            logger.warning(f"不支持的 SOCKS 版本: {ver}")
            await self._reply(writer, b'\x05\xFF')
            return False
        methods = await reader.readexactly(nmethods) if nmethods else b''
        if self.users:
            if 0x02 in methods:
                await self._reply(writer, b'\x05\x02')  # 选择用户名/密码认证
                return await self._authenticate(reader, writer)
            logger.warning("配置了用户认证，但客户端未提供用户名/密码方法")
            await self._reply(writer, b'\x05\xFF')
            return False
        if 0x00 in methods:
            await self._reply(writer, b'\x05\x00')
            logger.debug("无认证 SOCKS5 握手完成")
            return True
        logger.warning(f"客户端不支持的认证方法: {methods.hex()}")
        await self._reply(writer, b'\x05\xFF')
        return False

    async def _authenticate(self, reader: StreamReader, writer: StreamWriter) -> bool:
        """RFC 1929 用户名/密码认证。"""
        ver = await reader.readexactly(1)
        if ver != b'\x01':
            logger.warning(f"不支持的认证子协议版本: {ver.hex()}")
            await self._reply(writer, b'\x01\xFF')
            return False
        ulen = (await reader.readexactly(1))[0]
        username = (await reader.readexactly(ulen)).decode('ascii', errors='replace')
        plen = (await reader.readexactly(1))[0]
        password = (await reader.readexactly(plen)).decode('ascii', errors='replace')
        expected = self.users.get(username)
        if expected is not None and hmac.compare_digest(str(expected), password):
            await self._reply(writer, b'\x01\x00')
            logger.info(f"用户 {username} 认证成功")
            return True
        logger.warning(f"用户 {username} 认证失败")
        await self._reply(writer, b'\x01\x01')
        return False

    async def _read_request(self, reader: StreamReader) -> Tuple[int, str, int]:
        """读取并解析 SOCKS5 请求（VER CMD RSV ATYP + 地址 + 端口）。"""
        ver, cmd, _rsv, atyp = await reader.readexactly(4)
        if ver != 5:
            raise Socks5Error(_REPLY_FAIL, f"不支持的协议版本: {ver}")
        if cmd not in (1, 3):
            raise Socks5Error(_REPLY_CMD_NOT_SUPPORTED, f"不支持的命令: {cmd}")
        if atyp == 1:  # IPv4
            dst_addr = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        elif atyp == 3:  # 域名（原样透传，由 Trojan 服务器远端解析）
            addr_len = (await reader.readexactly(1))[0]
            if addr_len == 0:
                raise Socks5Error(_REPLY_HOST_UNREACHABLE, "域名长度为 0")
            try:
                dst_addr = (await reader.readexactly(addr_len)).decode('ascii')
            except UnicodeDecodeError:
                raise Socks5Error(_REPLY_HOST_UNREACHABLE, "域名解码失败")
        elif atyp == 4:  # IPv6
            dst_addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            raise Socks5Error(_REPLY_ATYP_NOT_SUPPORTED, f"不支持的地址类型: {atyp}")
        dst_port = struct.unpack('>H', await reader.readexactly(2))[0]
        return cmd, dst_addr, dst_port

    async def _handle_udp_associate(
        self, reader: StreamReader, writer: StreamWriter, client_addr: Optional[str], request_id: str
    ) -> None:
        """创建本地 UDP 中继套接字并移交 TrojanClient 管理其生命周期。"""
        family = socket.AF_INET6 if client_addr and ':' in client_addr else socket.AF_INET
        udp_socket = socket.socket(family, socket.SOCK_DGRAM)
        try:
            # 优先绑定到客户端来源地址，限制其他主机滥用；失败再退回通配地址
            try:
                udp_socket.bind((client_addr, 0))
            except OSError:
                udp_socket.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 0))
            udp_socket.setblocking(False)
        except OSError as e:
            udp_socket.close()
            logger.error(f"[{request_id}] 创建 UDP 套接字失败: {e}")
            await self._reply(writer, _REPLY_REFUSED)
            return

        bind_ip, bind_port = udp_socket.getsockname()[:2]
        atyp = 4 if family == socket.AF_INET6 else 1
        try:
            bnd_addr = socket.inet_pton(family, bind_ip)
        except OSError:
            bnd_addr = b'\x00' * (16 if family == socket.AF_INET6 else 4)
        logger.info(f"[{request_id}] UDP ASSOCIATE 中继: {bind_ip}:{bind_port}")
        await self._reply(writer, b'\x05\x00\x00' + bytes([atyp]) + bnd_addr + struct.pack('>H', bind_port))

        # 结束后 udp_socket 由 TrojanClient 关闭；client_writer 由 handle_socks5 关闭
        await self.trojan_client.handle_udp_associate(reader, writer, client_addr, udp_socket, request_id)
