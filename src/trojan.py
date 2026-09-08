"""Trojan 客户端：与远端 Trojan 服务器建立 TLS 连接并转发流量。

对外暴露 TrojanClient：
- get_connection / safe_close / release：建立与释放到 Trojan 服务器的 TLS 连接
- handle_connect：处理 SOCKS5 的 TCP CONNECT，双向转发
- handle_udp_associate：处理 UDP ASSOCIATE，按 Trojan UDP 格式全双工封装/解封
- log_stats：定期输出活跃连接数

设计说明（稳定性关键点）：
- Trojan 协议一条 TLS 连接只承载一个会话（无多路复用），因此每个代理
  请求独立建立连接，绝不共享 Reader/Writer，避免并发数据串流。
- SSLContext 在启动时创建一次并复用，减少每次握手开销。
- TCP 双向转发任一方向结束（EOF/错误）即收尾整个会话，防止半开连接悬挂。
- UDP 转发为全双工两个独立泵，按长度前缀分帧解析 TCP 流，天然支持
  粘包/拆包与并发的请求-响应（如同时发起多个 DNS 查询）。
"""
import ssl
import socket
import struct
import asyncio
import hashlib
from asyncio import StreamReader, StreamWriter
from typing import Dict, Optional, Tuple

from loguru import logger
from .protocol import (
    CRLF,
    build_trojan_request,
    encode_address,
    parse_socks5_udp_datagram,
    build_trojan_udp_packet,
    parse_trojan_udp_stream,
)

# 连接被目标拒绝时使用的 SOCKS5 应答（REP=0x05 连接被拒绝）
_SOCKS5_REPLY_REFUSED = b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'


class TrojanClient:
    def __init__(self, config: Dict):
        self.server_host = config['trojan_host']
        self.server_port = config['trojan_port']
        self.password = config['trojan_password']
        self.timeout = config['timeout']
        self.idle_timeout = config.get('idle_timeout', 300)
        self.buffer_size = config['buffer_size']
        self.ssl_verify = bool(config.get('ssl_verify', False))
        self.ssl_sni = config.get('ssl_sni') or self.server_host
        self.hashed_password = hashlib.sha224(self.password.encode()).hexdigest()
        self.active_connections = 0
        self._ssl_context = self._build_ssl_context()

    def _build_ssl_context(self) -> ssl.SSLContext:
        """构建 TLS 客户端上下文（进程内复用一次构建）。"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self.ssl_verify:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_default_certs()
        else:
            # 允许自签名/过期证书（保持历史行为）；可在配置中开启 ssl_verify
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        # 不再限定 RSA 密码套件：交由 TLS1.2/1.3 默认套件协商，
        # 兼容 ECDSA/ChaCha20 等各类 Trojan 服务端证书。
        return context

    @staticmethod
    def _set_nodelay(writer: StreamWriter) -> None:
        """关闭 Nagle 算法，降低小包转发的延迟。"""
        sock = writer.get_extra_info('socket')
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

    async def get_connection(
        self, dst_addr: str, dst_port: int, cmd: str = 'CONNECT'
    ) -> Optional[Tuple[StreamReader, StreamWriter]]:
        """与 Trojan 服务器建立一条新的 TLS 连接并发送 Trojan 请求头。"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.server_host,
                    self.server_port,
                    ssl=self._ssl_context,
                    server_hostname=self.ssl_sni,
                ),
                timeout=self.timeout,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, ssl.SSLError, OSError) as e:
            logger.error(f"连接到 {self.server_host}:{self.server_port} 失败: {type(e).__name__}: {e}")
            return None
        except Exception as e:
            logger.error(f"意外的连接错误: {type(e).__name__}: {e}")
            return None

        self._set_nodelay(writer)
        try:
            writer.write(self.hashed_password.encode() + CRLF + build_trojan_request(dst_addr, dst_port, cmd))
            await writer.drain()
        except (ValueError, ConnectionError, ssl.SSLError, OSError) as e:
            logger.error(f"发送 Trojan 请求失败: {type(e).__name__}: {e}")
            await self.safe_close(writer)
            return None

        self.active_connections += 1
        logger.debug(f"Trojan 连接已建立 (cmd={cmd}, 目标={dst_addr}:{dst_port})")
        return reader, writer

    async def safe_close(self, writer: Optional[StreamWriter]) -> None:
        """安全关闭连接（幂等，已关闭/出错时仅记录）。"""
        if writer and not writer.is_closing():
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=10)
            except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError) as e:
                logger.debug(f"关闭连接时发生错误: {type(e).__name__}: {e}")

    async def release(self, writer: Optional[StreamWriter]) -> None:
        """释放一条通过 get_connection 取得并计入活跃数的连接。"""
        if writer is None:
            return
        self.active_connections = max(0, self.active_connections - 1)
        await self.safe_close(writer)

    @staticmethod
    async def _reply(writer: StreamWriter, data: bytes, request_id: str = '') -> bool:
        """尽力向客户端发送应答；连接已断开时忽略错误。"""
        try:
            writer.write(data)
            await writer.drain()
            return True
        except (ConnectionError, ssl.SSLError, OSError) as e:
            logger.debug(f"[{request_id}] 发送 SOCKS5 应答失败: {type(e).__name__}: {e}")
            return False

    async def log_stats(self, interval: int = 60) -> None:
        """周期性输出活跃连接数（后台任务，由 main 启动并取消）。"""
        while True:
            await asyncio.sleep(max(1, interval))
            if self.active_connections:
                logger.info(f"当前活跃 Trojan 连接数: {self.active_connections}")
            else:
                logger.debug("当前无活跃 Trojan 连接")

    async def _pump(self, src: StreamReader, dst: StreamWriter, request_id: str, direction: str) -> None:
        """单方向转发流量；EOF、空闲超时或连接错误时返回。"""
        try:
            while True:
                if self.idle_timeout > 0:
                    data = await asyncio.wait_for(src.read(self.buffer_size), timeout=self.idle_timeout)
                else:
                    data = await src.read(self.buffer_size)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except asyncio.TimeoutError:
            logger.debug(f"[{request_id}] {direction} 空闲超过 {self.idle_timeout}s，停止转发")
        except (ConnectionError, ssl.SSLError, OSError) as e:
            logger.debug(f"[{request_id}] {direction} 转发结束: {type(e).__name__}: {e}")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning(f"[{request_id}] {direction} 意外错误: {type(e).__name__}: {e}")

    async def handle_connect(
        self,
        dst_addr: str,
        dst_port: int,
        client_reader: StreamReader,
        client_writer: StreamWriter,
        request_id: str,
    ) -> None:
        """处理 TCP CONNECT 请求：应答成功后双向转发。

        任一方向结束（EOF/超时/错误）即取消另一方向并释放资源，
        避免半开连接长期悬挂。client_writer 的生命周期归 SOCKS5 层管理。
        """
        conn = await self.get_connection(dst_addr, dst_port, cmd='CONNECT')
        if conn is None:
            await self._reply(client_writer, _SOCKS5_REPLY_REFUSED, request_id)
            return
        server_reader, server_writer = conn
        try:
            if not await self._reply(
                client_writer, b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00', request_id
            ):
                return
            logger.info(f"[{request_id}] 已通过 Trojan 连接到目标: {dst_addr}:{dst_port}")
            self._set_nodelay(client_writer)

            tasks = [
                asyncio.create_task(self._pump(client_reader, server_writer, request_id, '客户端→目标')),
                asyncio.create_task(self._pump(server_reader, client_writer, request_id, '目标→客户端')),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                if not task.cancelled() and task.exception() is not None:
                    logger.error(f"[{request_id}] 转发任务异常: {task.exception()!r}")
        finally:
            await self.release(server_writer)

    async def handle_udp_associate(
        self,
        client_reader: StreamReader,
        client_writer: StreamWriter,
        client_addr: str,
        udp_socket: socket.socket,
        request_id: str,
    ) -> None:
        """处理 UDP ASSOCIATE：本地 UDP 与 Trojan UDP-over-TCP 全双工转发。

        - Trojan 请求头按协议规范携带 0.0.0.0:0（客户端本地地址占位）。
        - 三个并发任务：本地 UDP → Trojan、Trojan → 本地 UDP、TCP 看门狗；
          客户端 TCP 连接关闭即结束整个 UDP 会话，防止资源泄漏。
        - 本udp_socket 的生命周期由本方法管理（结束时关闭）。
        """
        conn = await self.get_connection('0.0.0.0', 0, cmd='UDP ASSOCIATE')
        if conn is None:
            await self._reply(client_writer, _SOCKS5_REPLY_REFUSED, request_id)
            udp_socket.close()
            return
        server_reader, server_writer = conn
        loop = asyncio.get_running_loop()
        # 首个合法客户端数据包的来源 (ip, port)，后续响应都发往这里
        client_endpoint: Dict[str, tuple] = {'addr': None}

        async def pump_local_to_trojan() -> None:
            try:
                while True:
                    data, addr = await loop.sock_recvfrom(udp_socket, self.buffer_size)
                    if addr[0] != client_addr:
                        logger.warning(f"[{request_id}] 丢弃来自非关联客户端 {addr} 的 UDP 包")
                        continue
                    if len(data) < 4 or data[:3] != b'\x00\x00\x00':
                        logger.warning(f"[{request_id}] 无效的 SOCKS5 UDP 数据报头 (长度 {len(data)})")
                        continue
                    try:
                        _, target_addr, target_port, payload = parse_socks5_udp_datagram(data)
                    except (ValueError, IndexError, struct.error) as e:
                        logger.warning(f"[{request_id}] 无法解析 UDP 数据报: {e}")
                        continue
                    client_endpoint['addr'] = addr
                    server_writer.write(build_trojan_udp_packet(target_addr, target_port, payload))
                    await server_writer.drain()
                    logger.debug(f"[{request_id}] UDP → {target_addr}:{target_port} ({len(payload)} 字节)")
            except asyncio.CancelledError:
                raise
            except (ConnectionError, ssl.SSLError, OSError) as e:
                logger.warning(f"[{request_id}] 本地 UDP 接收结束: {type(e).__name__}: {e}")

        async def pump_trojan_to_local() -> None:
            buf = b''
            try:
                while True:
                    data = await server_reader.read(self.buffer_size)
                    if not data:
                        logger.debug(f"[{request_id}] Trojan 服务器关闭了 UDP 会话")
                        break
                    buf += data
                    packets, consumed = parse_trojan_udp_stream(buf)
                    if consumed == 0 and len(buf) > self.buffer_size * 4:
                        # 首包始终无法解析且缓冲持续膨胀，丢弃以避免内存泄漏
                        logger.warning(f"[{request_id}] Trojan UDP 流解析失败，丢弃 {len(buf)} 字节缓冲")
                        buf = b''
                        continue
                    buf = buf[consumed:]
                    peer = client_endpoint['addr']
                    if peer is None:
                        continue  # 客户端尚未发过包，无处投递
                    for src_addr, src_port, payload in packets:
                        response = b'\x00\x00\x00' + encode_address(src_addr, src_port) + payload
                        await loop.sock_sendto(udp_socket, response, peer)
                        logger.debug(f"[{request_id}] UDP ← {src_addr}:{src_port} ({len(payload)} 字节)")
            except asyncio.CancelledError:
                raise
            except (ConnectionError, ssl.SSLError, OSError) as e:
                logger.warning(f"[{request_id}] Trojan UDP 接收结束: {type(e).__name__}: {e}")

        async def watch_tcp() -> None:
            # SOCKS5 UDP 会话与 TCP 连接同生命周期：EOF/错误即返回
            try:
                while True:
                    data = await client_reader.read(self.buffer_size)
                    if not data:
                        return
            except (ConnectionError, OSError):
                return

        try:
            tasks = [
                asyncio.create_task(pump_local_to_trojan()),
                asyncio.create_task(pump_trojan_to_local()),
                asyncio.create_task(watch_tcp()),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            udp_socket.close()
            await self.release(server_writer)
            logger.info(f"[{request_id}] UDP 会话已结束")
