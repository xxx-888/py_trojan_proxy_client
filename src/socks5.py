"""本地 SOCKS5 服务端：完成握手/认证、解析请求并路由到 TrojanClient。

对外暴露 SOCKS5Server，接收本地应用的 SOCKS5 连接（支持 CONNECT 与
UDP ASSOCIATE，可选用户名/密码认证），解析目标地址后交给 TrojanClient
完成实际的 Trojan 协议转发。
"""
import ssl
import socket
import struct
import asyncio
import uuid
from asyncio import StreamReader, StreamWriter
from typing import Optional, Dict

from loguru import logger
from .trojan import TrojanClient


class SOCKS5Server:
    def __init__(self, trojan_client: TrojanClient, config: Dict):
        self.trojan_client = trojan_client
        self.listen_host = config['listen_host']
        self.listen_port = config['listen_port']
        self.users = config.get('users', {})
        self.udp_socket = None
        self.udp_bind_addr = None
        self.udp_bind_port = None
        self.client_addr = None
        self.handshake_timeout = config.get('timeout', 60) // 6
        self.read_timeout = config.get('timeout', 60)
        self.udp_timeout = config.get('timeout', 60) // 2
        self.udp_max_retries = config.get('max_retries', 3)
        self.buffer_size = config.get('buffer_size', 16384)

    async def safe_close(self, writer: Optional[StreamWriter]) -> None:
        """安全关闭 TCP 连接"""
        if writer and not writer.is_closing():
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=self.handshake_timeout)
            except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError) as e:
                logger.debug(f"关闭 TCP 连接时发生错误: {type(e).__name__}: {e}")

    async def handle_socks5(self, reader: StreamReader, writer: StreamWriter):
        """处理 SOCKS5 请求"""
        request_id = str(uuid.uuid4())[:8]
        try:
            client_addr, _ = writer.get_extra_info('peername')
            self.client_addr = client_addr
            logger.debug(f"[{request_id}] 客户端连接: {client_addr}")

            # 处理 SOCKS5 握手
            try:
                ver, nmethods = await asyncio.wait_for(reader.readexactly(2), timeout=self.handshake_timeout)
            except asyncio.IncompleteReadError as e:
                logger.error(f"[{request_id}] 握手数据不足: {e}")
                writer.write(b'\x05\xFF')
                await writer.drain()
                return
            if ver != 5:
                logger.error(f"[{request_id}] 不支持的 SOCKS 版本: {ver}")
                writer.write(b'\x05\xFF')
                await writer.drain()
                return

            methods = await reader.readexactly(nmethods)
            logger.debug(f"[{request_id}] 客户端支持的认证方法: {methods.hex()}")
            if self.users and 0x02 in methods:  # 用户名/密码认证
                writer.write(b'\x05\x02')  # 选择用户名/密码认证
                await writer.drain()

                # 处理用户名/密码认证
                try:
                    auth_ver = await asyncio.wait_for(reader.readexactly(1), timeout=self.handshake_timeout)
                    if auth_ver != b'\x01':
                        logger.error(f"[{request_id}] 不支持的认证版本: {auth_ver.hex()}")
                        writer.write(b'\x01\xFF')
                        await writer.drain()
                        return
                    ulen = await reader.readexactly(1)
                    username = (await reader.readexactly(ulen[0])).decode('ascii')
                    plen = await reader.readexactly(1)
                    password = (await reader.readexactly(plen[0])).decode('ascii')
                    logger.debug(f"[{request_id}] 认证请求: 用户名={username}, 密码=****")
                    if username in self.users and self.users[username] == password:
                        writer.write(b'\x01\x00')  # 认证成功
                        await writer.drain()
                        logger.info(f"[{request_id}] 用户 {username} 认证成功")
                    else:
                        logger.warning(f"[{request_id}] 用户 {username} 认证失败")
                        writer.write(b'\x01\x01')  # 认证失败
                        await writer.drain()
                        return
                except (asyncio.IncompleteReadError, UnicodeDecodeError) as e:
                    logger.error(f"[{request_id}] 认证数据解析失败: {e}")
                    writer.write(b'\x01\xFF')
                    await writer.drain()
                    return
            elif 0x00 in methods:  # 无认证
                if self.users:
                    logger.warning(f"[{request_id}] 配置了用户认证，但客户端请求无认证，拒绝连接")
                    writer.write(b'\x05\xFF')
                    await writer.drain()
                    return
                writer.write(b'\x05\x00')
                await writer.drain()
                logger.debug(f"[{request_id}] 无认证 SOCKS5 握手完成")
            else:
                logger.error(f"[{request_id}] 不支持的认证方法: {methods.hex()}")
                writer.write(b'\x05\xFF')
                await writer.drain()
                return

            # 处理 SOCKS5 请求头
            try:
                data = await asyncio.wait_for(reader.readexactly(4), timeout=self.handshake_timeout)
            except asyncio.IncompleteReadError as e:
                logger.error(f"[{request_id}] 请求头数据不足: {e}")
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return
            logger.debug(f"[{request_id}] 收到请求数据: {data.hex()}")
            ver, cmd, rsv, atyp = data
            if ver != 5:
                logger.error(f"[{request_id}] 不支持的协议版本: {ver}")
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return
            if cmd not in (1, 3):
                logger.error(f"[{request_id}] 不支持的命令: {cmd}")
                writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return

            # 解析目标地址
            try:
                original_dst_addr = None  # 保存原始域名
                if atyp == 1:  # IPv4
                    dst_addr = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
                elif atyp == 3:  # 域名
                    addr_len = (await reader.readexactly(1))[0]
                    logger.debug(f"[{request_id}] 域名长度: {addr_len}")
                    if addr_len == 0:
                        logger.debug(f"[{request_id}] 域名长度为 0，使用全零地址")
                        dst_addr = '0.0.0.0'
                    else:
                        domain_data = await reader.readexactly(addr_len)
                        try:
                            dst_addr = domain_data.decode('ascii')
                            original_dst_addr = dst_addr  # 保留原始域名
                            logger.debug(f"[{request_id}] 解析到的域名: {dst_addr}")
                        except UnicodeDecodeError as e:
                            logger.error(f"[{request_id}] 域名解码失败: {domain_data.hex()}, 错误: {e}")
                            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                            await writer.drain()
                            return
                elif atyp == 4:  # IPv6
                    dst_addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
                else:
                    logger.error(f"[{request_id}] 不支持的地址类型: {atyp}")
                    writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                    return
                dst_port = struct.unpack('>H', await reader.readexactly(2))[0]
            except (asyncio.IncompleteReadError, socket.error) as e:
                logger.error(f"[{request_id}] 解析地址失败: {e}")
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return

            # 对于 HTTPS 请求（通常端口为 443），优先使用原始域名
            if dst_port == 443 and original_dst_addr:
                logger.debug(f"[{request_id}] HTTPS 请求，保留原始域名: {original_dst_addr}")
                dst_addr = original_dst_addr
            else:
                # 仅在非 HTTPS 请求或无原始域名时解析 IP
                if original_dst_addr:
                    ip_addr = await self.trojan_client.resolve_hostname(original_dst_addr)
                    if ip_addr:
                        dst_addr = ip_addr
                    else:
                        logger.error(f"[{request_id}] 无法解析域名: {original_dst_addr}")
                        writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                        await writer.drain()
                        return

            logger.debug(f"[{request_id}] 解析到目标地址: {dst_addr}:{dst_port}")

            if cmd == 1:  # CONNECT
                if dst_addr == self.listen_host and dst_port == self.listen_port:
                    logger.warning(f"[{request_id}] 拒绝连接到代理服务器本身: {dst_addr}:{dst_port}")
                    writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                    return
                await self.trojan_client.handle_connect(dst_addr, dst_port, reader, writer, request_id)
            elif cmd == 3:  # UDP ASSOCIATE
                try:
                    self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.udp_socket.bind(('0.0.0.0', 0))
                    self.udp_bind_addr, self.udp_bind_port = self.udp_socket.getsockname()
                except OSError as e:
                    logger.error(f"[{request_id}] 创建 UDP 套接字失败: {e}")
                    writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                    return
                logger.debug(f"[{request_id}] UDP 绑定地址: {self.udp_bind_addr}:{self.udp_bind_port}")

                writer.write(
                    b'\x05\x00\x00\x01' + socket.inet_pton(socket.AF_INET, self.udp_bind_addr) +
                    struct.pack('>H', self.udp_bind_port)
                )
                await writer.drain()
                logger.info(f"[{request_id}] 处理 UDP ASSOCIATE 请求: {dst_addr}:{dst_port}, 绑定地址: {self.udp_bind_addr}:{self.udp_bind_port}")
                await self.trojan_client.handle_udp_associate(dst_addr, dst_port, reader, writer, client_addr, self.udp_socket, request_id)

        except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError) as e:
            logger.warning(f"[{request_id}] SOCKS5 请求处理失败: {type(e).__name__}: {e}")
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
        except Exception as e:
            logger.error(f"[{request_id}] 意外的 SOCKS5 请求错误: {type(e).__name__}: {e}")
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
        finally:
            await self.safe_close(writer)

    async def start(self):
        """启动 SOCKS5 服务器"""
        try:
            server = await asyncio.start_server(self.handle_socks5, self.listen_host, self.listen_port)
            logger.info(f"SOCKS5 服务器运行在 {self.listen_host}:{self.listen_port}")
            await server.serve_forever()
        except (OSError, asyncio.CancelledError) as e:
            logger.error(f"启动 SOCKS5 服务器失败: {e}")
            raise
