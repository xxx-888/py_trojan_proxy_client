"""Trojan 客户端：与远端 Trojan 服务器建立 TLS 连接并转发流量。

对外暴露 TrojanClient：
- get_connection / safe_close：连接的建立、复用与关闭（带简单连接池）
- handle_connect：处理 SOCKS5 的 TCP CONNECT，双向转发
- handle_udp_associate：处理 UDP ASSOCIATE，按 Trojan UDP 格式封装/解封
- resolve_hostname：必要时把域名解析为 IP
"""
import ssl
import socket
import struct
import asyncio
import hashlib
from asyncio import StreamReader, StreamWriter
from typing import Optional, Tuple, Dict

from loguru import logger
from .protocol import (
    build_trojan_request,
    encode_address,
    decode_address,
    parse_socks5_udp_datagram,
)


class TrojanClient:
    def __init__(self, config: Dict):
        self.udp_timeout = config.get('timeout', 60) // 2
        self.udp_max_retries = config.get('max_retries', 3)
        self.server_host = config['trojan_host']
        self.server_port = config['trojan_port']
        self.password = config['trojan_password']
        self.timeout = config['timeout']
        self.buffer_size = config['buffer_size']
        self.pool_cleanup_interval = config['pool_cleanup_interval']
        self.hashed_password = hashlib.sha224(self.password.encode()).hexdigest()
        self.connection_pool: Dict[Tuple[str, int, str], Tuple[StreamReader, StreamWriter]] = {}
        self.logger = logger

    async def get_connection(self, dst_addr: str, dst_port: int, cmd: str = 'CONNECT') -> Optional[Tuple[StreamReader, StreamWriter]]:
        """建立或重用与 Trojan 服务器的连接（按目标地址+命令做简单连接池）。"""
        key = (dst_addr, dst_port, cmd)
        if key in self.connection_pool:
            reader, writer = self.connection_pool[key]
            if not writer.is_closing():
                logger.debug(f"重用连接: {dst_addr}:{dst_port}")
                return reader, writer

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # 禁用主机名和证书验证以忽略过期证书
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.options |= ssl.OP_NO_COMPRESSION
        context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.server_host, self.server_port, ssl=context),
                timeout=self.timeout
            )
            trojan_request = build_trojan_request(dst_addr, dst_port, cmd)
            writer.write(self.hashed_password.encode() + b'\r\n' + trojan_request)
            await writer.drain()
            self.connection_pool[key] = (reader, writer)
            logger.debug(f"建立新连接: {dst_addr}:{dst_port}")
            return reader, writer
        except (asyncio.TimeoutError, ConnectionRefusedError, ssl.SSLError, OSError) as e:
            logger.error(f"连接到 {self.server_host}:{self.server_port} 失败: {type(e).__name__}: {e}")
            return None
        except Exception as e:
            logger.error(f"意外的连接错误: {type(e).__name__}: {e}")
            return None

    async def safe_close(self, writer: Optional[StreamWriter]) -> None:
        """安全关闭连接"""
        if writer and not writer.is_closing():
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=10)
            except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError) as e:
                logger.warning(f"关闭连接时发生错误: {type(e).__name__}: {e}")

    async def cleanup_connection_pool(self):
        """定期清理连接池中的过期连接"""
        while True:
            try:
                for key, (reader, writer) in list(self.connection_pool.items()):
                    if writer.is_closing():
                        del self.connection_pool[key]
                        logger.debug(f"清理已关闭的连接: {key}")
                logger.debug(f"连接池当前大小: {len(self.connection_pool)}")
            except Exception as e:
                logger.error(f"清理连接池时发生错误: {type(e).__name__}: {e}")
            await asyncio.sleep(self.pool_cleanup_interval)

    async def handle_connect(self, dst_addr: str, dst_port: int, client_reader: StreamReader, client_writer: StreamWriter, request_id: str):
        """处理 TCP CONNECT 请求"""
        server_reader, server_writer = await self.get_connection(dst_addr, dst_port, cmd='CONNECT')
        if not server_reader or not server_writer:
            logger.error(f"[{request_id}] 无法建立与 Trojan 服务器的连接: {dst_addr}:{dst_port}")
            client_writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            await self.safe_close(client_writer)
            return

        try:
            client_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            logger.info(f"[{request_id}] 已通过 Trojan 连接到目标: {dst_addr}:{dst_port}")

            async def forward_client_to_server():
                try:
                    while True:
                        data = await asyncio.wait_for(client_reader.read(self.buffer_size), timeout=self.timeout)
                        if not data:
                            break
                        server_writer.write(data)
                        await server_writer.drain()
                except (asyncio.TimeoutError, ConnectionError, ssl.SSLError, OSError) as e:
                    logger.warning(f"[{request_id}] 客户端到服务器转发错误: {type(e).__name__}: {e}")
                except Exception as e:
                    logger.error(f"[{request_id}] 意外的客户端到服务器转发错误: {type(e).__name__}: {e}")

            async def forward_server_to_client():
                try:
                    while True:
                        data = await asyncio.wait_for(server_reader.read(self.buffer_size), timeout=self.timeout)
                        if not data:
                            break
                        client_writer.write(data)
                        await client_writer.drain()
                except (asyncio.TimeoutError, ConnectionError, ssl.SSLError, OSError) as e:
                    logger.warning(f"[{request_id}] 服务器到客户端转发错误: {type(e).__name__}: {e}")
                except Exception as e:
                    logger.error(f"[{request_id}] 意外的服务器到客户端转发错误: {type(e).__name__}: {e}")

            await asyncio.gather(forward_client_to_server(), forward_server_to_client())
        except Exception as e:
            logger.error(f"[{request_id}] 转发错误: {type(e).__name__}: {e}")
        finally:
            await self.safe_close(server_writer)
            await self.safe_close(client_writer)
            key = (dst_addr, dst_port, 'CONNECT')
            if key in self.connection_pool:
                del self.connection_pool[key]

    async def handle_udp_associate(self, dst_addr: str, dst_port: int, client_reader: StreamReader, client_writer: StreamWriter, client_addr: str, udp_socket: socket.socket, request_id: str):
        """处理 UDP ASSOCIATE 请求"""
        logger.debug(f"[{request_id}] 处理 UDP ASSOCIATE 请求，目标: {dst_addr}:{dst_port}")

        server_reader, server_writer = await self.get_connection(dst_addr, dst_port, cmd='UDP ASSOCIATE')
        if not server_reader or not server_writer:
            logger.error(f"[{request_id}] 无法建立与 Trojan 服务器的 UDP 关联连接")
            client_writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            await self.safe_close(client_writer)
            return

        try:
            loop = asyncio.get_running_loop()
            udp_socket.setblocking(False)

            async def forward_udp():
                try:
                    while True:
                        data, addr = await loop.sock_recvfrom(udp_socket, self.buffer_size)
                        logger.debug(f"[{request_id}] 收到 UDP 数据包从 {addr}: {len(data)} 字节")

                        if addr[0] != client_addr:
                            logger.warning(f"[{request_id}] 来自未知客户端 {addr} 的 UDP 数据包，忽略")
                            continue

                        if len(data) < 10:
                            logger.warning(f"[{request_id}] 无效的 UDP 数据包，长度: {len(data)}")
                            continue

                        rsv, frag, atyp = data[:2], data[2], data[3]
                        if rsv != b'\x00\x00' or frag != 0:
                            logger.warning(f"[{request_id}] 无效的 RSV: {rsv} 或 FRAG: {frag}")
                            continue

                        try:
                            atyp, target_addr, target_port, payload = parse_socks5_udp_datagram(data)
                        except (ValueError, IndexError) as e:
                            logger.warning(f"[{request_id}] 无效的 UDP 数据包: {e}")
                            continue

                        # 构建 Trojan UDP 数据包：地址段 + 长度 + CRLF + 负载
                        length_bytes = struct.pack('>H', len(payload))
                        udp_packet = encode_address(target_addr, target_port) + length_bytes + b'\r\n' + payload

                        logger.info(f"[{request_id}] 转发 UDP 数据到 {target_addr}:{target_port}, 数据长度: {len(payload)}")
                        server_writer.write(udp_packet)
                        await server_writer.drain()

                        # 读取 Trojan UDP 响应并带重试
                        for attempt in range(self.udp_max_retries):
                            try:
                                response = await asyncio.wait_for(server_reader.read(self.buffer_size), timeout=self.udp_timeout)
                                if not response:
                                    logger.warning(f"[{request_id}] 服务器返回空响应")
                                    break

                                # 解析 Trojan UDP 响应（地址段）
                                try:
                                    _, _, resp_offset = decode_address(response, 0)
                                except (ValueError, IndexError):
                                    logger.warning(f"[{request_id}] 不支持的响应地址类型")
                                    continue

                                resp_offset += 2
                                resp_length = struct.unpack('>H', response[resp_offset:resp_offset + 2])[0]
                                resp_offset += 2
                                if response[resp_offset:resp_offset + 2] != b'\r\n':
                                    logger.warning(f"[{request_id}] 无效的 CRLF 分隔符")
                                    continue
                                resp_offset += 2
                                resp_payload = response[resp_offset:resp_offset + resp_length]

                                # 重构 SOCKS5 UDP 响应：RSV + FRAG + 地址段 + 负载
                                response_packet = b'\x00\x00\x00' + encode_address(target_addr, target_port) + resp_payload
                                await loop.sock_sendto(udp_socket, response_packet, addr)
                                logger.info(f"[{request_id}] 收到响应，数据长度: {len(resp_payload)}")
                                break
                            except asyncio.TimeoutError:
                                logger.warning(f"[{request_id}] 尝试 {attempt + 1}/{self.udp_max_retries}: 接收 {target_addr}:{target_port} 的响应超时")
                                if attempt == self.udp_max_retries - 1:
                                    logger.error(f"[{request_id}] 达到最大重试次数，放弃转发到 {target_addr}:{target_port}")
                            except Exception as e:
                                logger.error(f"[{request_id}] 解析响应错误: {type(e).__name__}: {e}")
                                break

                except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                    logger.warning(f"[{request_id}] UDP 处理错误: {type(e).__name__}: {e}")
                except Exception as e:
                    logger.error(f"[{request_id}] 意外的 UDP 处理错误: {type(e).__name__}: {e}")
                finally:
                    if udp_socket:
                        udp_socket.close()

            await asyncio.gather(
                forward_udp(),
                client_reader.read(self.buffer_size)
            )
        finally:
            if udp_socket:
                udp_socket.close()
            await self.safe_close(server_writer)
            await self.safe_close(client_writer)
            key = (dst_addr, dst_port, 'UDP ASSOCIATE')
            if key in self.connection_pool:
                del self.connection_pool[key]

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """解析域名到 IPv4 或 IPv6 地址，仅在必要时使用"""
        if not hostname or hostname == '0':
            logger.debug("收到无效或空域名")
            return None
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
            for family, _, _, _, sockaddr in addr_info:
                if family == socket.AF_INET:
                    return sockaddr[0]
                elif family == socket.AF_INET6:
                    return sockaddr[0]
            logger.warning(f"未找到有效 IP 地址: {hostname}")
            return None
        except socket.gaierror as e:
            logger.error(f"域名解析失败: {hostname}, 错误: {e}")
            return None
