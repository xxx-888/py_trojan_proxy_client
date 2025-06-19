import ssl
import socket
import hashlib
import struct
import asyncio
import uuid
from asyncio import StreamReader, StreamWriter
from typing import Optional, Tuple
from loguru import logger

# 配置日志
logger.remove()
logger.add("trojan_client.log", rotation="10MB", retention="7 days", level="INFO", backtrace=True, diagnose=True)
logger.add(lambda msg: print(msg, end=""), colorize=True, level="DEBUG")

def build_trojan_request(dst_addr: str, dst_port: int, cmd: str) -> bytes:
    """构建 Trojan 请求数据包"""
    cmd_byte = b'\x01' if cmd == 'CONNECT' else b'\x03'
    try:
        if ':' in dst_addr:  # IPv6
            atyp = b'\x04'
            addr_bytes = socket.inet_pton(socket.AF_INET6, dst_addr)
        else:
            try:
                socket.inet_pton(socket.AF_INET, dst_addr)  # IPv4
                atyp = b'\x01'
                addr_bytes = socket.inet_pton(socket.AF_INET, dst_addr)
            except socket.error:
                atyp = b'\x03'
                addr_bytes = len(dst_addr).to_bytes(1, 'big') + dst_addr.encode()
        port_bytes = struct.pack('>H', dst_port)
        return cmd_byte + atyp + addr_bytes + port_bytes + b'\r\n'
    except socket.error as e:
        logger.error(f"无效的地址 {dst_addr}: {e}")
        raise ValueError(f"无效的地址: {dst_addr}")

class TrojanClient:
    def __init__(self, server_host: str, server_port: int, password: str, timeout: int = 10):
        self.server_host = server_host
        self.server_port = server_port
        self.password = password
        self.timeout = timeout
        self.hashed_password = hashlib.sha224(password.encode()).hexdigest()

    async def connect(self, dst_addr: str, dst_port: int, cmd: str = 'CONNECT') -> Optional[Tuple[StreamReader, StreamWriter]]:
        """建立与 Trojan 服务器的连接"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.server_host, self.server_port, ssl=context),
                timeout=self.timeout
            )
            trojan_request = build_trojan_request(dst_addr, dst_port, cmd)
            writer.write(self.hashed_password.encode() + b'\r\n' + trojan_request)
            await writer.drain()
            return reader, writer
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            logger.error(f"连接到 {self.server_host}:{self.server_port} 失败: {e}")
            return None
        except Exception as e:
            logger.error(f"意外的连接错误: {e}")
            return None

    async def safe_close(self, writer: Optional[StreamWriter]) -> None:
        """安全关闭连接"""
        if writer and not writer.is_closing():
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=5)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                logger.warning("关闭连接时发生错误")

    async def handle_connect(self, dst_addr: str, dst_port: int, client_reader: StreamReader, client_writer: StreamWriter, request_id: str):
        """处理 TCP 连接请求"""
        server_reader, server_writer = await self.connect(dst_addr, dst_port, cmd='CONNECT')
        if not server_reader or not server_writer:
            client_writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            return

        try:
            client_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            logger.info(f"[{request_id}] 已通过 Trojan 连接到目标: {dst_addr}:{dst_port}")

            async def forward_client_to_server():
                try:
                    while True:
                        data = await asyncio.wait_for(client_reader.read(4096), timeout=self.timeout)
                        if not data:
                            break
                        server_writer.write(data)
                        await server_writer.drain()
                except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                    logger.warning(f"[{request_id}] 客户端到服务器转发错误: {e}")
                except Exception as e:
                    logger.error(f"[{request_id}] 意外的客户端到服务器转发错误: {e}")

            async def forward_server_to_client():
                try:
                    while True:
                        data = await asyncio.wait_for(server_reader.read(4096), timeout=self.timeout)
                        if not data:
                            break
                        client_writer.write(data)
                        await client_writer.drain()
                except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                    logger.warning(f"[{request_id}] 服务器到客户端转发错误: {e}")
                except Exception as e:
                    logger.error(f"[{request_id}] 意外的服务器到客户端转发错误: {e}")

            await asyncio.gather(forward_client_to_server(), forward_server_to_client())
        except Exception as e:
            logger.error(f"[{request_id}] 转发错误: {e}")
        finally:
            await self.safe_close(server_writer)
            await self.safe_close(client_writer)

    async def handle_udp_associate(self, dst_addr: str, dst_port: int, client_reader: StreamReader, client_writer: StreamWriter, client_addr: str, udp_socket: socket.socket, request_id: str):
        """处理 UDP ASSOCIATE 请求"""
        # 即使 dst_addr 是 0.0.0.0:0，也建立 Trojan UDP 关联
        logger.debug(f"[{request_id}] 处理 UDP ASSOCIATE 请求，目标: {dst_addr}:{dst_port}")

        # 使用客户端提供的地址，或默认 0.0.0.0:0 向服务器发送 UDP ASSOCIATE 请求
        server_reader, server_writer = await self.connect(dst_addr, dst_port, cmd='UDP ASSOCIATE')
        if not server_reader or not server_writer:
            logger.error(f"[{request_id}] 无法建立与 Trojan 服务器的 UDP 关联连接")
            client_writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            return

        try:
            loop = asyncio.get_running_loop()
            udp_socket.setblocking(False)

            async def forward_udp():
                try:
                    while True:
                        data, addr = await loop.sock_recvfrom(udp_socket, 4096)
                        logger.debug(f"[{request_id}] 收到 UDP 数据包从 {addr}: {data.hex()}")

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

                        offset = 4
                        if atyp == 1:
                            addr_bytes = data[offset:offset+4]
                            target_addr = socket.inet_ntop(socket.AF_INET, addr_bytes)
                            offset += 4
                        elif atyp == 3:
                            addr_len = data[offset]
                            target_addr = data[offset+1:offset+1+addr_len].decode('ascii')
                            ip_addr = await self.resolve_hostname(target_addr)
                            if ip_addr:
                                target_addr = ip_addr
                            else:
                                logger.warning(f"[{request_id}] 无法解析 UDP 数据包域名: {target_addr}")
                                continue
                            offset += 1 + addr_len
                        elif atyp == 4:
                            addr_bytes = data[offset:offset+16]
                            target_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                            offset += 16
                        else:
                            logger.warning(f"[{request_id}] 不支持的地址类型: {atyp}")
                            continue

                        target_port = struct.unpack('>H', data[offset:offset+2])[0]
                        payload = data[offset+2:]

                        # 构建 Trojan UDP 数据包
                        atyp_byte = b'\x01' if atyp == 1 else b'\x04' if atyp == 4 else b'\x03'
                        addr_bytes = addr_bytes if atyp in (1, 4) else len(target_addr).to_bytes(1, 'big') + target_addr.encode()
                        port_bytes = struct.pack('>H', target_port)
                        length_bytes = struct.pack('>H', len(payload))
                        udp_packet = atyp_byte + addr_bytes + port_bytes + length_bytes + b'\r\n' + payload

                        logger.info(f"[{request_id}] 转发 UDP 数据到 {target_addr}:{target_port}, 数据长度: {len(payload)}")
                        server_writer.write(udp_packet)
                        await server_writer.drain()

                        # 读取 Trojan UDP 响应
                        for attempt in range(3):
                            try:
                                response = await asyncio.wait_for(server_reader.read(4096), timeout=self.timeout)
                                if not response:
                                    logger.warning(f"[{request_id}] 服务器返回空响应")
                                    break

                                # 解析 Trojan UDP 响应
                                resp_offset = 0
                                resp_atyp = response[resp_offset]
                                resp_offset += 1
                                if resp_atyp == 1:
                                    resp_addr = socket.inet_ntop(socket.AF_INET, response[resp_offset:resp_offset+4])
                                    resp_offset += 4
                                elif resp_atyp == 3:
                                    resp_addr_len = response[resp_offset]
                                    resp_addr = response[resp_offset+1:resp_offset+1+resp_addr_len].decode('ascii')
                                    resp_offset += 1 + resp_addr_len
                                elif resp_atyp == 4:
                                    resp_addr = socket.inet_ntop(socket.AF_INET6, response[resp_offset:resp_offset+16])
                                    resp_offset += 16
                                else:
                                    logger.warning(f"[{request_id}] 不支持的响应地址类型: {resp_atyp}")
                                    continue

                                resp_port = struct.unpack('>H', response[resp_offset:resp_offset+2])[0]
                                resp_offset += 2
                                resp_length = struct.unpack('>H', response[resp_offset:resp_offset+2])[0]
                                resp_offset += 2
                                if response[resp_offset:resp_offset+2] != b'\r\n':
                                    logger.warning(f"[{request_id}] 无效的 CRLF 分隔符")
                                    continue
                                resp_offset += 2
                                resp_payload = response[resp_offset:resp_offset+resp_length]

                                # 重构 SOCKS5 UDP 响应
                                response_packet = b'\x00\x00\x00' + data[3:offset+2] + resp_payload
                                await loop.sock_sendto(udp_socket, response_packet, addr)
                                logger.info(f"[{request_id}] 收到响应，长度: {len(resp_payload)}")
                                break
                            except asyncio.TimeoutError:
                                logger.warning(f"[{request_id}] 尝试 {attempt + 1}/3: 接收 {target_addr}:{target_port} 的响应超时")
                                if attempt == 2:
                                    logger.error(f"[{request_id}] 达到最大重试次数，放弃转发到 {target_addr}:{target_port}")
                            except Exception as e:
                                logger.error(f"[{request_id}] 解析响应错误: {e}")
                                break

                except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                    logger.warning(f"[{request_id}] UDP 处理错误: {e}")
                except Exception as e:
                    logger.error(f"[{request_id}] 意外的 UDP 处理错误: {type(e).__name__}: {e}")
                finally:
                    if udp_socket:
                        udp_socket.close()

            await asyncio.gather(
                forward_udp(),
                client_reader.read(4096)
            )
        finally:
            if udp_socket:
                udp_socket.close()
            await self.safe_close(server_writer)
            await self.safe_close(client_writer)

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """解析域名到 IPv4 地址"""
        if not hostname or hostname == '0':
            logger.debug("收到无效或空域名")
            return None
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            return addr_info[0][4][0]
        except socket.gaierror as e:
            logger.error(f"域名解析失败: {hostname}, 错误: {e}")
            return None

class SOCKS5Server:
    def __init__(self, trojan_client: TrojanClient, listen_host: str = '127.0.0.1', listen_port: int = 10800):
        self.trojan_client = trojan_client
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.udp_socket = None
        self.udp_bind_addr = None
        self.udp_bind_port = None
        self.client_addr = None
        self.handshake_timeout = 5
        self.read_timeout = 10
        self.udp_timeout = 5
        self.udp_max_retries = 3

    async def safe_close(self, writer: Optional[StreamWriter]) -> None:
        """安全关闭 TCP 连接"""
        if writer and not writer.is_closing():
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=self.handshake_timeout)
            except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                logger.debug(f"关闭 TCP 连接时发生错误: {e}")

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
            await reader.readexactly(nmethods)
            writer.write(b'\x05\x00')
            await writer.drain()
            logger.debug(f"[{request_id}] SOCKS5 握手完成")

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
                            logger.debug(f"[{request_id}] 解析到的域名: {dst_addr}")
                            ip_addr = await self.trojan_client.resolve_hostname(dst_addr)
                            if ip_addr:
                                dst_addr = ip_addr
                            else:
                                logger.error(f"[{request_id}] 无法解析域名: {dst_addr}")
                                writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                                await writer.drain()
                                return
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

        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            logger.warning(f"[{request_id}] SOCKS5 请求处理失败: {e}")
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
            async with server:
                await server.serve_forever()
        except (OSError, asyncio.CancelledError) as e:
            logger.error(f"启动 SOCKS5 服务器失败: {e}")
            raise

async def main():
    try:
        trojan_client = TrojanClient(
            server_host='gos5.liflag.site',
            server_port=26659,
            password='fEICuSlkmW'
        )
        socks5_server = SOCKS5Server(trojan_client, listen_host='127.0.0.1', listen_port=10800)
        await socks5_server.start()
    except KeyboardInterrupt:
        logger.info("正在关闭服务器")
    except Exception as e:
        logger.error(f"主循环错误: {e}")

if __name__ == '__main__':
    asyncio.run(main())