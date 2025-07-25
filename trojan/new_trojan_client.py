import ssl
import socket
import hashlib
import struct
import asyncio
import json
import uuid
from asyncio import StreamReader, StreamWriter
from typing import Optional, Tuple, Dict
from loguru import logger

# 配置日志
logger.remove()
logger.add("trojan_client.log", rotation="10MB", retention="7 days", level="INFO", backtrace=True, diagnose=True)
logger.add(lambda msg: print(msg, end=""), colorize=True, level="DEBUG")

def load_config(config_path: str) -> Dict:
    """加载 JSON 配置文件"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        required_fields = ['trojan_host', 'trojan_port', 'trojan_password', 'listen_host', 'listen_port']
        for field in required_fields:
            if field not in config:
                logger.error(f"配置文件缺少必要字段: {field}")
                raise ValueError(f"配置文件缺少必要字段: {field}")
        # 设置默认值
        config.setdefault('timeout', 60)
        config.setdefault('max_retries', 3)
        config.setdefault('buffer_size', 16384)
        config.setdefault('pool_cleanup_interval', 30)
        config.setdefault('users', {})
        logger.info(f"成功加载配置文件: {config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"配置文件未找到: {config_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"配置文件格式错误: {e}")
        raise
    except Exception as e:
        logger.error(f"加载配置文件时发生意外错误: {type(e).__name__}: {e}")
        raise

def build_trojan_request(dst_addr: str, dst_port: int, cmd: str) -> bytes:
    """构建 Trojan 请求数据包"""
    cmd_byte = b'\x01' if cmd == 'CONNECT' else b'\x03'
    try:
        if ':' in dst_addr and not dst_addr.startswith('['):  # IPv6
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
        self.connection_pool = {}  # 基本连接池
        self.logger = logger

    async def get_connection(self, dst_addr: str, dst_port: int, cmd: str = 'CONNECT') -> Optional[Tuple[StreamReader, StreamWriter]]:
        """建立或重用与 Trojan 服务器的连接"""
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
                        # logger.debug(f"[{request_id}] 从客户端到服务器转发 {len(data)} 字节")
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
                        # logger.debug(f"[{request_id}] 从服务器到客户端转发 {len(data)} 字节")
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

                        offset = 4
                        addr_bytes = None
                        if atyp == 1:
                            addr_bytes = data[offset:offset+4]
                            target_addr = socket.inet_ntop(socket.AF_INET, addr_bytes)
                            offset += 4
                        elif atyp == 3:
                            addr_len = data[offset]
                            target_addr = data[offset+1:offset+1+addr_len].decode('ascii')
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

                        # 读取 Trojan UDP 响应并带重试
                        for attempt in range(self.udp_max_retries):
                            try:
                                response = await asyncio.wait_for(server_reader.read(self.buffer_size), timeout=self.udp_timeout)
                                if not response:
                                    logger.warning(f"[{request_id}] 服务器返回空响应")
                                    break

                                # 解析 Trojan UDP 响应
                                resp_offset = 0
                                resp_atyp = response[resp_offset]
                                resp_offset += 1
                                if resp_atyp == 1:
                                    socket.inet_ntop(socket.AF_INET, response[resp_offset:resp_offset+4])
                                    resp_offset += 4
                                elif resp_atyp == 3:
                                    resp_addr_len = response[resp_offset]
                                    response[resp_offset+1:resp_offset+1+resp_addr_len].decode('ascii')
                                    resp_offset += 1 + resp_addr_len
                                elif resp_atyp == 4:
                                    socket.inet_ntop(socket.AF_INET6, response[resp_offset:resp_offset+16])
                                    resp_offset += 16
                                else:
                                    logger.warning(f"[{request_id}] 不支持的响应地址类型: {resp_atyp}")
                                    continue

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

async def main():
    try:
        config = load_config('config.json')
        trojan_client = TrojanClient(config)
        socks5_server = SOCKS5Server(trojan_client, config)
        # 启动连接池清理任务
        asyncio.create_task(trojan_client.cleanup_connection_pool())
        await socks5_server.start()
    except KeyboardInterrupt:
        logger.info("正在关闭服务器")
    except Exception as e:
        logger.error(f"主循环错误: {type(e).__name__}: {e}")

if __name__ == '__main__':
    asyncio.run(main())