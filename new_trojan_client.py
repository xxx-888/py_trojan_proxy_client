import ssl
import socket
import hashlib
import struct
import asyncio
import uuid
import json
from asyncio import StreamReader, StreamWriter
from typing import Optional, Tuple, Dict
from loguru import logger
from dataclasses import dataclass
from datetime import datetime
import aiodns

# 配置日志
logger.remove()
logger.add("trojan_client.log", rotation="10MB", retention="7 days", level="INFO", backtrace=True, diagnose=True)
logger.add(lambda msg: print(msg, end=""), colorize=True, level="DEBUG")

@dataclass
class Config:
    """代理服务器配置类"""
    trojan_host: str
    trojan_port: int
    trojan_password: str
    listen_host: str
    listen_port: int
    users: Dict[str, str]  # 用户名:密码
    timeout: int = 15  # 延长超时时间
    max_retries: int = 3
    buffer_size: int = 8192
    pool_cleanup_interval: int = 30  # 缩短清理间隔

    @classmethod
    def from_file(cls, config_path: str) -> 'Config':
        """从JSON文件加载配置"""
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
            return cls(
                trojan_host=data['trojan_host'],
                trojan_port=data['trojan_port'],
                trojan_password=data['trojan_password'],
                listen_host=data['listen_host'],
                listen_port=data['listen_port'],
                users=data.get('users', {}),
                timeout=data.get('timeout', 15),
                max_retries=data.get('max_retries', 3),
                buffer_size=data.get('buffer_size', 8192),
                pool_cleanup_interval=data.get('pool_cleanup_interval', 30)
            )
        except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
            logger.error(f"加载配置文件失败: {e}")
            raise ValueError(f"无效的配置文件: {config_path}")

def build_trojan_request(dst_addr: str, dst_port: int, cmd: str) -> bytes:
    """构建Trojan请求数据包"""
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

class ConnectionPool:
    """Trojan服务器连接池"""

    def __init__(self, config: Config, max_size: int = 100):  # 增加最大连接数
        self.config = config
        self.pool: Dict[str, Tuple[StreamReader, StreamWriter, float]] = {}
        self.max_size = max_size
        self.lock = asyncio.Lock()

    async def get_connection(self, dst_addr: str, dst_port: int, cmd: str) -> Optional[Tuple[StreamReader, StreamWriter]]:
        """从连接池获取或创建新连接"""
        key = f"{dst_addr}:{dst_port}:{cmd}"
        async with self.lock:
            if key in self.pool:
                reader, writer, _ = self.pool[key]
                if not writer.is_closing():
                    try:
                        writer.write(b'\x00')
                        await writer.drain()
                        await asyncio.wait_for(reader.read(1), timeout=1.0)
                        logger.debug(f"复用现有连接: {key}")
                        return reader, writer
                    except (ConnectionError, asyncio.TimeoutError, OSError):
                        logger.warning(f"连接 {key} 已失效，移除")
                        await self.close_connection(key)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        for attempt in range(self.config.max_retries):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.config.trojan_host, self.config.trojan_port, ssl=context),
                    timeout=self.config.timeout
                )
                trojan_request = build_trojan_request(dst_addr, dst_port, cmd)
                hashed_password = hashlib.sha224(self.config.trojan_password.encode()).hexdigest()
                writer.write(hashed_password.encode() + b'\r\n' + trojan_request)
                await writer.drain()

                async with self.lock:
                    if len(self.pool) < self.max_size:
                        self.pool[key] = (reader, writer, datetime.now().timestamp())
                    else:
                        oldest_key = min(self.pool, key=lambda k: self.pool[k][2])
                        await self.close_connection(oldest_key)
                        self.pool[key] = (reader, writer, datetime.now().timestamp())
                logger.info(f"创建新连接: {key}")
                return reader, writer
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
                logger.warning(f"连接尝试 {attempt + 1}/{self.config.max_retries} 失败: {e}")
                if attempt == self.config.max_retries - 1:
                    logger.error(f"无法连接到 {self.config.trojan_host}:{self.config.trojan_port}")
                    return None
                return None
            except Exception as e:
                logger.error(f"意外的连接错误: {e}")
                return None
        return None

    async def close_connection(self, key: str) -> None:
        """关闭指定连接"""
        async with self.lock:
            if key in self.pool:
                reader, writer, _ = self.pool.pop(key)
                if not writer.is_closing():
                    try:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), timeout=5)
                    except (asyncio.TimeoutError, ConnectionError, OSError):
                        logger.warning(f"关闭连接 {key} 时发生错误")

    async def cleanup(self):
        """定期清理失效或过期的连接"""
        while True:
            async with self.lock:
                now = datetime.now().timestamp()
                for key in list(self.pool.keys()):
                    reader, writer, ts = self.pool[key]
                    if now - ts > self.config.pool_cleanup_interval or writer.is_closing():
                        logger.debug(f"清理过期或失效连接: {key}")
                        await self.close_connection(key)
                    else:
                        try:
                            writer.write(b'\x00')
                            await writer.drain()
                            await asyncio.wait_for(reader.read(1), timeout=1.0)
                        except (ConnectionError, asyncio.TimeoutError, OSError):
                            logger.debug(f"清理失效连接: {key}")
                            await self.close_connection(key)
            await asyncio.sleep(self.config.pool_cleanup_interval)

    async def close_all(self) -> None:
        """关闭所有连接"""
        async with self.lock:
            for key in list(self.pool.keys()):
                await self.close_connection(key)


async def safe_close(writer: Optional[StreamWriter]) -> None:
    """安全关闭连接"""
    if writer and not writer.is_closing():
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=5)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            logger.warning("关闭连接时发生错误")


class TrojanClient:
    def __init__(self, config: Config):
        self.config = config
        self.pool = ConnectionPool(config)
        self.dns_cache: Dict[str, Tuple[str, float]] = {}
        self.dns_cache_ttl = 60  # 缩短DNS缓存TTL

    async def connect(self, dst_addr: str, dst_port: int, cmd: str = 'CONNECT') -> Optional[Tuple[StreamReader, StreamWriter]]:
        """建立Trojan连接"""
        return await self.pool.get_connection(dst_addr, dst_port, cmd)

    async def handle_connect(self, dst_addr: str, dst_port: int, client_reader: StreamReader,
                            client_writer: StreamWriter, request_id: str):
        """处理TCP连接请求"""
        server_reader, server_writer = await self.connect(dst_addr, dst_port, cmd='CONNECT')
        if not server_reader or not server_writer:
            client_writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            return

        try:
            client_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            logger.info(f"[{request_id}] 已通过Trojan连接到目标: {dst_addr}:{dst_port}")

            async def forward_data(reader: StreamReader, writer: StreamWriter, direction: str):
                total_bytes = 0
                for attempt in range(self.config.max_retries):
                    try:
                        while True:
                            data = await asyncio.wait_for(reader.read(self.config.buffer_size), timeout=self.config.timeout)
                            if not data:
                                logger.debug(f"[{request_id}] {direction} 转发结束，总字节数: {total_bytes}")
                                break
                            total_bytes += len(data)
                            writer.write(data)
                            await writer.drain()
                            logger.debug(f"[{request_id}] {direction} 转发 {len(data)} 字节")
                        break
                    except asyncio.TimeoutError as e:
                        logger.warning(f"[{request_id}] {direction} 转发超时，第 {attempt + 1}/{self.config.max_retries} 次尝试")
                        if attempt == self.config.max_retries - 1:
                            logger.error(f"[{request_id}] {direction} 转发失败: {e}")
                            break
                    except (ConnectionError, OSError) as e:
                        logger.warning(f"[{request_id}] {direction} 转发错误: {e}")
                        if isinstance(e, OSError) and e.winerror == 64:
                            logger.warning(f"[{request_id}] 网络名不可用，尝试重新连接")
                            await self.pool.close_connection(f"{dst_addr}:{dst_port}:CONNECT")
                        break
                    except Exception as e:
                        logger.error(f"[{request_id}] 意外的{direction}转发错误: {type(e).__name__}: {e}")
                        break

            await asyncio.gather(
                asyncio.create_task(forward_data(client_reader, server_writer, "客户端到服务器")),
                asyncio.create_task(forward_data(server_reader, client_writer, "服务器到客户端"))
            )
        except Exception as e:
            logger.error(f"[{request_id}] 转发错误: {type(e).__name__}: {e}")
        finally:
            await safe_close(server_writer)
            await safe_close(client_writer)

    async def handle_udp_associate(self, dst_addr: str, dst_port: int, client_reader: StreamReader,
                                  client_writer: StreamWriter, client_addr: str, udp_socket: socket.socket,
                                  request_id: str):
        """处理UDP ASSOCIATE请求"""
        logger.debug(f"[{request_id}] 处理UDP ASSOCIATE请求，目标: {dst_addr}:{dst_port}")
        server_reader, server_writer = await self.connect(dst_addr, dst_port, cmd='UDP ASSOCIATE')
        if not server_reader or not server_writer:
            logger.error(f"[{request_id}] 无法建立UDP关联连接")
            client_writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            return

        try:
            loop = asyncio.get_running_loop()
            udp_socket.setblocking(False)

            async def forward_udp():
                try:
                    for _ in range(self.config.max_retries):
                        try:
                            data, addr = await loop.sock_recvfrom(udp_socket, self.config.buffer_size)
                            if addr[0] != client_addr:
                                logger.warning(f"[{request_id}] 来自未知客户端 {addr} 的UDP数据包，忽略")
                                continue

                            if len(data) < 10:
                                logger.warning(f"[{request_id}] 无效的UDP数据包，长度: {len(data)}")
                                continue

                            rsv, frag, atyp = data[:2], data[2], data[3]
                            if rsv != b'\x00\x00' or frag != 0:
                                logger.warning(f"[{request_id}] 无效的RSV: {rsv} 或FRAG: {frag}")
                                continue

                            offset = 4
                            if atyp == 1:
                                addr_bytes = data[offset:offset + 4]
                                target_addr = socket.inet_ntop(socket.AF_INET, addr_bytes)
                                offset += 4
                            elif atyp == 3:
                                addr_len = data[offset]
                                target_addr = data[offset + 1:offset + 1 + addr_len].decode('ascii')
                                ip_addr = await self.resolve_hostname(target_addr)
                                if ip_addr:
                                    target_addr = ip_addr
                                else:
                                    logger.warning(f"[{request_id}] 无法解析UDP数据包域名: {target_addr}")
                                    continue
                                offset += 1 + addr_len
                            elif atyp == 4:
                                addr_bytes = data[offset:offset + 16]
                                target_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                                offset += 16
                            else:
                                logger.warning(f"[{request_id}] 不支持的地址类型: {atyp}")
                                continue

                            target_port = struct.unpack('>H', data[offset:offset + 2])[0]
                            payload = data[offset + 2:]

                            atyp_byte = b'\x01' if atyp == 1 else b'\x04' if atyp == 4 else b'\x03'
                            addr_bytes = addr_bytes if atyp in (1, 4) else len(target_addr).to_bytes(1, 'big') + target_addr.encode()
                            port_bytes = struct.pack('>H', target_port)
                            length_bytes = struct.pack('>H', len(payload))
                            udp_packet = atyp_byte + addr_bytes + port_bytes + length_bytes + b'\r\n' + payload

                            server_writer.write(udp_packet)
                            await server_writer.drain()
                            logger.info(f"[{request_id}] 转发UDP数据到 {target_addr}:{target_port}")

                            for _ in range(self.config.max_retries):
                                try:
                                    response = await asyncio.wait_for(server_reader.read(self.config.buffer_size), timeout=self.config.timeout)
                                    if not response:
                                        logger.warning(f"[{request_id}] 服务器返回空响应")
                                        continue

                                    resp_offset = 0
                                    resp_atyp = response[resp_offset]
                                    resp_offset += 1
                                    if resp_atyp == 1:
                                        resp_addr = socket.inet_ntop(socket.AF_INET, response[resp_offset:resp_offset + 4])
                                        resp_offset += 4
                                    elif resp_atyp == 3:
                                        resp_addr_len = response[resp_offset]
                                        resp_addr = response[resp_offset + 1:resp_offset + 1 + resp_addr_len].decode('ascii')
                                        resp_offset += 1 + resp_addr_len
                                    elif resp_atyp == 4:
                                        resp_addr = socket.inet_ntop(socket.AF_INET6, response[resp_offset:resp_offset + 16])
                                        resp_offset += 16
                                    else:
                                        logger.warning(f"[{request_id}] 不支持的响应地址类型: {resp_atyp}")
                                        continue

                                    resp_port = struct.unpack('>H', response[resp_offset:resp_offset + 2])[0]
                                    resp_offset += 2
                                    resp_length = struct.unpack('>H', response[resp_offset:resp_offset + 2])[0]
                                    resp_offset += 2
                                    if response[resp_offset:resp_offset + 2] != b'\r\n':
                                        logger.warning(f"[{request_id}] 无效的CRLF分隔符")
                                        continue
                                    resp_offset += 2
                                    resp_payload = response[resp_offset:resp_offset + resp_length]

                                    response_packet = b'\x00\x00\x00' + data[3:offset + 2] + resp_payload
                                    await loop.sock_sendto(udp_socket, response_packet, addr)
                                    logger.info(f"[{request_id}] 收到响应，长度: {len(resp_payload)}")
                                    break
                                except asyncio.TimeoutError:
                                    logger.warning(f"[{request_id}] UDP响应超时，第 {_ + 1}/{self.config.max_retries} 次尝试")
                                    continue
                        except Exception as e:
                            logger.error(f"[{request_id}] UDP处理错误: {type(e).__name__}: {e}")
                            continue
                finally:
                    if udp_socket and not udp_socket._closed:
                        udp_socket.close()

            await asyncio.gather(
                asyncio.create_task(forward_udp()),
                asyncio.create_task(client_reader.read(self.config.buffer_size))
            )
        finally:
            if udp_socket and not udp_socket._closed:
                udp_socket.close()
            await safe_close(server_writer)
            await safe_close(client_writer)

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """解析域名到IPv4地址（带手动缓存）"""
        if not hostname or hostname == '0':
            logger.debug("收到无效或空域名")
            return None

        now = datetime.now().timestamp()
        if hostname in self.dns_cache:
            ip, timestamp = self.dns_cache[hostname]
            if now - timestamp < self.dns_cache_ttl:
                logger.debug(f"从缓存解析 {hostname} -> {ip}")
                return ip
            else:
                del self.dns_cache[hostname]

        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            ip_addr = addr_info[0][4][0]
            self.dns_cache[hostname] = (ip_addr, now)
            logger.debug(f"解析 {hostname} -> {ip_addr}")
            return ip_addr
        except socket.gaierror as e:
            logger.error(f"域名解析失败: {hostname}, 错误: {e}")
            try:

                resolver = aiodns.DNSResolver()
                result = await resolver.query(hostname, 'A')
                ip_addr = result[0].host
                self.dns_cache[hostname] = (ip_addr, now)
                logger.debug(f"备用解析 {hostname} -> {ip_addr}")
                return ip_addr
            except Exception as e2:
                logger.error(f"备用DNS解析失败: {hostname}, 错误: {e2}")
                return None

    async def safe_close(self, writer):
        pass


class SOCKS5Server:
    def __init__(self, trojan_client: TrojanClient, config: Config):
        self.trojan_client = trojan_client
        self.config = config
        self.udp_socket = None
        self.udp_bind_addr = None
        self.udp_bind_port = None
        self.client_addr = None

    async def authenticate(self, reader: StreamReader, writer: StreamWriter, request_id: str) -> bool:
        """处理SOCKS5用户名/密码认证"""
        if not self.config.users:
            return True
        try:
            ver, ulen = await asyncio.wait_for(reader.readexactly(2), timeout=self.config.timeout)
            if ver != 1:
                logger.error(f"[{request_id}] 不支持的认证版本: {ver}")
                writer.write(b'\x01\x01')
                await writer.drain()
                return False
            username = (await reader.readexactly(ulen)).decode('ascii')
            plen = (await reader.readexactly(1))[0]
            password = (await reader.readexactly(plen)).decode('ascii')
            if username in self.config.users and self.config.users[username] == password:
                writer.write(b'\x01\x00')
                await writer.drain()
                logger.debug(f"[{request_id}] 用户 {username} 认证成功")
                return True
            logger.warning(f"[{request_id}] 用户 {username} 认证失败")
            writer.write(b'\x01\x01')
            await writer.drain()
            return False
        except (asyncio.IncompleteReadError, UnicodeDecodeError) as e:
            logger.error(f"[{request_id}] 认证错误: {e}")
            writer.write(b'\x01\x01')
            await writer.drain()
            return False

    async def handle_socks5(self, reader: StreamReader, writer: StreamWriter):
        """处理SOCKS5请求"""
        request_id = str(uuid.uuid4())[:8]
        try:
            client_addr, _ = writer.get_extra_info('peername')
            self.client_addr = client_addr
            logger.debug(f"[{request_id}] 客户端连接: {client_addr}")

            try:
                ver, nmethods = await asyncio.wait_for(reader.readexactly(2), timeout=self.config.timeout)
                methods = await reader.readexactly(nmethods)
            except asyncio.IncompleteReadError as e:
                logger.error(f"[{request_id}] 握手数据不足: {e}")
                writer.write(b'\x05\xFF')
                await writer.drain()
                return
            if ver != 5:
                logger.error(f"[{request_id}] 不支持的SOCKS版本: {ver}")
                writer.write(b'\x05\xFF')
                await writer.drain()
                return
            auth_required = bool(self.config.users)
            writer.write(b'\x05\x02' if auth_required else b'\x05\x00')
            await writer.drain()

            if auth_required and not await self.authenticate(reader, writer, request_id):
                return

            try:
                data = await asyncio.wait_for(reader.readexactly(4), timeout=self.config.timeout)
                ver, cmd, rsv, atyp = data
            except asyncio.IncompleteReadError as e:
                logger.error(f"[{request_id}] 请求头数据不足: {e}")
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return
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

            try:
                if atyp == 1:
                    dst_addr = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
                elif atyp == 3:
                    addr_len = (await reader.readexactly(1))[0]
                    if addr_len == 0:
                        dst_addr = '0.0.0.0'
                    else:
                        domain_data = await reader.readexactly(addr_len)
                        dst_addr = domain_data.decode('ascii')
                        ip_addr = await self.trojan_client.resolve_hostname(dst_addr)
                        if ip_addr:
                            dst_addr = ip_addr
                        else:
                            logger.error(f"[{request_id}] 无法解析域名: {dst_addr}")
                            writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                            await writer.drain()
                            return
                elif atyp == 4:
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

            if cmd == 1:
                if dst_addr == self.config.listen_host and dst_port == self.config.listen_port:
                    logger.warning(f"[{request_id}] 拒绝连接到代理服务器本身: {dst_addr}:{dst_port}")
                    writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                    return
                await self.trojan_client.handle_connect(dst_addr, dst_port, reader, writer, request_id)
            elif cmd == 3:
                try:
                    self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.udp_socket.bind(('0.0.0.0', 0))
                    self.udp_bind_addr, self.udp_bind_port = self.udp_socket.getsockname()
                except OSError as e:
                    logger.error(f"[{request_id}] 创建UDP套接字失败: {e}")
                    writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                    return
                writer.write(
                    b'\x05\x00\x00\x01' + socket.inet_pton(socket.AF_INET, self.udp_bind_addr) +
                    struct.pack('>H', self.udp_bind_port)
                )
                await writer.drain()
                logger.info(f"[{request_id}] 处理UDP ASSOCIATE请求: {dst_addr}:{dst_port}")
                await self.trojan_client.handle_udp_associate(dst_addr, dst_port, reader, writer, client_addr,
                                                              self.udp_socket, request_id)

        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            logger.warning(f"[{request_id}] SOCKS5请求处理失败: {e}")
            writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
        except Exception as e:
            logger.error(f"[{request_id}] 意外的SOCKS5请求错误: {type(e).__name__}: {e}")
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
        finally:
            await self.trojan_client.safe_close(writer)

    async def start(self):
        """启动SOCKS5服务器"""
        try:
            asyncio.create_task(self.trojan_client.pool.cleanup())
            server = await asyncio.start_server(self.handle_socks5, self.config.listen_host, self.config.listen_port)
            logger.info(f"SOCKS5服务器运行在 {self.config.listen_host}:{self.config.listen_port}")
            async with server:
                await server.serve_forever()
        except (OSError, asyncio.CancelledError) as e:
            logger.error(f"启动SOCKS5服务器失败: {e}")
            raise
        finally:
            await self.trojan_client.pool.close_all()

async def main():
    try:
        config = Config.from_file('config.json')
        trojan_client = TrojanClient(config)
        socks5_server = SOCKS5Server(trojan_client, config)
        await socks5_server.start()
    except KeyboardInterrupt:
        logger.info("正在关闭服务器")
    except Exception as e:
        logger.error(f"主循环错误: {e}")

if __name__ == '__main__':
    asyncio.run(main())