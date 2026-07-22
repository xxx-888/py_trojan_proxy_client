import asyncio
import socket
import struct
import uuid
from asyncio import StreamReader, StreamWriter
from typing import Optional
from loguru import logger

# 配置日志：保存到文件并同时输出到控制台
logger.remove()
logger.add("socks5_server.log", rotation="10MB", retention="7 days", level="INFO", backtrace=True, diagnose=True)
logger.add(lambda msg: print(msg, end=""), colorize=True, level="DEBUG")


async def resolve_hostname(hostname: str) -> Optional[str]:
    """解析域名到 IPv4 地址"""
    if not hostname or hostname == '0':
        logger.debug("收到无效或空域名，使用全零地址")
        return '0.0.0.0'
    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        return addr_info[0][4][0]
    except socket.gaierror as e:
        logger.error(f"域名解析失败: {hostname}, 错误: {e}")
        return None


class SOCKS5Server:
    def __init__(self, listen_host: str = '127.0.0.1', listen_port: int = 10800):
        self.listen_host = listen_host  # 监听地址
        self.listen_port = listen_port  # 监听端口
        self.udp_socket = None  # UDP 套接字
        self.udp_bind_addr = None  # UDP 绑定地址
        self.udp_bind_port = None  # UDP 绑定端口
        self.client_addr = None  # 客户端地址
        self.handshake_timeout = 5  # 握手超时时间（秒）
        self.read_timeout = 10  # 数据读取超时时间（秒）
        self.udp_timeout = 5  # UDP 响应超时时间（秒）
        self.udp_max_retries = 3  # UDP 最大重试次数

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
        request_id = str(uuid.uuid4())[:8]  # 生成短请求 ID 用于日志追踪
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
                            ip_addr = await resolve_hostname(dst_addr)
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
            except (asyncio.IncompleteReadError, UnicodeDecodeError, socket.error) as e:
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
                await self.handle_connect(dst_addr, dst_port, reader, writer, request_id)
            elif cmd == 3:  # UDP ASSOCIATE
                try:
                    self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.udp_socket.bind(('0.0.0.0', 0))
                    self.udp_bind_addr, self.udp_bind_port = self.udp_socket.getsockname()
                except OSError as e:
                    logger.error(f"[{request_id}] 创建 UDP 套接字失败: {e}")
                    writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                    return
                logger.debug(f"[{request_id}] UDP 绑定地址: {self.udp_bind_addr}:{self.udp_bind_port}")

                writer.write(
                    b'\x05\x00\x00\x01' + socket.inet_pton(socket.AF_INET, self.udp_bind_addr) +
                    struct.pack('>H', self.udp_bind_port)
                )
                await writer.drain()
                logger.info(f"[{request_id}] 处理 UDP ASSOCIATE 请求: {dst_addr}:{dst_port}, 绑定地址: {self.udp_bind_addr}:{self.udp_bind_port}")
                await self.handle_udp_associate(dst_addr, dst_port, reader, writer, client_addr, request_id)

        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            logger.warning(f"[{request_id}] SOCKS5 请求处理失败: {e}")
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
        except Exception as e:
            logger.error(f"[{request_id}] 意外的 SOCKS5 请求错误: {type(e).__name__}: {e}")
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
        finally:
            await self.safe_close(writer)

    async def handle_connect(self, dst_addr: str, dst_port: int, client_reader: StreamReader, client_writer: StreamWriter, request_id: str):
        """处理 TCP CONNECT 请求"""
        try:
            target_reader, target_writer = await asyncio.open_connection(dst_addr, dst_port)
            logger.info(f"[{request_id}] 已连接到目标: {dst_addr}:{dst_port}")

            client_writer.write(b'\x05\x00\x00\x01' + socket.inet_pton(socket.AF_INET, '0.0.0.0') + b'\x00\x00')
            await client_writer.drain()

            async def forward_client_to_target():
                try:
                    while True:
                        data = await asyncio.wait_for(client_reader.read(4096), timeout=self.read_timeout)
                        if not data:
                            logger.debug(f"[{request_id}] 客户端关闭连接")
                            break
                        target_writer.write(data)
                        await target_writer.drain()
                except asyncio.TimeoutError:
                    logger.debug(f"[{request_id}] 客户端到目标转发超时")
                except ConnectionError as e:
                    logger.debug(f"[{request_id}] 客户端到目标转发连接错误: {e}")
                except OSError as e:
                    logger.debug(f"[{request_id}] 客户端到目标转发系统错误: {e}")
                except Exception as e:
                    logger.error(f"[{request_id}] 意外的客户端到目标转发错误: {type(e).__name__}: {e}")

            async def forward_target_to_client():
                try:
                    while True:
                        data = await asyncio.wait_for(target_reader.read(4096), timeout=self.read_timeout)
                        if not data:
                            logger.debug(f"[{request_id}] 目标关闭连接")
                            break
                        client_writer.write(data)
                        await client_writer.drain()
                except asyncio.TimeoutError:
                    logger.debug(f"[{request_id}] 目标到客户端转发超时")
                except ConnectionError as e:
                    logger.debug(f"[{request_id}] 目标到客户端转发连接错误: {e}")
                except OSError as e:
                    logger.debug(f"[{request_id}] 目标到客户端转发系统错误: {e}")
                except Exception as e:
                    logger.error(f"[{request_id}] 意外的目标到客户端转发错误: {type(e).__name__}: {e}")

            await asyncio.gather(forward_client_to_target(), forward_target_to_client())
        except ConnectionRefusedError as e:
            logger.error(f"[{request_id}] 连接到 {dst_addr}:{dst_port} 失败: {e}")
            client_writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
        except OSError as e:
            logger.error(f"[{request_id}] 连接到 {dst_addr}:{dst_port} 失败: {e}")
            client_writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
        except Exception as e:
            logger.error(f"[{request_id}] 处理 CONNECT 请求错误: {type(e).__name__}: {e}")
            client_writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
        finally:
            if 'target_writer' in locals():
                await self.safe_close(target_writer)

    async def handle_udp_associate(self, dst_addr: str, dst_port: int, client_reader: StreamReader, client_writer: StreamWriter, client_addr: str, request_id: str):
        """处理 UDP ASSOCIATE 请求"""
        try:
            loop = asyncio.get_running_loop()
            self.udp_socket.setblocking(False)

            async def forward_udp():
                try:
                    while True:
                        data, addr = await loop.sock_recvfrom(self.udp_socket, 4096)
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
                            ip_addr = await resolve_hostname(target_addr)
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

                        logger.info(f"[{request_id}] 转发 UDP 数据到 {target_addr}:{target_port}, 数据长度: {len(payload)}")
                        await loop.sock_sendto(self.udp_socket, payload, (target_addr, target_port))

                        for attempt in range(self.udp_max_retries):
                            try:
                                self.udp_socket.settimeout(self.udp_timeout)
                                response, _ = await loop.sock_recvfrom(self.udp_socket, 4096)
                                logger.info(f"[{request_id}] 收到响应，长度: {len(response)}")
                                response_packet = b'\x00\x00\x00' + data[3:offset+2] + response
                                await loop.sock_sendto(self.udp_socket, response_packet, addr)
                                break
                            except socket.timeout:
                                logger.warning(f"[{request_id}] 尝试 {attempt + 1}/{self.udp_max_retries}: 接收 {target_addr}:{target_port} 的响应超时")
                                if attempt == self.udp_max_retries - 1:
                                    logger.error(f"[{request_id}] 达到最大重试次数，放弃转发到 {target_addr}:{target_port}")

                except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                    logger.warning(f"[{request_id}] UDP 处理错误: {e}")
                except Exception as e:
                    logger.error(f"[{request_id}] 意外的 UDP 处理错误: {type(e).__name__}: {e}")
                finally:
                    if self.udp_socket:
                        self.udp_socket.close()
                        self.udp_socket = None

            await asyncio.gather(
                forward_udp(),
                client_reader.read(4096)
            )
        except Exception as e:
            logger.error(f"[{request_id}] UDP 关联错误: {type(e).__name__}: {e}")
        finally:
            if self.udp_socket:
                self.udp_socket.close()
                self.udp_socket = None
            await self.safe_close(client_writer)

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
        socks5_server = SOCKS5Server(listen_host='127.0.0.1', listen_port=10800)
        await socks5_server.start()
    except KeyboardInterrupt:
        logger.info("正在关闭服务器")
    except Exception as e:
        logger.error(f"主循环错误: {e}")

if __name__ == '__main__':
    asyncio.run(main())