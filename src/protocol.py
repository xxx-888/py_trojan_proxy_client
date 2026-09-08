"""Trojan / SOCKS5 协议相关的纯函数工具。

集中处理地址类型的编解码与 Trojan 请求/UDP 数据报的构造与解析，
被 trojan.py 与 socks5.py 复用，避免重复的字节处理代码。
"""
import socket
import struct
from typing import List, Tuple

from loguru import logger

# SOCKS5 / Trojan 地址类型 (ATYP)
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

CRLF = b'\r\n'


def encode_address(addr: str, port: int) -> bytes:
    """将「地址 + 端口」编码为协议地址段：ATYP + 地址 + 端口(2字节, 大端)。"""
    if ':' in addr and not addr.startswith('['):  # IPv6
        atyp = bytes([ATYP_IPV6])
        addr_bytes = socket.inet_pton(socket.AF_INET6, addr)
    else:
        try:
            socket.inet_pton(socket.AF_INET, addr)  # IPv4
            atyp = bytes([ATYP_IPV4])
            addr_bytes = socket.inet_pton(socket.AF_INET, addr)
        except socket.error:
            atyp = bytes([ATYP_DOMAIN])
            addr_bytes = len(addr).to_bytes(1, 'big') + addr.encode()
    return atyp + addr_bytes + struct.pack('>H', port)


def build_trojan_request(dst_addr: str, dst_port: int, cmd: str) -> bytes:
    """构造 Trojan 请求数据包：CMD + 地址段 + CRLF。"""
    cmd_byte = b'\x01' if cmd == 'CONNECT' else b'\x03'
    try:
        return cmd_byte + encode_address(dst_addr, dst_port) + CRLF
    except (socket.error, ValueError, UnicodeDecodeError, struct.error) as e:
        logger.error(f"无效的地址 {dst_addr}: {e}")
        raise ValueError(f"无效的地址: {dst_addr}")


def decode_address(data: bytes, offset: int) -> Tuple[int, str, int]:
    """从字节流解析地址（offset 指向 ATYP 字节）。

    返回 (atyp, 地址字符串, 解析后的新偏移)，供请求/响应复用。
    地址类型不支持或数据不完整时抛出 ValueError / IndexError。
    """
    atyp = data[offset]
    offset += 1
    if atyp == ATYP_IPV4:
        addr = socket.inet_ntop(socket.AF_INET, data[offset:offset + 4])
        offset += 4
    elif atyp == ATYP_DOMAIN:
        addr_len = data[offset]
        addr = data[offset + 1:offset + 1 + addr_len].decode('ascii')
        offset += 1 + addr_len
    elif atyp == ATYP_IPV6:
        addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    else:
        raise ValueError(f"不支持的地址类型: {atyp}")
    return atyp, addr, offset


def parse_socks5_udp_datagram(data: bytes) -> Tuple[int, str, int, bytes]:
    """解析 SOCKS5 UDP 请求数据报（含 2 字节 RSV + 1 字节 FRAG）。

    返回 (atyp, 目标地址, 目标端口, 负载)。调用方需自行校验 RSV/FRAG。
    """
    atyp, addr, offset = decode_address(data, 3)
    port = struct.unpack('>H', data[offset:offset + 2])[0]
    offset += 2
    payload = data[offset:]
    return atyp, addr, port, payload


def build_trojan_udp_packet(dst_addr: str, dst_port: int, payload: bytes) -> bytes:
    """构造 Trojan UDP 数据包：地址段 + 长度(2字节) + CRLF + 负载。"""
    return encode_address(dst_addr, dst_port) + struct.pack('>H', len(payload)) + CRLF + payload


def parse_trojan_udp_stream(buf: bytes) -> Tuple[List[Tuple[str, int, bytes]], int]:
    """从 TCP 流缓冲区中解析尽可能多的 Trojan UDP 数据包。

    TCP 是字节流，多个 UDP 包可能粘在一个 read() 里、也可能被拆开，
    因此按「地址段 + 长度前缀 + CRLF + 负载」逐包解析，尾部不完整的
    数据包保留在缓冲区中等待更多数据。

    返回 (完整解析出的 (地址, 端口, 负载) 列表, 已消费的字节数)；
    调用方应保留 buf[consumed:]。首包非法时 consumed 为 0，由调用方
    决定丢弃策略。
    """
    packets: List[Tuple[str, int, bytes]] = []
    offset = 0
    total = len(buf)
    while True:
        start = offset
        try:
            _, addr, offset = decode_address(buf, offset)
            if offset + 2 > total:
                raise IndexError('端口不完整')
            port = struct.unpack('>H', buf[offset:offset + 2])[0]
            offset += 2
            if offset + 2 > total:
                raise IndexError('长度不完整')
            length = struct.unpack('>H', buf[offset:offset + 2])[0]
            offset += 2
            if buf[offset:offset + 2] != CRLF:
                raise ValueError('无效的 CRLF 分隔符')
            offset += 2
            if offset + length > total:
                raise IndexError('负载不完整')
            packets.append((addr, port, buf[offset:offset + length]))
            offset += length
        except (ValueError, IndexError, struct.error):
            offset = start  # 回退到本包起点，等待后续数据补齐
            break
    return packets, offset
