import socket
import struct
import time
import os
import sys
import platform
import logging
import math

ICMP_ECHO_REQUEST = 8  # ICMP 回显请求类型
ICMP_CODE = 0          # ICMP 代码

class Ping:
    def __init__(self, dest_addr, timeout=2, ttl=64, count=4, packet_size=32, verbose=True):
        """
        初始化 Ping 实例
        :param dest_addr: 目标主机地址（IP 或域名）
        :param timeout: 超时时间（秒）
        :param ttl: TTL（生存时间）
        :param count: 发送的 Ping 次数
        :param packet_size: ICMP 数据包大小（字节）
        :param verbose: 是否打印详细日志
        """
        self.dest_addr = dest_addr
        self.timeout = max(0.1, float(timeout))
        self.ttl = max(1, min(255, int(ttl)))
        self.count = max(1, int(count))
        self.packet_size = max(8, int(packet_size))
        self.verbose = verbose
        self.sent_count = 0
        self.received_count = 0
        self.rtt_list = []
        self._setup_logger()

    def _setup_logger(self):
        """设置日志输出格式"""
        self.logger = logging.getLogger("Ping")
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.handlers = [handler]

    def checksum(self, data: bytes) -> int:
        """计算 ICMP 校验和"""
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff

    def build_packet(self, identifier: int, sequence: int) -> bytes:
        """构建 ICMP Echo 请求数据包"""
        payload = bytes((x % 256 for x in range(self.packet_size)))
        header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, 0, identifier, sequence)
        packet = header + payload
        chksum = self.checksum(packet)
        header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, chksum, identifier, sequence)
        return header + payload

    def ping_once(self, sock, dest_ip, identifier, sequence):
        """执行一次 Ping 操作"""
        packet = self.build_packet(identifier, sequence)
        send_time = time.time()
        try:
            sock.sendto(packet, (dest_ip, 0))
            self.sent_count += 1
            self.logger.info(f"[>] 向 {dest_ip} 发送 ICMP Echo 请求，序号={sequence}，大小={len(packet)} 字节")
            sock.settimeout(self.timeout)
            data, addr = sock.recvfrom(1024)
            recv_time = time.time()
            icmp_header = data[20:28]
            r_type, code, _, recv_id, recv_seq = struct.unpack("!BBHHH", icmp_header)
            if r_type == 0 and recv_id == identifier:
                rtt = (recv_time - send_time) * 1000
                self.logger.info(f"[<] 来自 {addr[0]} 的回复：icmp_seq={recv_seq}, 往返时间={rtt:.2f} ms")
                self.rtt_list.append(rtt)
                self.received_count += 1
            else:
                self.logger.warning(f"[!] 收到非预期 ICMP 包：type={r_type}, code={code}")
        except socket.timeout:
            self.logger.warning("[!] 请求超时")
        except Exception as e:
            self.logger.error(f"[!] 错误: {e}")

    def print_statistics(self):
        """输出 Ping 统计信息"""
        loss = (self.sent_count - self.received_count) / self.sent_count * 100
        self.logger.info(f"\n--- {self.dest_addr} ping 统计 ---")
        self.logger.info(f"{self.sent_count} 个包已发送，{self.received_count} 个已接收，丢包率 {loss:.0f}%")
        if self.rtt_list:
            min_rtt = min(self.rtt_list)
            max_rtt = max(self.rtt_list)
            avg_rtt = sum(self.rtt_list) / len(self.rtt_list)
            stddev = math.sqrt(sum((x - avg_rtt) ** 2 for x in self.rtt_list) / len(self.rtt_list))
            self.logger.info(f"往返时间 最小/平均/最大/标准差 = {min_rtt:.2f}/{avg_rtt:.2f}/{max_rtt:.2f}/{stddev:.2f} ms")

    def run(self):
        """执行 Ping 操作主逻辑"""
        try:
            dest_ip = socket.gethostbyname(self.dest_addr)
            self.logger.info(f"PING {self.dest_addr} ({dest_ip})")
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            if platform.system() == "Windows":
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", self.ttl))
            else:
                sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
            pid = os.getpid() & 0xFFFF
            for seq in range(1, self.count + 1):
                self.ping_once(sock, dest_ip, pid, seq)
                time.sleep(1)
            self.print_statistics()
        except socket.gaierror:
            self.logger.error(f"无法解析主机: {self.dest_addr}")
        except PermissionError:
            self.logger.error("请使用管理员权限运行此脚本。")
        finally:
            try:
                sock.close()
            except Exception:
                pass

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Ping 工具（ICMP Echo Request）")
    parser.add_argument("host", help="目标 IP 地址或域名")
    parser.add_argument("-c", "--count", type=int, default=4, help="发送的请求数量（默认：4）")
    parser.add_argument("-t", "--timeout", type=float, default=2, help="每次请求超时（秒，默认：2）")
    parser.add_argument("-l", "--ttl", type=int, default=64, help="TTL 值（默认：64）")
    parser.add_argument("-s", "--size", type=int, default=32, help="数据包大小（默认：32 字节）")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细日志")

    args = parser.parse_args()

    try:
        ping = Ping(
            dest_addr=args.host,
            timeout=args.timeout,
            ttl=args.ttl,
            count=args.count,
            packet_size=args.size,
            verbose=args.verbose
        )
        ping.run()
    except KeyboardInterrupt:
        print("\n用户中断 Ping。")
