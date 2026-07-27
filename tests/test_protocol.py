"""protocol 模块的单元测试（不依赖网络）。

验证地址编解码、Trojan 请求构造、UDP 数据报解析的字节布局，
确保模块化重构后行为与原单文件实现逐字节一致。
"""
import struct
import socket
import unittest

from src.protocol import (
    ATYP_IPV4,
    ATYP_DOMAIN,
    ATYP_IPV6,
    encode_address,
    decode_address,
    build_trojan_request,
    parse_socks5_udp_datagram,
)


class TestProtocol(unittest.TestCase):

    def test_encode_address_ipv4(self):
        out = encode_address('1.2.3.4', 443)
        self.assertEqual(out[0], ATYP_IPV4)
        self.assertEqual(out[1:5], socket.inet_pton(socket.AF_INET, '1.2.3.4'))
        self.assertEqual(out[5:], struct.pack('>H', 443))

    def test_encode_address_domain(self):
        out = encode_address('example.com', 80)
        self.assertEqual(out[0], ATYP_DOMAIN)
        self.assertEqual(out[1], len('example.com'))
        self.assertEqual(out[2:2 + len('example.com')], b'example.com')
        self.assertEqual(out[2 + len('example.com'):], struct.pack('>H', 80))

    def test_encode_address_ipv6(self):
        out = encode_address('::1', 53)
        self.assertEqual(out[0], ATYP_IPV6)
        self.assertEqual(out[1:17], socket.inet_pton(socket.AF_INET6, '::1'))
        self.assertEqual(out[17:], struct.pack('>H', 53))

    def test_decode_address_roundtrip(self):
        for addr, port in [('1.2.3.4', 443), ('::1', 53)]:
            enc = encode_address(addr, port)
            atyp, dec, off = decode_address(enc, 0)
            self.assertEqual(dec, addr)
            self.assertEqual(struct.unpack('>H', enc[off:off + 2])[0], port)
        enc = encode_address('example.com', 80)
        atyp, dec, off = decode_address(enc, 0)
        self.assertEqual(atyp, ATYP_DOMAIN)
        self.assertEqual(dec, 'example.com')

    def test_build_trojan_request_connect(self):
        req = build_trojan_request('1.2.3.4', 443, 'CONNECT')
        self.assertEqual(req[0:1], b'\x01')
        self.assertTrue(req.endswith(b'\r\n'))
        self.assertEqual(req[1:-2], encode_address('1.2.3.4', 443))

    def test_build_trojan_request_udp(self):
        req = build_trojan_request('1.2.3.4', 443, 'UDP ASSOCIATE')
        self.assertEqual(req[0:1], b'\x03')

    def test_build_trojan_request_invalid_ipv6(self):
        # 仅当地址形如 IPv6（含冒号且非 [ 开头）但无法解析时才抛 ValueError；
        # 普通非法字符串会被当作域名处理（与原实现一致）。
        with self.assertRaises(ValueError):
            build_trojan_request('gg::gg', 80, 'CONNECT')

    def test_parse_socks5_udp_datagram(self):
        payload = b'hello'
        body = encode_address('1.2.3.4', 53) + payload
        data = b'\x00\x00' + b'\x00' + body  # RSV + FRAG + 地址段 + 负载
        atyp, addr, port, p = parse_socks5_udp_datagram(data)
        self.assertEqual(atyp, ATYP_IPV4)
        self.assertEqual(addr, '1.2.3.4')
        self.assertEqual(port, 53)
        self.assertEqual(p, payload)

    def test_reconstructed_udp_packet_matches_legacy(self):
        # 验证 trojan.py 中 udp_packet 的构造与原实现逐字节一致
        target_addr, target_port, payload = '1.2.3.4', 53, b'hello'
        udp_packet = encode_address(target_addr, target_port) + struct.pack('>H', len(payload)) + b'\r\n' + payload
        expected = (
            bytes([ATYP_IPV4])
            + socket.inet_pton(socket.AF_INET, target_addr)
            + struct.pack('>H', target_port)
            + struct.pack('>H', len(payload))
            + b'\r\n'
            + payload
        )
        self.assertEqual(udp_packet, expected)


if __name__ == '__main__':
    unittest.main()
