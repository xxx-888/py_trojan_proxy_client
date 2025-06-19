import socks
import socket
import asyncio
import http.client

async def test_tcp_connect():
    """测试 TCP CONNECT"""
    print("测试 TCP CONNECT...")
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 7897)
    socket.socket = socks.socksocket

    try:
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.settimeout(5)
        tcp_socket.connect(("httpbin.org", 80))
        print("TCP 连接到 httpbin.org:80 成功")

        conn = http.client.HTTPConnection("httpbin.org", timeout=5)
        conn.sock = tcp_socket
        conn.request("GET", "/get")
        response = conn.getresponse()
        print(f"收到 HTTP 响应: {response.status} {response.reason}")
        print(f"响应内容: {response.read().decode()[:100]}...")

    except socket.timeout:
        print("TCP 连接超时")
    except ConnectionRefusedError as e:
        print(f"TCP 连接被拒绝: {e}")
    except Exception as e:
        print(f"TCP 测试错误: {e}")
    finally:
        tcp_socket.close()

async def test_udp_associate():
    """测试 UDP ASSOCIATE"""
    print("测试 UDP ASSOCIATE...")

    # 设置 SOCKS5 代理
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 7897)  # 例如 127.0.0.1:1080
    socket.socket = socks.socksocket  # 使用 SOCKS 代理套接字

    # 创建 UDP socket
    sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)

    # 目标服务器和端口
    target_ip = "8.8.8.8"
    target_port = 53

    # 发送数据
    message = b"Hello, UDP via SOCKS5"
    sock.sendto(message, (target_ip, target_port))

    # 接收数据
    sock.settimeout(5)  # 设置超时时间
    try:
        data, addr = sock.recvfrom(1024)
        print(f"Received data: {data} from {addr}")
    except socket.timeout:
        print("No response received.")
    finally:
        sock.close()


async def main():
    await test_tcp_connect()
    await test_udp_associate()

if __name__ == '__main__':
    asyncio.run(main())