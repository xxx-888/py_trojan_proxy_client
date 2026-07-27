# py_trojan_proxy_client

一个基于 Python `asyncio` 实现的 **Trojan 代理协议客户端**。它在本地启动一个 **SOCKS5 代理服务器**，将客户端流量通过 Trojan 协议转发到远端 Trojan 服务器，从而访问目标网络。

> ⚠️ **用途说明**：本项目仅用于学习网络协议实现、构建个人代理工具。请在你拥有合法使用权的网络环境下使用，遵守所在地法律法规。

---

## 工作原理

```
[本地应用]
    |  SOCKS5 (127.0.0.1:10800)
    v
[Trojan 客户端 / 本地 SOCKS5 服务端]   <- 本项目 (src/ Python 包)
    |  Trojan 协议 (TLS 加密, 443)
    v
[远端 Trojan 服务器]
    |
    v
[目标地址]  (example.com:443 / DNS / UDP)
```

1. 本地应用把请求发给本项目的 SOCKS5 监听端口。
2. 客户端完成 SOCKS5 握手（支持无认证 / 用户名密码认证），解析目标地址。
3. 与 Trojan 服务器建立 **TLS 连接**，发送 `SHA224(密码)` + Trojan 请求头。
4. 双向转发 TCP（CONNECT）与 UDP（UDP ASSOCIATE）流量，支持 HTTPS 域名透传与连接池复用。

---

## 功能特性

- ✅ 本地 **SOCKS5 服务端**（RFC 1928），支持 `CONNECT` 与 `UDP ASSOCIATE`
- ✅ **Trojan 协议**封装（TLS 加密，密码经 `SHA224` 摘要）
- ✅ **IPv4 / IPv6 / 域名** 三种目标地址类型（ATYP 1/3/4）
- ✅ **HTTPS 域名透传**：目标端口为 443 时保留原始域名，避免 SNI/证书问题
- ✅ **UDP 转发**：封装为 Trojan UDP 数据包，带超时与重试
- ✅ **连接池**：按 `(目标地址, 端口, 命令)` 复用 TLS 连接，并有后台清理任务
- ✅ **可选认证**：在 `config.json` 的 `users` 中配置用户名/密码，启用 SOCKS5 用户密码认证
- ✅ **可配置**：监听地址/端口、超时、缓冲区、重试次数、清理间隔均可在配置中设置
- ✅ 基于 `loguru` 的滚动日志（文件 + 控制台）

---

## 目录结构

```
py_trojan_proxy_client/
├── README.md                 # 本文件
├── run.py                    # 根目录启动器（python run.py）
├── .gitignore                # 忽略 config.json / *.exe / *.log / .idea 等
├── requirements.txt          # 依赖 (loguru)
├── config.example.json       # 配置模板（占位，不含真实凭据）
├── config.json               # 你的真实配置（本地保留，已被 .gitignore 忽略）
├── src/
│   ├── __init__.py           # 包标识
│   ├── __main__.py           # 支持 `python -m src` 启动入口
│   ├── config.py             # 配置加载与校验 + PROJECT_ROOT
│   ├── logger.py             # 日志初始化（loguru：文件 + 控制台）
│   ├── protocol.py           # 协议工具：地址编解码 / build_trojan_request / UDP 数据报解析
│   ├── trojan.py             # ★ TrojanClient：TLS 连接、CONNECT/UDP 转发、连接池、DNS
│   ├── socks5.py             # SOCKS5Server：握手/认证/解析/启动
│   └── main.py               # 入口：装配配置 / TrojanClient / SOCKS5Server 并启动
├── legacy/                   # 历史 / 实验版本（保留以备参考）
│   ├── trojan_client_old.py  # 早期版本：硬编码服务器参数，无配置文件
│   └── socks5_proxy.py       # 纯 SOCKS5 代理实验（不含 Trojan 转发）
├── tests/
│   ├── test_protocol.py      # 协议工具单元测试（地址编解码 / UDP 数据报 / build 请求）
│   └── test_proxy.py         # 集成测试占位（待补充）
├── new_trojan_client.exe     # 由 src 打包的 Windows 可执行文件（本地保留，已忽略）
└── trojan_client.log         # 运行日志（本地生成，已忽略）
```

---

## 安装

需要 **Python 3.8+**（推荐 3.10+）。

```bash
# 克隆仓库
git clone git@github.com:xxx-888/py_trojan_proxy_client.git
cd py_trojan_proxy_client

# 安装依赖
pip install -r requirements.txt
```

---

## 配置

复制模板并填入你的 Trojan 服务器信息：

```bash
cp config.example.json config.json
```

`config.json` 字段说明：

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `trojan_host` | 远端 Trojan 服务器域名或 IP | 必填 |
| `trojan_port` | 远端 Trojan 服务端口（通常为 443） | `443` |
| `trojan_password` | Trojan 密码（会做 SHA224 摘要） | 必填 |
| `listen_host` | 本地 SOCKS5 监听地址 | `127.0.0.1` |
| `listen_port` | 本地 SOCKS5 监听端口 | `10800` |
| `users` | SOCKS5 用户名/密码认证表 `{"user": "pass"}`，为空则关闭认证 | `{}` |
| `timeout` | 连接/读写超时（秒） | `60` |
| `max_retries` | UDP 响应最大重试次数 | `3` |
| `buffer_size` | 收发缓冲区大小（字节） | `16384` |
| `pool_cleanup_interval` | 连接池清理间隔（秒） | `180` |

> 🔒 `config.json` 含有真实密码，**已被 `.gitignore` 忽略，不会提交到仓库**。请勿手动将其加入版本控制。

---

## 使用方法

```bash
# 方式一：以 Python 包方式运行（自动定位 config.json）
python -m src

# 方式二：通过根目录启动器运行（效果相同）
python run.py
```

> ⚠️ 不要直接 `python src/main.py`：包内使用相对导入（`from .config import ...`），
> 必须以「模块/包」方式加载（`-m src` 或 `run.py`），当作脚本直接运行会丢失包上下文而报错。

启动后，将本机应用的代理设置为：

- 类型：**SOCKS5**
- 地址：`127.0.0.1`
- 端口：`10800`（与 `listen_port` 一致）

Windows 也可直接运行打包好的 `new_trojan_client.exe`（需同目录有 `config.json`）。

按 `Ctrl+C` 停止服务。

---

## 协议说明

- **SOCKS5**：实现 RFC 1928 的握手、`CONNECT`、`UDP ASSOCIATE`，地址类型支持 IPv4 / 域名 / IPv6。
- **Trojan**：握手后发送 `<SHA224(password)>\r\n` + `<CMD><ATYP><ADDR><PORT>\r\n`，TLS 之上承载。UDP 按 Trojan 规范封装（ATYP + ADDR + PORT + LENGTH + CRLF + PAYLOAD）。
- **连接复用**：以 `(目标地址, 端口, 命令)` 为键缓存 TLS 连接，后台定时清理已关闭连接。

---

## 安全提示

- ⚠️ **历史凭据已泄露**：早期提交（`6bcfa38`）曾将真实 `config.json` 提交进 Git 历史，其中 Trojan 密码已暴露。**请尽快在 Trojan 服务端修改该密码**，并重新生成 `config.json`。
- 本项目为客户端工具，不会对外暴露任何端口（仅监听 `127.0.0.1`）。如监听 `0.0.0.0` 请自行评估风险。
- 日志中可能包含目标域名/IP，**不要分享含日志的压缩包**。

---

## 后续优化计划

以下为后续可完善方向（暂未实现，部分已实现）：

- [x] 单元测试 / 集成测试（已新增 `tests/test_protocol.py`，覆盖协议编解码）
- [ ] 配置文件校验与更友好的错误提示
- [ ] 系统托盘 GUI / 命令行参数（覆盖配置文件）
- [ ] 多服务器负载均衡与自动切换
- [ ] 性能基准测试与 pyproject.toml 打包（`python -m build`）
- [ ] 跨平台构建脚本（PyInstaller）

---

## 许可证

本项目仅供学习与研究使用。
