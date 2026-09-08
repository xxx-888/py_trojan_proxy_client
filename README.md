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
    |  Trojan 协议 (TLS 加密, 通常 443)
    v
[远端 Trojan 服务器]
    |
    v
[目标地址]  (example.com:443 / DNS / UDP)
```

1. 本地应用把请求发给本项目的 SOCKS5 监听端口。
2. 客户端完成 SOCKS5 握手（支持无认证 / 用户名密码认证），解析目标地址。
3. 与 Trojan 服务器建立 **TLS 连接**，发送 `SHA224(密码)` + Trojan 请求头。
4. 双向转发 TCP（CONNECT）与 UDP（UDP ASSOCIATE）流量。

---

## 功能特性

- ✅ 本地 **SOCKS5 服务端**（RFC 1928），支持 `CONNECT` 与 `UDP ASSOCIATE`
- ✅ **Trojan 协议**封装（TLS 加密，密码经 `SHA224` 摘要，最低 TLS 1.2）
- ✅ **IPv4 / IPv6 / 域名** 三种目标地址类型（ATYP 1/3/4）
- ✅ **域名远端解析**：目标域名原样透传给 Trojan 服务器解析，避免本地 DNS 泄露与污染
- ✅ **UDP 全双工转发**：按 Trojan UDP 格式封装/解封，正确处理 TCP 粘包/拆包，支持并发的请求-响应（如同时发起多个 DNS 查询）
- ✅ **稳定性设计**：每个代理请求独立 TLS 连接（Trojan 协议不支持复用，避免并发数据串流）；TCP 任一方向结束即收尾，杜绝半开连接悬挂；UDP 会话随 TCP 连接生命周期自动回收
- ✅ **性能优化**：SSLContext 进程内复用、TCP_NODELAY、大缓冲转发、后台线程写日志
- ✅ **可选认证**：在 `config.json` 的 `users` 中配置用户名/密码，启用 SOCKS5 用户密码认证（RFC 1929，常数时间比较）
- ✅ **可配置 TLS**：支持自签/过期证书（默认），也可开启证书校验与自定义 SNI
- ✅ 基于 `loguru` 的滚动日志（文件 + 控制台），级别可配置
- ✅ **单文件 exe**：PyInstaller 打包，配置与日志都在 exe 同目录

---

## 快速开始

需要 **Python 3.10+**（开发环境为 3.14，3.10+ 均可运行）。

```bash
git clone https://github.com/xxx-888/py_trojan_proxy_client.git
cd py_trojan_proxy_client

# 创建虚拟环境并安装依赖
python -m venv venv
venv\Scripts\pip install -r requirements.txt   # Windows
# source venv/bin/activate && pip install -r requirements.txt  # Linux/macOS

# 复制配置模板并填入你的 Trojan 服务器信息
cp config.example.json config.json
```

启动（两种方式等价，均支持 `--config` / `--version` 参数）：

```bash
venv\Scripts\python run.py     # 方式一：根目录启动器
venv\Scripts\python -m src     # 方式二：模块方式运行
```

> ⚠️ 不要直接 `python src/main.py`：包内使用相对导入（`from .config import ...`），
> 必须以「模块/包」方式加载，当作脚本直接运行会丢失包上下文而报错。

启动后，将本机应用的代理设置为：

- 类型：**SOCKS5**
- 地址：`127.0.0.1`
- 端口：`10800`（与 `listen_port` 一致）

按 `Ctrl+C` 停止服务。

### 使用预编译 exe（Windows）

两种途径：

1. **GitHub Releases**：推送 `v*` 标签后，CI 会自动构建并发布 `trojan_client.exe`（见下方「自动构建」）。
2. **本地自行打包**：双击或执行 `build.bat`（首次执行 `build.bat --dev` 自动装依赖）。

运行时把 `config.json` 放在 **exe 同目录** 即可（日志文件也会生成在同目录）：

```
trojan_client.exe                    # 自动查找同目录/当前目录 config.json
trojan_client.exe -c D:\path\to\config.json
trojan_client.exe --version
```

也可用环境变量 `TROJAN_CONFIG` 指定配置路径。

---

## 配置说明

`config.json` 字段（完整示例见 `config.example.json`）：

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `trojan_host` | 远端 Trojan 服务器域名或 IP | 必填 |
| `trojan_port` | 远端 Trojan 服务端口（通常为 443） | 必填 |
| `trojan_password` | Trojan 密码（会做 SHA224 摘要） | 必填 |
| `listen_host` | 本地 SOCKS5 监听地址 | 必填 |
| `listen_port` | 本地 SOCKS5 监听端口 | 必填 |
| `users` | SOCKS5 用户名/密码认证表 `{"user": "pass"}`，为空则关闭认证 | `{}` |
| `timeout` | 与 Trojan 服务器建立连接的超时（秒） | `10` |
| `idle_timeout` | 转发空闲超时（秒），连接静默超过该时长后关闭；`0` 表示不超时（适合 SSH 等长连接场景） | `300` |
| `buffer_size` | 收发缓冲区大小（字节） | `65536` |
| `stats_interval` | 活跃连接数统计输出间隔（秒） | `60` |
| `ssl_verify` | 是否校验 Trojan 服务器证书（自签证书需设为 `false`） | `false` |
| `ssl_sni` | TLS SNI，留空则使用 `trojan_host` | `""` |
| `log_level` | 日志级别：`TRACE`/`DEBUG`/`INFO`/`WARNING`/`ERROR` | `INFO` |

> 🔒 `config.json` 含有真实密码，**已被 `.gitignore` 忽略，不会提交到仓库**。请勿手动将其加入版本控制。

---

## 自动构建（GitHub Actions）

仓库自带 CI（`.github/workflows/build.yml`）：

- **push / PR 到 main**：运行全部测试 → PyInstaller 打包 → 上传 `trojan_client.exe` 构建产物
- **推送 `v*` 标签**（如 `git tag v1.1.0 && git push origin v1.1.0`）：自动创建 GitHub Release 并附上 exe

---

## 开发与测试

```bash
# 运行全部测试（协议单元测试 + 本地回环集成测试，不依赖外网与真实服务器）
venv\Scripts\python -m unittest discover -s tests -t . -v
```

集成测试通过本地 **Mock Trojan 服务器**（真实 TLS + Trojan 协议）覆盖：

- SOCKS5 握手 / 用户名密码认证（成功与失败路径）
- CONNECT 双向转发（含 300KB 大块数据）
- UDP ASSOCIATE 数据报往返（含并发多目标的响应归属）
- Trojan UDP over TCP 的粘包/拆包分帧

### 目录结构

```
py_trojan_proxy_client/
├── README.md                 # 本文件
├── LICENSE                   # MIT 许可证
├── run.py                    # 根目录启动器（python run.py）
├── build.bat                 # Windows 本地打包脚本（PyInstaller）
├── .github/workflows/build.yml  # CI：测试 + 构建 + 发布 Release
├── .gitignore                # 忽略 config.json / *.exe / dist 等
├── requirements.txt          # 依赖 (loguru)
├── config.example.json       # 配置模板（占位，不含真实凭据）
├── config.json               # 你的真实配置（本地保留，已被 .gitignore 忽略）
├── src/
│   ├── __init__.py           # 包标识 + 版本号
│   ├── __main__.py           # 支持 `python -m src` 启动入口
│   ├── config.py             # 配置查找/加载/校验 + PROJECT_ROOT（兼容打包）
│   ├── logger.py             # 日志初始化（loguru：文件 + 控制台，enqueue）
│   ├── protocol.py           # 协议工具：地址编解码 / UDP 分帧与解析
│   ├── trojan.py             # ★ TrojanClient：TLS 连接、CONNECT/UDP 转发、统计
│   ├── socks5.py             # SOCKS5Server：握手/认证/解析/UDP 中继/启动
│   └── main.py               # 入口：参数解析、装配组件并启动
├── tests/
│   ├── certs.py              # 测试专用自签名 TLS 证书（仅本地回环使用）
│   ├── test_protocol.py      # 协议工具单元测试
│   ├── test_config.py        # 配置加载/校验测试
│   └── test_proxy.py         # 全链路集成测试（Mock Trojan TLS 服务器）
├── legacy/                   # 历史 / 实验版本（保留以备参考）
└── dist/trojan_client.exe    # 本地打包产物（已忽略，Release 由 CI 发布）
```

---

## 协议说明

- **SOCKS5**：实现 RFC 1928 的握手、`CONNECT`、`UDP ASSOCIATE`，地址类型支持 IPv4 / 域名 / IPv6；认证实现 RFC 1929。
- **Trojan**：握手后发送 `<SHA224(password)>\r\n` + `<CMD><ATYP><ADDR><PORT>\r\n`，TLS 之上承载。UDP 按 Trojan 规范封装（ATYP + ADDR + PORT + LENGTH + CRLF + PAYLOAD）。
- **连接模型**：Trojan 协议一条 TLS 连接只承载一个会话（无多路复用），因此每个代理请求独立建立连接——这并非连接池的缺失，而是并发安全的要求；共享连接会导致多个会话的数据串流。

---

## 安全提示

- ⚠️ **历史凭据已泄露**：早期提交（`6bcfa38`）曾将真实 `config.json` 提交进 Git 历史，其中 Trojan 密码已暴露。**请尽快在 Trojan 服务端修改该密码**，并重新生成 `config.json`。
- 本项目为客户端工具，默认仅监听 `127.0.0.1`。如监听 `0.0.0.0` 请务必配置 `users` 认证，并自行评估风险。
- `ssl_verify: false` 会跳过服务器证书校验（兼容自签证书），存在被中间人攻击的可能；服务器证书有效时建议开启。
- 日志中可能包含目标域名/IP，**不要分享含日志的压缩包**。

---

## 许可证

[MIT](LICENSE) © 2026 xxx-888
