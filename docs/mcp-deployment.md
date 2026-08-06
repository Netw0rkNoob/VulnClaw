# VulnClaw MCP 工具部署方案

## 概览

VulnClaw 保留 4 个 MCP 服务，其中 2 个本地实现开箱即用，2 个需部署外部服务。

| 服务 | 模式 | 状态 | 用途 |
|---|---|---|---|
| fetch | 本地 (httpx) | 开箱即用 | HTTP/HTTPS 请求、GET/POST/PUT 等方法、headers/params/cookies/body/json/form、API 测试 |
| memory | 本地 (JSON) | 开箱即用 | 跨会话记忆持久化 |
| chrome-devtools | stdio MCP | 需部署 | 浏览器自动化/JS 执行/截图 |
| burp | stdio MCP | 需部署 | 抓包/重放/HTTP 拦截（替代 Yakit） |

`fetch` 是内置本地工具，无需启动外部 MCP 服务。默认行为是直接发送 `GET` 请求并返回完整响应 body；模型可按需指定 `method`、`headers`、`params`、`cookies`、`body`、`data`、`form`、`json`、`timeout`、`follow_redirects`、`verify_tls` 和 `max_body_chars`。`max_body_chars` 省略或设为 `0` 表示不裁剪，只有正整数才限制响应 body 长度。为适配 CTF/靶场中的自签 HTTPS，`verify_tls` 默认关闭；需要严格证书校验时显式设为 `true`。

---

## 1. Chrome DevTools MCP

### 仓库

https://github.com/ChromeDevTools/chrome-devtools-mcp

### 前置条件

- Node.js LTS (v20+)
- Chrome 浏览器（Stable 或 Chrome for Testing）
- ffmpeg（screencast 功能需要，可选）

### 安装

无需手动安装，VulnClaw 配置中已使用 `npx -y chrome-devtools-mcp@latest` 自动拉取。

### 启动 Chrome 远程调试

PowerShell:

```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir=C:\tmp\chrome-debug
```

cmd:

```bat
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir=C:\tmp\chrome-debug
```

Linux/Mac:

```bash
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-debug
```

### VulnClaw 配置

编辑 `~/.vulnclaw/config.yaml`，Windows 默认路径为 `C:\Users\<用户名>\.vulnclaw\config.yaml`：

```yaml
mcp:
  servers:
    chrome-devtools:
      enabled: true
      transport:
        type: stdio
        command: npx
        args:
          - "-y"
          - "chrome-devtools-mcp@latest"
          - "--browser-url=http://127.0.0.1:9222"
```

可以通过 CLI 启用 Chrome DevTools MCP：

```bash
vulnclaw config set mcp.servers.chrome-devtools.enabled true
```

如需指定 `--browser-url`，仍需编辑上面的 `config.yaml`。

### 提供的能力（31+ 工具）

- **输入自动化**: 点击、拖拽、表单填充、对话框处理
- **导航**: 页面管理、URL 跳转、元素等待
- **性能分析**: Trace 录制、Google CrUX 集成
- **网络**: 请求监控、网络拦截
- **调试**: 截图、Console 日志、Lighthouse 审计
- **内存**: 堆快照分析
- **模拟**: 设备/视口模拟

### 渗透测试场景

- 访问目标页面截图取证
- 执行 JS 检测 DOM XSS
- 监控网络请求发现 API 端点
- 自动化表单交互测试 CSRF/认证绕过

---

## 2. Burp Suite MCP（替代 Yakit）

### 仓库

https://github.com/PortSwigger/mcp-server

### 前置条件

- Java（PATH 中可用，`java --version` 验证）
- Burp Suite（Community 或 Professional 均可 —— 见下方说明）
- `jar` 命令可用

> **Community vs Professional**：实测（对照 PortSwigger/mcp-server 源码
> `Tools.kt`）该扩展仅有一个工具受 Edition 限制——`get_proxy_issues`
> （`api.burpSuite().version().edition() == PROFESSIONAL` 时才注册，对应
> Burp Scanner，Community 版本身就没有 Scanner）。抓包/重放/拦截相关的
> 全部工具（`send_http1_request`、`send_http2_request`、
> `create_repeater_tab`、`send_to_intruder`、`get_proxy_http_history` 等）
> 与 Edition 无关，在 Community 版上同样可用。已在 Kali 自带的 Burp Suite
> Community Edition 上端到端验证：加载扩展、启用 MCP、通过 SSE 发送真实
> HTTP 请求并在 Burp 自己的 Logger 中确认该请求确实经过了 Burp 的引擎。
> 因此本文档一直标注的“Community 版功能有限”对本节描述的抓包/重放场景
> 并不成立——只有想用 Burp Scanner 才需要 Professional。

### 安装步骤

#### Step 1: 克隆并构建

```bash
git clone https://github.com/PortSwigger/mcp-server.git burp-mcp
cd burp-mcp
./gradlew embedProxyJar
# Windows 用: gradlew.bat embedProxyJar
# 产物: build/libs/burp-mcp-all.jar
```

#### Step 2: 加载到 Burp Suite

1. 打开 Burp Suite -> Extensions 标签页
2. 点击 Add -> Type 选择 Java
3. 选择 `build/libs/burp-mcp-all.jar`
4. 点击 Next 完成加载

#### Step 3: 启用 MCP Server

1. 在 Burp 中找到 MCP 标签页
2. 勾选 "Enabled"
3. 默认监听 `http://127.0.0.1:9876`
4. 可选：修改 Host/Port

### VulnClaw 配置

编辑 `~/.vulnclaw/config.yaml`，Windows 默认路径为 `C:\Users\<用户名>\.vulnclaw\config.yaml`：

```yaml
mcp:
  servers:
    burp:
      enabled: true
      transport:
        type: sse
        url: "http://127.0.0.1:9876"
```

VulnClaw 直接连接 Burp 扩展暴露的 SSE 服务，不再通过 `java -jar` 代理启动 Burp MCP。

### 提供的能力

- **抓包**: 查看 Proxy History 中的请求/响应
- **重放**: 构造并发送自定义 HTTP 请求
- **拦截**: 实时修改请求/响应
- **扫描**: 调用 Burp Scanner（Pro 版）
- **Intruder**: 参数化攻击

### 替代 Yakit 的对照

| 功能 | Yakit | Burp MCP |
|---|---|---|
| MITM 抓包 | MITM 劫持 | Proxy History |
| 请求重放 | Web Fuzzer | send_http1_request |
| 流量分析 | 流量分析 | get_proxy_history |
| 漏洞扫描 | 插件扫描 | Burp Scanner |
| MCP 集成 | 未实现 (Issue #2703) | 官方支持 v1.3.0 |

---

## 快速验证

### 验证 Chrome DevTools MCP

```bash
# 1. 启动 Chrome 调试模式
# 2. 启动 VulnClaw
vulnclaw chat

# 3. 输入测试命令
> 打开 http://example.com 并截图
```

### 验证 Burp MCP

```bash
# 1. 启动 Burp Suite 并启用 MCP 扩展
# 2. 启动 VulnClaw
vulnclaw chat

# 3. 输入测试命令
> 查看 Burp 抓包历史
```

---

## 故障排查

### Chrome DevTools 连不上

1. 确认 Chrome 已启动远程调试：`curl http://127.0.0.1:9222/json`
2. 确认 Node.js 已安装：`node --version`
3. 尝试手动运行：`npx -y chrome-devtools-mcp@latest --browser-url=http://127.0.0.1:9222`
4. 如需连接固定调试端口，确认 `config.yaml` 中包含 `--browser-url=http://127.0.0.1:9222`

### Burp MCP 连不上

1. 确认 Burp 中 MCP 标签页显示 "Enabled"
2. 确认端口可达：`curl http://127.0.0.1:9876`
3. 确认 Java 版本：`java --version`（需要 Java 11+）
4. 检查 JAR 路径是否正确
