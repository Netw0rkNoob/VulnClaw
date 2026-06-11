<div align="center">

# VulnClaw 🦞

> *AI 驱动的渗透测试 CLI 工具 — 说人话，打漏洞。*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![OpenAI Compatible](https://img.shields.io/badge/API-OpenAI_Compatible-green)](https://platform.openai.com/)
[![MCP](https://img.shields.io/badge/Toolchain-MCP-orange)](https://modelcontextprotocol.io/)
[![PyPI](https://img.shields.io/badge/PyPI-v0.3.0-blueviolet)](https://pypi.org/project/vulnclaw/)
[![Security](https://img.shields.io/badge/Scope-Authorized_Only-red)](#-安全声明)
<br>

🌐 **English version**: [`README_EN.md`](README_EN.md)

**本项目是可独立运行的 AI 渗透测试 Agent。**

<br>

基于 LLM Agent + MCP 工具链 + 渗透 Skill 编排，
配合 OpenAI / MiniMax / DeepSeek 等兼容模型，
自然语言输入 → 自动完成「信息收集 → 漏洞发现 → 漏洞利用 → 报告生成」全流程。

[快速开始](#快速开始) · [架构设计](#️-架构) · [Skill 体系](#-内置-skill)

</div>

---

## 它能做什么

输入自然语言，AI 自动执行渗透测试全流程：

```
用户输入：帮我对 http://target.example.com 进行渗透测试

VulnClaw 自动执行：
  Round 1:  信息收集 → 指纹识别、端口扫描、目录枚举
  Round 2:  漏洞发现 → 检测注入点、已知 CVE、配置缺陷
  Round 3:  漏洞利用 → PoC 验证、权限获取
  Round 4:  报告生成 → 结构化报告 + Python PoC 脚本
```

<img width="1148" height="642" alt="image" src="https://github.com/user-attachments/assets/576e1cf6-25da-4969-864b-40e77d020dbf" />


适用于已授权的渗透测试、CTF 竞赛、安全教学、红队演练等场景。

---

## 特性

- **自然语言驱动** — 用人话描述渗透意图，自动识别阶段和工具
- **13 个 LLM Provider** — OpenAI / MiniMax / DeepSeek / 智谱 / Moonshot / 千问 / SiliconFlow / 豆包 / 百川 / 阶跃星辰 / 商汤 / 零一万物，一键切换
- **MCP 工具链** — 已内置 12 个 MCP 服务配置和 23 个工具定义；当前 `fetch` / `memory` 以稳定的 `local` 模式运行，其余 MCP 集成多仍处于预览或占位阶段，待完整 session 生命周期管理落地后再逐步恢复真实协议接入
- **AI Agent 核心** — OpenAI 兼容协议 + Tool Calling + 自主渗透循环
- **20 个渗透 Skill** — 7 核心 + 13 专项 Skill（含 CTF Web/Crypto/Misc + osint-recon），含 138 个参考文档
- **编解码/加解密工具** — 29 种操作（Base64/Hex/URL/AES/JWT/Morse 等），LLM 可精确调用，不再靠猜测
- **Python 代码执行** — 内置 `python_execute` 工具，适合 payload 构造和响应解析；当前仍属高风险实验能力，不应视为强隔离沙箱
- **持续性渗透测试** — 周期循环（默认 100 轮/周期 × 10 周期 = 1000 轮），每周期自动生成报告，直到手动终止
- **推理过程显示控制** — `think on/off` 一键切换 LLM 思考过程的显示/隐藏，默认关闭，干净输出只看结论
- **沙盒模式提示词** — 解锁 AI 安全测试能力，CTF / 授权渗透场景专用
- **自动报告 & PoC** — 生成结构化 Markdown 报告和可运行的 Python PoC 脚本
- **Web UI 模式** — `vulnclaw web` 启动本地 Web 界面，浏览器操作渗透测试全流程，默认 `127.0.0.1:7788`
- **安全知识库** — 已内置知识库模块与基础种子数据，CLI 可维护；检索增强正在逐步接入主流程

---

## 快速开始

### 安装

```bash
# 从 PyPI 安装（推荐）
pip install vulnclaw

# 从源码安装
git clone https://github.com/Unclecheng-li/VulnClaw.git
cd VulnClaw
pip install -e .
```

### 四步启动

```bash
# 1. 选择提供商（自动填充 Base URL 和模型名）
vulnclaw config provider minimax   (或 openai/deepseek/zhipu/moonshot/qwen/siliconflow)

# 1.2（可选）自定义 Base URL 或模型名
vulnclaw config set llm.base_url https://your-own-api.example.com/v1 
vulnclaw config set llm.model your-model-name

# 2. 设置 API Key
vulnclaw config set llm.api_key sk-your-key-here

# 3. 默认：打开原 CLI / REPL
vulnclaw

# 4. 可选：打开 TUI 工作台
vulnclaw tui
```

### 环境检查

```bash
vulnclaw doctor
```

输出示例：

```
🦞 VulnClaw 环境检查

  Python: 3.14.4
  Node.js: v24.14.1
  npx: 已安装
  nmap: 已安装

LLM 配置:
  Provider: openai
  API Key: 已设置
  Base URL: https://api.openai.com/v1
  Model: gpt-4o

MCP 服务:
  fetch: 已启用 [P0]
  memory: 已启用 [P0]
  ...

✅ 环境就绪，运行 vulnclaw 开始
```

---

## CLI 命令速查

`vulnclaw --help` 查看所有命令：

```bash
$ vulnclaw --help

🦞 VulnClaw — AI-powered penetration testing CLI

 Usage: vulnclaw [OPTIONS] COMMAND [ARGS]...

 Options:
   --version  Show version and exit.
   --help     Show this message and exit.

 Commands:
   run           🚀 一键全流程渗透测试
   persistent    🔄 持续性渗透测试（100轮/周期）
   recon         🔍 仅信息收集阶段
   scan          🔎 执行漏洞扫描阶段
   exploit       💥 执行漏洞利用阶段
   report        📝 从会话记录生成报告
   repl          💬 启动经典 REPL 交互界面
   config        ⚙️  管理配置（set/get/list/provider）
   init          🔧 初始化配置
   doctor        🏥  检查运行环境
   tui           🖥️  打开终端图形化工作台
   web           🌐 启动本地 Web UI
```

### 命令详解

| 命令 | 说明 | 示例 |
|------|------|------|
| `vulnclaw` | 默认打开原 CLI / REPL 交互界面 | `vulnclaw` |
| `vulnclaw tui` | 显式打开终端图形化工作台 | `vulnclaw tui` / `vulnclaw tui --target target.com` |
| `vulnclaw repl` | 启动经典 REPL 交互界面 | `vulnclaw repl` |
| `vulnclaw run <target>` | 一键全流程渗透测试 | `vulnclaw run 192.168.1.1` |
| `vulnclaw persistent <target>` | 持续性渗透（100轮/周期） | `vulnclaw persistent 192.168.1.1` |
| `vulnclaw recon <target>` | 仅信息收集（不利用漏洞） | `vulnclaw recon target.com` |
| `vulnclaw scan <target>` | 漏洞扫描阶段 | `vulnclaw scan target.com --ports 80,443` |
| `vulnclaw exploit <target>` | 漏洞利用阶段 | `vulnclaw exploit target.com --cve CVE-2024-1234` |
| `vulnclaw report <session>` | 从会话 JSON 生成报告 | `vulnclaw report session_xxx.json` |
| `vulnclaw config set <key> <value>` | 设置配置项 | `vulnclaw config set llm.api_key sk-xxx` |
| `vulnclaw config get <key>` | 查看配置项 | `vulnclaw config get llm.model` |
| `vulnclaw config list` | 列出所有配置 | `vulnclaw config list` |
| `vulnclaw config provider <name>` | 切换 LLM 提供商 | `vulnclaw config provider minimax` |
| `vulnclaw init` | 初始化配置文件 | `vulnclaw init` |
| `vulnclaw doctor` | 检查运行环境 | `vulnclaw doctor` |
| `vulnclaw web` | 启动本地 Web UI | `vulnclaw web` / `vulnclaw web --port 8080` |

### TUI 工作台

`vulnclaw tui` 是可选的终端图形化工作台入口。它会在终端中展示授权目标、检查模式、运行概览、安全边界、命令预览、历史状态、报告和内联环境诊断，让用户先确认范围再启动任务。

```bash
vulnclaw tui
vulnclaw tui --target https://target.example --mode quick --only-port 443
vulnclaw tui --dry-run --target https://target.example --mode deep --only-path /admin
```

默认 `vulnclaw` 仍然进入原 CLI / REPL 交互；只有显式输入 `vulnclaw tui` 才会进入 TUI。
运行概览会读取已选目标的历史快照、风险数量、持久化约束和约束拦截次数，帮助用户在继续测试前确认上下文没有衰减。
在 TUI 的“设置测试范围”中可以直接编辑允许动作和禁止动作，例如只允许 `recon,scan`，或禁止 `exploit,post_exploitation`。

### 配置管理

```bash
# 查看所有提供商并切换
vulnclaw config provider --list    # 查看所有可用提供商
vulnclaw config provider minimax   # 切换到 MiniMax

# 手动设置（custom 模式）
vulnclaw config set llm.base_url https://your-api.com/v1
vulnclaw config set llm.model your-model-name
vulnclaw config set llm.api_key sk-your-key
```

---

## 使用方式

### 方式一：原 CLI / REPL 交互模式（默认）

```bash
$ vulnclaw
```

无参数启动会进入原本的 🦞 交互界面，用自然语言对话：

```
🦞 vulnclaw> 对 192.168.1.100 进行渗透测试，这是我授权的靶场

[*] 进入自主渗透模式，按 Ctrl+C 可随时中断
── Round 1 ──
  [+] 目标: 192.168.1.100
  [+] 开放端口: 22, 80, 443, 8080
```

### 方式二：TUI 工作台（显式启用）

```bash
$ vulnclaw tui
```

TUI 会先展示目标、检查模式、运行概览和安全边界，让你确认授权范围后再启动任务：

```text
VulnClaw TUI 工作台

授权目标        https://example.com
检查模式        快速摸底 / recon
运行概览        历史快照、风险数量、持久化约束、约束拦截
安全边界        仅测试端口 443，禁止 exploit/persistent/post_exploitation

1 设置授权目标
2 选择检查模式
3 设置测试范围
4 开始授权安全检查
8 模型/API 配置
```

常用启动方式：

```bash
vulnclaw tui
vulnclaw tui --target https://target.example --mode quick --only-port 443
vulnclaw tui --dry-run --target https://target.example --mode deep --only-path /admin
```

菜单 3 “设置测试范围”可编辑主机、端口、路径、排除项、允许动作和禁止动作；这些边界会进入启动前确认和实际任务命令。
菜单 7 “环境诊断入口”会在 TUI 内显示 Python、Node/npx/uvx/nmap、LLM 配置和 MCP 服务/工具摘要；需要完整详情时再运行 `vulnclaw doctor`。
菜单 8 “模型/API 配置”可直接切换 Provider、Base URL、Model 和 API Key，保存后工作台会立刻使用新配置。

### 方式三：经典 REPL 子命令

```bash
$ vulnclaw repl
```

进入经典 🦞 交互界面，用自然语言对话：

```
🦞 vulnclaw> 对 192.168.1.100 进行渗透测试，这是我授权的靶场

[*] 进入自主渗透模式，按 Ctrl+C 可随时中断
── Round 1 ──
  [+] 目标: 192.168.1.100
  [+] 开放端口: 22, 80, 443, 8080
  [+] Web 指纹: Apache/2.4.62
── Round 2 ──
  [+] 发现 /manager/html (Tomcat Manager)
  [+] 命中 CVE-202X-XXXX: Apache Tomcat 认证绕过
── Round 3 ──
  [+] 漏洞验证成功

🦞 192.168.1.100 | 报告> 生成渗透报告
[+] 报告已保存: ./reports/192.168.1.100_20260418.md
[+] PoC 脚本已保存: ./pocs/CVE-202X-XXXX.py
```

#### 经典 REPL 内置命令

| 命令                  | 说明                                       |
| --------------------- | ------------------------------------------ |
| `target <host>`       | 设置渗透测试目标                           |
| `status`              | 查看当前状态（目标、阶段、工具、推理显示） |
| `tools`               | 列出当前可用 MCP 工具                      |
| `think`               | 切换推理过程显示/隐藏                      |
| `think on` / `off`    | 精确控制推理过程显示                       |
| `persistent`          | 启动持续性渗透测试（100轮/周期，自动报告） |
| `persistent <host>`   | 对指定目标启动持续性渗透                   |
| `clear`               | 清空当前会话                               |
| `help`                | 显示帮助信息                               |
| `exit` / `quit` / `q` | 退出 VulnClaw                              |

#### 自主渗透模式

VulnClaw 检测到以下关键词 + 目标时，自动进入多轮自主渗透循环：

| 触发方式 | 示例 |
| -------- | ---- |
| 渗透指令 | `对 http://target.com 进行渗透测试` |
| CTF / 找 flag | `帮我对 http://ctf.site 找出flag` |
| 爆破 / 绕过 | `对 http://target.com 弱口令爆破` |
| **显式触发** | `目标：http://target.com，进入自主渗透模式` |

> 💡 在 REPL 中输入 `Ctrl+C` 可随时中断自主循环。切换目标时自动重置会话上下文。

### 方式二：单命令模式

```bash
# 一键全流程渗透测试
vulnclaw run 192.168.1.100

# 持续性渗透测试（每周期100轮，最多10周期，自动生成报告）
vulnclaw persistent 192.168.1.100

# 自定义周期参数
vulnclaw persistent 192.168.1.100 --rounds 200 --cycles 5

# 仅信息收集
vulnclaw recon 192.168.1.100

# 漏洞扫描（可指定端口）
vulnclaw scan 192.168.1.100 --ports 80,443,8080

# 漏洞利用（可指定 CVE）
vulnclaw exploit 192.168.1.100 --cve CVE-2024-1234 --cmd id

# 生成报告
vulnclaw report session.json
```

### 方式三：持续性渗透模式

适用于需要长时间深度渗透的场景。VulnClaw 以**周期循环**方式运行：

```
┌──────────────────────────────────────────────┐
│  Cycle 1 (100轮) → 自动报告 → 继续          │
│  Cycle 2 (100轮) → 自动报告 → 继续          │
│  Cycle 3 (100轮) → 自动报告 → 继续          │
│  ...                                         │
│  直到 Ctrl+C 或达到最大周期数（默认10）      │
└──────────────────────────────────────────────┘
```

**特点**：
- **跨周期状态保持** — 每个周期保留之前的所有发现、漏洞和步骤记录
- **周期报告** — 每个周期结束自动生成独立的 Markdown 报告（含新增漏洞和累计汇总）
- **灵活中断** — Ctrl+C 随时中断，中断时仍生成本周期报告
- **增量发现** — 报告区分"本周期新增"和"累计总计"，清晰追踪进展
- **可配置** — 每周期轮数、最大周期数、是否自动报告均可配置

```bash
# CLI 方式
vulnclaw persistent 192.168.1.100              # 默认 100轮/周期 × 10周期
vulnclaw persistent 192.168.1.100 -r 200 -c 5  # 200轮/周期 × 5周期
vulnclaw persistent 192.168.1.100 --no-report   # 不自动生成报告

# TUI 方式
vulnclaw tui --target 192.168.1.100 --mode continuous

# REPL 方式
🦞 vulnclaw> target 192.168.1.100
🦞 vulnclaw> persistent
# 或直接
🦞 vulnclaw> persistent 192.168.1.100
```

### 方式四：Web UI 模式

通过浏览器操作渗透测试全流程，适合偏好图形界面的用户。

```bash
# 安装 Web 依赖
pip install vulnclaw[web]

# 启动 Web UI（默认 127.0.0.1:7788）
vulnclaw web

# 自定义端口
vulnclaw web --port 8080

# 仅检查启动信息（不实际启动服务）
vulnclaw web --dry-run
```

启动后浏览器访问 `http://127.0.0.1:7788` 即可使用。

> ⚠️ 默认仅绑定本地回环地址。如需远程访问须显式指定 `--host 0.0.0.0 --allow-remote`，请确保网络环境安全。

---

## LLM 提供商配置

VulnClaw 支持所有 OpenAI 兼容协议的 API，内置 8 个提供商预设：

```bash
vulnclaw config provider --list    # 查看所有提供商
vulnclaw config provider minimax   # 一键切换
```

| 提供商      | 命令                   | 默认模型              |
| ----------- | ---------------------- | --------------------- |
| OpenAI      | `provider openai`      | gpt-4o                |
| MiniMax     | `provider minimax`     | MiniMax-M3            |
| DeepSeek    | `provider deepseek`    | deepseek-v4-pro       |
| 智谱 GLM    | `provider zhipu`       | glm-4.7               |
| Kimi        | `provider moonshot`    | kimi-k2.6             |
| 通义千问    | `provider qwen`        | qwen3-max             |
| SiliconFlow | `provider siliconflow` | DeepSeek-V4-Flash     |
| 豆包        | `provider doubao`      | Doubao-Seed-2.0-Pro   |
| 百川        | `provider baichuan`    | Baichuan4-Turbo       |
| 阶跃星辰    | `provider stepfun`     | step-3.5-flash        |
| 商汤        | `provider sensetime`   | SenseNova-6.7-Flash-Lite |
| 零一万物    | `provider yi`          | yi-lightning          |
| 自定义      | `provider custom`      | 手动填写              |

---

## 架构

```
┌─────────────────────────────────────────────┐
│                VulnClaw CLI                  │
│  ┌─────────┐  ┌─────────┐  ┌────────────┐  │
│  │  自然语言 │  │  任务编排 │  │ 报告 & PoC │  │
│  │  交互层  │  │  引擎    │  │   生成器   │  │
│  └────┬────┘  └────┬────┘  └─────┬──────┘  │
│       └─────────────┼─────────────┘        │
│               ┌─────▼──────┐                │
│               │ LLM Agent  │                │
│               │ (越狱+Skill)│               │
│               └─────┬──────┘                │
│               ┌─────▼──────┐                │
│               │ MCP 编排层  │                │
│               │ (11 服务)  │                │
│               └─────┬──────┘                │
│               ┌─────▼──────┐                │
│               │ 安全知识库  │                │
│               └────────────┘                │
└─────────────────────────────────────────────┘
```

### 核心模块

| 模块           | 文件                                             | 说明                                          |
| -------------- | ------------------------------------------------ | --------------------------------------------- |
| **CLI/TUI 入口** | `cli/main.py` + `cli/tui.py`                   | Typer 命令 + 默认原 CLI/REPL + 显式 TUI       |
| **Agent 核心** | `agent/core.py`                                  | AgentCore 协调入口（核心重构后主要保留少量协调职责） |
| **动态提示词** | `agent/prompts.py`                               | 基础身份 + 核心契约 + Skill + MCP 工具列表    |
| **Prompt 组装** | `agent/system_prompt.py` + `prompt_context.py`  | system prompt / round context / attack summary 组装 |
| **输入分析**   | `agent/input_analysis.py`                        | 目标识别、阶段识别、用户漏洞提示提取          |
| **反死循环 / CTF** | `agent/anti_loop.py` + `ctf_mode.py`        | 完成信号、攻击路径、失败目标、flag 状态机      |
| **会话状态**   | `agent/context.py`                               | 阶段追踪 + 漏洞发现 + 步骤记录                |
| **Skill / KB 上下文** | `agent/skill_context.py` + `kb_context.py` | Skill 选择与知识库 prompt 注入                |
| **目标状态继承** | `target_state/store.py`                        | 同目标成果沉淀、恢复、快照、回滚、target 报告 |
| **MCP 编排**   | `mcp/registry.py` + `lifecycle.py` + `router.py` | 服务注册 + 生命周期 + 自然语言→工具路由       |
| **Skill 调度** | `skills/loader.py` + `dispatcher.py`             | 目录格式 Skill + 16 种意图动态调度            |
| **编解码工具** | `skills/crypto_tools.py`                         | 29 种编解码/加解密操作，注册为内置 Agent 工具  |
| **配置管理**   | `config/schema.py` + `settings.py`               | Pydantic 模型 + YAML 持久化 + 8 Provider 预设 |
| **报告生成**   | `report/generator.py` + `poc_builder.py`         | Markdown 报告 + Python PoC 模板               |
| **安全知识库** | `kb/store.py` + `retriever.py`                   | JSON 存储 + CVE/技术/工具检索                 |

---

## MCP 工具链

| MCP 服务            | 工具数 | 用途                   | 优先级 |
| ------------------- | ------ | ---------------------- | ------ |
| fetch               | 1      | HTTP 请求、API 测试    | P0     |
| memory              | 2      | 上下文记忆、状态持久化 | P0     |
| chrome-devtools     | 4      | 浏览器自动化           | P0     |
| js-reverse          | 2      | JS 逆向工程            | P0     |
| burp                | 2      | HTTP 抓包、重放        | P0     |
| frida-mcp           | 2      | 移动端 Hook            | P1     |
| adb-mcp             | 3      | 安卓设备控制           | P1     |
| jadx                | 2      | APK 反编译             | P1     |
| ida-pro-mcp         | 2      | 二进制逆向             | P1     |
| sequential-thinking | 1      | 复杂推理链             | P1     |
| context7            | 1      | 代码上下文检索         | P1     |
| everything-search   | 1      | 本地文件搜索           | P2     |

> 共 12 个 MCP 服务、23 个工具定义。另有 3 个内置 Agent 工具（`load_skill_reference` + `crypto_decode` + `python_execute`），无需 MCP 即可调用。
>
> 当前 `fetch` / `memory` 以 `local` 模式稳定运行；其余服务多为 `preview / placeholder`。后续会通过独立的 session 生命周期管理层逐步恢复并扩展真实 MCP 协议接入。

---

## 内置 Skill

### 核心 Skill (7)

| Skill             | 说明               |
| ----------------- | ------------------ |
| pentest-flow      | 渗透测试全流程编排 |
| recon             | 信息收集流程       |
| vuln-discovery    | 漏洞发现流程       |
| exploitation      | 漏洞利用流程       |
| post-exploitation | 后渗透流程         |
| reporting         | 报告生成流程       |
| waf-bypass        | WAF 绕过技巧库     |

### 专项 Skill (12)

| Skill                     | 参考文档数 | 说明                                         |
| ------------------------- | ---------- | -------------------------------------------- |
| web-pentest               | 4          | Web 应用渗透                                 |
| android-pentest           | 9          | 安卓应用渗透                                 |
| client-reverse            | 20         | 客户端逆向分析                               |
| web-security-advanced     | 33         | Web 安全进阶（注入、绕过、利用链）           |
| ai-mcp-security           | 7          | AI/MCP 安全测试                              |
| intranet-pentest-advanced | 15         | 内网渗透进阶                                 |
| pentest-tools             | 18         | 渗透工具速查                                 |
| rapid-checklist           | 3          | 快速检查清单                                 |
| crypto-toolkit            | 3          | 编解码/加解密（29 种操作，注册为内置工具）   |
| **ctf-web**               | 8          | CTF Web 攻击知识库（PHP绕过/RCE/SSTI/反序列化） |
| **ctf-crypto**            | 6          | CTF 密码学攻击知识库（RSA/AES/ECC/PRNG/格攻击） |
| **ctf-misc**              | 6          | CTF 杂项知识库（PyJail/BashJail/编码链/VM逆向） |
| **osint-recon**           | 7          | OSINT 开源情报收集（四维模型：服务器/网站/域名/人员） |

Skill 会根据用户输入自动调度，无需手动选择。专项 Skill 含 `references/` 目录下的详细方法论文档，LLM 可通过 `load_skill_reference` 工具按需加载。

### 内置编解码/加解密工具 (crypto_decode)

`crypto_decode` 注册为 Agent 内置工具，LLM 在任何上下文中均可调用，不再靠猜测解码结果：

| 类别     | 操作                                                                                     |
| -------- | ---------------------------------------------------------------------------------------- |
| 编解码   | base64, base32, base58, hex, url, html, unicode, rot13, caesar, morse（各有 encode/decode） |
| 哈希     | md5, sha1, sha256, sha512                                                                |
| 加解密   | aes_encrypt, aes_decrypt（CBC 模式，PKCS7 填充）                                          |
| JWT      | jwt_decode, jwt_encode                                                                   |
| 自动识别 | auto_decode — 尝试所有常见编码，返回匹配结果                                              |

---

## 配置管理

### 命令行配置

```bash
vulnclaw config list                          # 查看所有配置
vulnclaw config get llm.model                 # 查看单项
vulnclaw config set llm.api_key sk-xx         # 设置 API Key
vulnclaw config set session.max_rounds 30     # 设置自主渗透最大轮数（默认 15）
vulnclaw config set session.stale_rounds_threshold 8  # 设置死循环检测阈值（默认 5）
vulnclaw config set session.show_thinking false # 隐藏推理过程（也可在 REPL 中用 think off）
```

### 可配置项

| 配置项                   | 默认值 | 说明                                     |
| ------------------------ | ------ | ---------------------------------------- |
| `llm.provider`           | openai | LLM 提供商（8 个内置 + custom）          |
| `llm.api_key`            | 空     | API Key                                  |
| `llm.base_url`           | 按 provider | API 基础 URL，可自定义              |
| `llm.model`              | 按 provider | 模型名称，可自定义                   |
| `llm.temperature`        | 0.1    | 采样温度                                 |
| `llm.max_tokens`         | 4096   | 单次最大输出 token                       |
| `session.max_rounds`     | 15     | 自主渗透循环最大轮数（建议 10-50）       |
| `session.output_dir`     | ./vulnclaw-output | 报告输出目录                    |
| `session.report_format`  | markdown | 报告格式（markdown / html）            |
| `session.poc_language`   | python | PoC 生成语言（python / bash）            |
| `session.show_thinking`  | false  | 显示 LLM 推理过程（think 标签内容，默认关闭） |
| `session.persistent_rounds_per_cycle` | 100 | 持续性渗透每周期轮数 |
| `session.persistent_max_cycles` | 10 | 持续性渗透最大周期数（0=无限） |
| `session.persistent_auto_report` | true | 持续性渗透每周期自动生成报告 |
| `session.stale_rounds_threshold` | 5 | 死循环检测阈值 — 连续无新发现轮数达到此值时触发强制策略切换 |

### 环境变量

| 变量                          | 说明                   |
| ----------------------------- | ---------------------- |
| `VULNCLAW_LLM_PROVIDER`       | LLM 提供商名称         |
| `VULNCLAW_LLM_API_KEY`        | API Key                |
| `VULNCLAW_LLM_BASE_URL`       | API 基础 URL           |
| `VULNCLAW_LLM_MODEL`          | 模型名称               |
| `VULNCLAW_SESSION__MAX_ROUNDS`| 自主渗透最大轮数       |
| `VULNCLAW_SESSION__STALE_ROUNDS_THRESHOLD` | 死循环检测阈值 |

优先级：**环境变量 > 配置文件 > 内置默认值**

配置文件位于 `~/.vulnclaw/config.yaml`。

---

## 安全声明

VulnClaw 仅用于**已授权的安全测试**。使用本工具前，请确保：

1. 你已获得目标系统的**明确授权**
2. 测试范围已与目标所有者**书面确认**
3. 你遵守当地**法律法规**

未经授权对系统进行渗透测试是违法行为。本工具作者不对滥用行为承担责任。

---

## 许可证

[MIT License](LICENSE)

---

## 加入社区

与更多安全爱好者一起交流、分享与成长

| 社区交流群 | 开发者群聊 |
|:--:|:--:|
| 欢迎加入讨论分享，获取最新产品动态与使用技巧 | 加入我们，参与开源贡献与技术深度探讨 |
| ![VulnClaw 社区交流群](assets/社区交流群.jpg) | ![VulnClaw 开发者群聊](assets/VulnClaw开发者群聊.png) |
| **QQ 群号：954402631** | **QQ 群号：1065858551** |

---

<div align="center">

> 🦞 **VulnClaw** — 让每一次渗透都有章可循。

</div>

