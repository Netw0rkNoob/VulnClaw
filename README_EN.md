<div align="center">

# VulnClaw 🦞

> *AI-Powered Penetration Testing CLI — Speak plainly, find real bugs.*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![OpenAI Compatible](https://img.shields.io/badge/API-OpenAI_Compatible-green)](https://platform.openai.com/)
[![MCP](https://img.shields.io/badge/Toolchain-MCP-orange)](https://modelcontextprotocol.io/)
[![PyPI](https://img.shields.io/badge/PyPI-v0.3.0-blueviolet)](https://pypi.org/project/vulnclaw/)
[![Security](https://img.shields.io/badge/Scope-Authorized_Only-red)](#-security-notice)
<br>

**This project is a standalone AI penetration testing Agent.**

<br>

Built on LLM Agent + MCP Toolchain + Pentest Skill orchestration,
compatible with OpenAI / MiniMax / DeepSeek and similar models.
Natural language input → automated "Recon → Vulnerability Discovery → Exploitation → Reporting".

[Quick Start](#quick-start) · [Architecture](#-architecture) · [Skills](#-built-in-skills)

</div>

---

## What It Does

Give it a natural language command and watch it run a full pentest:

```
User:   "Run a penetration test on http://target.example.com"

VulnClaw executes:
  Round 1:  Recon → Fingerprinting, port scan, directory enumeration
  Round 2:  Vulnerability Discovery → Injection points, known CVEs, misconfigs
  Round 3:  Exploitation → PoC verification, access obtained
  Round 4:  Reporting → Structured report + Python PoC script
```

<img width="1148" height="642" alt="image" src="https://github.com/user-attachments/assets/576e1cf6-25da-4969-864b-40e77d020dbf" />

Suitable for authorized pentests, CTF competitions, security training, and red team operations.

---

## Features

- **Natural Language Driven** — Describe your intent in plain English, it auto-identifies phases and tools
- **8 LLM Providers** — OpenAI / MiniMax / DeepSeek / Zhipu / Moonshot / Qwen / SiliconFlow, one-command switch
- **MCP Toolchain** — Ships with 11 MCP service configs and 23 tool definitions; `fetch` / `memory` currently run in stable `local` mode, while most other MCP integrations remain preview or placeholder until full session lifecycle management is completed
- **AI Agent Core** — OpenAI-compatible protocol + Tool Calling + autonomous pentest loop
- **20 Pentest Skills** — 7 core + 13 specialized skills (incl. CTF Web/Crypto/Misc + osint-recon), 138 reference documents
- **Encode/Decode & Crypto Tools** — 29 operations (Base64/Hex/URL/AES/JWT/Morse etc.), LLM calls them directly, no guessing
- **Python Code Execution** — Built-in `python_execute` tool for payload crafting and response parsing; currently still a high-risk experimental capability, not a strong isolation sandbox
- **Persistent Pentesting** — Cyclic runs (100 rounds/cycle × 10 cycles = 1000 rounds), auto-reports every cycle, runs until you stop it
- **Thinking Process Control** — `think on/off` toggles LLM reasoning visibility, off by default for clean output
- **Sandbox Mode Prompting** — Unlocks AI security testing capabilities, designed for CTF and authorized pentest scenarios
- **Auto Report & PoC** — Generates structured Markdown reports and runnable Python PoC scripts
- **Web UI Mode** — `vulnclaw web` launches a local web interface for browser-based pentest operations, default `127.0.0.1:7788`
- **Security Knowledge Base** — Includes the KB module and baseline seed data today; retrieval augmentation is being integrated into the main workflow incrementally

---

## Quick Start

### Installation

```bash
# Install from PyPI (recommended)
pip install vulnclaw

# Install from source
git clone https://github.com/Unclecheng-li/VulnClaw.git
cd VulnClaw
pip install -e .
```

### Four-Step Launch

```bash
# 1. Select provider (auto-fills Base URL and model name)
vulnclaw config provider minimax   # or openai / deepseek / zhipu / moonshot / qwen / siliconflow

# 1.2 (optional) custom Base URL or model name
vulnclaw config set llm.base_url https://your-own-api.example.com/v1
vulnclaw config set llm.model your-model-name

# 2. Set API Key
vulnclaw config set llm.api_key sk-your-key-here

# 3. Default: open the original CLI / REPL
vulnclaw

# 4. Optional: open the TUI workbench
vulnclaw tui
```

### Environment Check

```bash
vulnclaw doctor
```

Sample output:

```
🦞 VulnClaw Environment Check

  Python: 3.14.4
  Node.js: v24.14.1
  npx: installed
  nmap: installed

LLM Config:
  Provider: openai
  API Key: set
  Base URL: https://api.openai.com/v1
  Model: gpt-4o

MCP Services:
  fetch: enabled [P0]
  memory: enabled [P0]
  ...

✅ Ready. Run vulnclaw to start.
```

---

## CLI Command Reference

Run `vulnclaw --help` to see all available commands:

```bash
$ vulnclaw --help

🦞 VulnClaw — AI-powered penetration testing CLI

 Usage: vulnclaw [OPTIONS] COMMAND [ARGS]...

 Options:
   --version  Show version and exit.
   --help     Show this message and exit.

 Commands:
   run           🚀 Full pentest in one shot
   persistent    🔄 Persistent pentesting (100 rounds/cycle)
   recon         🔍 Reconnaissance only (no exploitation)
   scan          🔎 Vulnerability scanning
   exploit       💥 Exploitation phase
   report        📝 Generate report from session JSON
   repl          💬 Start the classic REPL
   config        ⚙️  Manage config (set/get/list/provider)
   init          🔧 Initialize configuration
   doctor        🏥  Check runtime environment
   tui           🖥️  Open the terminal UI workbench
   web           🌐 Launch local Web UI
```

### Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `vulnclaw` | Open the original CLI / REPL by default | `vulnclaw` |
| `vulnclaw tui` | Explicitly open the terminal UI workbench | `vulnclaw tui` / `vulnclaw tui --target target.com` |
| `vulnclaw repl` | Start the classic REPL interactive shell | `vulnclaw repl` |
| `vulnclaw run <target>` | Full pentest in one shot | `vulnclaw run 192.168.1.1` |
| `vulnclaw persistent <target>` | Persistent pentesting | `vulnclaw persistent 192.168.1.1` |
| `vulnclaw recon <target>` | Reconnaissance only | `vulnclaw recon target.com` |
| `vulnclaw scan <target>` | Vulnerability scanning | `vulnclaw scan target.com --ports 80,443` |
| `vulnclaw exploit <target>` | Exploitation phase | `vulnclaw exploit target.com --cve CVE-2024-1234` |
| `vulnclaw report <session>` | Generate report from session | `vulnclaw report session_xxx.json` |
| `vulnclaw config set <key> <value>` | Set a config value | `vulnclaw config set llm.api_key sk-xxx` |
| `vulnclaw config get <key>` | View a config value | `vulnclaw config get llm.model` |
| `vulnclaw config list` | List all config | `vulnclaw config list` |
| `vulnclaw config provider <name>` | Switch LLM provider | `vulnclaw config provider deepseek` |
| `vulnclaw init` | Initialize config files | `vulnclaw init` |
| `vulnclaw doctor` | Check runtime environment | `vulnclaw doctor` |
| `vulnclaw web` | Launch local Web UI | `vulnclaw web` / `vulnclaw web --port 8080` |

### TUI Workbench

`vulnclaw tui` is the optional terminal UI workbench entry. It shows the authorized target, check mode, runtime overview, safety boundary, command preview, target history, report entry, and inline environment diagnostics before a task starts.

```bash
vulnclaw tui
vulnclaw tui --target https://target.example --mode quick --only-port 443
vulnclaw tui --dry-run --target https://target.example --mode deep --only-path /admin
```

The default `vulnclaw` command still opens the original CLI / REPL. The TUI opens only when users explicitly run `vulnclaw tui`.
The runtime overview reads the selected target's snapshots, finding counts, persisted constraints, and blocked constraint violations so users can confirm context before continuing.
The TUI "Set testing scope" flow can edit allowed actions and blocked actions directly, for example allowing only `recon,scan` or blocking `exploit,post_exploitation`.

### Provider Configuration

```bash
# List all providers and switch
vulnclaw config provider --list    # list all available providers
vulnclaw config provider minimax   # switch to MiniMax

# Manual setup (custom mode)
vulnclaw config set llm.base_url https://your-api.com/v1
vulnclaw config set llm.model your-model-name
vulnclaw config set llm.api_key sk-your-key
```

---

## Usage

### Mode 1: Original CLI / REPL Interactive Mode (Default)

```bash
$ vulnclaw
```

No-args startup opens the original 🦞 interactive shell for natural-language use:

```text
🦞 vulnclaw> pentest 192.168.1.100 — this is my authorized lab

[*] Entering autonomous pentest mode. Press Ctrl+C to interrupt at any time.
── Round 1 ──
  [+] Target: 192.168.1.100
  [+] Open ports: 22, 80, 443, 8080
```

### Mode 2: TUI Workbench (Explicit)

```bash
$ vulnclaw tui
```

The TUI shows target, mode, runtime overview, and safety boundary before launching a task:

```text
VulnClaw TUI Workbench

Authorized target    https://example.com
Check mode           Quick recon / recon
Runtime overview     history snapshots, findings, persisted constraints
Safety boundary      only port 443, block exploit/persistent/post_exploitation

1 Set authorized target
2 Choose check mode
3 Set testing scope
4 Start authorized security check
8 Model/API settings
```

Common launch examples:

```bash
vulnclaw tui
vulnclaw tui --target https://target.example --mode quick --only-port 443
vulnclaw tui --dry-run --target https://target.example --mode deep --only-path /admin
```

Menu item 3, "Set testing scope", edits host, port, path, exclusions, allowed actions, and blocked actions. These boundaries are shown in the pre-launch confirmation and passed into the actual task command.
Menu item 7, "Environment diagnostics", shows Python, Node/npx/uvx/nmap, LLM configuration, and MCP service/tool summaries inside the TUI. Run `vulnclaw doctor` only when you need the full details.
Menu item 8, "Model/API settings", switches Provider, Base URL, Model, and API Key directly in the workbench. Saved changes are used by the current TUI session immediately.

### Mode 3: Classic REPL Subcommand

```bash
$ vulnclaw repl
```

Enter the classic 🦞 interactive shell and chat in natural language:

```
🦞 vulnclaw> pentest 192.168.1.100 — this is my authorized lab

[*] Entering autonomous pentest mode. Press Ctrl+C to interrupt at any time.
── Round 1 ──
  [+] Target: 192.168.1.100
  [+] Open ports: 22, 80, 443, 8080
  [+] Web fingerprint: Apache/2.4.62
── Round 2 ──
  [+] Discovered /manager/html (Tomcat Manager)
  [+] Matched CVE-202X-XXXX: Apache Tomcat Auth Bypass
── Round 3 ──
  [+] Vulnerability verified

🦞 192.168.1.100 | report> generate pentest report
[+] Report saved: ./reports/192.168.1.100_20260418.md
[+] PoC saved: ./pocs/CVE-202X-XXXX.py
```

#### Classic REPL Built-in Commands

| Command             | Description                                             |
| ------------------- | ------------------------------------------------------- |
| `target <host>`     | Set pentest target                                      |
| `status`            | View current state (target, phase, tools, thinking)    |
| `tools`             | List available MCP tools                               |
| `think`             | Toggle thinking process display                         |
| `think on` / `off`  | Explicitly control thinking visibility                  |
| `persistent`        | Start persistent pentesting (100 rounds/cycle)         |
| `persistent <host>` | Start persistent pentest on a target                   |
| `clear`             | Clear current session                                  |
| `help`              | Show help                                              |
| `exit` / `quit` / `q` | Exit VulnClaw                                       |

#### Autonomous Pentest Mode

VulnClaw auto-enters multi-round autonomous loop when it detects these keywords + a target:

| Trigger               | Example                                             |
| --------------------- | --------------------------------------------------- |
| Pentest command       | `pentest http://target.com`                        |
| CTF / find flag      | `find the flag on http://ctf.site`                |
| Brute / bypass       | `bruteforce weak credentials on http://target.com` |
| **Explicit**          | `target: http://target.com, enter autonomous mode` |

> 💡 Press `Ctrl+C` to interrupt the autonomous loop at any time. Switching targets automatically resets session context.

### Mode 2: Single Command

```bash
# Full pentest in one shot
vulnclaw run 192.168.1.100

# Persistent pentesting (100 rounds/cycle × 10 cycles, auto-report)
vulnclaw persistent 192.168.1.100

# Custom cycle parameters
vulnclaw persistent 192.168.1.100 --rounds 200 --cycles 5

# Recon only
vulnclaw recon 192.168.1.100

# Vulnerability scan (specify ports)
vulnclaw scan 192.168.1.100 --ports 80,443,8080

# Exploitation (specify CVE)
vulnclaw exploit 192.168.1.100 --cve CVE-2024-1234 --cmd id

# Generate report
vulnclaw report session.json
```

### Mode 3: Persistent Pentest

For long-running deep penetration. VulnClaw runs in **cyclic loops**:

```
┌──────────────────────────────────────────────┐
│  Cycle 1 (100 rounds) → auto-report → continue │
│  Cycle 2 (100 rounds) → auto-report → continue │
│  Cycle 3 (100 rounds) → auto-report → continue │
│  ...                                             │
│  Until Ctrl+C or max cycles reached (default 10) │
└──────────────────────────────────────────────┘
```

**Features**:
- **Cross-cycle state** — Each cycle preserves all previous findings, vulnerabilities, and step records
- **Cycle reports** — Auto-generates independent Markdown report per cycle (new findings + cumulative summary)
- **Graceful interrupt** — Ctrl+C at any time still generates the current cycle's report
- **Incremental discovery** — Reports distinguish "new this cycle" from "cumulative total"
- **Fully configurable** — Rounds per cycle, max cycles, auto-report toggle all customizable

```bash
# CLI mode
vulnclaw persistent 192.168.1.100              # default: 100 rounds/cycle × 10 cycles
vulnclaw persistent 192.168.1.100 -r 200 -c 5  # 200 rounds/cycle × 5 cycles
vulnclaw persistent 192.168.1.100 --no-report   # disable auto-report

# TUI mode
vulnclaw tui --target 192.168.1.100 --mode continuous

# REPL mode
🦞 vulnclaw> target 192.168.1.100
🦞 vulnclaw> persistent
# or directly
🦞 vulnclaw> persistent 192.168.1.100
```

### Mode 4: Web UI

Operate the full pentest workflow through a browser — ideal for users who prefer a graphical interface.

```bash
# Install Web dependencies
pip install vulnclaw[web]

# Launch Web UI (default: 127.0.0.1:7788)
vulnclaw web

# Custom port
vulnclaw web --port 8080

# Dry-run (validate launch info without starting the server)
vulnclaw web --dry-run
```

Once launched, open `http://127.0.0.1:7788` in your browser.

> ⚠️ By default the server binds to localhost only. To allow remote access you must explicitly pass `--host 0.0.0.0 --allow-remote` — make sure your network is secure.

---

## LLM Provider Configuration

VulnClaw supports all OpenAI-compatible APIs with 8 built-in provider presets:

```bash
vulnclaw config provider --list    # list all providers
vulnclaw config provider minimax   # one-command switch
```

| Provider     | Command                  | Default Model          |
| ------------ | ------------------------ | ---------------------- |
| OpenAI      | `provider openai`        | gpt-4o                 |
| MiniMax     | `provider minimax`       | MiniMax-M3             |
| DeepSeek    | `provider deepseek`      | deepseek-v4-pro        |
| Zhipu GLM   | `provider zhipu`         | glm-4.7                |
| Kimi        | `provider moonshot`      | kimi-k2.6              |
| Qwen        | `provider qwen`          | qwen3-max              |
| SiliconFlow | `provider siliconflow`   | DeepSeek-V4-Flash      |
| Doubao      | `provider doubao`        | Doubao-Seed-2.0-Pro    |
| Baichuan    | `provider baichuan`      | Baichuan4-Turbo        |
| StepFun     | `provider stepfun`       | step-3.5-flash         |
| SenseTime   | `provider sensetime`     | SenseNova-6.7-Flash-Lite |
| Yi          | `provider yi`            | yi-lightning           |
| Custom      | `provider custom`        | manual                 |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│                   VulnClaw CLI                   │
│  ┌─────────┐  ┌─────────┐  ┌────────────┐  │
│  │ Natural  │  │  Task   │  │  Report    │  │
│  │ Language │  │Orchestr.│  │ & PoC Gen  │  │
│  │Interface │  │ Engine  │  │            │  │
│  └────┬────┘  └────┬────┘  └─────┬──────┘  │
│       └─────────────┼─────────────┘          │
│               ┌─────▼──────┐                 │
│               │ LLM Agent  │                 │
│               │(Jailbreak+  │                 │
│               │  Skills)    │                 │
│               └─────┬──────┘                 │
│               ┌─────▼──────┐                 │
│               │ MCP Layer  │                 │
│               │ (11 Svcs)  │                 │
│               └─────┬──────┘                 │
│               ┌─────▼──────┐                 │
│               │ Security    │                 │
│               │ Knowledge   │                 │
│               └────────────┘                 │
└─────────────────────────────────────────────┘
```

### Core Modules

| Module              | File                                                  | Description                                        |
| ------------------- | ----------------------------------------------------- | -------------------------------------------------- |
| **CLI/TUI Entry**   | `cli/main.py` + `cli/tui.py`                         | Typer commands + default original CLI/REPL + explicit TUI |
| **Agent Core**      | `agent/core.py`                                      | AgentCore coordination entrypoint (after the refactor it mainly keeps thin coordination responsibilities) |
| **Dynamic Prompts** | `agent/prompts.py`                                   | Base identity + core contract + skills + MCP tools  |
| **Prompt Assembly** | `agent/system_prompt.py` + `prompt_context.py`       | System prompt / round context / attack summary assembly |
| **Input Analysis**  | `agent/input_analysis.py`                            | Target detection, phase detection, explicit vuln-hint extraction |
| **Anti-loop / CTF** | `agent/anti_loop.py` + `ctf_mode.py`                | Completion signals, attack-path heuristics, failed-target tracking, flag state machine |
| **Session State**   | `agent/context.py`                                   | Phase tracking + findings + step records            |
| **Skill / KB Context** | `agent/skill_context.py` + `kb_context.py`       | Skill selection and knowledge-base prompt injection |
| **Target State**    | `target_state/store.py`                              | Per-target persistence, resume, snapshots, rollback, target-level reports |
| **MCP Orchestration**| `mcp/registry.py` + `lifecycle.py` + `router.py`    | Service registry + lifecycle + NL→tool routing     |
| **Skill Dispatcher** | `skills/loader.py` + `dispatcher.py`               | Directory-format Skills + 16-intent dynamic routing |
| **Crypto Tools**    | `skills/crypto_tools.py`                             | 29 encode/decode/crypto ops, registered as built-in tools |
| **Config**          | `config/schema.py` + `settings.py`                   | Pydantic models + YAML persistence + 8 provider presets |
| **Report Generator** | `report/generator.py` + `poc_builder.py`          | Markdown reports + Python PoC templates             |
| **Security KB**     | `kb/store.py` + `retriever.py`                     | JSON storage + CVE/technique/tool retrieval        |

---

## MCP Toolchain

| MCP Service         | Tools | Use Case                    | Priority |
| ------------------- | ----- | ---------------------------- | ------- |
| fetch              | 1     | HTTP requests, API testing    | P0      |
| memory             | 2     | Context memory, state persist | P0      |
| chrome-devtools    | 4     | Browser automation            | P0      |
| js-reverse         | 2     | JavaScript reversing          | P0      |
| burp               | 2     | HTTP interception & replay    | P0      |
| frida-mcp          | 2     | Mobile Hook                   | P1      |
| adb-mcp            | 3     | Android device control        | P1      |
| jadx               | 2     | APK decompilation             | P1      |
| ida-pro-mcp        | 2     | Binary reversing              | P1      |
| sequential-thinking| 1     | Complex reasoning chains       | P1      |
| context7           | 1     | Code context retrieval        | P1      |
| everything-search   | 1     | Local file search             | P2      |

> 11 MCP services, 23 tool definitions total. Plus 3 built-in Agent tools (`load_skill_reference` + `crypto_decode` + `python_execute`) callable without MCP.
>
> `fetch` / `memory` currently run in stable `local` mode; most other services remain `preview / placeholder`. Full MCP protocol access will be restored and expanded after a dedicated session lifecycle manager is introduced.

---

## Built-in Skills

### Core Skills (7)

| Skill              | Description                         |
| ------------------ | ----------------------------------- |
| pentest-flow       | Full pentest workflow orchestration  |
| recon              | Information gathering               |
| vuln-discovery     | Vulnerability discovery              |
| exploitation       | Exploitation                       |
| post-exploitation  | Post-exploitation                  |
| reporting          | Report generation                  |
| waf-bypass        | WAF bypass techniques              |

### Specialized Skills (13)

| Skill                      | Ref Docs | Description                                          |
| -------------------------- | -------- | ---------------------------------------------------- |
| web-pentest                | 4        | Web application pentesting                            |
| android-pentest            | 9        | Android application pentesting                        |
| client-reverse            | 20       | Client-side reverse engineering                      |
| web-security-advanced      | 33       | Advanced web security (injection, bypass, chains)     |
| ai-mcp-security            | 7        | AI/MCP security testing                              |
| intranet-pentest-advanced  | 15       | Advanced internal network pentesting                  |
| pentest-tools              | 18       | Pentest tool quick reference                         |
| rapid-checklist            | 3        | Rapid validation checklists                          |
| crypto-toolkit             | 3        | Encode/decode/crypto (29 ops, registered as built-in)|
| ctf-web                   | 8        | CTF Web attacks (PHP bypass/RCE/SSTI/deserialization)|
| ctf-crypto                | 6        | CTF cryptography (RSA/AES/ECC/PRNG/lattice attacks)  |
| ctf-misc                  | 6        | CTF Misc (PyJail/BashJail/encoding chains/VM RE)    |
| osint-recon               | 7        | OSINT four-dimension model (server/web/domain/person)|

Skills are auto-dispatched based on user input — no manual selection needed. Specialized skills include detailed methodology documents in `references/`, loadable via the `load_skill_reference` tool.

### Built-in Encode/Decode & Crypto Tool (`crypto_decode`)

Registered as a built-in Agent tool, callable in any context — no more guessing at decoded output:

| Category  | Operations                                                                                   |
| --------- | -------------------------------------------------------------------------------------------- |
| Encoding  | base64, base32, base58, hex, url, html, unicode, rot13, caesar, morse (each with encode/decode) |
| Hashing   | md5, sha1, sha256, sha512                                                                   |
| Encrypt   | aes_encrypt, aes_decrypt (CBC mode, PKCS7 padding)                                          |
| JWT       | jwt_decode, jwt_encode                                                                      |
| Auto      | auto_decode — tries all common encodings, returns matching results                            |

---

## Configuration

### CLI Configuration

```bash
vulnclaw config list                          # view all settings
vulnclaw config get llm.model                 # view single setting
vulnclaw config set llm.api_key sk-xx         # set API key
vulnclaw config set session.max_rounds 30     # set max autonomous rounds (default 15)
vulnclaw config set session.stale_rounds_threshold 8  # set dead-loop threshold (default 5)
vulnclaw config set session.show_thinking false  # hide thinking process (also in REPL: think off)
```

### Configurable Options

| Option                                  | Default        | Description                                      |
| --------------------------------------- | -------------- | ------------------------------------------------ |
| `llm.provider`                         | openai         | LLM provider (8 built-in + custom)              |
| `llm.api_key`                          | empty          | API key                                          |
| `llm.base_url`                         | per provider   | API base URL, customizable                       |
| `llm.model`                            | per provider   | Model name, customizable                        |
| `llm.temperature`                      | 0.1            | Sampling temperature                             |
| `llm.max_tokens`                       | 4096           | Max output tokens per call                       |
| `session.max_rounds`                    | 15             | Max rounds per autonomous pentest (10-50 recommended)|
| `session.output_dir`                    | ./vulnclaw-output | Report output directory                    |
| `session.report_format`                  | markdown       | Report format (markdown / html)                |
| `session.poc_language`                  | python         | PoC generation language (python / bash)          |
| `session.show_thinking`                 | false          | Show LLM reasoning (think tag content, default off)|
| `session.persistent_rounds_per_cycle`   | 100            | Rounds per cycle in persistent mode              |
| `session.persistent_max_cycles`        | 10             | Max cycles in persistent mode (0=unlimited)     |
| `session.persistent_auto_report`        | true           | Auto-generate report after each cycle            |
| `session.stale_rounds_threshold`        | 5              | Dead-loop threshold — triggers forced strategy switch after this many rounds with no new findings |

### Environment Variables

| Variable                                        | Description              |
| ----------------------------------------------- | ---------------------- |
| `VULNCLAW_LLM_PROVIDER`                       | LLM provider name      |
| `VULNCLAW_LLM_API_KEY`                        | API key                |
| `VULNCLAW_LLM_BASE_URL`                       | API base URL           |
| `VULNCLAW_LLM_MODEL`                          | Model name             |
| `VULNCLAW_SESSION__MAX_ROUNDS`                | Max autonomous rounds  |
| `VULNCLAW_SESSION__STALE_ROUNDS_THRESHOLD`    | Dead-loop threshold    |

Priority: **Environment Variables > Config File > Built-in Defaults**

Config file location: `~/.vulnclaw/config.yaml`.

---

## Security Notice

VulnClaw is intended **solely for authorized security testing**. Before using this tool, ensure:

1. You have **explicit authorization** for the target system
2. Scope has been **confirmed in writing** with the target owner
3. You comply with all applicable **local laws and regulations**

Unauthorized penetration testing is illegal. The author assumes no liability for misuse.

---

## License

[MIT License](LICENSE)

---

## Join the Community

Connect with security enthusiasts to share, learn, and grow together.

| Community Group | Developer Group |
|:--:|:--:|
| Join discussions and get the latest product updates and usage tips | Join us for open-source contributions and deep technical discussions |
| ![VulnClaw Community Group](assets/社区交流群.jpg) | ![VulnClaw Developer Group](assets/VulnClaw开发者群聊.png) |
| **QQ Group: 954402631** | **QQ Group: 1065858551** |

---

<div align="center">

> 🦞 **VulnClaw** — Every pentest should follow a process.

</div>
