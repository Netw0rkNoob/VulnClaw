# Contributing to VulnClaw

感谢你为 VulnClaw 做贡献。

这份文档的目标不是规定繁琐流程，而是帮助你快速理解当前代码结构，尽量在正确的层次修改代码，减少“功能能跑，但架构越来越乱”的情况。

---

## 项目结构

```text
VulnClaw/
|-- vulnclaw/
|   |-- __init__.py              # 包版本与基础元数据
|   |-- orchestrator.py          # CLI / Web 共享任务编排入口
|   |-- repl_runner.py           # REPL 共享执行辅助
|   |-- agent/                   # Agent 核心逻辑
|   |   |-- core.py              # AgentCore 壳层与协调入口
|   |   |-- llm_client.py        # LLM 调用、重试、工具总结回传
|   |   |-- tool_call_manager.py # tool-call 去重、执行、结果封装
|   |   |-- builtin_tools.py     # python_execute / nmap_scan / MCP 桥接
|   |   |-- context.py           # 会话状态、finding、步骤、生命周期状态
|   |   |-- runtime_state.py     # 运行时循环状态
|   |   |-- loop_controller.py   # auto / persistent 主循环
|   |   |-- finding_parser.py    # finding 提取、证据等级与生命周期归类
|   |   |-- prompt_context.py    # 回合上下文与攻击摘要
|   |   |-- prompts.py           # prompt 构建辅助
|   |   |-- system_prompt.py     # 动态 system prompt 组合
|   |   |-- input_analysis.py    # 目标、阶段、漏洞提示提取
|   |   |-- anti_loop.py         # 防死循环、失败目标、攻击路径跟踪
|   |   |-- recon_tracker.py     # recon 维度完成度追踪
|   |   |-- ctf_mode.py          # CTF flag 识别与验证
|   |   |-- skill_context.py     # Skill 上下文选择
|   |   |-- kb_context.py        # 知识库上下文注入
|   |   `-- think_filter.py      # think 标签显示与隐藏
|   |-- cli/
|   |   |-- main.py              # CLI 命令、doctor、web 启动、target-state CLI
|   |   |-- tui.py               # Rich 版 TUI（回退用）
|   |   |-- repl.py              # REPL 交互逻辑
|   |   |-- textui/              # Textual 版 TUI
|   |   |   |-- app.py           # VulnClawApp 应用入口
|   |   |   |-- screens/
|   |   |   |   `-- main.py      # Dashboard 主屏幕（侧边栏 + ContentSwitcher）
|   |   |   `-- widgets/
|   |   |       |-- sidebar.py   # 左侧固定导航菜单
|   |   |       |-- status_bar.py# 三列状态栏（target / mode / model）
|   |   |       |-- overview.py  # 目标历史概览面板
|   |   |       |-- scope.py     # 边界约束配置面板
|   |   |       |-- exec_pane.py # 流式执行面板（LLM 输出 + 工具状态）
|   |   |       |-- log_panel.py # RichLog 流式日志封装
|   |   |       |-- tool_panel.py# 工具调用状态树
|   |   |       `-- input_bar.py # 底部自然语言输入栏
|   |-- config/                  # 配置 schema、加载、保存、环境变量覆盖
|   |-- kb/                      # 知识库存储、检索、更新
|   |-- mcp/
|   |   |-- lifecycle.py         # attach / probe / call / degrade 行为
|   |   |-- registry.py          # 服务状态、健康度、attach 状态、工具注册
|   |   `-- router.py            # 自然语言意图到 MCP 工具建议
|   |-- report/                  # 报告生成、过滤、PoC 生成
|   |-- skills/                  # 内置 markdown skills、loader、dispatcher
|   |-- target_state/            # 目标历史、preview、diff、rollback、resume plan
|   |-- web/
|   |   |-- app.py               # FastAPI 路由与静态前端服务
|   |   |-- schemas.py           # Web API 请求/响应模型
|   |   |-- task_manager.py      # Web 任务状态与历史持久化
|   |   |-- stream.py            # SSE 事件编码
|   |   |-- services/            # config / report / target / task / MCP 服务层
|   |   `-- static/              # 当前端 dist 不存在时的 fallback 静态页
|   `-- warstories/              # 内置案例 markdown 内容
|-- frontend/
|   |-- src/
|   |   |-- pages/               # Dashboard / Tasks / Target / Snapshots / Reports / Settings
|   |   |-- api/                 # 前端 API 请求封装
|   |   |-- hooks/               # React Query hooks
|   |   `-- types/               # 前端共享类型
|   `-- package.json             # 前端构建与开发脚本
|-- scripts/                     # release preflight / dist 校验脚本
|-- tests/                       # 后端、CLI、MCP、release、web、report 测试
|-- .github/workflows/           # CI / preflight / release 工作流
|-- README.md                    # 中文说明
|-- README_EN.md                 # 英文说明
|-- pyproject.toml               # 打包元数据与 Hatch 构建规则
`-- CONTRIBUTING.md              # 本文件
```

---

## 如何快速定位代码

### 1. 修改 Agent 行为时，优先看 `vulnclaw/agent/`

适用场景：
- 自主 / 持续渗透循环行为
- 工具调用编排
- LLM 请求与响应处理
- recon / CTF / anti-loop 逻辑
- finding 生命周期、证据等级、结果解析

当前架构里，`core.py` 更像协调壳层。除非确实是入口级逻辑，否则优先修改对应 helper/module，而不是继续把逻辑堆回 `core.py`。

### 2. 修改共享任务流时，优先看 `vulnclaw/orchestrator.py` 和 `vulnclaw/repl_runner.py`

适用场景：
- CLI / Web / REPL 共享任务生命周期
- restore -> run -> save -> summarize 流程
- REPL 单次执行辅助

如果同一行为同时出现在 CLI 和 Web，通常应该收敛到这里，而不是分别在 `cli/main.py` 和 `web/services/task_service.py` 各写一份。

### 3. 修改命令行或 TUI 行为时，看 `vulnclaw/cli/`

适用场景：
- Typer 命令与参数绑定
- REPL 交互体验
- `doctor` 输出
- `web` 启动器行为
- `target-state` 子命令
- **Textual TUI 界面、布局、交互**

`cli/main.py` 负责入口、参数绑定和命令路由。TUI 逻辑分为两层：
- **旧版 Rich TUI**：`vulnclaw/cli/tui.py`，仅留作 `VULNCLAW_TUI_LEGACY=1` 回退
- **新版 Textual TUI**：`vulnclaw/cli/textui/`，包含主屏幕 `screens/main.py`、流式执行视图 `widgets/exec_pane.py`、侧边栏 `widgets/sidebar.py` 等

修改 TUI 布局、快捷键、流式回调时，在 `textui/` 目录内修改，`cli/main.py` 仅做入口切换。避免把 TUI 渲染逻辑写进 `main.py`。

### 3.1 修改 TUI 工作台时，看 `vulnclaw/cli/tui.py` 和 `vulnclaw/cli/tui_textual.py`

适用场景：
- TUI 仪表盘布局与渲染
- 斜杠命令系统（`/target`、`/mode`、`/start` 等）
- 命令面板（Command Palette）交互
- 提示/确认状态机
- TUI 配色主题

**架构关系：**

```
main.py (Typer CLI)
  └─ tui.py (run_tui → 委托)
       └─ tui_textual.py (run_tui_textual → Textual App)
            ├─ DashboardScreen
            │   ├─ CommandPalette     (一级：斜杠补全下拉)
            │   ├─ SecondaryPopup     (二级：参数输入弹窗)
            │   └─ RichLog + spinner  (执行模式：输出区 + 拖尾动画)
            └─ VulnClawApp
```

| 文件 | 职责 |
|------|------|
| `tui.py` | 数据类（`TuiState`、`TuiMode`、`TuiTaskDraft`）、Rich 仪表盘渲染（`build_dashboard`）、颜色常量（`C_PRIMARY` 等）、斜杠命令注册表（`SLASH_COMMANDS`）、入口 `run_tui()` |
| `tui_textual.py` | Textual App 实现：`DashboardScreen`（布局 + 执行模式）、`CommandPalette`（一级下拉面板）、`SecondaryPopup`（二级弹窗）、`VulnClawApp`（CSS）、斜杠命令处理器、提示状态机、子进程执行引擎 |

**斜杠命令系统：**

命令通过函数装饰器 `@_register_handler("...")` 注册，`_dispatch()` 根据输入分发。命令签名：`fn(session: dict, args: str) -> str | None`。
`SLASH_COMMANDS` 字典（`tui.py`）决定命令面板中可见的命令列表。

- 返回 `"quit"` → 退出 TUI
- 返回 `"launch"` → 启动渗透任务（TUI 内子进程执行，不再退回 CLI）
- 返回 `None` → 设置提示状态（触发二级弹窗）

支持内联参数：`/target example.com`、`/mode deep`、`/scope host=1.2.3.4`，无参数时弹出二级弹窗进行交互式输入。

**提示状态机：**

`session["_prompt"]` 元组类型（同时设置 `_show_popup = True` 触发二级弹窗）：
- `("input", label, callback, default)` — 弹窗显示描述 + 输入框，Enter 确认
- `("choice", label, choices, callback)` — 弹窗显示描述 + 选项列表，方向键选择 + Enter 确认
- `("confirm", label, callback)` — 弹窗显示描述 + y/n，按键直接确认（y = True, n/esc = False）
- `("message", text)` — 弹窗显示纯文本，Enter/Escape 关闭（回调为 None）
- `("chain", fields, idx, callback)` — 弹窗显示链式多字段输入（如 scope 逐项设置），每步 Enter 进入下一字段，完成后触发 callback（可级联弹窗）

**命令面板（CommandPalette）：**

继承 `ListView`，输入 `/` 时弹出在输入框上方。`↑↓` 移动高亮指针（不填入输入框），`Tab`/`Enter` 选中补全。`show_commands()` 使用 `query_children(ListItem).remove()` 清空旧条目 + `mount()` 挂载新条目（标准 Textual API，替代旧版私有 `_nodes` 操作）。CSS 含 `.-highlight` 高亮样式（`#fab283 30%` 背景 + 白色文字）。方向键导航通过 `DashboardScreen.on_key` 拦截 `up`/`down` 后调用 `action_cursor_up/down`。

**二级弹窗（SecondaryPopup）：**

继承 `Vertical`，当斜杠命令缺少参数时自动弹出。五种子模式：
| 模式 | 示例 | 组件 |
|------|------|------|
| `input` | `/target` | `Static` 描述 + `Input` 输入框 |
| `choice` | `/mode` | `Static` 描述 + `ListView` 选项列表（方向键 + Enter） |
| `confirm` | `/start`（深度验证） | `Static` 描述 + y/n 提示（按键直接确认） |
| `message` | `/diag` | `Static` 描述（Enter/Escape 关闭） |
| `chain` | `/scope` | 逐字段输入 `[1/7] → [2/7] → ...`，完成后级联触发下一个弹窗 |

`_resolve(value)` 确认并调用回调修改状态，`_cancel()` 关闭弹窗不修改状态。Escape 键在弹窗打开时调用 `_cancel()`（不改变原值）。`_on_done` 回调确保弹窗关闭后仪表盘自动刷新。

**Escape 键行为：**

逐层关闭：二级弹窗 `_cancel()` → 命令面板 `hide_palette()` → prompt `_cancel_prompt()`。空闲状态下不再退出 TUI（仅 `/quit` 或 `Ctrl+C` 退出）。

**执行模式：**

`/run` 或 `/start` 返回 `"launch"` 时不退出 TUI，改为 TUI 内子进程执行：
1. 隐藏仪表盘（`#dashboard.-hidden`），显示 `RichLog` 输出区（`#output-log.-active`）
2. 输入框左侧显示**拖尾动画**：5 个方块无间距，领头 `[bold #fab283]■` 带两级拖尾（`[#fab283]■` + `[#808080]■`），0.12s 更新一帧，左右来回弹跳
3. 禁用输入框，通过 `subprocess.Popen` 启动子进程（`python -m vulnclaw.cli.main <cmd> <args>`），`encoding="utf-8"` 避免 GBK 解码错误，实时流式读取 `stdout` 管道
4. 后台线程读取子进程输出推入 `Queue`，主线程通过 `set_timer(0.3s)` 轮询写入 `RichLog`
5. 执行完成：隐藏拖尾动画、启用输入框、重新加载配置
6. `Ctrl+Shift+C` 复制输出日志到系统剪贴板（Windows: `clip`，macOS: `pbcopy`，Linux: `xclip`）

**配色方案（opencode 风格）：**

| 变量 | 色值 | 用途 |
|------|------|------|
| `C_PRIMARY` | `#fab283` | 菜单键、高亮选择 |
| `C_SECONDARY` | `#5c9cf5` | 模式标签、信息标识 |
| `C_ACCENT` | `#9d7cd8` | 标题、Header |
| `C_SUCCESS` | `#7fd88f` | 已配置/成功状态 |
| `C_WARNING` | `#f5a742` | 未设置/需关注 |
| `C_ERROR` | `#e06c75` | 错误/无效输入 |
| `C_MUTED` | `#808080` | 次要文字、描述 |
| `C_BORDER` | `#484848` | 面板边框 |

Textual CSS 中 UI 元素（Header、状态栏、输入框）使用终端自适应背景（`$background`、`$surface`、`$boost`），强调色硬编码上述色值。

### 4. 修改配置时，看 `vulnclaw/config/`

- `schema.py`：配置模型定义
- `settings.py`：加载、保存、环境变量覆盖、目录路径

不要在业务逻辑里到处手写配置解析。

### 5. 修改报告逻辑时，看 `vulnclaw/report/`

适用场景：
- Markdown / HTML 报告渲染
- 报告内容过滤
- PoC 生成
- 验证摘要与定位信息

主入口是 `generator.py`，但要注意它现在会同时影响 target-state 报告和 persistent-cycle 报告。

### 6. 修改 MCP 行为时，看 `vulnclaw/mcp/`

- `registry.py`：服务状态、健康度、attach 状态、工具注册
- `lifecycle.py`：attach / probe / call / degrade 逻辑
- `router.py`：自然语言意图到 MCP 工具建议

当前状态：
- `fetch` / `memory`：本地可执行
- `chrome-devtools` / `burp`：已有真实 stdio attach、动态工具发现、持久会话骨架
- 其他服务：大多仍然降级到结构化 placeholder

如果改动 MCP，请同步考虑：
- diagnostics 展示
- error_type 分类
- attach 失败后的降级行为

### 7. 修改断点续测 / 成果继承时，看 `vulnclaw/target_state/`

适用场景：
- target-state 持久化
- merge 规则
- preview / diff / rollback
- resume strategy 与 summary 生成

这里负责“同一目标跨命令共享成果”。不要把这类逻辑重新塞回 `core.py`，也不要在页面层重复写。

### 8. 修改 Web 后端时，看 `vulnclaw/web/`

- `app.py`：FastAPI 路由与前端静态资源服务
- `schemas.py`：请求/响应模型
- `task_manager.py`：Web 任务状态与历史
- `services/`：config / report / target / task / MCP 服务层

原则上优先把逻辑放进 `web/services/`，避免路由函数变成大杂烩。

### 9. 修改 Web UI 时，看 `frontend/`

适用场景：
- Dashboard / Task Console / Target State / Snapshots / Reports / Settings 页面
- React Query hooks
- 前端 API 绑定
- 控制台交互与样式优化

前后端契约要和 `vulnclaw/web/schemas.py` 保持一致。

### 10. 修改打包 / 发布流程时，看 `scripts/`、`.github/workflows/`、`pyproject.toml`

适用场景：
- 本地 preflight
- dist 产物校验
- CI / release workflow
- build include / exclude
- 包元数据

版本真源以 `pyproject.toml` 为主，`vulnclaw/__init__.py` 是 fallback。

---

## Contribution Tips

- 尽量在正确模块里改代码，不要把已经拆出去的职责重新堆回 `core.py`
- 如果改的是共享任务流，优先考虑 `orchestrator.py` / `repl_runner.py`
- 改行为逻辑时，尽量同步补测试
- 改打包/发布逻辑时，同时检查 `pyproject.toml`、`scripts/`、`.github/workflows/`
- 改文档时，确保能力描述和当前真实实现一致，尤其是 MCP、sandbox、安全边界这类容易误导的部分

---

## 提交 PR 前建议确认

至少检查：
1. 相关测试通过
2. 文档和实现一致
3. 新逻辑放在正确模块，而不是重新把职责塞回大文件
4. 如果影响版本、CLI 输出、README、打包流程，相关文件已同步更新

---

## Web UI Notes

如果你在改 Web UI，优先看：
- `vulnclaw/web/`
- `frontend/`

当前 Web 侧已经不只是占位骨架，主要包括：
- 后端 API
- 任务状态持久化
- target preview / diff
- MCP diagnostics
- Settings 安全模式配置

原则：
- Web 层复用现有 agent / target_state / report 主干
- 不在 Web 层复制一套新的恢复逻辑
- 不让前端直接持有敏感密钥

---

## Suggested Preflight

提交前建议至少跑一遍：

```bash
python scripts/release_preflight.py
python scripts/release_preflight.py --build
```

它会检查：
- `pyproject.toml` 与 `vulnclaw.__version__` 的版本一致性
- 后端 `pytest -q`
- 前端 `npx tsc -b`
- 可选的 build 与 dist 产物校验
