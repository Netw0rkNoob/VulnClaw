# Contributing to VulnClaw

感谢你为 VulnClaw 做贡献。

这份文档的目标不是规定繁琐流程，而是帮助你快速理解当前代码结构，尽量在正确的层次修改代码，减少"功能能跑，但架构越来越乱"的情况。

---

## 一、项目结构

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
|   |   |-- response_observations.py # 非漏洞观察记录（不创建 finding）
|   |   |-- prompt_context.py    # 回合上下文与攻击摘要
|   |   |-- prompts.py           # prompt 构建辅助
|   |   |-- system_prompt.py     # 动态 system prompt 组合
|   |   |-- input_analysis.py    # 目标、阶段、漏洞提示提取
|   |   |-- anti_loop.py         # 防死循环、失败目标、攻击路径跟踪
|   |   |-- recon_tracker.py     # recon 维度完成度追踪
|   |   |-- ctf_mode.py          # CTF flag 识别与验证
|   |   |-- skill_context.py     # Skill 上下文选择
|   |   |-- kb_context.py        # 知识库上下文注入
|   |   |-- think_filter.py      # think 标签显示与隐藏
|   |   |-- agent_context.py     # AgentCore 与 helper 之间的 typed seam
|   |   |-- agent_graph.py       # 可持久化、可恢复的多 Agent 生命周期图
|   |   |-- agent_state.py       # 模型主导 solve 的证据、步骤、工具调用与完成闸门状态
|   |   |-- solver.py            # 模型主导求解引擎
|   |   |-- parallel_agents.py   # 有界并行多 Agent 协调
|   |   |-- team.py              # 角色化团队规划与自适应委派
|   |   |-- roles.py             # 角色注册与硬工具白名单
|   |   |-- reflexion.py         # 失败自省与自我纠正
|   |   |-- reasoning_state.py   # 结构化推理状态
|   |   |-- constraint_policy.py # 任务/阶段/工具约束策略裁决
|   |   |-- finding_similarity.py # finding 语义相似度去重
|   |   |-- memory.py            # 短/中/长期 Agent 记忆管理
|   |   |-- network_scan.py      # 网络扫描规划与薄弱环节分析
|   |   |-- recon_tools.py       # 信息收集工具（空间测绘/子域/JS/目录枚举）
|   |   |-- token_counter.py     # token 估算、工具交换组分组、滑动窗口截断
|   |   |-- context_budget.py   # 统一上下文预算与结构化压缩（prepare_context 唯一入口）
|   |   |-- subagent/            # 模型驱动并行子 Agent 扇出
|   |   |   |-- budget.py        # 子 Agent LLM 预算/准入/结算
|   |   |   |-- integration.py  # spawn_subagents 工具与主 solve 集成
|   |   |   |-- merge.py        # 子证据/claim/step 合并回父状态
|   |   |   |-- models.py       # 子 Agent 任务/结果/生命周期模型
|   |   |   |-- service.py      # Group Leader/Leaf 异步运行时
|   |   |   |-- solve.py        # 子 Agent solve 循环
|   |   |   `-- tooling.py      # 子 Agent 工具注册与约束
|   |   `-- chatgpt_proxy.py     # ChatGPT 后端 OpenAI 兼容代理（Responses API）
|   |-- cli/
|   |   |-- main.py              # CLI 命令、doctor、web 启动、target-state CLI
|   |   |-- tui.py               # TUI 数据类、仪表盘渲染、配色常量
|   |   `-- tui_textual.py       # Textual 驱动的 TUI 工作台
|   |-- config/                  # 配置 schema、加载、保存、环境变量覆盖
|   |   |-- schema.py           # Pydantic 配置模型（LLM/MCP/Session/Safety/Subagent/Recon）
|   |   |-- settings.py         # 加载、环境变量覆盖、旧字段迁移
|   |   `-- domain_models.py    # 领域叶子类型（Phase/EvidenceRef/Finding 等）
|   |-- kb/                      # 知识库存储、检索、更新
|   |-- mcp/
|   |   |-- lifecycle.py         # attach / probe / call / degrade 行为
|   |   |-- registry.py          # 服务状态、健康度、attach 状态、工具注册
|   |   `-- router.py            # 自然语言意图到 MCP 工具建议
|   |-- findings/                # 结构化上报、证据快照、独立验证与 PoC 检查
|   |-- report/                  # 报告渲染、过滤、findings.json/SARIF 输出
|   |-- skills/                  # 内置 markdown skills、loader、dispatcher
|   |   |-- core/                  # 7 个核心 flat-format Skill（单个 .md 文件）
|   |   |-- specialized/           # 目录格式专项 Skill，每个子目录含 SKILL.md
|   |   |   |-- <skill-name>/
|   |   |   |   |-- SKILL.md      # frontmatter + 触发条件 + 行为准则
|   |   |   |   `-- references/  # 可由 load_skill_reference 按需加载的资料
|   |   |   `-- secknowledge-skill/ # CTF/SRC/Web+AI 安全测试知识库集成
|   |   |-- crypto_tools.py        # crypto_decode 内置工具实现
|   |   |-- dispatcher.py          # 自然语言意图到 Skill 的路由
|   |   `-- loader.py             # flat/directory Skill 加载与 reference 读取
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
|   |-- agent/                  # agent 层单元测试（subagent/context/token/streaming）
|   |-- cli/                    # CLI/TUI 测试
|   `-- web/                    # Web API 测试
|-- .github/workflows/           # CI / preflight / release 工作流
|-- README.md                    # 中文说明
|-- README_EN.md                 # 英文说明
|-- pyproject.toml               # 打包元数据与 Hatch 构建规则
`-- CONTRIBUTING.md              # 本文件
```

---

## 二、代码导航

按修改场景快速定位应查看的模块。

### 2.1 修改 Agent 行为 → `vulnclaw/agent/`

适用场景：
- 自主 / 持续渗透循环行为
- 工具调用编排
- LLM 请求与响应处理
- recon / CTF / anti-loop 逻辑
- finding 生命周期、证据等级、结果解析
- 上下文预算与压缩（`context_budget.py`）
- 子 Agent 扇出与合并（`subagent/`）

`core.py` 是协调壳层。除非确实是入口级逻辑，否则优先修改对应 helper/module，不要把逻辑堆回 `core.py`。

**上下文预算**：所有 LLM 调用路径（含 `structured_call`/team planner/adviser/report summary）必须经过 `context_budget.prepare_context()` 预算入口。新增旁路 LLM 调用时，务必包装 `_fit_context_window(agent, messages, tools, purpose="...")`。

**子 Agent**：`subagent/` 是独立的扇出运行时。修改扇出逻辑时注意：`max_depth` 硬顶为 2；`SubagentConfig` 全部数值项有 `le=` 上界；子进程退出必须是 `terminate→wait→kill` 三段式；TUI 中渲染子代理输出必须先转义再写入 `markup=True` 面板。

### 2.2 修改共享任务流 → `vulnclaw/orchestrator.py` / `vulnclaw/repl_runner.py`

适用场景：
- CLI / Web / REPL 共享任务生命周期
- restore → run → save → summarize 流程
- REPL 单次执行辅助

同一行为同时出现在 CLI 和 Web 时，应收敛到这里，不要在 `cli/main.py` 和 `web/services/task_service.py` 各写一份。

### 2.3 修改命令行或 REPL → `vulnclaw/cli/main.py`

适用场景：
- Typer 命令
- REPL 体验
- `doctor` 输出
- `web` 启动器行为
- `target-state` 子命令

这一层负责入口、参数绑定和用户输出，不适合承载核心渗透逻辑。

### 2.4 修改 TUI 工作台 → `vulnclaw/cli/tui.py` / `vulnclaw/cli/tui_textual.py`

适用场景：
- TUI 仪表盘布局与渲染
- 斜杠命令系统（`/target`、`/mode`、`/start` 等）
- 命令面板（Command Palette）交互
- 提示/确认状态机

**架构关系：**

| 文件 | 职责 |
|------|------|
| `tui.py` | 数据类、Rich 仪表盘渲染、颜色常量、斜杠命令注册表、入口 `run_tui()` |
| `tui_textual.py` | Textual App 实现：DashboardScreen、CommandPalette、SecondaryPopup、斜杠命令处理器、提示状态机、子进程执行引擎 |

### 2.5 修改配置 → `vulnclaw/config/`

- `schema.py`：配置模型定义
- `settings.py`：加载、保存、环境变量覆盖、目录路径

不要在业务逻辑里到处手写配置解析。

### 2.6 修改上报 / 验证 / 报告逻辑 → `vulnclaw/findings/` + `vulnclaw/report/`

适用场景：
- `findings/intake.py`：`submit_finding` 工具的校验、证据归属与入库去重
- `findings/evidence.py`：稳定证据快照的写入与校验
- `findings/verification.py`：任务结束时的独立漏洞审计（证据审查 / PoC）
- `findings/poc.py`：类型专用 PoC 计划构建与受控执行
- Markdown / HTML 报告渲染、报告内容过滤、findings.json / SARIF 输出

渲染主入口是 `report/generator.py`，同时影响 target-state 报告和 persistent-cycle 报告；
渲染器只消费 `findings/verification.py` 产出的已审计快照，不得自行改写状态。
共享 `finding_service.py` / `report_service.py` 负责历史数据审计及导出编排；报告生成器不执行验证。
新候选经 `submit_finding` 登记；网络扫描和插件只记录观察证据，不直接调用
`add_finding`。Team 和子代理通过同一个证据提交器合并；恢复已有业务数据时保留历史记录。

### 2.7 修改 MCP 行为 → `vulnclaw/mcp/`

- `registry.py`：服务状态、健康度、attach 状态、工具注册
- `lifecycle.py`：attach / probe / call / degrade 逻辑
- `router.py`：自然语言意图到 MCP 工具建议

当前状态：
- `fetch` / `memory`：本地可执行
- `chrome-devtools` / `burp`：已有真实 stdio attach、动态工具发现、持久会话骨架
- 其他服务：大多仍然降级到结构化 placeholder

改动 MCP 时，请同步考虑 diagnostics 展示、error_type 分类、attach 失败后的降级行为。

### 2.8 修改断点续测 / 成果继承 → `vulnclaw/target_state/`

适用场景：
- target-state 持久化
- merge 规则
- preview / diff / rollback
- resume strategy 与 summary 生成

这里负责"同一目标跨命令共享成果"。不要把这类逻辑重新塞回 `core.py`，也不要在页面层重复写。

### 2.9 修改 Web 后端 → `vulnclaw/web/`

- `app.py`：FastAPI 路由与前端静态资源服务
- `schemas.py`：请求/响应模型
- `task_manager.py`：Web 任务状态与历史
- `services/`：config / report / target / task / MCP 服务层

优先把逻辑放进 `web/services/`，避免路由函数变成大杂烩。

### 2.10 修改 Web UI → `frontend/`

适用场景：
- Dashboard / Task Console / Target State / Snapshots / Reports / Settings 页面
- React Query hooks
- 前端 API 绑定
- 控制台交互与样式优化

前后端契约要和 `vulnclaw/web/schemas.py` 保持一致。

当前 Web 侧主要包括：后端 API、任务状态持久化、target preview / diff、MCP diagnostics、Settings 安全模式配置。

原则：
- Web 层复用现有 agent / target_state / report 主干
- 不在 Web 层复制一套新的恢复逻辑
- 不让前端直接持有敏感密钥

### 2.11 修改打包 / 发布流程 → `scripts/`、`.github/workflows/`、`pyproject.toml`

适用场景：
- 本地 preflight
- dist 产物校验
- CI / release workflow
- build include / exclude
- 包元数据

版本真源以 `pyproject.toml` 为主，`vulnclaw/__init__.py` 是 fallback。

### 2.12 修改或新增 Skill → `vulnclaw/skills/`

适用场景：
- 新增核心渗透流程说明
- 新增专项知识库或 reference 文档
- 调整自然语言到 Skill 的自动调度规则
- 更新 `load_skill_reference` 可读取的资料集

当前 Skill 有两种格式：

| 格式 | 位置 | 用途 |
|------|------|------|
| flat-format | `vulnclaw/skills/core/*.md` | 核心流程型 Skill |
| directory-format | `vulnclaw/skills/specialized/<skill-name>/` | 专项 Skill，必须包含 `SKILL.md`，可选 `references/` |

directory-format 约定：
- `SKILL.md` 使用 YAML frontmatter，至少包含 `name` 和 `description`
- `references/` 下放 `.md`、`.yaml`、`.yml` 文件，文件名会暴露给 Agent
- reference 内容应按主题拆分，避免把大型知识库全部塞进 `SKILL.md`
- 需要触发该 Skill 时，在 `dispatcher.py` 的 `SKILL_INTENT_MAP` 增加强信号关键词
- 新增或修改 Skill 后，同步更新 `tests/test_skills.py` 和 README 的 Skill 表

`secknowledge-skill` 是当前的外部知识库集成示例，同步外部 Skill 时请保留来源、许可证和集成说明。

### 2.13 注意事项

- 尽量在正确模块里改代码，不要把已经拆出去的职责重新堆回 `core.py`
- 如果改的是共享任务流，优先考虑 `orchestrator.py` / `repl_runner.py`
- 改行为逻辑时，尽量同步补测试
- 改打包/发布逻辑时，同时检查 `pyproject.toml`、`scripts/`、`.github/workflows/`
- 改文档时，确保能力描述和当前真实实现一致，尤其是 MCP、sandbox、安全边界这类容易误导的部分

---

## 三、分支协作规范

### 3.1 概述

#### 规范目的

为保障 main 主分支的稳定性与可发布性，统一多人协作开发流程，降低代码合并冲突与线上故障风险，制定本规范。所有贡献者提交代码均需遵循本流程。

#### 核心原则

- **主干稳定**：main 分支为生产级稳定分支，任何时候均可直接发布运行
- **分层验证**：所有功能与修复先进入 dev 开发分支集成测试，验证无误后再同步至 main
- **PR 准入**：禁止直接向长期分支推送代码，所有变更必须通过 Pull Request 流程审核合入
- **历史清晰**：保持提交记录整洁可读，遵循统一的命名与提交规范

### 3.2 分支模型

仓库采用「双长期分支 + 多临时分支」的 Git Flow 精简模型。

#### 长期分支（受保护，禁止直接推送）

| 分支名 | 角色 | 权限规则 | 说明 |
|--------|------|----------|------|
| `main` | 生产主分支 | 仅管理员可通过 PR 合入；禁止直接推送、强制推送与删除 | 存放正式发布的稳定代码，每一次合入对应一个可发布版本，附带版本标签 |
| `dev` | 开发集成分支 | 所有贡献者通过 PR 合入；禁止直接推送、强制推送与删除 | 日常开发的主分支，所有新功能、Bug 修复均先合入此分支，进行集成测试与验证 |

#### 临时分支（开发完成后删除）

临时分支均从对应基准分支切出，功能完成并合入后立即删除。

| 分支类型 | 命名格式 | 基准分支 | 合入目标 | 适用场景 |
|----------|----------|----------|----------|----------|
| 功能分支 | `feature/功能描述` | dev | dev | 新增功能、特性、重构、文档大版本更新 |
| 修复分支 | `fix/问题描述` | dev | dev | 修复开发环境、测试环境发现的非紧急 Bug |
| 文档分支 | `docs/描述` | dev | dev | 纯文档修改、说明更新、注释补充 |

### 3.3 标准开发流程（功能 / 修复分支）

#### 步骤 1：同步基准分支，创建开发分支

```bash
# 切换到 dev 分支，拉取远程最新代码
git checkout dev
git pull origin dev

# 基于 dev 创建功能/修复分支，遵循命名规范
git checkout -b feature/i18n-frontend
```

#### 步骤 2：本地开发与提交

提交信息遵循「类型：简短描述」格式，例如：

```
feat: 新增前端 i18n 国际化支持
fix: 修复 base64url 解码异常问题
docs: 更新 README 安装说明
```

建议小步提交，每个提交对应一个独立的逻辑变更。

#### 步骤 3：同步上游，变基整理提交

提交 PR 前，先同步 dev 最新代码，避免合并冲突：

```bash
# 拉取最新 dev 代码
git fetch origin dev

# 基于最新 dev 进行变基，保持线性提交历史
git rebase origin/dev
```

若出现冲突，本地解决后执行 `git add . && git rebase --continue`。

变基完成后，推送至自己的远程分支：

```bash
git push origin feature/i18n-frontend
```

#### 步骤 4：提交 Pull Request

在 GitHub 仓库页面发起 PR，源分支选你的功能分支，目标分支选择 `dev`。

PR 标题与提交信息保持一致，描述中需包含：
- 变更内容概述
- 改动的文件与影响范围
- 测试验证情况
- 关联的 Issue（必须）

等待 CI 自动检查通过，等待代码审核。

#### 步骤 5：审核通过，合入分支

审核通过、所有检查通过后，由维护者执行合并。合并完成后，删除该功能分支。

### 3.4 PR 审核与准入规则

#### 强制准入条件

所有 PR 合入前必须同时满足：

- **必须关联已有 Issue**，并在 PR 描述中使用 `Fixes #123` 或 `Closes #123` 关联
- CI 自动化检查全部通过（测试、构建、代码规范校验）
- 无未解决的代码评审评论
- 与目标分支无合并冲突
- 代码已基于目标分支最新版本变基

#### 审核要求

- 合入 `dev`：至少 1 名维护者审核通过
- 合入 `main`：必须由仓库所有者或核心维护者最终审核通过

### 3.5 常见规范与注意事项

- **禁止直接推送长期分支**：main 和 dev 均受分支保护规则保护，必须走 PR 流程
- **禁止强制推送长期分支**：严禁对 main 和 dev 执行 `git push --force`
- **及时清理分支**：PR 合并完成后，及时删除对应的临时分支
- **同步上游优先用变基**：拉取上游代码时，优先使用 `git rebase` 而非 `git merge`
- **大变更提前沟通**：涉及架构调整、核心模块重构的大型变更，建议先通过 Issue 或讨论区达成共识后再开发

---

## 四、PR 提交规范

### 4.1 议题优先原则（Issue First）

所有 PR **必须**关联一个已有 issue。如果您发现 bug 或想提新功能，请先创建 issue。

- PR 描述中请使用 `Fixes #123` 或 `Closes #123` 关联对应 issue
- 没有关联 issue 的 PR 将不会被审查
- 小修复（错别字、单行改错）可以开一个简短 issue，简要说明即可

### 4.2 PR 标题格式

标题请遵循[约定式提交（Conventional Commits）](https://www.conventionalcommits.org/)规范：

```
<类型>(可选范围): <简短描述>
```

**类型：**

| 类型 | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `docs` | 文档变更 |
| `style` | 代码格式（不影响逻辑） |
| `refactor` | 重构（不改变功能） |
| `perf` | 性能优化 |
| `test` | 测试相关 |
| `chore` | 构建/工具/依赖变更 |

**示例：**

- `feat: 增加用户登录功能`
- `fix(api): 修复超时未返回错误的问题`
- `docs: 更新安装说明`
- `chore: 升级 httpx 到 0.28.0`

### 4.3 PR 描述要求

- 必须说明：解决了什么问题（关联 issue），以及您是怎么修复的
- UI 变更（Web UI 或 TUI）：请附带截图或 GIF 对比前后效果
- 逻辑变更：请说明您如何验证（手动测试步骤 / 单元测试覆盖情况）
- 禁止：直接粘贴 AI 生成的大段描述。维护者不欢迎"AI 废话文学"，请用自己的话精简描述

### 4.4 提交前验证

在提交 PR 前，请确认：

**后端验证：**
```bash
# 代码风格检查
ruff check vulnclaw tests

# 运行测试
pytest -q
```

**前端验证：**
```bash
cd frontend
npm ci
npx tsc -b
```

**完整预检（可选）：**
```bash
python scripts/release_preflight.py
python scripts/release_preflight.py --build
```

至少检查：
1. 相关测试通过
2. 文档和实现一致
3. 新逻辑放在正确模块，而不是重新把职责塞回大文件
4. 如果影响版本、CLI 输出、README、打包流程，相关文件已同步更新

---

## 五、代码风格指南

以下不是强制规则，但遵循它们会让审查更顺利：

**后端（Python）：**
- 运行 `ruff check vulnclaw tests` 检查代码风格（配置见 `pyproject.toml`）
- 行长度限制：100 字符
- 目标 Python 版本：3.10+

**前端（TypeScript/React）：**
- 运行 `npx tsc -b` 确保类型检查通过
- 遵循项目现有 React 组件风格

**通用原则：**
- 函数粒度：尽量保持单一职责，不要写过于庞大的函数
- 避免 else：优先使用提前返回（early return）
- 错误处理：推荐使用 try/catch 或 .catch()，视场景而定
- 类型安全（TypeScript）：避免滥用 any，尽量定义精确类型
- 变量不可变性：优先使用 const 而非 let
- 命名：使用简洁但表意清晰的英文单词
