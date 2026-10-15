# VulnClaw 测试布局

测试目录按 `vulnclaw/` 的架构分层组织，每个子目录是一个测试包（含 `__init__.py`），
镜像被测源码包。新增测试请放进对应层，保持结构整洁、便于定位与评估覆盖。

| 测试目录 | 覆盖的源码 |
|----------|-----------|
| `tests/agent/` | `vulnclaw/agent/` — 核心 agent、solve/team/rounds 引擎、工具、上下文、推理/反思、CTF、角色、约束策略 |
| `tests/cli/` | `vulnclaw/cli/` — CLI 命令、非交互/headless 流程、TUI 相关断言 |
| `tests/config/` | `vulnclaw/config/` — 配置 schema、settings、token provider、domain models |
| `tests/findings/` | `vulnclaw/findings/` — 结构化上报、证据快照、独立验证、PoC 执行（本地服务） |
| `tests/i18n/` | `vulnclaw/i18n/` — 翻译目录一致性、阶段本地化 |
| `tests/intel/` | `vulnclaw/intel/` — CVE / OSINT / 合规 / 拓扑 / 修复建议 |
| `tests/kb/` | `vulnclaw/kb/` — 知识库检索与降级回退 |
| `tests/mcp/` | `vulnclaw/mcp/` — MCP 生命周期、传输探测、fetch cookies |
| `tests/meta/` | 项目元信息 — 版本一致性、发布工作流、导入冒烟 |
| `tests/plugins/` | `vulnclaw/plugins/` — 插件注册/运行时/集成/CLI |
| `tests/report/` | `vulnclaw/report/` — 报告渲染、findings/SARIF 输出、PDF、fetch 复现 |
| `tests/run/` | 运行/持久化生命周期 — `orchestrator` / `run_context` / `target_state` / `headless` |
| `tests/skills/` | `vulnclaw/skills/` — 技能解析、路由、flag skills |
| `tests/traffic/` | `vulnclaw/traffic/` — 流量捕获/规范化/回放/后端 |
| `tests/web/` | `vulnclaw/web/` — Web UI 后端、鉴权、服务层 |

约定：
- 模块级的 i18n 测试（如 `test_intake`）跟随其所属模块归入对应层；
  `tests/i18n/` 只放纯 i18n（目录一致性等）。
- 每层测试文件按被测模块的主导 import 归类。

## 运行

```bash
# 全量
pytest

# 单层
pytest tests/agent

# 覆盖率（opt-in，保持普通运行快速）
pytest --cov=vulnclaw --cov-report=term-missing
```

覆盖率配置见根 `pyproject.toml` 的 `[tool.coverage.*]`；设有 `fail_under = 70` 作为
回归下限（当前整体约 74%），随覆盖提升可上调。
