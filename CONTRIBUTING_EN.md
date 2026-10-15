# Contributing to VulnClaw

Thank you for your interest in contributing to VulnClaw! 🦞

This document is available in both [Chinese](CONTRIBUTING.md) and English (this file).

This guide helps you quickly understand the codebase structure, modify code at the right layer, and avoid "it works but the architecture is becoming a mess" situations.

---

## 1. Project Structure

```text
VulnClaw/
|-- vulnclaw/
|   |-- __init__.py              # Package version and metadata
|   |-- orchestrator.py          # Shared task orchestration for CLI / Web
|   |-- repl_runner.py           # Shared REPL execution helpers
|   |-- agent/                   # Agent core logic
|   |   |-- core.py              # AgentCore coordination entrypoint
|   |   |-- llm_client.py        # LLM calls, retries, tool result forwarding
|   |   |-- tool_call_manager.py # Tool-call dedup, execution, result packaging
|   |   |-- builtin_tools.py     # python_execute / nmap_scan / MCP bridge
|   |   |-- context.py           # Session state, findings, steps, lifecycle
|   |   |-- context_budget.py    # Unified context budget & structured compaction
|   |   |-- token_counter.py     # Token estimation, tool-exchange grouping, truncation
|   |   |-- subagent/            # Model-driven parallel sub-agent fan-out
|   |   |   |-- budget.py        # Sub-agent LLM budget/admission/settlement
|   |   |   |-- integration.py  # spawn_subagents tool & solve integration
|   |   |   |-- merge.py        # Merge sub-evidence/claims/steps to parent
|   |   |   |-- models.py       # Sub-agent task/result/lifecycle models
|   |   |   |-- service.py      # Group Leader / Leaf async runtime
|   |   |   |-- solve.py        # Sub-agent solve loop
|   |   |   `-- tooling.py      # Sub-agent tool registration & constraints
|   |   |-- runtime_state.py     # Runtime loop state
|   |   |-- loop_controller.py   # Auto / persistent main loop
|   |   |-- response_observations.py # Non-finding observation recording (never creates findings)
|   |   |-- prompt_context.py    # Round context & attack summary
|   |   |-- solver.py            # Model-led solve engine
|   |   |-- team.py              # Role-based team planning & adaptive delegation
|   |   |-- roles.py             # Role registry & hard tool whitelist
|   |   |-- agent_state.py       # AgentState: evidence, steps, tool calls, completion gate
|   |   |-- memory.py            # Short/mid/long-term agent memory management
|   |   `-- ...
|   |-- cli/
|   |   |-- main.py              # CLI commands, doctor, web launcher
|   |   |-- tui.py               # TUI data classes, Rich dashboard, color constants
|   |   `-- tui_textual.py       # Textual-driven TUI workbench
|   |-- config/                  # Config schema, loading, saving, env override
|   |-- kb/                      # Knowledge base storage, retrieval, update
|   |-- mcp/                     # MCP lifecycle, registry, router
|   |-- findings/                # Structured submission, evidence snapshots, independent verification, PoC checks
|   |-- report/                  # Report rendering, filtering, findings.json/SARIF output
|   |-- skills/                  # Built-in markdown skills, loader, dispatcher
|   |-- target_state/            # Target history, preview, diff, rollback, resume
|   |-- web/                     # FastAPI backend, schemas, services, static frontend
|   `-- ...
|-- frontend/                    # React + TypeScript Web UI
|-- scripts/                     # Release preflight / dist validation
|-- tests/                       # Backend, CLI, MCP, release, web, report tests
|   |-- agent/                  # Agent-layer unit tests (subagent/context/token/streaming)
|   |-- cli/                    # CLI/TUI tests
|   `-- web/                    # Web API tests
|-- .github/workflows/           # CI / preflight / release workflows
|-- README.md                    # Chinese README
|-- README_EN.md                 # English README
|-- CHANGELOG.md                 # Changelog
|-- pyproject.toml               # Packaging metadata & Hatch build rules
`-- CONTRIBUTING.md              # This file (Chinese)
```

---

## 2. Code Navigation

Find the right module for your change quickly.

### 2.1 Modifying Agent Behavior → `vulnclaw/agent/`

Applies to:
- Autonomous / persistent pentest loop behavior
- Tool call orchestration
- LLM request & response handling
- Recon / CTF / anti-loop logic
- Finding lifecycle, evidence levels, result parsing
- Context budget & compaction (`context_budget.py`)
- Sub-agent fan-out & merging (`subagent/`)

`core.py` is the coordination shell. Prefer modifying the specific helper/module over piling logic into `core.py`.

**Context Budget**: All LLM call paths (including `structured_call` / team planner / adviser / report summary) must go through `context_budget.prepare_context()`. When adding new bypass LLM calls, always wrap with `_fit_context_window(agent, messages, tools, purpose="...")`.

**Sub-Agents**: `subagent/` is an independent fan-out runtime. When modifying fan-out logic, note: `max_depth` is hard-capped at 2; all `SubagentConfig` numeric fields have `le=` upper bounds; subprocess exit must follow `terminate→wait→kill` three-stage cleanup; TUI rendering of sub-agent output must escape before writing to `markup=True` panels.

### 2.2 Modifying Shared Task Flow → `vulnclaw/orchestrator.py`

When the same behavior appears in both CLI and Web, consolidate it here.

### 2.3 Modifying CLI or REPL → `vulnclaw/cli/main.py`

This layer handles entry points, parameter binding, and user output. Core pentest logic does not belong here.

### 2.4 Modifying TUI → `vulnclaw/cli/tui.py` / `vulnclaw/cli/tui_textual.py`

| File | Responsibility |
|------|------|
| `tui.py` | Data classes, Rich dashboard rendering, color constants, slash command registry |
| `tui_textual.py` | Textual App: DashboardScreen, CommandPalette, slash command handlers, sub-agent event monitoring |

### 2.5 Modifying Configuration → `vulnclaw/config/`

- `schema.py`: Configuration model definitions (LLM/MCP/Session/Safety/Subagent/Recon)
- `settings.py`: Loading, saving, env var overlay, legacy field migration

### 2.6–2.12

See the Chinese [CONTRIBUTING.md](CONTRIBUTING.md) for the full module-by-module guide (report, MCP, target-state, Web backend, Web UI, packaging, skills). The structure is identical; only the language differs.

---

## 3. Branch & PR Workflow

### 3.1 Branch Model

The repository uses a streamlined Git Flow with two long-lived branches:

| Branch | Role | Push Rules |
|--------|------|-----------|
| `main` | Production stable | PR merge only; no direct push, force push, or deletion |
| `dev` | Development integration | PR merge only; no direct push, force push, or deletion |

Temporary branches (delete after merge):

| Type | Naming | Base | Target |
|------|--------|------|--------|
| Feature | `feature/description` | dev | dev |
| Fix | `fix/description` | dev | dev |
| Docs | `docs/description` | dev | dev |

### 3.2 Standard Development Flow

```bash
# 1. Sync dev and create your branch
git checkout dev
git pull origin dev
git checkout -b feature/your-feature

# 2. Develop and commit (Conventional Commits)
git commit -m "feat: add new scanner integration"

# 3. Rebase on latest dev before PR
git fetch origin dev
git rebase origin/dev

# 4. Push and open PR targeting dev
git push origin feature/your-feature
```

### 3.3 PR Requirements

All PRs must:
- Reference an existing issue (`Fixes #123` or `Closes #123`)
- Pass CI checks (tests, build, lint)
- Have no unresolved review comments
- Be rebased on the target branch

**Review requirements:**
- Merge to `dev`: at least 1 maintainer approval
- Merge to `main`: repository owner or core maintainer approval

### 3.4 Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(optional scope): <short description>
```

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation change |
| `style` | Code formatting (no logic change) |
| `refactor` | Refactoring |
| `perf` | Performance improvement |
| `test` | Test-related |
| `chore` | Build/tooling/dependency change |

---

## 4. Pre-Submission Checklist

Before opening a PR, verify:

**Backend:**
```bash
ruff check vulnclaw tests
pytest -q
```

**Frontend:**
```bash
cd frontend
npm ci
npx tsc -b
```

**Check:**
1. Relevant tests pass
2. Documentation matches implementation
3. New logic is in the correct module, not stuffed back into a large file
4. If affecting version, CLI output, README, or packaging — related files are updated

---

## 5. Code Style

**Backend (Python):**
- Run `ruff check vulnclaw tests` (config in `pyproject.toml`)
- Line length limit: 100 characters
- Target Python: 3.10+

**Frontend (TypeScript/React):**
- Run `npx tsc -b` for type checking
- Follow existing React component patterns

**General:**
- Single-responsibility functions
- Prefer early returns
- Use try/catch for error handling
- Avoid `any` in TypeScript
- Prefer `const` over `let`
- Clear, concise English naming

---

## 6. International Contributions

Non-Chinese-speaking contributors are welcome! Here's how to get started:

1. **README_EN.md** is the English documentation — check it first
2. **Code comments** are primarily in Chinese, but English comments are welcome
3. **Issues and PRs** can be written in English
4. **i18n**: The project supports Chinese/English UI — see `vulnclaw/i18n/`
5. If you need help translating a section of Chinese documentation, feel free to ask in an issue

---

<div align="center">

> 🦞 **VulnClaw** — Every pentest should follow a process.

</div>
