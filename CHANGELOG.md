# 更新日志

---

<details>
<summary><strong>Unreleased</strong> — 语言支持（bilingual UI）</summary>

- **新增英文 / 中文双语界面** — 默认语言改为英文（无法识别环境信号时不再落到中文）。CLI/REPL 工具调用行、状态横幅、solve 报告标题、知识库状态、上下文截断提示、LLM 重试/恢复提示与推理状态块均随当前语言输出；zh 模式下输出保持逐字节不变。切换方式：REPL `/language` 命令、`VULNCLAW_LANG=zh|en` 环境变量、`session.language` 配置。
- **修复 `/language` 命令输出** — 移除确认文本前的多余 ASCII 字母 `f`。
- **Agent 英文关键词支持** — finding parser、阶段检测、CTF 判定、输入分析、认证墙、技能分发与 MCP 路由等识别表补充英文等价信号词，英文提示下子 agent 的发现分类、阶段迁移与技能注入与中文模式一致。
- **知识库状态本地化** — KB 初始化/降级/禁用详情随当前语言输出。

</details>

<details open>
<summary><strong>v0.3.7</strong> — sub-agent fan-out + cold/hot memory + context budget</summary>

- **新增模型驱动的并行子 Agent 扇出** — 默认 solve 引擎新增 `spawn_subagents` 工具，主模型可在一轮内提交多个独立、自包含的攻击方向并发探索；子循环继承目标约束与已有证据，禁用递归扇出并采用单次/并发/每次 solve 生命周期预算。子证据合并回父状态时统一重分配 `eNNN`，同步修正 claim、pin、progress signal 和 tool-call 引用；CLI 新增 fan-out 生命周期事件展示。
- **新增 TUI 子代理实时监控面板** — Textual TUI 执行任务时通过带随机会话令牌的私有 JSON 行协议接收 `spawn/start/progress/finish/batch_done` 事件，按批次实时展示每个子代理的角色、状态、步数、目标或最新进展；每次执行使用独立 `run_id`、输出队列和事件 token，旧 worker 的迟到输出、结束哨兵及定时器不会污染或提前终止新任务。普通 CLI 日志保持不变，窄终端仍可从原始日志查看事件。
- **新增冷热记忆分离** — 会话历史超过 48 条消息或 32K token 时，旧消息自动归档到冷记忆 JSONL 分片（每 64MB 轮转，最多 8 分片），热上下文仅保留近期完整工具交换组；新增 `memory_search` 工具从冷记忆按关键词检索带上下文的片段。`ContextManager` 新增 `max_tokens`/`search_max_chars` 配置，大工具输出超预算时自动归档并替换为冷记忆指针+预览。`/compact` 改用 `group_tool_exchanges` 按工具交换组原子切分，不再拆散 assistant `tool_calls` 与对应 `tool` 消息。`_trim()` 改为 token+条数双重安全网，不再直接丢弃最早消息。
- **新增统一上下文预算与结构化压缩** — `context_budget.py` 提供 `prepare_context()` 唯一预算入口，覆盖所有 LLM 调用路径（`call_llm`/`call_llm_auto`/`call_llm_stream`/`call_llm_auto_stream`/`structured_call`/team planner/adviser/report summary）。预算公式：`usable = max_context_tokens - output_reserve`，trigger=usable×0.70，target=usable×0.55；工具 schema token 计入预算。压缩时按不可拆分工具组分组、保留最近 N 组、其余生成确定性 `[context digest v1]` 摘要（含 target/scope/verified_claims/pinned_facts/evidence 引用），原子回写 `ContextManager.replace_history_with_digest`。审计事件记录前后 token/原因/组数/evidence IDs，敏感字段（authorization/cookie/api_key）自动脱敏。新增 `ContextBudget`/`ContextCompactionResult`/`ContextDigest`/`ContextCompactionEvent` 类型。配置：`context_auto_compact=true`（默认启用）、`context_compact_trigger_ratio=0.70`、`context_compact_target_ratio=0.55`、`context_recent_message_groups=12`、`context_summary_max_tokens=3500`、`context_output_reserve_tokens=0`（自动取 min(max_tokens,8192)）、`context_compaction_mode=structured`、`context_compaction_audit_enabled=true`。旧 `solve_auto_compact`/`solve_compact_trigger_ratio` 标 deprecated，未显式设置新字段时自动迁移。
- **修复子 Agent 合并边界与审计完整性** — 父状态合并子 Agent 证据及辅助历史时继续遵守各项硬容量上限并清理淘汰引用；`spawn_subagents` 作为本地调度元工具不再被误判为 scan，子会话的约束违规消息与结构化事件会完整合并；所有子 Agent 预算/容量配置拒绝零值和负数。仅当子 Agent 在进入 `child_solve`（即启动 LLM/工具）之前的工厂/种子/setup 阶段失败时才退还其生命周期预算（确定零成本）；一旦进入 `child_solve` 即计入预算，避免昂贵的后期失败悄悄回收扇出广度。`max_concurrent` 文档提示：使用 chrome-devtools/burp 等外部 stdio MCP 时应设为 1，避免并发子 Agent 共享单条 stdio 会话交错。
- **加固子 Agent 扇出安全与子进程生命周期** — `SubagentConfig` 全部数值项补上界 `le=`（`max_depth` 硬顶为 2，防止逐层预算叠乘导致扇出指数爆炸），越界的 `VULNCLAW_SUBAGENT_*` 环境变量改为拒绝并告警而非静默丢弃；修复子证据合并后 `duplicate_of` 在源证据被容量截断丢弃时残留指向子侧 id 的悬挂引用（改为清空，避免后续随 `evidence_seq` 增长误解析到无关证据）；TUI 输出日志对来自子进程的不可信内容（子代理 `goal`/`NO_PATH` 复述等）先转义再写入 `markup=True` 面板，杜绝 `[/quote]` 等未闭合标签触发 `MarkupError` 击穿 TUI，或 `[link=]`/`[red]` 注入操作员终端；子进程中断/切换/退出改为 `terminate→wait→kill` 三段式并在退出时统一清理，子进程为 `SIGTERM` 注册与 `SIGINT` 一致的清理入口，避免遗留 MCP/nmap 孙进程被孤儿化。
- **重构工具循环上下文管理** — `call_llm_auto`/`call_llm_auto_stream` 不再每轮截断全部历史，而是构建稳定前缀（system prompt + 有界历史 + 任务指令）+ 可变工具循环尾部；仅在尾部超过高水位（默认 32K）时压缩至目标（26K），保留稳定前缀和近期完整工具交换组，减少不必要的上下文丢失。流式调用改为 `asyncio.to_thread` 包装同步 provider stream，避免子代理并发时阻塞事件循环。
- **Skill 参考资料化架构** — skill resolver 现在只向 prompt 注入可选参考索引（skill 名称、描述、reference 文件列表和路由原因），不再自动注入 primary skill 正文、默认 `pentest-flow` 剧本或 WAF 绕过知识。`load_skill_reference` 被定义为模型自主选择的参考资料读取工具，返回内容不再视为强制流程、阶段计划或工具调度。
- **纠偏层去命令化** — solve 系统提示和 correction layer 改为输出 diagnostic notes：只描述工具健康、重复调用、same-body、parser/filter、POP 链等证据状态，不再直接命令模型“必须使用某工具/某 payload/某验证顺序”。`NO_PATH`/`ASK_USER` 闸门只说明未解决的高信号证据，不替模型规划下一步。
- **架构调整 active context 证据工作集** — 大工具输出仍完整写入 `AgentState.evidence`，但默认不再把完整 HTML/body/stdout/stderr 重复塞进模型 active context；模型可见 tool transcript 使用 bounded high-signal preview，包含 raw size/hash、关键行、表单/参数、endpoint、源码 sink/filter、flag-like token 和请求面摘要。新增 `evidence_search` 用于在 raw evidence 中按关键词/正则查找精确片段；`evidence_view` 继续用于分页查看原始证据。相同 raw 输出再次出现时只注入 `same_as=eXXX` 引用，减少 context rot，同时不牺牲证据闸门、报告和按需回查的完整性。

- **修复 PHP5 反序列化差分误判** — `http_probe_batch` 现在会把响应头写入证据并默认关闭 TLS 校验，`runtime_diff_probe` 可从 `X-Powered-By: PHP/5.x` 推断目标运行时；遇到 `O:+n:` / `C:+n:` 这类 signed length 候选时，会明确标记为必须远程验证，防止模型把本地新版 PHP 的 `unserialize_ok=false` 误判成远程不可利用。
- **增强 PHP POP 链高信号记忆** — 看到 `unserialize`、魔术方法和 `eval/assert/system/exec` 等 sink 同时出现时，会固定“魔术方法入口对象 → sink 对象”的对象图提示，避免模型只序列化 sink 类而漏掉真正触发链。
- **强化 `fetch` HTTPS 兼容性** — 即使模型显式传入 `verify_tls=true`，证书链校验失败时也会自动以 `verify_tls=false` 重试一次，并在工具结果中标注，减少 CTF/lab 站点因本机 CA 问题浪费一次模型回合。
- **强化外部题解类 `ASK_USER` 闸门** — 当 flag/shell 目标仍有 parser/filter、源码 sink、请求面等高信号证据时，模型重复询问“是否查看公开题解/外部资料”会持续被拒绝；真正的授权、凭证、范围问题仍允许询问用户。
- **新增 `runtime_diff_probe` 运行时差分探测工具** — 模型在遇到“正则/字符串过滤器 → 运行时解析器/解释器”的边界时，可按需批量生成并验证 parser-accepted/filter-missed 候选；当前支持通用 regex 检查和 PHP serialize/unserialize 本地差分，并会提示目标/本地运行时版本不一致风险。
- **新增 `ASK_USER` 近成功防误停闸门** — 当目标仍要求 flag/shell 且已有源码 sink、parser/filter 边界、本地 proof、请求面等高信号证据时，不接受模型过早询问“是否查看外部题解/公开思路”，而是把拒绝原因反馈给模型继续做本地差分、精确编码或远程验证。
- **增强 parser/filter 纠偏记忆** — correction layer 会固定 `preg_match`/regex/blacklist 与 `unserialize`、模板、表达式、XML/JSON 等运行时解析器之间的边界事实，并提示优先用小规模差分实验代替大范围 payload 猜测。
- **重构默认 solve 引擎为模型主导模式** — 删除旧 `ResearchState` / 研究方向 / plan-action-observe 生命周期；solve 现在像 Claude Code/Codex 一样由模型自行决定下一步、工具调用、`FINAL:` 完成、`ASK_USER:` 询问或 `NO_PATH:` 终止。
- **新增 `AgentState` 证据记忆** — 工具结果统一写入 `AgentState.evidence` 并完整保留 raw；active context 默认使用高信号预览，新增 `evidence_list` / `evidence_search` / `evidence_view` 让模型按需回看历史证据。
- **改为 Codex-style 工具 transcript** — solve 工具调用后会把 assistant `tool_calls` 与 `role=tool` 结果追加进模型上下文，并继续采样；只有 provider 拒绝 tool transcript 时才降级为完整工具文本，避免旧的 `Summarizing...` 摘要污染上下文。
- **新增 `shell_command` 内置工具** — 模型可按需运行本地 `php -r`、`curl`、`rg`/`Select-String` 等命令做精确验证；默认完整返回 stdout/stderr，可用 `max_output_chars` 主动裁剪。
- **新增源码自动还原能力** — `fetch` / `http_probe_batch` 遇到 `highlight_file`、HTML 高亮源码和混杂 HTML/JS body 时，会自动在 raw body 前追加 clean source；`source_extract` 仍可按需重读历史 evidence 并提取危险 sink、服务器端源码线索、表单、input 与 endpoint 信号。修复高亮源码 `<span>` 被误当成换行导致源码 token 化、模型无法准确读代码的问题。
- **新增轻量纠偏层** — 记录工具耗时、失败降级、重复调用、请求面、same-body/响应差异和新发现信号，作为 AgentState prompt hint 提供给模型；纠偏层不做阶段规划、不主动安排工具。
- **新增高信号证据固定** — 从工具原始输出中提取源码 SQL、HTML 表单/input、PHP/API 链接和 JavaScript endpoint 构造，写入长期可见 pinned facts，避免后续 HTTP 试错把真实入口淹没；SQL 源码场景会提示模型优先从服务端表达式推导 payload，并在 comment 结尾失败时尝试 no-comment 小步变体。
- **新增 `http_probe_batch` 内置工具** — 一次比较多组 URL/参数/header/body/raw URL 变体，返回状态码、长度、hash、title、关键 body 信号、实际请求面、完整 body 和 same-body 分组；`max_body_chars` 只有显式设为正数时才裁剪。复杂 Cookie/精确编码 payload 推荐使用 `headers.Cookie`，输出会展示模型实际发送的 method/URL/params/headers/cookies/body/json。
- **新增 `NO_PATH` 近成功防误停闸门** — 当源码 sink、表单/参数、请求面、本地 proof、same-body/响应差异等高信号证据仍未耗尽时，solve 会拒绝模型因单次 payload 无回显或远端 same-body 就提前停止，并把“验证 method/URL/headers/cookies/body、编码、触发条件和替代回显通道”的纠偏提示反馈给模型继续行动。
- **增强 `fetch` 本地工具** — 默认 GET，支持 HTTP/HTTPS、自定义 method/headers/params/cookies/body/data/form/json、timeout/follow_redirects/verify_tls/max_body_chars；默认返回完整响应 body，CTF/靶场 HTTPS 默认不校验证书，减少模型退回 `python_execute` 手写请求的 token 消耗。
- **工具输出改为 raw evidence + active preview** — `python_execute` / `shell_command` / HTTP 工具默认完整保存 raw stdout/stderr/body 到 `AgentState.evidence`；大输出进入模型上下文时改为 bounded high-signal preview，显式配置正数上限时仍可在工具层主动裁剪 raw 输出。
- **修复终端 payload 渲染崩溃** — 工具输出、工具参数和 solve 观察摘要改为 Rich 纯文本渲染，避免 SQL payload 中的 `[/**/]`、`[xxx]` 被误解析为 Rich markup 标签。
- **修复证据查看空转问题** — `evidence_view` / `evidence_list` 现在会写入 AgentState 工具调用记录；重复读取同一 evidence 覆盖范围会被短路，连续多轮只有证据查看且没有新增 evidence 时触发 stall guard，避免模型把预算耗在反复翻同一批日志上。
- **保留 `python_execute` 原始证据** — `python_execute` 的完整 stdout/stderr 会写入 AgentState；小输出可直接进入 active context，大输出使用高信号预览，`python_execute_max_output_chars` 显式设为正数时才在工具层裁剪 raw 输出。
- **保留并强化证据闸门** — `FINAL:` 声称的 flag/结论必须由真实工具输出支撑或引用证据编号；不满足时不会假完成，而是把拒绝原因反馈给模型继续探索。
- **新增 solve 自动复盘报告** — 目标达成后基于 `AgentState` 确定性生成 Markdown 报告并默认打印，包含解题思路、关键证据、复现请求包、curl、响应片段和证据索引；新增 `session.solve_auto_report` / `session.solve_report_show` 配置。
- **上下文压缩改为显式/必要时触发** — solve 默认保留正常历史；仅在上下文接近上限、用户执行 `/compact` 或显式启用自动压缩时压缩。
- **工具改为可用能力清单** — 目录扫描、JS 收集、空间测绘、nmap、skill 读取等只作为工具暴露，框架不再按阶段模板主动安排。
- **工具失败不再打崩 solve** — MCP/browser 初始化失败、AnyIO cancel-scope 清理噪声等会作为工具失败证据返回给模型，模型可继续改用其他工具。
- **进度显示改为 Turn** — CLI 不再显示 `Step x/N`，`solve_max_steps` 明确为防失控安全预算，不作为模型工作流轮数；默认安全预算从 80 提高到 240，避免慢模型在接近答案时被过早截断。
- **导入授权红队 Skill** — 吸收 `codex-redteam-mode` 的授权红队 detail packs 到 `vulnclaw/skills/specialized/`；jailbreak、拒绝绕过、会话 patch 等破限内容未导入。
- **新增 SQL 注入实战知识条目** — 基于 fushuling《SQL注入一命通关!》二次整理 `web-sqli-fushuling-one-pass.md`，并接入 `secknowledge-skill` 路由和内置 KB seed。

</details>

---

<details>
<summary><strong>v0.4.1</strong> — 并行探索 + 记忆引擎 + 信息收集工具链 + MCP streamable-http</summary>

- **多方向并行探索** — solve 引擎支持同时探索多个方向（默认 max_parallel=3），单个方向异常不影响其他，每个方向有独立的证据缓冲区和工具调用记录。
- **agent 记忆引擎** — 共享研究状态新增工具调用日志（跨方向可见），reason 阶段显式列出已放弃方向并禁止重复提出，explore 上下文带"已执行工具"摘要；checkpoint 机制在图状态没变时跳过 reason 避免空转；已放弃方向做 Jaccard 去重兜底。
- **结论判定优化** — 放宽了"有进展"的标准（发现新接口、确认未授权都算推进），不再轻易丢弃有价值的发现；最后一步增加证据复核，防止误判丢弃实际有数据返回的探索。
- **完成判定否定闸门** — 模型在 complete 字段里写"未达到完成标准"等否定结论时不会再被误判为已完成；显式要求 complete=true 布尔值 + evidence fact 引用。
- **JS 信息收集（js_recon）** — 抓取页面及全部 JS 文件，提取 API 路径 / 关联域名 / 硬编码密钥；动态发现 PascalCase 实体名并与 base path + CRUD 动词排列组合推断隐藏接口；收集到的接口自动做 GET+POST 未授权探测。
- **未授权探测（unauth_test）** — 批量无凭据请求，按状态码/响应体/内容类型判定；支持有/无 token 差分对比确认未授权；自动跳过 delete/save/sms 等破坏性接口。
- **目录枚举（dir_enum）** — 并发字典爆破，带 404 基线与全局伪装 200 识别（随机路径返回 200 自动停止），状态码与响应长度过滤。
- **空间测绘（space_search）** — FOFA / Hunter / Quake / Shodan / ZoomEye / 0.zone 六引擎统一查询，engine=all 时并发查询所有已配置 key 的引擎。
- **子域名枚举（subdomain_enum）** — 空间测绘被动聚合 + 内置字典 DNS 爆破，自动去重。
- **MCP streamable-http 支持** — 支持 Chrome DevTools MCP 等 HTTP 传输的 MCP 服务器；惰性连接（启动时不占 session slot）；首次调用时自动建连 + 工具发现；连接失败降级为 service_unavailable 不影响 solve 循环。
- **Chrome MCP 工具名修正** — 占位工具改为真实 Chrome MCP 工具名（chrome_navigate / chrome_read_page / chrome_pentest_* 等）。
- 工具返回 undefined 标记为失败而非静默成功；事实序号 / 方向序号在 session 恢复后正确续接；新增 ReconConfig 配置区块与 solve_max_parallel 配置项。

</details>

<details>
<summary><strong>v0.4.0</strong> — 核心：自主引擎从「固定轮数工作流」重构为「目标驱动求解」</summary>

- **新增目标驱动求解引擎（默认）** — 基于已验证事实、研究方向与证据记录的计划/行动循环，以「目标达成 / 研究方向耗尽 / 安全预算」为终止条件，结构上杜绝"原地打转"；新增 `vulnclaw solve` 命令，`run`/REPL 自主模式默认改走该引擎（`session.engine=rounds` 可回退旧逻辑）。
- **新增证据级反幻觉闸门** — 录制所有真实工具输出作为唯一可信证据；声称的 flag/完成必须在真实输出里逐字符出现才被采信，否则判定幻觉并继续探索；拿到验证过的 flag 即时收敛。
- **新增结构化推理 + 自适应反思** — 已知事实（带置信度）/约束/攻击链结构化沉淀并注入提示词；失败自动归类并按 L0–L4 渐进升级 payload 绕过策略，persistent 模式跨周期保留失败记忆。
- **新增漏洞检测插件体系** — 低耦合插件运行时 + 内置只读 Web 插件（安全响应头 / JWT / JS 端点），结果可去重合并进 findings 与报告链路；新增 `vulnclaw plugins list/info/run` 命令。
- **修复 #45 工具被误约束** — 动作约束不再把 HTTP 方法（OPTIONS/POST）或使用 `requests` 误判为「利用」；只有实际攻击载荷（SQLi/RCE/路径穿越等）才算 exploit；`load_skill_reference`/`crypto_decode` 等纯本地工具豁免范围约束。
- 新增 `session.engine` / `solve_*` / `reflexion_*` / `plugin_*` 等配置项，均支持环境变量注入。

</details>
