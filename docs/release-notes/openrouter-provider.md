# OpenRouter provider preset

## English

VulnClaw now includes OpenRouter as a first-class LLM Provider Preset across configuration, both terminal interfaces, and Web settings. The preset uses the reviewed `https://openrouter.ai/api/v1` endpoint, the `openai/gpt-4o` default Model ID, existing generic static-key settings, authenticated capability-aware model discovery, required-parameter enforcement, and sanitized bounded error handling.

OpenRouter is a Model Gateway. Its default routing can select or fall back across multiple Upstream Model Providers, which have independent retention and training policies. OpenRouter also retains request metadata. Review account privacy, data-collection, and ZDR settings before sending sensitive target data; this release does not promise end-to-end zero retention. Prefer a dedicated static inference key with a spending cap. Free variants and dynamic routers trade availability and determinism for convenience.

Deployment requires no migration, dependency change, or new environment variable. Supply an inference key through `VULNCLAW_LLM_API_KEY` or the existing configuration fields and allow outbound HTTPS to `openrouter.ai`. Deploy the backend and built frontend together. Rollback is code-only; older releases preserve the persisted `openrouter` string as a custom/unknown provider value.

## 中文

VulnClaw 现已在配置、两套终端界面和 Web 设置中将 OpenRouter 作为一等 LLM Provider Preset。该预设使用经过审查的 `https://openrouter.ai/api/v1` 端点、默认 Model ID `openai/gpt-4o`、现有通用静态密钥配置、带认证的能力过滤模型发现、必需参数强制策略，以及经过清理且有界的错误处理。

OpenRouter 是模型网关。默认路由可能选择多个上游模型提供商或在它们之间回退，而这些上游有独立的数据保留和训练政策；OpenRouter 也会保留请求元数据。发送敏感目标数据前请检查账户隐私、数据收集和 ZDR 设置；本版本不承诺端到端零保留。建议使用带消费上限的专用静态推理密钥。免费模型和动态路由器以可用性与确定性换取便利。

部署不需要迁移、依赖变更或新的环境变量。通过 `VULNCLAW_LLM_API_KEY` 或现有配置字段提供推理密钥，并允许到 `openrouter.ai` 的出站 HTTPS；后端与构建后的前端应一起部署。回滚只需回滚代码；旧版本会把已持久化的 `openrouter` 字符串保留为自定义或未知提供商值。
