"""Information-gathering tools: space-mapping, subdomain/JS/dir enumeration.

These are built-in agent tools (wired in builtin_tools.py) that give the agent
real reconnaissance capability instead of guessing:

- space_search      统一空间测绘 (FOFA / Hunter / Quake / Shodan / ZoomEye / 0.zone)
- subdomain_enum    子域名枚举 (空间测绘被动聚合 + 可选小字典 DNS 爆破)
- js_recon          JS 信息收集 (参考 URLFinder：抓 JS 提端点/域名/密钥)
- dir_enum          目录枚举 (参考 dirsearch：并发字典爆破 + 404 基线/伪装识别)

设计原则：被动优先、严格遵守 host/path/port 约束、所有外呼带超时与并发上限、
绝不在源码里硬编码任何 API key（从 config.recon 或环境变量读取）。
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import socket
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urljoin, urlparse

from vulnclaw.agent.builtin_tools import enforce_host_path_constraints

# ── 内置目录字典（紧凑版；config.recon.dir_wordlist_path 可覆盖为大字典）────────
_BUILTIN_DIR_WORDLIST: tuple[str, ...] = (
    # 后台 / 管理
    "admin", "admin/login", "administrator", "manage", "manager", "backend", "system",
    "console", "ht", "qd", "dashboard", "admin.php", "admin.jsp", "admin.do", "login",
    "login.jsp", "login.php", "login.action", "signin", "auth", "sso", "cas",
    # API / 文档
    "api", "api/v1", "api/v2", "v1", "v2", "graphql", "swagger", "swagger-ui.html",
    "swagger/index.html", "v2/api-docs", "openapi.json", "api-docs", "actuator",
    "actuator/env", "actuator/health", "druid", "druid/index.html",
    # 配置 / 调试 / 信息泄露
    "config", "config.json", "config.php", "configuration", "env", ".env", ".git/config",
    ".git/HEAD", ".svn/entries", ".DS_Store", "debug", "test", "demo", "info", "info.php",
    "phpinfo.php", "status", "health", "metrics", "monitor", "console", "server-status",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "web.config", "WEB-INF/web.xml",
    # 备份 / 临时
    "backup", "backup.zip", "backup.tar.gz", "bak", "old", "www.zip", "web.zip",
    "site.zip", "data.zip", "db.sql", "database.sql", "dump.sql", "test.txt", "1.txt",
    # 上传 / 文件
    "upload", "uploads", "files", "file", "download", "static", "assets", "public",
    "tmp", "temp", "images", "img", "data", "doc", "docs",
    # 业务常见（中英混杂拼音）
    "user", "users", "member", "hy", "order", "dd", "pay", "payment", "list", "index",
    "home", "main", "portal", "wx", "mp", "xcx", "miniprogram", "h5", "mobile",
)

# ── 端点提取正则（参考 URLFinder）──────────────────────────────────────────────
_URL_RE = re.compile(r"""https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[^\s"'`<>()\\{}|^]*)?""")
# 宽泛路径提取：任何引号内以 / 开头、含 2+ 段的路径（参考 URLFinder 的宽匹配策略）
_PATH_RE = re.compile(
    r"""(?P<q>["'`])(?P<v>/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-./?=&%]*)(?P=q)""",
    re.IGNORECASE,
)
# 短片段提取：不以 / 开头但看起来像 REST 端点的引号内字符串（如 "User/list"）
# 动词后允许跟 ForXxx / All / ById 等框架变体（listForLayUI、getAllByType...）
_FRAG_RE = re.compile(
    r"""(?P<q>["'`])(?P<v>[A-Za-z][A-Za-z0-9_]*/(?:list|save|get|add|edit|delete|update|"""
    r"""detail|query|search|info|check|export|import|download|upload|count|page|batch|"""
    r"""remove|create|modify|status|enable|disable|reset|send|verify|login|logout|"""
    r"""register|authorize|token|refresh|config|setting|menu|role|permission|tree|"""
    r"""all|find|select|insert|submit|audit|approve|reject|publish|cancel|close|open|"""
    r"""start|stop|run|execute|invoke|call|notify|push|pull|sync|async)"""
    r"""(?:[A-Z][a-zA-Z0-9]*)*"""
    r"""[a-zA-Z0-9_\-./?=&%]*)(?P=q)""",
    re.IGNORECASE,
)
# REST base path 提取：如 "/jalis/rest"、"/smweb/rest"、"/api/v1"
_BASE_PATH_RE = re.compile(
    r"""(?P<q>["'`])(?P<v>/[a-zA-Z0-9_\-]+/(?:rest|api(?:/v\d+)?))(?P=q)""",
    re.IGNORECASE,
)
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']?([^"'\s>]+)""", re.IGNORECASE)

# CRUD 动词模板——与 base path 和 JS 中出现的实体名排列组合
_CRUD_VERBS = ("list", "get", "save", "add", "delete", "update", "detail", "query",
               "info", "export", "tree", "page", "count", "all", "search")
# 动态实体名提取：从 JS 中找所有 PascalCase 标识符（首字母大写、2+ 字母），
# 而非硬编码实体列表——任何业务实体都能被捕获
_PASCAL_CASE_RE = re.compile(
    r"""(?P<q>["'`])(?P<v>[A-Z][a-zA-Z0-9]{1,30}(?:[A-Z][a-zA-Z0-9]*)*)(?P=q)"""
)

# 敏感信息 / 凭证泄露指纹
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_ak", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PRIVATE) ?(?:PRIVATE )?KEY-----")),
    ("generic_key", re.compile(
        r"""(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key|app[_-]?secret|token|password|passwd)"""
        r"""["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_\-]{12,64})["'`]"""
    )),
    ("aliyun_ak", re.compile(r"LTAI[0-9A-Za-z]{12,24}")),
)


def _get_recon_cfg(agent: Any) -> Any:
    from vulnclaw.config.schema import ReconConfig

    cfg = getattr(getattr(agent, "config", None), "recon", None)
    return cfg if cfg is not None else ReconConfig()


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _host_of(url_or_host: str) -> str:
    if "://" in url_or_host:
        return (urlparse(url_or_host).hostname or "").lower()
    return url_or_host.split("/")[0].split(":")[0].lower()


def _dedup_cap(items: list[str], cap: int) -> list[str]:
    return list(dict.fromkeys(i for i in items if i))[:cap]


# ── 空间测绘引擎 ───────────────────────────────────────────────────────────────


async def _engine_fofa(client: Any, query: str, size: int, cfg: Any) -> tuple[list[dict], str]:
    if not (cfg.fofa_email and cfg.fofa_key):
        return [], "fofa: 未配置 fofa_email/fofa_key"
    fields = "host,ip,port,title,domain,server,protocol"
    params = {
        "email": cfg.fofa_email,
        "key": cfg.fofa_key,
        "qbase64": _b64(query),
        "fields": fields,
        "size": str(min(size, 10000)),
    }
    r = await client.get("https://fofa.info/api/v1/search/all", params=params)
    data = r.json()
    if data.get("error"):
        return [], f"fofa: {data.get('errmsg', 'error')}"
    recs = []
    for row in data.get("results", []) or []:
        row = (list(row) + [""] * 7)[:7]
        recs.append({
            "host": row[0], "ip": row[1], "port": row[2], "title": row[3],
            "domain": row[4], "server": row[5], "url": row[0],
        })
    return recs, f"fofa: {data.get('size', len(recs))} 命中"


async def _engine_hunter(client: Any, query: str, size: int, cfg: Any) -> tuple[list[dict], str]:
    if not cfg.hunter_key:
        return [], "hunter: 未配置 hunter_key"
    end = datetime.now()
    start = end - timedelta(days=365)
    params = {
        "api-key": cfg.hunter_key,
        "search": _b64(query),
        "page": "1",
        # Hunter 仅接受 [10,100] 的 page_size，过小会报「页面大小不合法」
        "page_size": str(min(max(size, 10), 100)),
        "is_web": "3",
        "start_time": start.strftime("%Y-%m-%d"),
        "end_time": end.strftime("%Y-%m-%d"),
    }
    r = await client.get("https://hunter.qianxin.com/openApi/search", params=params)
    data = r.json()
    if data.get("code") != 200:
        return [], f"hunter: {data.get('message', data.get('code'))}"
    arr = (data.get("data") or {}).get("arr") or []
    recs = []
    for it in arr:
        recs.append({
            "host": it.get("url") or it.get("domain", ""), "ip": it.get("ip", ""),
            "port": it.get("port", ""), "title": it.get("web_title", ""),
            "domain": it.get("domain", ""), "server": it.get("component", ""),
            "url": it.get("url", ""),
        })
    return recs, f"hunter: {(data.get('data') or {}).get('total', len(recs))} 命中"


async def _engine_quake(client: Any, query: str, size: int, cfg: Any) -> tuple[list[dict], str]:
    if not cfg.quake_key:
        return [], "quake: 未配置 quake_key"
    body = {"query": query, "start": 0, "size": min(size, 100), "ignore_cache": True}
    r = await client.post(
        "https://quake.360.net/api/v3/search/quake_service",
        headers={"X-QuakeToken": cfg.quake_key, "Content-Type": "application/json"},
        content=json.dumps(body),
    )
    data = r.json()
    if data.get("code") not in (0, "0"):
        return [], f"quake: {data.get('message', data.get('code'))}"
    recs = []
    for it in data.get("data", []) or []:
        svc = it.get("service", {}) or {}
        http = svc.get("http", {}) or {}
        recs.append({
            "host": http.get("host") or it.get("ip", ""), "ip": it.get("ip", ""),
            "port": it.get("port", ""), "title": http.get("title", ""),
            "domain": it.get("domain", ""), "server": svc.get("name", ""),
            "url": http.get("host", ""),
        })
    return recs, f"quake: {(data.get('meta') or {}).get('pagination', {}).get('total', len(recs))} 命中"


async def _engine_shodan(client: Any, query: str, size: int, cfg: Any) -> tuple[list[dict], str]:
    if not cfg.shodan_key:
        return [], "shodan: 未配置 shodan_key"
    r = await client.get(
        "https://api.shodan.io/shodan/host/search",
        params={"key": cfg.shodan_key, "query": query},
    )
    data = r.json()
    if "matches" not in data:
        return [], f"shodan: {data.get('error', 'no matches')}"
    recs = []
    for it in data.get("matches", []):
        hostnames = it.get("hostnames") or []
        recs.append({
            "host": (hostnames[0] if hostnames else it.get("ip_str", "")),
            "ip": it.get("ip_str", ""), "port": it.get("port", ""),
            "title": (it.get("http", {}) or {}).get("title", ""),
            "domain": ",".join(it.get("domains") or []),
            "server": it.get("product", ""), "url": (hostnames[0] if hostnames else ""),
        })
    return recs, f"shodan: {data.get('total', len(recs))} 命中"


async def _engine_zoomeye(client: Any, query: str, size: int, cfg: Any) -> tuple[list[dict], str]:
    if not cfg.zoomeye_key:
        return [], "zoomeye: 未配置 zoomeye_key"
    body = {"qbase64": _b64(query), "page": 1, "pagesize": min(size, 100)}
    r = await client.post(
        "https://api.zoomeye.org/v2/search",
        headers={"API-KEY": cfg.zoomeye_key, "Content-Type": "application/json"},
        content=json.dumps(body),
    )
    data = r.json()
    if data.get("code") not in (60000, 0, None) and "data" not in data:
        return [], f"zoomeye: {data.get('message', data.get('code'))}"
    recs = []
    for it in data.get("data", []) or []:
        recs.append({
            "host": it.get("url") or it.get("domain") or it.get("ip", ""),
            "ip": it.get("ip", ""), "port": it.get("port", ""),
            "title": it.get("title", ""), "domain": it.get("domain", ""),
            "server": it.get("product", ""), "url": it.get("url", ""),
        })
    return recs, f"zoomeye: {data.get('total', len(recs))} 命中"


async def _engine_zerozone(client: Any, query: str, size: int, cfg: Any) -> tuple[list[dict], str]:
    if not cfg.zerozone_key:
        return [], "zerozone: 未配置 zerozone_key"
    body = {
        "title": query, "query_type": "site", "page": 1,
        "pagesize": min(size, 100), "zone_key_id": cfg.zerozone_key,
    }
    r = await client.post(
        "https://0.zone/api/data/",
        headers={"Content-Type": "application/json"},
        content=json.dumps(body),
    )
    data = r.json()
    items = data.get("data") if isinstance(data.get("data"), list) else []
    if not items and data.get("code") not in (0, 200, None):
        return [], f"zerozone: {data.get('message', data.get('code'))}"
    recs = []
    for it in items:
        recs.append({
            "host": it.get("url") or it.get("domain", ""), "ip": it.get("ip", ""),
            "port": it.get("port", ""), "title": it.get("title", ""),
            "domain": it.get("domain", ""), "server": it.get("server", ""),
            "url": it.get("url", ""),
        })
    return recs, f"zerozone: {data.get('total', len(recs))} 命中"


_ENGINES = {
    "fofa": _engine_fofa, "hunter": _engine_hunter, "quake": _engine_quake,
    "shodan": _engine_shodan, "zoomeye": _engine_zoomeye, "zerozone": _engine_zerozone,
}

# 仅给定 domain 时，各引擎的默认查询语法
_DOMAIN_QUERY = {
    "fofa": 'domain="{d}"', "hunter": 'domain="{d}"', "quake": 'domain:"{d}"',
    "shodan": "hostname:{d}", "zoomeye": 'hostname:"{d}"', "zerozone": "{d}",
}


def _make_client(cfg: Any):
    import httpx

    return httpx.AsyncClient(verify=False, timeout=cfg.http_timeout, follow_redirects=True)


async def execute_space_search(agent: Any, args: dict[str, Any]) -> str:
    """统一空间测绘查询。engine ∈ {fofa,hunter,quake,shodan,zoomeye,zerozone,all}。"""
    cfg = _get_recon_cfg(agent)
    engine = str(args.get("engine", "fofa") or "fofa").strip().lower()
    query = str(args.get("query", "") or "").strip()
    domain = str(args.get("domain", "") or "").strip()
    size = int(args.get("size", cfg.space_size) or cfg.space_size)

    if not query and not domain:
        return "[!] space_search 需要 query 或 domain 参数"

    engines = list(_ENGINES) if engine == "all" else [engine]
    invalid = [e for e in engines if e not in _ENGINES]
    if invalid:
        return f"[!] 不支持的 engine: {', '.join(invalid)}；可选: {', '.join(_ENGINES)}, all"

    out: list[str] = [f"# 空间测绘 — {'/'.join(engines)}  query={query or domain}"]
    try:
        async with _make_client(cfg) as client:
            async def run(eng: str) -> tuple[str, list[dict], str]:
                q = query or _DOMAIN_QUERY[eng].format(d=domain)
                try:
                    recs, note = await _ENGINES[eng](client, q, size, cfg)
                    return eng, recs, note
                except Exception as e:  # 单引擎失败不影响其他引擎
                    return eng, [], f"{eng}: 请求异常 {e}"

            results = await asyncio.gather(*(run(e) for e in engines))
    except Exception as e:
        return f"[!] space_search 执行错误: {e}"

    for eng, recs, note in results:
        out.append(f"\n## {note}")
        for rec in recs[:size]:
            line = f"  {rec.get('ip',''):<16}:{str(rec.get('port','')):<6} {rec.get('host','')}"
            extra = " | ".join(x for x in (rec.get("title", ""), rec.get("server", "")) if x)
            out.append(line + (f"  [{extra}]" if extra else ""))
        if not recs:
            out.append("  (无结果或未配置 key)")
    return "\n".join(out)


# ── 子域名枚举 ─────────────────────────────────────────────────────────────────

_SUBDOMAIN_BRUTE = (
    "www", "api", "app", "m", "mail", "admin", "test", "dev", "stage", "uat", "pre",
    "static", "cdn", "img", "static1", "oa", "vpn", "sso", "cas", "auth", "portal",
    "gateway", "gw", "open", "service", "wx", "mp", "h5", "pay", "passport", "id",
    "data", "db", "file", "files", "upload", "download", "docs", "wiki", "git", "svn",
    "jenkins", "ci", "monitor", "grafana", "kibana", "es", "redis", "mysql", "nacos",
)


async def execute_subdomain_enum(agent: Any, args: dict[str, Any]) -> str:
    """子域名枚举：空间测绘被动聚合 + 可选小字典 DNS 爆破。"""
    cfg = _get_recon_cfg(agent)
    domain = str(args.get("domain", "") or "").strip().lower()
    if not domain:
        return "[!] subdomain_enum 需要 domain 参数"
    if "://" in domain:
        domain = _host_of(domain)

    do_brute = bool(args.get("brute", True))
    found: set[str] = set()
    notes: list[str] = []

    # 1) 被动：从各空间测绘引擎聚合
    engines = [e for e in _ENGINES if getattr(cfg, _key_field(e))]
    if engines:
        try:
            async with _make_client(cfg) as client:
                async def run(eng: str):
                    q = _DOMAIN_QUERY[eng].format(d=domain)
                    try:
                        recs, note = await _ENGINES[eng](client, q, cfg.space_size, cfg)
                        notes.append(note)
                        for rec in recs:
                            for f in (rec.get("domain", ""), _host_of(rec.get("host", ""))):
                                if f and f.endswith(domain):
                                    found.add(f.lstrip("*.").lower())
                    except Exception as e:
                        notes.append(f"{eng}: 异常 {e}")
                await asyncio.gather(*(run(e) for e in engines))
        except Exception as e:
            notes.append(f"被动聚合异常: {e}")
    else:
        notes.append("未配置任何空间测绘 key，跳过被动聚合")

    # 2) 主动：小字典 DNS 解析爆破
    if do_brute:
        sem = asyncio.Semaphore(cfg.max_concurrency)
        loop = asyncio.get_running_loop()

        async def resolve(sub: str) -> None:
            host = f"{sub}.{domain}"
            async with sem:
                try:
                    await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, host), timeout=5
                    )
                    found.add(host)
                except Exception:
                    pass

        await asyncio.gather(*(resolve(s) for s in _SUBDOMAIN_BRUTE))
        notes.append(f"DNS 爆破字典 {len(_SUBDOMAIN_BRUTE)} 条")

    subs = sorted(found)
    head = [f"# 子域名枚举 — {domain}  共 {len(subs)} 个", "  " + "; ".join(notes)]
    return "\n".join(head + [f"  {s}" for s in subs]) if subs else "\n".join(head + ["  (未发现子域名)"])


def _key_field(engine: str) -> str:
    return {
        "fofa": "fofa_key", "hunter": "hunter_key", "quake": "quake_key",
        "shodan": "shodan_key", "zoomeye": "zoomeye_key", "zerozone": "zerozone_key",
    }[engine]


# ── JS 信息收集（参考 URLFinder）──────────────────────────────────────────────


def extract_from_js(content: str, base_host: str = "") -> dict[str, list[str]]:
    """从 HTML/JS 文本中提取 urls / paths / domains / secrets（纯函数，便于测试）。

    关键改进（参考 URLFinder）：
    1. 宽泛路径匹配——任何引号内 /xxx/yyy 都提取，不限关键字白名单
    2. 短片段提取——"User/list" 这类不以 / 开头的 CRUD 片段也捕获
    3. base path + 实体名 + CRUD 动词排列组合推断——即便 JS 里只出现 "/jalis/rest"
       和 "User"，也能自动推断出 /jalis/rest/User/list 等隐含端点
    """
    urls = _URL_RE.findall(content)
    paths = [m.group("v") for m in _PATH_RE.finditer(content)]

    # 短片段（如 "User/list"）
    frags = [m.group("v") for m in _FRAG_RE.finditer(content)]

    # base path 提取（如 "/jalis/rest"、"/smweb/rest"）
    bases = list(dict.fromkeys(m.group("v").rstrip("/") for m in _BASE_PATH_RE.finditer(content)))

    # 实体名动态提取：从 JS 中找所有 PascalCase 标识符（排除常见 JS 关键字/类名噪音）
    _JS_NOISE = frozenset({
        "Object", "Array", "String", "Number", "Boolean", "Function", "Date", "Error",
        "Math", "JSON", "Promise", "RegExp", "Map", "Set", "Symbol", "Proxy", "Reflect",
        "Infinity", "NaN", "Null", "True", "False", "Undefined", "Arguments", "This",
        "Window", "Document", "Element", "Node", "Event", "Console", "Navigator",
        "History", "Location", "Storage", "XMLHttpRequest", "FormData", "Headers",
        "Request", "Response", "Blob", "File", "FileReader", "FileList", "Image",
        "Canvas", "Context", "Worker", "WebSocket", "AbortController", "AbortSignal",
        "TypeError", "RangeError", "SyntaxError", "ReferenceError", "URIError",
        "EvalError", "InternalError", "AggregateError", "WeakMap", "WeakSet",
        "ArrayBuffer", "DataView", "Float32Array", "Float64Array", "Int8Array",
        "Int16Array", "Int32Array", "Uint8Array", "Uint16Array", "Uint32Array",
        "Intl", "Atomics", "SharedArrayBuffer", "Generator", "AsyncFunction",
        "Iterator", "AsyncIterator", "BigInt", "FinalizationRegistry",
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
        "Content", "Accept", "Authorization", "Cache", "Origin", "Referer",
        "Script", "Link", "Style", "Div", "Span", "Input", "Button", "Form",
        "Table", "Html", "Body", "Head", "Meta", "Title", "Base", "Href",
    })
    entities = list(dict.fromkeys(
        m.group("v") for m in _PASCAL_CASE_RE.finditer(content)
        if m.group("v") not in _JS_NOISE and len(m.group("v")) <= 30
    ))

    # base + entity + CRUD 推断
    inferred: list[str] = []
    if bases and entities:
        for base in bases[:5]:
            for entity in entities[:30]:
                for verb in _CRUD_VERBS:
                    inferred.append(f"{base}/{entity}/{verb}")
    # base + 短片段拼接
    for base in bases[:5]:
        for frag in frags:
            if not frag.startswith("/"):
                inferred.append(f"{base}/{frag}")

    all_paths = paths + [f"/{f}" if not f.startswith("/") else f for f in frags] + inferred

    domains = sorted({_host_of(u) for u in urls if _host_of(u)})
    if base_host:
        base_root = ".".join(base_host.split(".")[-2:])
        domains = [d for d in domains if base_root in d] + [d for d in domains if base_root not in d]
    secrets: list[str] = []
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(content):
            secrets.append(f"{label}: {m.group(0)[:80]}")
    return {
        "urls": _dedup_cap(urls, 200),
        "paths": _dedup_cap(all_paths, 500),
        "domains": _dedup_cap(domains, 100),
        "secrets": _dedup_cap(secrets, 50),
    }


async def execute_js_recon(agent: Any, args: dict[str, Any]) -> str:
    """抓取目标页面及其引用的 JS 文件，提取端点 / 域名 / 密钥。"""
    cfg = _get_recon_cfg(agent)
    url = str(args.get("url", "") or "").strip()
    if not url:
        return "[!] js_recon 需要 url 参数"
    if "://" not in url:
        url = "http://" + url
    host = _host_of(url)

    violation = enforce_host_path_constraints(agent, host=host, target=host)
    if violation:
        return violation

    max_js = int(args.get("max_js", cfg.js_max_files) or cfg.js_max_files)
    agg = {"urls": [], "paths": [], "domains": [], "secrets": []}
    fetched = 0
    try:
        async with _make_client(cfg) as client:
            resp = await client.get(url)
            html = resp.text
            for k, v in extract_from_js(html, host).items():
                agg[k].extend(v)

            # 收集 <script src> 并补全为绝对 URL
            js_urls = []
            for src in _SCRIPT_SRC_RE.findall(html):
                full = urljoin(url, src)
                if full.lower().split("?")[0].endswith(".js"):
                    js_urls.append(full)
            js_urls = _dedup_cap(js_urls, max_js)

            sem = asyncio.Semaphore(cfg.max_concurrency)

            async def grab(js_url: str) -> None:
                nonlocal fetched
                async with sem:
                    try:
                        jr = await client.get(js_url)
                        fetched += 1
                        for k, v in extract_from_js(jr.text, host).items():
                            agg[k].extend(v)
                    except Exception:
                        pass

            await asyncio.gather(*(grab(j) for j in js_urls))
    except Exception as e:
        return f"[!] js_recon 执行错误: {e}"

    for k in agg:
        agg[k] = _dedup_cap(agg[k], 200 if k != "secrets" else 50)

    out = [f"# JS 信息收集 — {url}  (抓取 {fetched} 个 JS)"]

    # 关键发现提前：敏感信息和未授权探测结果放最前面，减少被截断后 LLM 反复重调
    if agg["secrets"]:
        out.append(f"\n## ⚠ 疑似敏感信息 ({len(agg['secrets'])})")
        out += [f"  {s}" for s in agg["secrets"]]

    auto_probe = args.get("auto_probe", True)
    probe_targets = agg["paths"] + [u for u in agg["urls"] if _host_of(u) == host]
    if auto_probe and probe_targets:
        probe_out = await execute_unauth_test(
            agent,
            {
                "base_url": url,
                "endpoints": probe_targets,
                "auth_header": args.get("auth_header"),
                "max_endpoints": int(args.get("max_endpoints", 60) or 60),
            },
        )
        out.append("\n" + probe_out)

    out.append(f"\n## 接口/路径 ({len(agg['paths'])})")
    out += [f"  {p}" for p in agg["paths"][:120]]
    out.append(f"\n## 关联域名 ({len(agg['domains'])})")
    out += [f"  {d}" for d in agg["domains"][:60]]
    out.append(f"\n## 绝对 URL ({len(agg['urls'])})")
    out += [f"  {u}" for u in agg["urls"][:60]]
    return "\n".join(out)


# ── 未授权访问探测（JS 收集到的接口逐个验证）────────────────────────────────────

# 破坏性动作：即便只发 GET 也可能触发副作用（短信轰炸/改数据），一律跳过
_DESTRUCTIVE_RE = re.compile(
    r"(?i)(delete|remove|destroy|update|modify|edit|/add|/create|insert|/save|clear|"
    r"reset|drop|logout|sign ?out|sms|sendcode|send_?sms|captcha|verifycode|/pay|/order/cancel)"
)
# 强鉴权墙信号：出现即判定为登录/拦截页（避免把含 "login" 导航链接的公开页误判）
_AUTHWALL_MARKERS = (
    "请登录", "请先登录", "未登录", "未授权", "无权限", "权限不足", "登录后查看",
    "unauthorized", "access denied", "not logged in", "please log in",
    "authentication required", "需要登录",
)
_PASSWORD_FIELD_RE = re.compile(r"""(?i)(?:type|name)\s*=\s*["']password["']""")


def _parse_auth_header(raw: Any) -> dict[str, str]:
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    text = str(raw)
    if ":" in text:
        name, _, value = text.partition(":")
        return {name.strip(): value.strip()}
    # 裸 token → 当作 Bearer
    return {"Authorization": f"Bearer {text.strip()}"}


def _is_auth_wall(body: str) -> bool:
    """是否为登录/鉴权拦截页：强文案信号或存在密码输入框（不靠裸 login 字样误判）。"""
    head = body[:4000]
    low = head.lower()
    if any(m.lower() in low for m in _AUTHWALL_MARKERS):
        return True
    return bool(_PASSWORD_FIELD_RE.search(head))


def _classify_unauth(status: int, body: str, ctype: str) -> tuple[str, bool]:
    """返回 (判定文案, 是否疑似未授权线索)。"""
    if status in (401, 403):
        return "✓ 已鉴权拦截", False
    if status in (301, 302, 307, 308):
        return "↪ 跳转(疑似登录)", False
    if status == 404:
        return "— 不存在", False
    if status == 405:
        return "· 方法不允许", False
    if status == 200:
        if not body.strip():
            return "· 200 空响应", False
        if _is_auth_wall(body):
            return "· 200 登录/鉴权墙", False
        is_data = ("json" in ctype.lower()) or body.lstrip()[:1] in ("{", "[")
        if is_data:
            return "⚠ 疑似未授权(返回数据)", True
        if "html" in ctype.lower() or body.lstrip()[:1] == "<":
            return "· 200 HTML 页面(非接口)", False  # 公开页面，非接口未授权
        return "⚠ 200 需人工确认", True
    return f"? HTTP {status}", False


async def _probe_endpoints(
    client: Any, base: str, endpoints: list[str], auth: dict[str, str],
    cap: int, sem: asyncio.Semaphore,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    base_host = _host_of(base)
    seen: set[str] = set()
    todo: list[str] = []
    for ep in endpoints:
        full = ep if "://" in ep else urljoin(base, ep)
        if _host_of(full) != base_host:  # 不打非授权范围的关联域名
            continue
        if _DESTRUCTIVE_RE.search(full):  # 读写分离红线：跳过破坏性接口
            results.append({"url": full, "status": "-", "verdict": "🚫 跳过(破坏性接口)", "lead": False, "length": 0})
            continue
        if full in seen:
            continue
        seen.add(full)
        todo.append(full)
    todo = todo[:cap]

    # REST CRUD list/query/search 端点通常需要 POST（含框架变体如 listForLayUI）
    _POST_VERBS_RE = re.compile(
        r"(?i)/(?:list|query|search|page|find|select|export|count|batch|all)"
        r"(?:[A-Z][a-zA-Z0-9]*)*(?:\?|$)"
    )

    async def one(url: str) -> None:
        async with sem:
            # 优先 GET；对 REST CRUD list/query 端点额外尝试 POST
            methods = ["GET"]
            if _POST_VERBS_RE.search(url):
                methods.append("POST")

            best_row: dict[str, Any] | None = None
            for method in methods:
                try:
                    if method == "GET":
                        r = await client.get(url)
                    else:
                        r = await client.post(url, content="{}", headers={"Content-Type": "application/json"})
                except Exception as e:
                    if best_row is None:
                        best_row = {"url": url, "status": "ERR", "verdict": f"请求失败:{e}",
                                    "lead": False, "length": 0, "method": method}
                    continue
                body = r.text
                ctype = r.headers.get("content-type", "")
                verdict, lead = _classify_unauth(r.status_code, body, ctype)
                row = {"url": url, "status": r.status_code, "verdict": verdict,
                       "lead": lead, "length": len(r.content), "method": method}
                if lead and auth:
                    try:
                        hdrs = dict(auth)
                        if method == "POST":
                            hdrs["Content-Type"] = "application/json"
                            ra = await client.post(url, content="{}", headers=hdrs)
                        else:
                            ra = await client.get(url, headers=hdrs)
                        if ra.status_code == 200 and abs(len(ra.content) - len(r.content)) <= max(50, len(r.content) * 0.1):
                            row["verdict"] = "🔴 未授权确认(无token=有token)"
                    except Exception:
                        pass
                # 保留发现线索更强的那个方法
                if best_row is None or (lead and not best_row.get("lead")) or (lead and len(r.content) > best_row.get("length", 0)):
                    best_row = row
            if best_row is not None:
                results.append(best_row)

    await asyncio.gather(*(one(u) for u in todo))
    # 线索优先、再按状态排序
    results.sort(key=lambda x: (not x.get("lead"), str(x.get("status"))))
    return results


async def execute_unauth_test(agent: Any, args: dict[str, Any]) -> str:
    """对一批接口逐个做未授权访问探测（仅安全 GET，跳过破坏性接口）。"""
    cfg = _get_recon_cfg(agent)
    base = str(args.get("base_url") or args.get("url") or "").strip()
    endpoints = args.get("endpoints") or []
    if isinstance(endpoints, str):
        endpoints = [e.strip() for e in re.split(r"[\s,]+", endpoints) if e.strip()]
    if not base and endpoints:
        base = endpoints[0]
    if not base:
        return "[!] unauth_test 需要 base_url（或在 endpoints 中给出完整 URL）"
    if "://" not in base:
        base = "http://" + base
    host = _host_of(base)

    violation = enforce_host_path_constraints(agent, host=host, target=host)
    if violation:
        return violation
    if not endpoints:
        return "[!] unauth_test 需要 endpoints（接口路径/URL 列表，通常来自 js_recon）"

    auth = _parse_auth_header(args.get("auth_header"))
    cap = int(args.get("max_endpoints", 60) or 60)
    try:
        async with _make_client(cfg) as client:
            sem = asyncio.Semaphore(cfg.max_concurrency)
            rows = await _probe_endpoints(client, base, endpoints, auth, cap, sem)
    except Exception as e:
        return f"[!] unauth_test 执行错误: {e}"

    leads = [r for r in rows if r.get("lead")]
    out = [f"# 未授权访问探测 — {host}  探测 {len(rows)} 个接口，疑似线索 {len(leads)}"]
    if auth:
        out.append("  (已启用 有/无 token 差分对比)")
    for r in rows:
        st = r.get("status")
        method = r.get("method", "GET")
        tag = f"[{str(st):>3}]" if method == "GET" else f"[{str(st):>3} {method}]"
        out.append(f"  {tag:>12} {str(r.get('length','')):>7}B  {r['verdict']:<22} {r['url']}")
    if leads:
        out.append("\n⚠ 重点人工复核（确认是否能读他人数据/是否敏感）：")
        out += [f"  {r['url']}" for r in leads]
    return "\n".join(out)


# ── 目录枚举（参考 dirsearch）──────────────────────────────────────────────────


def _load_wordlist(cfg: Any) -> list[str]:
    path = (cfg.dir_wordlist_path or "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [ln.strip().lstrip("/") for ln in f if ln.strip() and not ln.startswith("#")]
            if words:
                return words
        except OSError:
            pass
    return list(_BUILTIN_DIR_WORDLIST)


_HIT_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}


async def execute_dir_enum(agent: Any, args: dict[str, Any]) -> str:
    """目录枚举：并发字典爆破，带 404 基线 / 全局伪装识别与状态码过滤。"""
    cfg = _get_recon_cfg(agent)
    base = str(args.get("url", "") or "").strip()
    if not base:
        return "[!] dir_enum 需要 url 参数"
    if "://" not in base:
        base = "http://" + base
    base = base.rstrip("/") + "/"
    host = _host_of(base)

    violation = enforce_host_path_constraints(agent, host=host, target=host)
    if violation:
        return violation

    extensions = args.get("extensions") or []
    if isinstance(extensions, str):
        extensions = [e.strip() for e in extensions.split(",") if e.strip()]
    words = _load_wordlist(cfg)
    if args.get("wordlist"):
        extra = args["wordlist"]
        words = (extra if isinstance(extra, list) else [extra]) + words

    # 展开扩展名
    candidates: list[str] = []
    for w in words:
        candidates.append(w)
        for ext in extensions:
            ext = ext.lstrip(".")
            if "." not in w.split("/")[-1]:
                candidates.append(f"{w}.{ext}")
    candidates = _dedup_cap(candidates, cfg.dir_max_requests)

    try:
        import httpx

        async with _make_client(cfg) as client:
            # 404 基线 + 全局伪装识别：请求随机不存在路径
            baseline_len = None
            try:
                rnd = await client.get(urljoin(base, "vulnclaw_nope_8f3a2c1e9b/"))
                if rnd.status_code in (200, 301, 302):
                    baseline_len = len(rnd.text)
                    # 随机路径竟返回 200 → 全局伪装响应，停止爆破（CLAUDE.md 铁律）
                    if rnd.status_code == 200:
                        return (
                            f"[!] dir_enum 终止：随机路径 {base}vulnclaw_nope_... 返回 200"
                            f"（长度 {baseline_len}），目标疑似对任意路径返回 200，目录爆破无意义。"
                        )
            except Exception:
                pass

            sem = asyncio.Semaphore(cfg.max_concurrency)
            hits: list[tuple[int, int, str]] = []

            async def probe(path: str) -> None:
                target = urljoin(base, path)
                async with sem:
                    try:
                        r = await client.get(target)
                    except Exception:
                        return
                code = r.status_code
                length = len(r.content)
                if code in _HIT_CODES:
                    if baseline_len is not None and code in (200, 301, 302) and length == baseline_len:
                        return  # 与伪装基线同长，判为噪音
                    hits.append((code, length, path))

            await asyncio.gather(*(probe(p) for p in candidates))
    except Exception as e:
        return f"[!] dir_enum 执行错误: {e}"

    hits.sort(key=lambda x: (x[0], -x[1]))
    out = [f"# 目录枚举 — {base}  请求 {len(candidates)} 条，命中 {len(hits)}"]
    if baseline_len is not None:
        out.append(f"  (404 基线长度 ≈ {baseline_len})")
    for code, length, path in hits:
        out.append(f"  [{code}] {length:>8}B  {base}{path}")
    return "\n".join(out) if hits else "\n".join(out + ["  (无有效命中)"])
