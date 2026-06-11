# 侦察报告模板

## 使用说明

在信息收集任务完成时，使用 `python_execute` 工具将以下模板填充为完整报告，
保存到用户指定路径或桌面。

## Markdown 报告模板

```markdown
# 🦞 {目标} 侦察报告

> 生成时间：{日期时间}
> 工具：VulnClaw v0.3.0

---

## 1. 目标概览

| 项目 | 内容 |
|------|------|
| 目标 URL | {url} |
| IP 地址 | {ip} |
| 服务器 | {server} |
| 框架/CMS | {framework} |
| CDN | {cdn} |
| SSL 证书 | {ssl_info} |

---

## 2. 技术侦察

### 2.1 HTTP 响应头
| 响应头 | 值 | 安全提示 |
|--------|---|---------|
| Server | {value} | {注意点} |
| X-Powered-By | {value} | 泄露技术栈 |
| ... | ... | ... |

### 2.2 DNS 记录
| 类型 | 值 |
|------|---|
| A | {ip} |
| CNAME | {cname} |
| MX | {mx} |
| TXT | {txt} |

### 2.3 子域名
| 子域名 | IP | 说明 |
|--------|---|------|
| {sub} | {ip} | {note} |

### 2.4 开放端口
| 端口 | 服务 | 版本 |
|------|------|------|
| 80 | HTTP | nginx/1.18 |
| 443 | HTTPS | nginx/1.18 |

### 2.5 目录与文件
| 路径 | 状态码 | 说明 |
|------|--------|------|
| /robots.txt | 200 | {内容摘要} |
| /sitemap.xml | 200 | {内容摘要} |
| /.git/HEAD | 403/200 | {是否泄露} |

---

## 3. 内容侦察

### 3.1 页面元数据
- **Title**：{title}
- **Description**：{desc}
- **Keywords**：{keywords}
- **Author**：{author}

### 3.2 外部链接
| 链接 | 类型 | 说明 |
|------|------|------|
| {url} | GitHub | 个人主页 |
| {url} | B站 | 视频空间 |
| {url} | CDN | 资源加载 |

### 3.3 JavaScript 文件
| 文件 | 关键发现 |
|------|---------|
| {path} | {api_endpoint/config/key} |

### 3.4 隐藏信息
- HTML 注释：{comments}
- 隐藏字段：{hidden_fields}
- 邮箱/联系方式：{contacts}

---

## 4. 人物追踪

### 4.1 作者信息
| 项目 | 内容 | 来源 | 置信度 |
|------|------|------|--------|
| 昵称 | {name} | {source} | 🟢/🟡/🔴 |
| GitHub | {url} | {source} | 🟢 |
| B站 | {url} | {source} | 🟢 |
| 邮箱 | {email} | {source} | 🟡 |
| 位置 | {location} | {source} | 🟡 |

### 4.2 技术画像
- **主力语言**：{languages}
- **技术栈**：{stack}
- **开源项目**：{repos}
- **关注领域**：{interests}

### 4.3 跨平台关联
| 平台 | 用户名/ID | 匹配度 | 说明 |
|------|----------|--------|------|
| {platform} | {id} | 高/中/低 | {note} |

---

## 5. 关键发现

| # | 发现 | 风险等级 | 说明 |
|---|------|---------|------|
| 1 | {finding} | 🔴高/🟡中/🟢低 | {detail} |

---

## 6. 建议

1. {suggestion_1}
2. {suggestion_2}

---

*本报告由 VulnClaw 自动生成，所有信息来源于公开渠道。*
```

## Python 保存代码

```python
import os
from datetime import datetime

def save_recon_report(target, report_content, output_path=None):
    """保存侦察报告到文件"""
    if not output_path:
        # 默认保存到桌面
        desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
        safe_name = re.sub(r'[^\w]', '_', target)[:30]
        date_str = datetime.now().strftime('%Y%m%d_%H%M')
        output_path = os.path.join(desktop, f'{safe_name}_侦察报告_{date_str}.md')
    
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    return output_path
```
