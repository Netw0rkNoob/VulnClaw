# OSINT 工具使用手册

## 1. crt.sh — 证书透明度子域名查询

### 用法
```python
import httpx

def query_crtsh(domain):
    """通过 crt.sh 查询子域名"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = httpx.get(url, timeout=30)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value', '')
                for n in name.split('\n'):
                    n = n.strip().lower()
                    if n and '*' not in n:
                        subdomains.add(n)
            return sorted(subdomains)
    except Exception as e:
        return [f"查询失败: {e}"]
    return []
```

### 注意
- crt.sh 可能较慢，设置 30s 超时
- 结果包含通配符证书（`*.example.com`），需过滤
- 去重后返回

## 2. GitHub API — 代码与用户搜索

### 搜索代码（检测泄露）
```python
def search_github_code(query, max_results=10):
    """搜索 GitHub 代码（检测密钥/配置泄露）"""
    url = "https://api.github.com/search/code"
    params = {'q': query, 'per_page': max_results}
    headers = {'Accept': 'application/vnd.github.v3+json'}
    
    r = httpx.get(url, params=params, headers=headers)
    if r.status_code == 200:
        items = r.json().get('items', [])
        return [{
            'repo': item['repository']['full_name'],
            'path': item['path'],
            'url': item['html_url'],
        } for item in items]
    return []
```

### 常用搜索 dork
```
"domain.com" password
"domain.com" api_key
"domain.com" secret
"domain.com" .env
filename:.env domain.com
filename:config domain.com
org:company-name password
```

## 3. DNS 查询

### Python 内置 DNS 查询
```python
import socket

def dns_lookup(domain):
    """基础 DNS 查询"""
    results = {}
    try:
        # A 记录
        results['A'] = socket.gethostbyname_ex(domain)[2]
    except:
        results['A'] = '解析失败'
    
    return results
```

### 完整 DNS 查询（需要 dnspython）
```python
# 如果环境有 dnspython
try:
    import dns.resolver
    
    def full_dns_lookup(domain):
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        results = {}
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                results[rtype] = [str(r) for r in answers]
            except:
                pass
        return results
except ImportError:
    pass
```

## 4. WHOIS 查询

### 在线 WHOIS API
```python
def whois_lookup(domain):
    """通过在线 API 查询 WHOIS"""
    # 使用 whoisjson.com 免费 API
    url = f"https://whoisjson.com/api/v1/whois?domain={domain}"
    try:
        r = httpx.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                'registrar': data.get('registrar'),
                'creation_date': data.get('creation_date'),
                'expiration_date': data.get('expiration_date'),
                'name_servers': data.get('name_servers'),
                'registrant': data.get('registrant'),
            }
    except:
        pass
    return {}
```

## 5. Google Dorking

### 常用搜索语法
| 语法 | 用途 | 示例 |
|------|------|------|
| `site:` | 限定域名 | `site:github.com "unclec"` |
| `intitle:` | 标题关键词 | `intitle:"index of" site:example.com` |
| `inurl:` | URL 关键词 | `inurl:admin site:example.com` |
| `filetype:` | 文件类型 | `filetype:pdf site:example.com` |
| `"exact phrase"` | 精确匹配 | `"UncleCheng" security` |
| `related:` | 相关网站 | `related:github.com` |

### 信息收集常用 dork
```
site:github.com "目标用户名"
site:bilibili.com "目标用户名"
site:zhihu.com "目标用户名"
"邮箱@domain.com"
"手机号"
```

## 6. Shodan/Censys（需 API Key）

### Shodan 搜索
```python
def shodan_search(api_key, query):
    import shodan
    api = shodan.Shodan(api_key)
    try:
        results = api.search(query)
        return [{
            'ip': result['ip_str'],
            'port': result['port'],
            'org': result.get('org', ''),
            'data': result['data'][:200],
        } for result in results['matches'][:10]]
    except Exception as e:
        return [f"Shodan 查询失败: {e}"]
```

## 7. Wayback Machine

### 查询历史快照
```python
def wayback_query(domain):
    """查询 Wayback Machine 历史快照"""
    url = f"http://archive.org/wayback/available?url={domain}"
    try:
        r = httpx.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            snapshots = data.get('archived_snapshots', {})
            if snapshots.get('closest'):
                return snapshots['closest']['url']
    except:
        pass
    return None
```

## 8. 旁站查询（同 IP 反查域名）

### 在线工具
| 工具 | URL | 说明 |
|------|-----|------|
| 站长工具 | https://stool.chinaz.com/same | 国内最常用 |
| 微步在线 | https://x.threatbook.cn | 威胁情报+旁站 |
| crt.sh | https://crt.sh | 用 IP 查证书关联域名 |
| Censys | https://search.censys.io | 全球资产搜索 |
| Fofa | https://fofa.info | 空间搜索引擎 |

### python_execute 旁站查询
```python
import httpx

def reverse_ip_lookup(ip):
    """通过 crt.sh 反查同 IP 域名"""
    domains = set()
    try:
        r = httpx.get(f"https://crt.sh/?q={ip}&output=json", timeout=30)
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get('name_value', '').split('\n'):
                    name = name.strip()
                    if name and '*' not in name:
                        domains.add(name)
    except Exception as e:
        print(f"crt.sh 查询失败: {e}")
    return sorted(domains)

# 使用
ip = "1.2.3.4"
result = reverse_ip_lookup(ip)
print(f"[+] 同 IP 域名 ({len(result)}):")
for d in result:
    print(f"  - {d}")
```

## 9. C 段查询（同网段存活主机）

### 在线工具
| 工具 | URL | 说明 |
|------|-----|------|
| Fofa | https://fofa.info | `ip="1.2.3.0/24"` |
| Shodan | https://www.shodan.io | `net:1.2.3.0/24` |
| Censys | https://search.censys.io | `ip:/1.2.3.0-1.2.3.255/` |

### python_execute C 段扫描
```python
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_c_segment(ip, timeout=1, max_workers=100):
    """扫描 C 段存活主机"""
    prefix = ".".join(ip.split(".")[:3])
    alive = []

    def check(host_ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host_ip, 80))
            s.close()
            if result == 0:
                return host_ip
        except:
            pass
        return None

    targets = [f"{prefix}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check, t): t for t in targets}
        for future in as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)

    return sorted(alive, key=lambda x: int(x.split(".")[-1]))

# 使用
ip = "1.2.3.4"
hosts = scan_c_segment(ip)
print(f"[+] C 段存活主机 ({len(hosts)}):")
for h in hosts:
    print(f"  - {h}")
```

## 10. ICP 备案查询

### 在线工具
| 工具 | URL | 说明 |
|------|-----|------|
| 工信部备案查询 | https://beian.miit.gov.cn | 官方权威 |
| 站长工具备案查询 | https://icp.chinaz.com | 便捷查询 |
| 天眼查 | https://www.tianyancha.com | 企业+备案关联 |
| 爱站备案查询 | https://www.aizhan.com/cha/ | 批量查询 |

### python_execute ICP 备案查询
```python
import httpx

def icp_lookup(domain):
    """查询 ICP 备案信息（使用公开 API）"""
    # 方法1: 使用 chinaz API（需要 API key）
    # 方法2: 使用公开查询接口
    try:
        # 使用 whois 查询中国域名信息
        url = f"https://whois.chinaz.com/{domain}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        r = httpx.get(url, headers=headers, timeout=10)
        # 解析备案信息
        import re
        icp_match = re.search(r'备案号[：:]\s*([^<\s]+)', r.text)
        if icp_match:
            return icp_match.group(1)
    except:
        pass

    # 如果是境外域名，通常无 ICP 备案
    return "未查到备案（可能为境外域名）"
```

## 11. 子域名发现（多方法）

### 方法组合策略
1. **crt.sh** — 证书透明度（最快）
2. **搜索引擎 dork** — Google/Bing site: 搜索
3. **DNS 爆破** — 常见前缀字典
4. **DNS 区域传送** — 尝试 axfr
5. **JS 文件分析** — 从页面 JS 中提取子域名

### python_execute 子域名爆破
```python
import socket
from concurrent.futures import ThreadPoolExecutor

def subdomain_brute(domain, wordlist=None, max_workers=20):
    """子域名爆破"""
    if wordlist is None:
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'staging',
            'api', 'test', 'portal', 'cdn', 'ns1', 'ns2', 'mx',
            'app', 'web', 'git', 'ci', 'jenkins', 'jira',
            'vpn', 'remote', 'shop', 'store', 'news',
        ]

    found = []
    def check(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip)
        except:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(check, wordlist)
        found = [r for r in results if r]

    return sorted(found, key=lambda x: x[0])

# 使用
domain = "example.com"
subs = subdomain_brute(domain)
print(f"[+] 发现子域名 ({len(subs)}):")
for sub, ip in subs:
    print(f"  - {sub} → {ip}")
```

### DNS 区域传送尝试
```python
import socket

def try_zone_transfer(domain):
    """尝试 DNS 区域传送"""
    # 获取 NS 记录
    try:
        ns_servers = socket.getaddrinfo(domain, None)
    except:
        return []

    # 尝试对每个 NS 服务器进行区域传送
    # 注意：现代 DNS 服务器通常已禁用此功能
    import subprocess
    results = []
    try:
        result = subprocess.run(
            ['dig', 'axfr', domain, '@' + domain],
            capture_output=True, text=True, timeout=10
        )
        if 'XFR size' in result.stdout:
            results.append(result.stdout)
    except:
        pass

    return results
```
