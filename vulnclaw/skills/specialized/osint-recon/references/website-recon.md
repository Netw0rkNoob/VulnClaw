# 网站信息收集参考

## 1. 网站架构识别

### 技术栈推断方法
1. **HTTP 响应头** — Server、X-Powered-By、Set-Cookie 特征
2. **HTML 源码特征** — meta generator、特定 class/id 命名
3. **JS 文件路径** — /static/js/app.js、/wp-content/、/assets/
4. **Cookie 名称** — PHPSESSID(php)、JSESSIONID(Java)、_rails_session(Rails)
5. **URL 路径** — ?id= (PHP)、/api/ (REST)、/wp-admin/ (WordPress)

### 常见架构组合
| 语言 | 框架 | 数据库 | 服务器 | 特征 |
|------|------|--------|--------|------|
| PHP | Laravel | MySQL | Apache/Nginx | Set-Cookie: laravel_session |
| PHP | WordPress | MySQL | Apache | /wp-content/, /wp-admin/ |
| Python | Django | PostgreSQL | Nginx+Gunicorn | CSRF middleware cookie |
| Python | Flask | SQLite/MySQL | Nginx+uWSGI | Set-Cookie: session= |
| Java | Spring | MySQL/Oracle | Tomcat | JSESSIONID |
| Node.js | Express | MongoDB | Nginx | X-Powered-By: Express |
| Ruby | Rails | PostgreSQL | Nginx+Puma | _rails_session |

### python_execute 架构探测
```python
import httpx

url = "https://target.com"
r = httpx.get(url, timeout=10)

# 1. 响应头分析
headers = r.headers
print(f"Server: {headers.get('Server', 'N/A')}")
print(f"X-Powered-By: {headers.get('X-Powered-By', 'N/A')}")

# 2. Cookie 分析
cookies = r.cookies
for cookie in cookies:
    print(f"Cookie: {cookie.name} = {cookie.value[:20]}...")

# 3. HTML 特征分析
html = r.text
# WordPress
if 'wp-content' in html or 'wp-includes' in html:
    print("[+] WordPress 检测")
# Laravel
if 'laravel_session' in str(cookies):
    print("[+] Laravel 检测")
# Django
if 'csrftoken' in str(cookies) or 'csrfmiddlewaretoken' in html:
    print("[+] Django 检测")
# Hexo
if 'hexo' in html.lower():
    print("[+] Hexo 博客检测")
# Hugo
if 'hugo' in html.lower():
    print("[+] Hugo 博客检测")
```

## 2. Web 指纹识别

### CMS 指纹特征
| CMS | 特征路径 | 特征字符串 |
|-----|---------|-----------|
| WordPress | /wp-login.php, /wp-content/ | wp-content, xmlrpc.php |
| Joomla | /administrator/ | /media/jui/ |
| Drupal | /misc/drupal.js | Drupal.settings |
| Discuz | /forum.php | discuz_uid |
| Typecho | /admin/login.php | typecho |
| Hexo | /archives/ | hexo |
| Ghost | /ghost/ | ghost-frontend |

### 前端框架特征
| 框架 | 特征 |
|------|------|
| React | data-reactroot, __NEXT_DATA__ |
| Vue.js | data-v-xxx, __vue__ |
| Angular | ng-version, _nghost |
| jQuery | jQuery in scripts |
| Bootstrap | bootstrap.css/js |

### python_execute 指纹识别
```python
import httpx, re

url = "https://target.com"
r = httpx.get(url, timeout=10)
html = r.text

# CMS 检测
cms_signatures = {
    "WordPress": ["wp-content", "wp-includes", "wp-admin"],
    "Joomla": ["/administrator/", "media/jui"],
    "Drupal": ["Drupal.settings", "/misc/drupal"],
    "Hexo": ["hexo", "/archives/"],
    "Hugo": ["hugo", "gohugo"],
    "Ghost": ["ghost-frontend", "/ghost/"],
}

for cms, sigs in cms_signatures.items():
    if any(sig in html for sig in sigs):
        print(f"[+] CMS: {cms}")

# 前端框架检测
fw_signatures = {
    "React": ["data-reactroot", "__NEXT_DATA__", "react"],
    "Vue.js": ["data-v-", "__vue__", "vue"],
    "Angular": ["ng-version", "_nghost", "angular"],
    "jQuery": ["jquery", "jQuery"],
    "Bootstrap": ["bootstrap"],
}

for fw, sigs in fw_signatures.items():
    if any(sig.lower() in html.lower() for sig in sigs):
        print(f"[+] 前端框架: {fw}")

# JS 文件提取
js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html)
print(f"JS 文件: {js_files[:10]}")
```

## 3. WAF 检测

### 常见 WAF 特征
| WAF | 拦截特征 |
|-----|---------|
| Cloudflare | Server: cloudflare, CF-Ray header |
| AWS WAF | Server: AmazonS3, x-amz-request-id |
| 阿里云 WAF | Set-Cookie 包含 acw_tc |
| 腾讯云 WAF | 特定拦截页面 |
| 宝塔 WAF | 拦截页面含 "宝塔" |
| 安全狗 | 拦截页面含 "safedog" |
| ModSecurity | 特定 403 响应 |

### python_execute WAF 检测
```python
import httpx

url = "https://target.com"

# 1. 正常请求
r1 = httpx.get(url)

# 2. 触发 WAF 的请求
waf_payloads = [
    "/?id=1' OR 1=1--",
    "/?search=<script>alert(1)</script>",
    "/../../../etc/passwd",
    "/?file=php://filter/convert.base64-encode/resource=index",
]

for payload in waf_payloads:
    r2 = httpx.get(url + payload, follow_redirects=False)
    # 状态码变化
    if r2.status_code in [403, 406, 429, 501]:
        print(f"[!] WAF 检测: {payload} → {r2.status_code}")
    # 响应长度显著变化
    if abs(len(r2.text) - len(r1.text)) > 500:
        print(f"[!] 响应长度变化: 正常={len(r1.text)}, 攻击={len(r2.text)}")

# 3. 检查特定 WAF 响应头
waf_headers = {
    "cloudflare": ["cf-ray", "server: cloudflare"],
    "aws": ["x-amz-request-id", "x-amz-cf-id"],
    "阿里云": ["acw_tc"],
}
for waf_name, sigs in waf_headers.items():
    for sig in sigs:
        if sig in str(r1.headers).lower():
            print(f"[+] WAF 检测: {waf_name}")
```

## 4. 敏感目录 & 敏感文件

### 常见敏感路径列表
```
/robots.txt
/sitemap.xml
/.git/
/.svn/
/.env
/.DS_Store
/web.config
/config.php
/config.yml
/backup/
/admin/
/login/
/api/
/swagger/
/graphql
/phpinfo.php
/test/
/debug/
/console/
/actuator/
/.well-known/
```

### python_execute 目录扫描
```python
import httpx

target = "https://target.com"
paths = [
    "/robots.txt", "/sitemap.xml", "/.git/", "/.env", "/.DS_Store",
    "/admin/", "/backup/", "/config.php", "/api/", "/phpinfo.php",
    "/.git/config", "/.git/HEAD", "/wp-config.php",
    "/swagger/", "/graphql", "/actuator/",
]

for path in paths:
    try:
        r = httpx.get(target + path, timeout=5, follow_redirects=False)
        if r.status_code in [200, 301, 302, 401, 403]:
            print(f"[{r.status_code}] {path}")
    except:
        pass
```

## 5. 源码泄露检查

### 常见源码泄露类型
| 类型 | 路径 | 检测方法 |
|------|------|---------|
| Git 仓库 | /.git/config, /.git/HEAD | 200 且含 git 内容 |
| SVN 仓库 | /.svn/entries | 200 且含 svn 内容 |
| .DS_Store | /.DS_Store | 下载后解析 |
| .env 文件 | /.env | 含 DB_PASSWORD 等 |
| web.config | /web.config | IIS 配置 |
| 备份文件 | /.bak, /.swp, /.old, /~ | 直接下载 |
| Docker | /Dockerfile, /docker-compose.yml | 容器配置 |
| package.json | /package.json | Node.js 依赖 |
| composer.json | /composer.json | PHP 依赖 |

### Git 仓库泄露利用
```python
import httpx

target = "https://target.com"

# 1. 检查 .git/HEAD
r = httpx.get(f"{target}/.git/HEAD")
if r.status_code == 200 and "ref:" in r.text:
    print("[!] Git 仓库泄露!")
    # 2. 尝试获取 ref
    ref_path = r.text.strip().split("ref: ")[1] if "ref: " in r.text else ""
    if ref_path:
        r2 = httpx.get(f"{target}/.git/{ref_path}")
        if r2.status_code == 200:
            print(f"[+] Git ref: {r2.text.strip()}")

# 3. 尝试获取 config
r3 = httpx.get(f"{target}/.git/config")
if r3.status_code == 200:
    print(f"[+] Git config:\n{r3.text}")
```

## 6. 旁站查询（同 IP 反查域名）

### 查询方法
1. **站长工具** — https://stool.chinaz.com/same
2. **微步在线** — https://x.threatbook.cn
3. **crt.sh** — 用 IP 查询证书关联域名
4. **Censys** — https://search.censys.io

### python_execute 旁站查询
```python
import httpx, json

ip = "1.2.3.4"

# 方法1: crt.sh 查询同 IP 证书
r = httpx.get(f"https://crt.sh/?q={ip}&output=json", timeout=15)
if r.status_code == 200:
    domains = set()
    for entry in r.json():
        for name in entry.get('name_value', '').split('\n'):
            if name.strip() and '*' not in name:
                domains.add(name.strip())
    print(f"[+] 同 IP 域名 ({len(domains)}):")
    for d in sorted(domains):
        print(f"  - {d}")
```

## 7. C 段查询（同网段存活主机）

### python_execute C 段扫描
```python
import httpx, socket
from concurrent.futures import ThreadPoolExecutor

# 从域名获取 IP
domain = "target.com"
ip = socket.gethostbyname(domain)
# 提取 C 段
c_segment = ".".join(ip.split(".")[:3])

def check_host(ip, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, 80))
        s.close()
        if result == 0:
            return ip
    except:
        pass
    return None

# 扫描 C 段（1-254）
alive_hosts = []
with ThreadPoolExecutor(max_workers=50) as executor:
    ips = [f"{c_segment}.{i}" for i in range(1, 255)]
    results = executor.map(check_host, ips)
    alive_hosts = [ip for ip in results if ip]

print(f"[+] C 段存活主机: {alive_hosts}")
```
