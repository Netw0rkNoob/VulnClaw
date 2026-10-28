# 服务器信息收集参考

## 1. 开放端口 & 服务版本识别

### nmap 常用命令
```bash
# 全端口扫描（慢但全面）
nmap -p- -sV <target>

# 常见端口快速扫描
nmap -sV -top-ports 1000 <target>

# UDP 端口扫描
nmap -sU --top-ports 100 <target>

# 服务版本识别 + OS 检测
nmap -sV -O <target>
```

### python_execute 方式（无 nmap 时）
```python
import socket

def scan_port(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except:
        return False

host = "target.com"
common_ports = [21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,6379,8080,8443,9200,27017]
open_ports = [p for p in common_ports if scan_port(host, p)]
print(f"开放端口: {open_ports}")
```

### 服务版本识别（Banner Grabbing）
```python
import socket

def grab_banner(host, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # HTTP 服务发送请求获取 banner
        if port in [80, 443, 8080, 8443]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        else:
            s.send(b"\r\n")
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        s.close()
        return banner[:200]
    except:
        return None
```

## 2. 真实 IP 探测（CDN 后的源站 IP）

### 方法一：DNS 历史记录
- SecurityTrails (https://securitytrails.com/dns-trials)
- DNSHistory (https://dnshistory.org)
- ViewDNS (https://viewdns.info/iphistory/)
- Netcraft Site Report (https://sitereport.netcraft.com/)

### 方法二：全局 Ping
```python
import httpx
# 使用多地 Ping 服务
urls = [
    f"https://www.whatsmydns.net/#A/{domain}",
    f"https://ping.pe/{domain}",
    f"https://tools.keycdn.com/curl?url={domain}",
]
# 如果不同地区解析到不同 IP，说明使用了 CDN
# 如果多地解析到同一 IP，该 IP 可能是真实源站
```

### 方法三：邮件头提取
- 注册/登录目标网站，收取邮件
- 查看邮件头中的 `Received:` 字段
- 可能暴露邮件服务器的真实 IP

### 方法四：子域名解析
- CDN 通常只为主域名服务
- 子域名（如 mail.ftp.dev.staging）可能直接解析到源站 IP
- 检查所有子域名的 A 记录，排除 CDN IP

### 方法五：SSL 证书搜索
```python
import httpx
domain = "target.com"
r = httpx.get(f"https://crt.sh/?q=%.{domain}&output=json")
if r.status_code == 200:
    # 查找不同子域名的证书关联的 IP
    for entry in r.json():
        print(entry.get('name_value', ''))
```

## 3. 操作系统指纹

### TTL 推断
| TTL 值 | 可能的操作系统 |
|--------|-------------|
| ≈ 64 | Linux / Unix / macOS |
| ≈ 128 | Windows |
| ≈ 255 | 网络设备 / 老式 Unix |

```python
import subprocess
# Ping 获取 TTL
result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True)
# Windows: ping -n 1 host
# 从输出中提取 TTL
import re
ttl_match = re.search(r'TTL[=:]\s*(\d+)', result.output, re.I)
if ttl_match:
    ttl = int(ttl_match.group(1))
    if ttl <= 64:
        print("推测: Linux/Unix")
    elif ttl <= 128:
        print("推测: Windows")
    else:
        print("推测: 网络设备")
```

### nmap OS 检测
```bash
nmap -O <target>
# 更激进（需要 root）
sudo nmap -O --osscan-guess <target>
```

## 4. 中间件版本识别

### HTTP 响应头分析
```
Server: Apache/2.4.49 (Ubuntu)
Server: nginx/1.18.0
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.3
X-Powered-By: Express
X-AspNet-Version: 4.0.30319
```

### 错误页面特征
- Apache: 默认 404 页面含 "Apache" 字样
- Nginx: 默认 404 页面含 "nginx" 字样
- IIS: 默认错误页含 IIS 版本信息
- Tomcat: 默认 404 页面含 Apache Tomcat 版本

### 特征文件探测
```python
import httpx
target = "https://target.com"
# Apache
r = httpx.get(f"{target}/server-status")  # 403 = 存在
r = httpx.get(f"{target}/server-info")    # 403 = 存在
# Nginx
r = httpx.get(f"{target}/nginx_status")   # 可能暴露状态
# Tomcat
r = httpx.get(f"{target}/manager/html")   # 管理界面
# IIS
r = httpx.get(f"{target}/aspnet_client/") # ASP.NET 特征
```

## 5. 数据库识别

### 端口探测
| 数据库 | 默认端口 | 说明 |
|--------|---------|------|
| MySQL | 3306 | 最常见 |
| PostgreSQL | 5432 | 常见于 Rails/Django |
| MSSQL | 1433 | Windows 环境 |
| MongoDB | 27017 | NoSQL |
| Redis | 6379 | 缓存/消息队列 |
| Oracle | 1521 | 企业级 |
| Memcached | 11211 | 缓存 |

### 错误信息特征
- MySQL: `You have an error in your SQL syntax`
- PostgreSQL: `ERROR: syntax error at or near`
- MSSQL: `Microsoft SQL Server`
- Oracle: `ORA-01756`

### python_execute 检测
```python
import socket

def check_db(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # 尝试读取 banner
        s.send(b"\r\n")
        banner = s.recv(1024)
        s.close()
        return banner.hex()[:40], banner[:100]
    except:
        return None, None

db_ports = {
    3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
    27017: "MongoDB", 6379: "Redis", 1521: "Oracle",
}
for port, name in db_ports.items():
    hex_banner, banner = check_db(host, port)
    if hex_banner:
        print(f"[+] {name} ({port}): {banner}")
```
