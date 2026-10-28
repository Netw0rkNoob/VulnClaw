# CTFd 平台操作指南

## CTFd API 基础

```python
import httpx

CTFD_URL = "https://ctf.example.com"
session = httpx.Client()

def login(username, password):
    """登录 CTFd"""
    r = session.post(f"{CTFD_URL}/login", data={
        "name": username,
        "password": password,
    })
    return r

def get_challenges():
    """获取所有题目"""
    r = session.get(f"{CTFD_URL}/api/v1/challenges")
    return r.json()

def get_challenge_detail(chal_id):
    """获取单个题目详情"""
    r = session.get(f"{CTFD_URL}/api/v1/challenges/{chal_id}")
    return r.json()

def get_challenge_files(chal_id):
    """获取题目附件"""
    r = session.get(f"{CTFD_URL}/api/v1/challenges/{chal_id}/files")
    return r.json()

def download_file(file_id):
    """下载题目文件"""
    r = session.get(f"{CTFD_URL}/api/v1/files/{file_id}")
    return r.content

def submit_flag(flag):
    """提交 flag"""
    r = session.post(f"{CTFD_URL}/api/v1/challenges/attempt", json={
        "challenge_id": chal_id,
        "submission": flag,
    })
    return r.json()

def get_scoreboard():
    """获取排行榜"""
    r = session.get(f"{CTFD_URL}/api/v1/scoreboard")
    return r.json()

def get_user_info():
    """获取当前用户信息"""
    r = session.get(f"{CTFD_URL}/api/v1/users/me")
    return r.json()
```

## 检测平台类型

```python
def detect_platform(url):
    """检测 CTF 平台类型"""
    # CTFd
    r = httpx.get(f"{url}/login")
    if 'ctfd' in r.text.lower() or 'csrf_token' in r.text:
        return "CTFd"

    # RBCG / CTFdLight
    if '/static/core' in r.text:
        return "RBCG"

    # HCTF / others
    return "Unknown"
```

## 常见 CTFd API

```
GET  /api/v1/challenges          # 所有题目
GET  /api/v1/challenges/{id}     # 题目详情
GET  /api/v1/challenges/{id}/files # 题目文件
POST /api/v1/challenges/attempt  # 提交 flag
GET  /api/v1/scoreboard          # 排行榜
GET  /api/v1/users/me            # 当前用户
GET  /api/v1/notifications       # 公告
```

## 批量下载附件

```python
def download_all_files(url, output_dir):
    """批量下载所有题目附件"""
    import os
    os.makedirs(output_dir, exist_ok=True)

    challenges = get_challenges()['data']
    for chal in challenges:
        chal_id = chal['id']
        try:
            files = get_challenge_files(chal_id)['data']
            for f in files:
                filename = f['filename']
                content = download_file(f['id'])
                with open(os.path.join(output_dir, filename), 'wb') as out:
                    out.write(content)
                print(f"Downloaded: {filename}")
        except Exception as e:
            print(f"Failed to download challenge {chal_id}: {e}")
```

## 自动解题模板

```python
def auto_solve(url, username, password, solve_func):
    """自动解题模板

    solve_func(challenge_data) -> flag
    """
    session = httpx.Client()
    login(username, password)

    challenges = get_challenges()['data']
    for chal in challenges:
        chal_id = chal['id']
        detail = get_challenge_detail(chal_id)['data']
        files = get_challenge_files(chal_id)['data']

        print(f"Solving: {detail['name']}")
        flag = solve_func(detail, files)

        if flag:
            result = submit_flag(flag)
            if result.get('data', {}).get('status') == 'correct':
                print(f"[✓] {detail['name']}: {flag}")
            else:
                print(f"[✗] {detail['name']}: Wrong flag")
        else:
            print(f"[-] {detail['name']}: No solve function")
```
