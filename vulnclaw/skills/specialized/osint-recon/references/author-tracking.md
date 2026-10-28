# 作者追踪方法

## 核心流程

```
页面提取作者标识 → 确定唯一标识符(用户名/邮箱) → 跨平台搜索 → 信息汇总
```

## Step 1: 从页面提取作者标识

### HTML Meta 标签
```python
import re

def extract_author_from_meta(html):
    """从 HTML meta 标签提取作者信息"""
    authors = []
    
    # <meta name="author" content="XXX">
    m = re.findall(r'<meta\s+name=["\']author["\']\s+content=["\']([^"\']+)["\']', html)
    authors.extend(m)
    
    # <meta name="copyright" content="XXX">
    m = re.findall(r'<meta\s+name=["\']copyright["\']\s+content=["\']([^"\']+)["\']', html)
    authors.extend(m)
    
    # OG 标签
    m = re.findall(r'<meta\s+property=["\']article:author["\']\s+content=["\']([^"\']+)["\']', html)
    authors.extend(m)
    
    return list(set(authors))
```

### 页面链接提取
```python
def extract_social_links(html):
    """从页面提取社交媒体链接"""
    links = re.findall(r'href=["\'](https?://[^"\']+)["\']', html)
    
    social = {}
    for link in links:
        if 'github.com' in link:
            social['github'] = link
        elif 'bilibili.com' in link:
            social['bilibili'] = link
        elif 'weibo.com' in link or 'weibo.cn' in link:
            social['weibo'] = link
        elif 'zhihu.com' in link:
            social['zhihu'] = link
        elif 'twitter.com' in link or 'x.com' in link:
            social['twitter'] = link
        elif 'linkedin.com' in link:
            social['linkedin'] = link
        elif 'youtube.com' in link:
            social['youtube'] = link
        elif 'facebook.com' in link:
            social['facebook'] = link
    
    return social
```

## Step 2: GitHub 追踪

### 用户信息 API
```python
import httpx

def get_github_profile(username):
    """获取 GitHub 用户公开信息"""
    r = httpx.get(f"https://api.github.com/users/{username}")
    if r.status_code != 200:
        return None
    
    data = r.json()
    return {
        'name': data.get('name'),
        'bio': data.get('bio'),
        'email': data.get('email'),
        'blog': data.get('blog'),
        'location': data.get('location'),
        'company': data.get('company'),
        'public_repos': data.get('public_repos'),
        'followers': data.get('followers'),
        'following': data.get('following'),
        'created_at': data.get('created_at'),
        'avatar_url': data.get('avatar_url'),
    }

def get_github_repos(username):
    """获取用户公开仓库（推断技术栈）"""
    r = httpx.get(f"https://api.github.com/users/{username}/repos?per_page=100")
    if r.status_code != 200:
        return []
    
    repos = r.json()
    languages = {}
    for repo in repos:
        lang = repo.get('language')
        if lang:
            languages[lang] = languages.get(lang, 0) + 1
    
    return {
        'top_languages': sorted(languages.items(), key=lambda x: -x[1])[:5],
        'repo_count': len(repos),
        'starred_total': sum(r.get('stargazers_count', 0) for r in repos),
    }
```

### 从 GitHub 提交记录提取邮箱
```python
def get_github_commit_email(username, repo):
    """从 GitHub 提交记录提取作者邮箱"""
    r = httpx.get(f"https://api.github.com/repos/{username}/{repo}/commits?per_page=10")
    if r.status_code != 200:
        return []
    
    emails = set()
    for commit in r.json():
        author = commit.get('commit', {}).get('author', {})
        if author.get('email'):
            emails.add(author['email'])
    
    return list(emails)
```

## Step 3: 跨平台关联

### 用用户名搜索其他平台
```python
# 常见平台检测
PLATFORMS = {
    'GitHub': 'https://github.com/{username}',
    'B站': 'https://space.bilibili.com/search?keyword={username}',
    '知乎': 'https://www.zhihu.com/search?type=content&q={username}',
    'CSDN': 'https://blog.csdn.net/{username}',
    '掘金': 'https://juejin.cn/user/{username}',
    'Twitter': 'https://twitter.com/{username}',
    'LinkedIn': 'https://www.linkedin.com/in/{username}',
}

async def cross_platform_search(username, fetch_tool):
    """用用户名在多个平台搜索"""
    results = {}
    for platform, url_template in PLATFORMS.items():
        url = url_template.format(username=username)
        try:
            resp = await fetch_tool(url=url)
            if resp.get('status') == 200:
                results[platform] = f"✅ 找到 ({url})"
            else:
                results[platform] = f"❌ 未找到"
        except:
            results[platform] = f"⚠️ 检测失败"
    return results
```

## Step 4: 信息汇总模板

```markdown
## 人物画像：{昵称}

### 基础信息
- **昵称**：xxx
- **真实姓名**：xxx（如有）
- **邮箱**：xxx
- **位置**：xxx
- **职业/公司**：xxx

### 技术画像
- **主力语言**：Python / JavaScript / ...
- **技术栈偏好**：...
- **开源贡献**：N 个仓库，M 颗星
- **感兴趣领域**：...

### 社交媒体
- GitHub: xxx
- B站: xxx
- 知乎: xxx
- ...

### 关联信息
- 跨平台相同 ID：xxx
- 已知项目：xxx
- 历史泄露：xxx
```
