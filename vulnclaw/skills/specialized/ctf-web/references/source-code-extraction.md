# CTF Web 源码提取方法参考

## 核心认知

- CTF Web 题常使用 `highlight_file(__FILE__)` 展示源码，输出的是 HTML 着色代码
- 也有题目只在 HTML 注释或隐藏元素中暴露部分源码，这是设计的一部分
- **源码是重要线索，但不是唯一线索**——有些题目的关键入口在 robots.txt、响应头、隐藏文件等处

---

## 方法一：strip_tags 提取（highlight_file 场景首选）

**适用**：`highlight_file()` / `show_source()` 展示源码的页面

```python
import httpx, re
r = httpx.get(url)
# 去掉所有 HTML 标签，获取纯文本
clean = re.sub(r'<[^>]+>', '', r.text)
# 可选：去除多余空行
clean = re.sub(r'\n{3,}', '\n\n', clean)
print(clean)
```

**注意**：
- 会去掉所有 HTML 标签，如果源码中本身有 HTML 字符串也会被去掉
- fetch 工具拿到的 HTML 着色输出**不适合直接目测还原**，建议用 python_execute 验证

---

## 方法二：php://filter 读取源码

**适用**：有文件包含漏洞（`include`/`require`）的场景

```
?page=php://filter/convert.base64-encode/resource=index.php
?page=php://filter/read=convert.base64-encode/resource=flag.php
```

获取到 base64 编码的源码后：
```python
import base64
source = base64.b64decode(base64_string).decode('utf-8')
print(source)
```

---

## 方法三：.phps 后缀

**适用**：服务器配置了 PHP 源码展示

```
/learning.phps
/index.phps
```

---

## 方法四：备份文件 / 版本控制泄露

| 路径 | 说明 |
|------|------|
| `.git/HEAD` | Git 仓库泄露 |
| `.svn/entries` | SVN 仓库泄露 |
| `index.php.bak` | 备份文件 |
| `index.php~` | 编辑器临时文件 |
| `www.zip` / `web.tar.gz` | 整站打包 |
| `.index.php.swp` | Vim 交换文件 |

---

## 方法五：HTML 注释和隐藏元素

有些题目在 HTML 注释中放置源码或提示：

```python
import httpx, re
r = httpx.get(url)
# 提取 HTML 注释内容
comments = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
for c in comments:
    print(c)
```

---

## 方法六：响应头和 Cookie

有些题目在响应头中藏有提示：

```python
import httpx
r = httpx.get(url)
print("Headers:", dict(r.headers))
print("Cookies:", dict(r.cookies))
```

---

## 源码完整性判断

提取到源码后，可以检查是否完整：

| 检查项 | 说明 |
|--------|------|
| 大括号匹配 | `if` 没有闭合的 `}` 可能意味着源码被截断，也可能是题目故意如此 |
| 存在输出语句 | 如果没有 `echo`/`print`/`die`，可能还有未看到的代码 |
| 存在危险函数 | 如果没有 `eval`/`system` 等，RCE 入口可能在其他页面 |

**注意**：源码不完整有两种可能——
1. 提取方法有问题 → 换方法重新提取
2. 题目就是只暴露这么多 → 需要继续探索其他线索（其他页面、参数、文件）
