# PHP 代码审计 Checklist

## 第一步：识别输入入口

### 超全局变量
```php
$_GET['param']        // URL 查询参数
$_POST['param']       // POST 表单数据
$_REQUEST['param']    // GET + POST + COOKIE
$_COOKIE['param']     // Cookie 值
$_SERVER['HTTP_X']    // HTTP 请求头
$_FILES['file']       // 上传文件
$_SESSION['key']      // Session 数据（如果可控）
```

### 隐蔽输入
```php
php://input           // POST 原始数据
getallheaders()       // 所有 HTTP 头
getenv()              // 环境变量
file_get_contents()   // 从文件/URL 读取
```

## 第二步：识别危险函数

### 代码执行
```php
eval()                // 执行任意 PHP 代码
assert()              // PHP < 7 可执行代码
preg_replace(/e)      // /e 修饰符执行替换结果
create_function()     // 创建匿名函数
call_user_func()      // 调用回调函数
call_user_func_array()// 调用回调函数（数组参数
array_map()           // 对数组元素应用回调
usort()               // 自定义排序（可注入回调
array_filter()        // 过滤数组（可注入回调
```

### 命令执行
```php
system()              // 执行外部程序，输出结果
exec()                // 执行外部程序，返回最后一行
shell_exec()          // 执行命令，返回完整输出
passthru()            // 执行外部程序，输出原始数据
popen()               // 打开进程管道
proc_open()           // 打开进程（更灵活
pcntl_exec()          // 执行程序（需要 pcntl 扩展
反引号 `cmd`           // 等价于 shell_exec()
```

### 文件操作
```php
include() / require()          // 文件包含
include_once() / require_once()
file_get_contents()            // 读取文件
file_put_contents()            // 写入文件
fopen() + fread()              // 打开并读取
readfile()                     // 输出文件内容
highlight_file() / show_source()// 高亮显示源码
unlink()                       // 删除文件
rename()                       // 重命名文件
copy()                         // 复制文件
move_uploaded_file()           // 移动上传文件
```

### 反序列化
```php
unserialize()        // 反序列化对象
__wakeup()           // 反序列化时调用
__destruct()         // 对象销毁时调用
__toString()         // 对象被当字符串使用时调用
__call()             // 调用不存在的方法时触发
__get()              // 访问不存在的属性时触发
```

## 第三步：分析过滤/检查逻辑

### 正则过滤分析清单
```php
preg_match("/pattern/flags", $input)

□ 是否有 i 修饰符？  → 没有 → 可大小写绕过
□ 是否有 m 修饰符？  → 有 → 考虑换行符绕过 ^$
□ 是否有 s 修饰符？  → 有 → . 匹配换行
□ 检查的是字符串还是数组？ → 数组绕过
□ 是否可以回溯超限？  → PCRE 回溯限制绕过
```

### 常见过滤函数
```php
str_replace()        // 字符串替换（可双写绕过）
str_ireplace()       // 不区分大小写替换
strstr() / strpos()  // 字符串查找（可大小写绕过 / 数组绕过）
strlen()             // 长度检查（可利用特性绕过）
in_array()           // 数组检查（弱类型比较）
is_numeric()         // 数字检查（十六进制/科学计数法）
intval()             // 整数转换（特性绕过）
trim()               // 去空白（%0a%0d 绕过）
htmlspecialchars()   // HTML 转义（默认不转义单引号）
addslashes()         // 添加斜杠（宽字节/GBK 绕过）
mysql_real_escape_string() // 转义（宽字节/GBK 绕过）
```

## 第四步：画出数据流图

```
用户输入 → [过滤A] → [过滤B] → 危险函数
          ↓
          被过滤？
          ↓ 否
          [绕过检查] → 危险函数执行
```

### 路径选择原则
1. **过滤最少的路径优先**
2. **参数最少的路径优先**（3 个参数的路径 < 5 个参数的路径）
3. **结果可见的路径优先**（system() 优先于 exec()）
4. **简单绕过优先**（大小写绕过 < 编码绕过 < 链式绕过）

## 第五步：输出可见性分析

### 确认命令输出是否可见
```
1. system() 输出 → 直接在 HTTP 响应中
2. exec() 输出 → 需要额外 echo
3. eval() + system() → 输出在 eval 上下文中
4. highlight_file() + system() → 输出在源码高亮之后
```

### 不确定时先测试
```php
// 先用简单命令测试输出可见性
system('id');
system('echo TESTFLAG123');
// 在 HTTP 响应中搜索 TESTFLAG123
```

### 响应分析技巧
```python
# 使用 python_execute 分析响应
import httpx
r = httpx.get(url, params=payload)
print(f"Status: {r.status_code}")
print(f"Length: {len(r.text)}")
print(f"Headers: {dict(r.headers)}")
# 只看最后 N 字符（flag 常在末尾）
print(f"Tail: {r.text[-500:]}")
# 搜索 flag 模式
import re
flags = re.findall(r'(NSSCTF\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\})', r.text)
if flags:
    print(f"FLAG FOUND: {flags}")
```
