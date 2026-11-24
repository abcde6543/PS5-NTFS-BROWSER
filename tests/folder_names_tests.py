#!/usr/bin/env python3
"""New folders on NTFS drives must get names Windows can use.

Uploaded and copied files already go through vfs_safe_name(), but "New
folder" and the destination folder of a copy were created as typed: an NTFS
drive then held folders such as "CON", "a:b" or "name." that Explorer can't
open or delete.

Needs mkntfs. usage: folder_names_tests.py build/ntfs-browser
"""
import http.client, json, os, shutil, socket, subprocess, sys, tempfile, time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
PORT = 18095
WORK = tempfile.mkdtemp(prefix="ntfsb-names2-")
IMG = os.path.join(WORK, "n.img")
NATIVE = os.path.join(WORK, "console")
failures = []

BAD = ["CON", "con.txt", "a:b", "x|y", "what?", "name.", "name ", "LPT0", "COM¹"]
GOOD = ["Saves", "Spiel (2)", "日本語", "COM10", "Console"]


def check(name, cond, detail=""):
    print("%-44s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def req(method, path, params=None):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    c.request(method, path + q, headers={"X-NTFSB": "1"})
    r = c.getresponse()
    b = r.read()
    c.close()
    try:
        return r.status, json.loads(b)
    except ValueError:
        return r.status, None


def names(path):
    s, j = req("GET", "/api/list", {"vol": "ntfs0", "path": path})
    return sorted(e["n"] for e in j["entries"]) if s == 200 else []


def main():
    os.makedirs(NATIVE)
    with open(os.path.join(NATIVE, "f.txt"), "w") as f:
        f.write("x")
    with open(IMG, "wb") as f:
        f.truncate(64 << 20)
    subprocess.run(["mkntfs", "-F", "-Q", "-L", "names", IMG], check=True, capture_output=True)
    log = open(os.path.join(WORK, "server.log"), "w")
    proc = subprocess.Popen([BIN, "-p", str(PORT), IMG], cwd=WORK, stdout=log, stderr=log)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        for n in BAD:
            s, _ = req("POST", "/api/mkdir", {"vol": "ntfs0", "path": "/" + n})
            check("mkdir %r refused (400)" % n, s == 400, "HTTP %s" % s)
        s, _ = req("POST", "/api/mkdir", {"vol": "ntfs0", "path": "/ok/CON"})
        check("mkdir '/ok/CON' refused (400)", s == 400, "HTTP %s" % s)
        s, _ = req("POST", "/api/copy", {"vol": "ps5", "path": os.path.join(NATIVE, "f.txt"),
                                         "dvol": "ntfs0", "dest": "/Back:up"})
        check("copy into '/Back:up' refused (400)", s == 400, "HTTP %s" % s)
        root = names("/")
        check("none of them was created", root == [], "root now: %s" % root)
        for n in GOOD:
            s, _ = req("POST", "/api/mkdir", {"vol": "ntfs0", "path": "/" + n})
            check("mkdir %r works" % n, s == 200 and n in names("/"), "HTTP %s" % s)
        s, _ = req("POST", "/api/mkdir", {"vol": "ps5", "path": os.path.join(NATIVE, "a:b")})
        check("console side keeps its own rules (a:b)", s == 200 and os.path.isdir(os.path.join(NATIVE, "a:b")),
              "HTTP %s" % s)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(10)
        log.close()
    shutil.rmtree(WORK, ignore_errors=True)
    print("\n%s" % ("ALL PASSED" if not failures else "FAILED: " + ", ".join(failures)))
    sys.exit(1 if failures else 0)


main()
