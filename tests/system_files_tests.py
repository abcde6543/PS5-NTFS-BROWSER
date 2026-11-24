#!/usr/bin/env python3
"""Windows' metadata below $Extend can't be deleted or written into.

$Extend's files ($ObjId, $Quota, $Reparse, ...) have record numbers from 24
up, so the "system files can't be deleted" check (record < 24) missed them:
the API deleted all three on a fresh mkntfs volume.

Needs root (mkntfs), like the other server tests.
usage: system_files_tests.py build/ntfs-browser
"""
import http.client, json, os, shutil, socket, subprocess, sys, tempfile, time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
PORT = 18092
WORK = tempfile.mkdtemp(prefix="ntfsb-sys-")
IMG = os.path.join(WORK, "sys.img")
failures = []


def check(name, cond, detail=""):
    print("%-44s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def req(method, path, params=None, body=None):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    c.request(method, path + q, body=body, headers={"X-NTFSB": "1"})
    r = c.getresponse()
    b = r.read()
    c.close()
    try:
        return r.status, json.loads(b)
    except ValueError:
        return r.status, None


def delete(path):
    s, j = req("POST", "/api/delete", {"vol": "ntfs0", "path": path})
    if s != 200 or not j or "job" not in j:
        return "HTTP %s" % s
    for _ in range(100):
        _, js = req("GET", "/api/jobs")
        m = [x for x in js["jobs"] if x["id"] == j["job"]]
        if m and m[0]["state"] in ("done", "failed", "cancelled"):
            return m[0]["state"]
        time.sleep(0.1)
    return "timed out"


def names(path):
    s, j = req("GET", "/api/list", {"vol": "ntfs0", "path": path})
    return sorted(e["n"] for e in j["entries"]) if s == 200 else None


def main():
    with open(IMG, "wb") as f:
        f.truncate(64 << 20)
    subprocess.run(["mkntfs", "-F", "-Q", "-L", "sys", IMG], check=True, capture_output=True)
    log = open(os.path.join(WORK, "server.log"), "w")
    proc = subprocess.Popen([BIN, "-p", str(PORT), IMG], cwd=WORK, stdout=log, stderr=log)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        before = names("/$Extend")
        check("$Extend lists its metadata files", before and "$Quota" in before, "%s" % before)
        for n in ("$ObjId", "$Quota", "$Reparse"):
            r = delete("/$Extend/" + n)
            check("delete /$Extend/%s refused" % n, r != "done", r)
        check("$Extend unchanged", names("/$Extend") == before, "%s" % names("/$Extend"))
        s, _ = req("POST", "/api/mkdir", {"vol": "ntfs0", "path": "/$Extend/new"})
        check("mkdir inside $Extend refused", s >= 400, "HTTP %s" % s)
        s, _ = req("POST", "/api/upload", {"vol": "ntfs0", "path": "/$Extend", "name": "x.bin"}, b"x")
        check("upload into $Extend refused", s >= 400, "HTTP %s" % s)
        check("$Extend still unchanged", names("/$Extend") == before, "%s" % names("/$Extend"))
        # Ordinary files are not affected.
        s, _ = req("POST", "/api/upload", {"vol": "ntfs0", "path": "/", "name": "Extend.txt"}, b"x")
        check("upload of an ordinary file works", s == 200, "HTTP %s" % s)
        check("deleting it works", delete("/Extend.txt") == "done")
    finally:
        proc.terminate()
        proc.wait(10)
        log.close()
    shutil.rmtree(WORK, ignore_errors=True)
    print("\n%s" % ("ALL PASSED" if not failures else "FAILED: " + ", ".join(failures)))
    sys.exit(1 if failures else 0)


main()
