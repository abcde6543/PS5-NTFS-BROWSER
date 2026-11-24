#!/usr/bin/env python3
"""Writing to the console never replaces a different file.

The README promises that the server "only overwrites partly copied files"
and that the writer "never replaces files". On NTFS drives a file of the
same name but a different size is refused; on the console side it used to
be replaced: an upload or a copy of "save.dat" with another size silently
took the place of the existing save.dat.

Uses only the console side (vol=ps5), so it needs neither root nor ntfs-3g.
usage: no_overwrite_tests.py build/ntfs-browser
"""
import http.client, json, os, shutil, socket, subprocess, sys, tempfile, time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
PORT = 18094
WORK = tempfile.mkdtemp(prefix="ntfsb-noover-")
DEST = os.path.join(WORK, "console")
SRC = os.path.join(WORK, "source")
failures = []
ORIGINAL = b"A" * 100


def check(name, cond, detail=""):
    print("%-48s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
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


def content():
    with open(os.path.join(DEST, "save.dat"), "rb") as f:
        return f.read()


def main():
    os.makedirs(DEST)
    os.makedirs(SRC)
    with open(os.path.join(DEST, "save.dat"), "wb") as f:
        f.write(ORIGINAL)
    with open(os.path.join(SRC, "save.dat"), "wb") as f:
        f.write(b"B" * 300)
    log = open(os.path.join(WORK, "server.log"), "w")
    proc = subprocess.Popen([BIN, "-p", str(PORT)], cwd=WORK, stdout=log, stderr=log)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)

        s, j = req("POST", "/api/upload", {"vol": "ps5", "path": DEST, "name": "save.dat",
                                           "check": "1", "size": "200"})
        check("pre-check reports the other file (409)", s == 409, "HTTP %s %s" % (s, j))
        s, j = req("POST", "/api/upload", {"vol": "ps5", "path": DEST, "name": "save.dat"}, b"C" * 200)
        check("upload of another size refused (409)", s == 409, "HTTP %s %s" % (s, j))
        check("existing file unchanged after upload", content() == ORIGINAL, "%d bytes" % len(content()))

        s, j = req("POST", "/api/copy", {"vol": "ps5", "path": os.path.join(SRC, "save.dat"),
                                         "dvol": "ps5", "dest": DEST})
        state = None
        if s == 200 and j and "job" in j:
            for _ in range(100):
                _, js = req("GET", "/api/jobs")
                m = [x for x in js["jobs"] if x["id"] == j["job"]]
                if m and m[0]["state"] in ("done", "failed", "cancelled"):
                    state = m[0]
                    break
                time.sleep(0.1)
        check("copy of another size fails", state is not None and state["state"] == "failed",
              str(state and (state["state"], state["error"])))
        check("existing file unchanged after copy", content() == ORIGINAL, "%d bytes" % len(content()))

        s, j = req("POST", "/api/upload", {"vol": "ps5", "path": DEST, "name": "new.dat"}, b"N" * 50)
        check("upload of a new file works", s == 200 and
              open(os.path.join(DEST, "new.dat"), "rb").read() == b"N" * 50, "HTTP %s" % s)
        check("no .part files left", not [n for n in os.listdir(DEST) if n.endswith(".part")],
              "%s" % os.listdir(DEST))
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(10)
        log.close()
    shutil.rmtree(WORK, ignore_errors=True)
    print("\n%s" % ("ALL PASSED" if not failures else "FAILED: " + ", ".join(failures)))
    sys.exit(1 if failures else 0)


main()
