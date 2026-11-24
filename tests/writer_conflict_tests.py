#!/usr/bin/env python3
"""A file that is being written must not get a second writer or be deleted.

An upload whose connection stalls keeps its file open (the server waits up
to 30 s for more data). Before this was checked:
- a second upload of the same file finished fine, but when the stalled one
  gave up, its close stored its own, smaller "initialized size" over the
  file, so everything after that point read back as zeros;
- deleting the file freed its clusters while the stalled upload still wrote
  into them; once another file had taken them, the old upload wrote into it.

Needs root (mkntfs and ntfs-3g), like the other tests.
usage: writer_conflict_tests.py build/ntfs-browser
"""
import http.client, json, os, shutil, socket, subprocess, sys, tempfile, time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
PORT = 18091
WORK = tempfile.mkdtemp(prefix="ntfsb-conflict-")
IMG = os.path.join(WORK, "c.img")
MNT = os.path.join(WORK, "mnt")
failures = []


def sh(*a):
    return subprocess.run(a, check=True, capture_output=True)


def check(name, cond, detail=""):
    print("%-52s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def req(method, path, params=None, body=None):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    c.request(method, path + q, body=body, headers={"X-NTFSB": "1"})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, b


def jreq(method, path, params=None, body=None):
    s, b = req(method, path, params, body)
    try:
        return s, json.loads(b)
    except ValueError:
        return s, None


def stalled_upload(name, total, first):
    """Start an upload, send only the first bytes and keep the connection."""
    q = urllib.parse.urlencode({"vol": "ntfs0", "path": "/up", "name": name})
    sk = socket.create_connection(("127.0.0.1", PORT))
    sk.sendall(("POST /api/upload?%s HTTP/1.1\r\nHost: 127.0.0.1\r\nX-NTFSB: 1\r\n"
                "Content-Length: %d\r\n\r\n" % (q, total)).encode())
    sk.sendall(first)
    time.sleep(1.0)  # let the server write what it got
    return sk


def wait_job(j):
    for _ in range(300):
        _, js = jreq("GET", "/api/jobs")
        m = [x for x in js["jobs"] if x["id"] == j["job"]]
        if m and m[0]["state"] in ("done", "failed", "cancelled"):
            return m[0]
        time.sleep(0.1)


def main():
    os.makedirs(MNT)
    with open(IMG, "wb") as f:
        f.truncate(64 << 20)
    sh("mkntfs", "-F", "-Q", "-L", "conflict", IMG)
    sh("ntfs-3g", IMG, MNT)
    os.makedirs(os.path.join(MNT, "up"))
    sh("umount", MNT)
    log = open(os.path.join(WORK, "server.log"), "w")
    proc = subprocess.Popen([BIN, "-p", str(PORT), IMG], cwd=WORK, stdout=log, stderr=log)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)

        # 1. Second writer while the first one is stalled.
        size = 8 << 20
        data = os.urandom(size)
        old = stalled_upload("movie.bin", size, data[:2 << 20])
        s, _ = req("POST", "/api/upload", {"vol": "ntfs0", "path": "/up", "name": "movie.bin"}, data)
        check("second upload of an open file refused (409)", s == 409, "HTTP %s" % s)
        s, _ = req("POST", "/api/upload", {"vol": "ntfs0", "path": "/up", "name": "movie.bin",
                                           "check": "1", "size": str(size)})
        check("resume check of an open file refused (409)", s == 409, "HTTP %s" % s)
        old.close()  # the stalled upload fails and closes its file
        time.sleep(1.5)
        s, _ = req("POST", "/api/upload", {"vol": "ntfs0", "path": "/up", "name": "movie.bin"}, data)
        check("upload after the old one is gone succeeds", s == 200, "HTTP %s" % s)
        time.sleep(0.5)
        s, got = req("GET", "/api/file", {"vol": "ntfs0", "path": "/up/movie.bin"})
        check("file content complete", got == data,
              "first difference at %s" % next((i for i in range(0, size, 4096)
                                               if got[i:i + 4096] != data[i:i + 4096]), None))

        # 2. Delete while an upload still writes the file.
        old = stalled_upload("old.bin", 4 << 20, b"O" * (1 << 20))
        s, j = jreq("POST", "/api/delete", {"vol": "ntfs0", "path": "/up/old.bin"})
        jj = wait_job(j) if s == 200 and j else None
        check("delete of an open file refused", jj is not None and jj["state"] == "failed",
              "HTTP %s, job %s" % (s, jj and (jj["state"], jj["error"])))
        try:
            old.sendall(b"O" * (3 << 20))
            old.settimeout(30)
            status = old.recv(4096).decode(errors="replace").split("\r\n")[0]
        except OSError as e:
            status = "socket error %s" % e
        old.close()
        check("the upload still finishes", " 200 " in status, status)
        s, got = req("GET", "/api/file", {"vol": "ntfs0", "path": "/up/old.bin"})
        check("its content is intact", got == b"O" * (4 << 20), "HTTP %s, %d bytes" % (s, len(got)))
        s, j = jreq("POST", "/api/delete", {"vol": "ntfs0", "path": "/up/old.bin"})
        jj = wait_job(j) if s == 200 and j else None
        check("delete after the upload works", jj is not None and jj["state"] == "done",
              "%s" % (jj and jj["error"]))
        check("server still running", proc.poll() is None)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(10)
        log.close()

    r = subprocess.run(["ntfsfix", "-n", IMG], capture_output=True, text=True)
    check("volume still consistent (ntfsfix -n)", r.returncode == 0, r.stdout[-300:])
    shutil.rmtree(WORK, ignore_errors=True)
    print("\n%s" % ("ALL PASSED" if not failures else "FAILED: " + ", ".join(failures)))
    sys.exit(1 if failures else 0)


main()
