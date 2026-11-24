#!/usr/bin/env python3
"""Long and unusual names must never be cut short on the way to the driver.

A shortened path or name still names something: a path cut right after a '/'
names its folder, and a name cut to 511 bytes can be another file's name.
Each case below hit the wrong file (or stored a mangled name) before the fix.

Needs root (mkntfs and ntfs-3g), like the other tests.
usage: longname_tests.py build/ntfs-browser
"""
import http.client, json, os, shutil, socket, subprocess, sys, tempfile, time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
PORT = 18090
WORK = tempfile.mkdtemp(prefix="ntfsb-names-")
IMG = os.path.join(WORK, "names.img")
MNT = os.path.join(WORK, "mnt")
failures = []

LONG_DIR = "日" * 255          # 765 UTF-8 bytes: the longest legal NTFS name
SUB = "本" * 85                # 255 bytes: "/LONG_DIR/SUB/" is exactly 1023 bytes
TWIN_SHORT = "a" + "中" * 170  # 511 bytes
TWIN_LONG = TWIN_SHORT + "b"       # 512 bytes: its first 511 bytes are TWIN_SHORT
UPLOAD = "文" * 196 + ".txt"   # 592 bytes
COPY_SRC = "音" * 251 + ".bin" # 255 UTF-16 units, 757 bytes


def sh(*a):
    return subprocess.run(a, check=True, capture_output=True)


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


def raw_post(path_and_query):
    """POST with a hand-made query (for %00, which urlencode can't produce)."""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    c.request("POST", path_and_query, headers={"X-NTFSB": "1"})
    r = c.getresponse()
    b = r.read()
    c.close()
    try:
        return r.status, json.loads(b)
    except ValueError:
        return r.status, None


def wait_job(j):
    if not j or "job" not in j:
        return None
    for _ in range(300):
        _, js = req("GET", "/api/jobs")
        m = [x for x in js["jobs"] if x["id"] == j["job"]]
        if m and m[0]["state"] in ("done", "failed", "cancelled"):
            return m[0]
        time.sleep(0.1)
    return None


def names(path):
    s, j = req("GET", "/api/list", {"vol": "ntfs0", "path": path})
    return [e["n"] for e in j["entries"]] if s == 200 else None


def build_image():
    os.makedirs(MNT)
    with open(IMG, "wb") as f:
        f.truncate(64 << 20)
    sh("mkntfs", "-F", "-Q", "-L", "names", IMG)
    sh("ntfs-3g", IMG, MNT)
    try:
        d = os.path.join(MNT, LONG_DIR, SUB)
        os.makedirs(d)
        for n in ("c.txt", "keep.txt"):
            with open(os.path.join(d, n), "w") as f:
                f.write(n)
        os.makedirs(os.path.join(MNT, "Saves"))
        with open(os.path.join(MNT, "Saves", "save.dat"), "w") as f:
            f.write("save")
        os.makedirs(os.path.join(MNT, "twins"))
        for n in (TWIN_SHORT, TWIN_LONG):
            with open(os.path.join(MNT, "twins", n), "w") as f:
                f.write(n[-1])
        os.makedirs(os.path.join(MNT, "src"))
        with open(os.path.join(MNT, "src", COPY_SRC), "w") as f:
            f.write("data")
        os.makedirs(os.path.join(MNT, "dst"))
    finally:
        sh("umount", MNT)


def main():
    build_image()
    log = open(os.path.join(WORK, "server.log"), "w")
    proc = subprocess.Popen([BIN, "-p", str(PORT), IMG], cwd=WORK, stdout=log, stderr=log)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)

        # 1. A 1028-byte path: cut at 1023 bytes it is "/LONG_DIR/SUB/", the folder.
        target = "/%s/%s/c.txt" % (LONG_DIR, SUB)
        s, j = req("POST", "/api/delete", {"vol": "ntfs0", "path": target})
        wait_job(j)
        left = names("/%s/%s" % (LONG_DIR, SUB))
        check("over-long path refused (414)", s == 414, "HTTP %s" % s)
        check("its folder and the other file survive", left is not None and "keep.txt" in left,
              "folder now: %s" % left)

        # 2. %00 inside a value: the part before it used to be acted on.
        s, j = raw_post("/api/delete?vol=ntfs0&path=%2FSaves%00%2Fnot-there")
        wait_job(j)
        check("path with %00 refused (414)", s == 414, "HTTP %s" % s)
        check("/Saves survives", "save.dat" in (names("/Saves") or []), "listing %s" % names("/Saves"))

        # 3. Deleting the 512-byte name must not delete its 511-byte twin.
        s, j = req("POST", "/api/delete", {"vol": "ntfs0", "path": "/twins/" + TWIN_LONG})
        jj = wait_job(j)
        left = names("/twins") or []
        check("delete of a 512-byte name finishes", s == 200 and jj and jj["state"] == "done",
              "HTTP %s %s" % (s, jj and jj["error"]))
        check("the 511-byte twin survives", TWIN_SHORT in left, "left: %d entries" % len(left))
        check("the 512-byte name is gone", TWIN_LONG not in left)

        # 4. Upload with a 592-byte name keeps the whole name.
        s, j = req("POST", "/api/upload", {"vol": "ntfs0", "path": "/", "name": UPLOAD}, b"hello")
        root = names("/") or []
        check("upload with a 592-byte name succeeds", s == 200, "HTTP %s" % s)
        check("stored under its full name", UPLOAD in root,
              "got %s" % [len(n) for n in root if n.startswith("文")])

        # 5. Drive-to-drive copy of a 757-byte name keeps the whole name.
        s, j = req("POST", "/api/copy", {"vol": "ntfs0", "path": "/src/" + COPY_SRC,
                                         "dvol": "ntfs0", "dest": "/dst"})
        jj = wait_job(j)
        dst = names("/dst") or []
        check("copy of a 757-byte name finishes", jj is not None and jj["state"] == "done",
              "%s" % (jj and jj["error"]))
        check("copied under its full name", COPY_SRC in dst, "got %s" % [len(n) for n in dst])
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
