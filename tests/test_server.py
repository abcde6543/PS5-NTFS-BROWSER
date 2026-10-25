#!/usr/bin/env python3
"""HTTP API tests: runs the desktop build against an NTFS image.

Usage: tests/test_server.py build/ntfs-browser
"""
import concurrent.futures
import hashlib
import http.client
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import struct
import time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
WORK = tempfile.mkdtemp(prefix="ntfssrv-")
MNT = os.path.join(WORK, "mnt")
IMG = os.path.join(WORK, "vol.img")
DEST = os.path.join(WORK, "dest")
PORT = 18085
failures = []


def sh(*a):
    subprocess.run(a, check=True, capture_output=True)


def req(method, path, params=None, headers=None, trusted=True):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    h = dict(headers or {})
    if trusted:
        h["X-NTFSB"] = "1"
    c.request(method, path + q, headers=h)
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, dict(r.getheaders()), body


def jget(path, params=None, method="GET"):
    s, h, b = req(method, path, params)
    return s, json.loads(b) if b else None


def check(name, cond, detail=""):
    print("%-44s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def build_image():
    with open(IMG, "wb") as f:
        f.truncate(192 << 20)
    sh("mkntfs", "-F", "-Q", "-L", "Games & Media", IMG)
    os.makedirs(MNT)
    sh("ntfs-3g", IMG, MNT)
    try:
        os.makedirs(os.path.join(MNT, "Movies/Ünïcode 🎬"))
        with open(os.path.join(MNT, "Movies/Ünïcode 🎬/clip.mp4"), "wb") as f:
            f.write(random.Random(1).randbytes(5_000_000))
        with open(os.path.join(MNT, "readme.txt"), "w") as f:
            f.write("Hello PS5!\n" * 100)
        os.makedirs(os.path.join(MNT, "Games/Big Game/sub"))
        for i in range(25):
            with open(os.path.join(MNT, "Games/Big Game/part%02d.bin" % i), "wb") as f:
                f.write(random.Random(i).randbytes(400_000 + i))
        with open(os.path.join(MNT, "Games/Big Game/sub/save.dat"), "wb") as f:
            f.write(b"save" * 1000)
        with open(os.path.join(MNT, 'odd:name?.txt'), "w") as f:
            f.write("exFAT-unsafe name")
        with open(os.path.join(MNT, "big.bin"), "wb") as f:
            f.write(random.Random(9).randbytes(30_000_000))
    finally:
        sh("umount", MNT)


def file_hash_ntfs(path):
    s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": path})
    return hashlib.sha256(b).hexdigest(), b


def main():
    print("work dir:", WORK)
    build_image()
    os.makedirs(DEST)
    env = dict(os.environ)
    proc = subprocess.Popen([BIN, "-p", str(PORT), IMG], cwd=WORK, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        run_tests()
        expect = write_tests()
    finally:
        proc.terminate()
        out = proc.communicate(timeout=5)[0].decode(errors="replace")
        if failures:
            print("--- server output ---\n" + out)
    verify_offline(expect)
    print()
    if failures:
        print("FAILED:", ", ".join(failures))
        sys.exit(1)
    print("All server tests passed.")
    shutil.rmtree(WORK, ignore_errors=True)


def verify_offline(expect):
    """After the server exits: independent tools must agree the drive is fine."""
    tool = os.path.join(os.path.dirname(BIN), "ntfstool")
    r = subprocess.run([tool, "check", IMG], capture_output=True, text=True)
    check("consistency check after writes", r.returncode == 0, r.stdout + r.stderr)
    r = subprocess.run(["ntfsresize", "--check", "--force", IMG], capture_output=True, text=True)
    check("ntfsresize --check after writes", r.returncode == 0, r.stdout + r.stderr)
    sh("ntfs-3g", "-o", "ro", IMG, MNT)
    try:
        ok = True
        for rel, data in (expect or {}).items():
            name = rel.replace("video:clip?.mp4", "video_clip_.mp4")
            with open(os.path.join(MNT, "Backup/PS5", name), "rb") as f:
                if f.read() != data:
                    ok = False
                    break
        ok = ok and os.path.isdir(os.path.join(MNT, "New Folder/inner"))
        check("ntfs-3g reads everything we wrote", ok and bool(expect))
    finally:
        sh("umount", MNT)

    # A drive Windows didn't unmount cleanly must stay read-only.
    dirty = os.path.join(WORK, "dirty.img")
    shutil.copy(IMG, dirty)
    set_volume_dirty(dirty)
    p = subprocess.Popen([BIN, "-p", str(PORT + 1), dirty], cwd=WORK,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PORT + 1), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        c = http.client.HTTPConnection("127.0.0.1", PORT + 1, timeout=10)
        c.request("POST", "/api/writable?vol=ntfs0&on=1", headers={"X-NTFSB": "1"})
        r = c.getresponse()
        body = json.loads(r.read())
        check("dirty volume refuses writing", r.status == 409 and "cleanly" in body.get("error", ""), str(body))
    finally:
        p.terminate()
        p.wait()


def run_tests():
    s, h, b = req("GET", "/")
    check("index page served", s == 200 and b"NTFS Browser" in b and "text/html" in h["Content-Type"])

    s, j = jget("/api/status")
    check("status", s == 200 and j["app"] == "NTFS Browser" and j["port"] == PORT)

    s, j = jget("/api/volumes")
    ntfs = [v for v in j["volumes"] if v["kind"] == "ntfs"]
    check("volume auto-mounted", len(ntfs) == 1 and ntfs[0]["label"] == "Games & Media",
          json.dumps(j))

    s, j = jget("/api/volinfo", {"vol": "ntfs0"})
    check("free space reported", s == 200 and 0 < j["free"] < j["size"], str(j))

    s, j = jget("/api/list", {"vol": "ntfs0", "path": "/"})
    names = {e["n"]: e for e in j["entries"]}
    check("root listing", {"Movies", "Games", "readme.txt", "big.bin"} <= set(names), str(list(names)))
    check("system files hidden from root", not any(n.startswith("$Mft") for n in names))
    check("sizes in listing", names["big.bin"]["s"] == 30_000_000 and names["Games"]["d"] == 1)

    s, j = jget("/api/list", {"vol": "ntfs0", "path": "/Movies/Ünïcode 🎬"})
    check("unicode folder listing", s == 200 and j["entries"][0]["n"] == "clip.mp4", str(j))

    s, j = jget("/api/list", {"vol": "ntfs0", "path": "/movies/ÜNÏCODE 🎬"})
    check("case-insensitive path", s == 200 and len(j["entries"]) == 1)

    s, j = jget("/api/list", {"vol": "ntfs0", "path": "/nope"})
    check("missing folder -> 404", s == 404 and "error" in j)

    s, j = jget("/api/list", {"vol": "ntfs9", "path": "/"})
    check("unknown volume -> 404", s == 404)

    s, j = jget("/api/list", {"vol": "ntfs0", "path": "/readme.txt"})
    check("listing a file -> 400", s == 400)

    s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": "/readme.txt"})
    check("text download", s == 200 and b == b"Hello PS5!\n" * 100 and h["Content-Type"].startswith("text/plain"))

    ref = random.Random(9).randbytes(30_000_000)
    s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": "/big.bin", "dl": "1"})
    check("30 MB download intact", s == 200 and b == ref and "attachment" in h["Content-Disposition"])

    s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": "/big.bin"},
                  {"Range": "bytes=1000000-1999999"})
    check("range request", s == 206 and b == ref[1000000:2000000] and
          h["Content-Range"] == "bytes 1000000-1999999/30000000")

    s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": "/big.bin"}, {"Range": "bytes=-100"})
    check("suffix range", s == 206 and b == ref[-100:])

    s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": "/big.bin"}, {"Range": "bytes=29999990-"})
    check("open-ended range", s == 206 and b == ref[29999990:])

    s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": "/big.bin"}, {"Range": "bytes=40000000-"})
    check("unsatisfiable range -> 416", s == 416)

    s, h, b = req("HEAD", "/api/file", {"vol": "ntfs0", "path": "/big.bin"})
    check("HEAD has length, no body", s == 200 and h["Content-Length"] == "30000000" and b == b"")

    s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": "/Movies/Ünïcode 🎬/clip.mp4"})
    check("video mime + unicode file", s == 200 and h["Content-Type"] == "video/mp4" and len(b) == 5_000_000)

    # Keep-alive: several requests on one connection.
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    ok = True
    for _ in range(5):
        c.request("GET", "/api/status")
        r = c.getresponse()
        ok = ok and r.status == 200 and json.loads(r.read())["app"] == "NTFS Browser"
    c.close()
    check("keep-alive reuse", ok)

    # Parallel streams from the same volume.
    def grab(i):
        start = i * 1_000_000
        s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": "/big.bin"},
                      {"Range": "bytes=%d-%d" % (start, start + 2_999_999)})
        return b == ref[start:start + 3_000_000]
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        res = list(ex.map(grab, range(16)))
    check("16 parallel range downloads", all(res))

    # Security: state-changing routes need POST + the custom header.
    s, h, b = req("GET", "/api/copy", {"vol": "ntfs0", "path": "/readme.txt", "dest": DEST})
    check("copy via GET rejected", s == 405)
    s, h, b = req("POST", "/api/copy", {"vol": "ntfs0", "path": "/readme.txt", "dest": DEST}, trusted=False)
    check("copy without X-NTFSB rejected", s == 403)
    s, h, b = req("GET", "/api/list", {"vol": "ps5", "path": "/../../etc/.."})
    check("path traversal normalised", s == 200 and json.loads(b)["path"] == "/")
    s, h, b = req("GET", "/api/list", {"vol": "ntfs0", "path": "/x%00y"})
    check("embedded NUL rejected", s in (400, 404))
    s, h, b = req("GET", "/api/file", {"vol": "ntfs0", "path": "/readme.txt"})
    check("no CORS header", "Access-Control-Allow-Origin" not in h)

    # Copy a folder tree.
    s, j = jget("/api/copy", {"vol": "ntfs0", "path": "/Games/Big Game", "dest": DEST}, "POST")
    check("copy job accepted", s == 200 and j["job"] > 0, str(j))
    job = wait_job(j["job"])
    check("folder copy finished", job and job["state"] == "done", str(job))
    ok = True
    for i in range(25):
        p = os.path.join(DEST, "Big Game", "part%02d.bin" % i)
        ok = ok and open(p, "rb").read() == random.Random(i).randbytes(400_000 + i)
    ok = ok and open(os.path.join(DEST, "Big Game/sub/save.dat"), "rb").read() == b"save" * 1000
    check("copied tree byte-identical", ok)
    check("progress accounting", job["done_files"] == 26 and job["done_bytes"] == job["total_bytes"])
    leftovers = [f for r, d, fs in os.walk(DEST) for f in fs if f.endswith(".part")]
    check("no .part files left", not leftovers)

    # Copy again: everything should be skipped (resume).
    s, j = jget("/api/copy", {"vol": "ntfs0", "path": "/Games/Big Game", "dest": DEST}, "POST")
    job = wait_job(j["job"])
    check("re-copy skips existing files", job["skipped_files"] == 26, str(job))

    # Unsafe characters for exFAT are replaced.
    s, j = jget("/api/copy", {"vol": "ntfs0", "path": "/odd:name?.txt", "dest": DEST}, "POST")
    job = wait_job(j["job"])
    check("exFAT-unsafe name sanitised",
          job["state"] == "done" and os.path.exists(os.path.join(DEST, "odd_name_.txt")), str(job))

    # Destination folders are created on demand.
    newdest = os.path.join(DEST, "new/nested")
    s, j = jget("/api/copy", {"vol": "ntfs0", "path": "/readme.txt", "dest": newdest}, "POST")
    job = wait_job(j["job"])
    check("destination created", job["state"] == "done" and
          open(os.path.join(newdest, "readme.txt")).read() == "Hello PS5!\n" * 100)

    # Cancel a big copy quickly.
    s, j = jget("/api/copy", {"vol": "ntfs0", "path": "/", "dest": os.path.join(DEST, "c")}, "POST")
    jget("/api/jobs/cancel", {"id": j["job"]}, "POST")
    job = wait_job(j["job"])
    check("cancel", job["state"] == "cancelled", str(job))

    # Copying a native folder into itself is refused.
    s, j = jget("/api/copy", {"vol": "ps5", "path": DEST, "dest": os.path.join(DEST, "inner")}, "POST")
    check("copy into itself refused", s == 400)

    s, j = jget("/api/jobs/clear", {}, "POST")
    check("clear finished jobs", s == 200 and not j["jobs"])

    # Unmount and remount through the API.
    s, j = jget("/api/unmount", {"vol": "ntfs0"}, "POST")
    check("unmount", s == 200 and not [v for v in j["volumes"] if v["kind"] == "ntfs"])
    time.sleep(3.5)  # the hotplug thread must not remount it by itself
    s, j = jget("/api/volumes")
    check("stays unmounted across rescans", not [v for v in j["volumes"] if v["kind"] == "ntfs"])
    s, j = jget("/api/mount", {"path": IMG}, "POST")
    vols = [v for v in j["volumes"] if v["kind"] == "ntfs"] if s == 200 else []
    check("mount by path", len(vols) == 1, str(j))
    s, j = jget("/api/mount", {"path": "/etc/hostname"}, "POST")
    check("mount non-NTFS file -> error", s == 400 and "NTFS" in j["error"], str(j))

    # Native listing works too.
    s, j = jget("/api/list", {"vol": "ps5", "path": DEST})
    check("native listing", s == 200 and any(e["n"] == "Big Game" for e in j["entries"]))
    s, h, b = req("GET", "/api/file", {"vol": "ps5", "path": os.path.join(DEST, "Big Game/sub/save.dat")})
    check("native download", s == 200 and b == b"save" * 1000)


def set_volume_dirty(img):
    """Set the 'dirty' flag in $Volume's $VOLUME_INFORMATION, like Windows
    does when it is shut down uncleanly."""
    with open(img, "r+b") as f:
        bs = f.read(512)
        cl = struct.unpack_from("<H", bs, 11)[0] * bs[13]
        mft = struct.unpack_from("<Q", bs, 0x30)[0] * cl
        f.seek(mft + 3 * 1024)
        r = bytearray(f.read(1024))
        uo, uc = struct.unpack_from("<HH", r, 4)
        saved = [bytes(r[i * 512 - 2:i * 512]) for i in range(1, uc)]
        for i in range(1, uc):
            r[i * 512 - 2:i * 512] = r[uo + 2 * i:uo + 2 * i + 2]
        p = struct.unpack_from("<H", r, 0x14)[0]
        while True:
            t, l = struct.unpack_from("<II", r, p)
            if t == 0xFFFFFFFF:
                raise RuntimeError("no volume information")
            if t == 0x70:
                vo = struct.unpack_from("<H", r, p + 20)[0]
                flags = struct.unpack_from("<H", r, p + vo + 10)[0]
                struct.pack_into("<H", r, p + vo + 10, flags | 1)
                break
            p += l
        for i in range(1, uc):
            r[uo + 2 * i:uo + 2 * i + 2] = r[i * 512 - 2:i * 512]
            r[i * 512 - 2:i * 512] = r[uo:uo + 2]
        f.seek(mft + 3 * 1024)
        f.write(r)


def write_tests():
    """PS5 -> NTFS: enable writing, copy a tree onto the drive, resume."""
    srcdir = os.path.join(WORK, "native-src")
    os.makedirs(os.path.join(srcdir, "Saves/deep/er"))
    s, j = jget("/api/volumes")
    vid = [x for x in j["volumes"] if x["kind"] == "ntfs"][0]["id"]
    rnd = random.Random(42)
    expect = {}
    for i in range(400):
        rel = "Saves/file_%03d.dat" % i if i % 3 else "Saves/deep/er/f%03d.bin" % i
        data = rnd.randbytes(rnd.randint(0, 60000))
        expect[rel] = data
        open(os.path.join(srcdir, rel), "wb").write(data)
    big = rnd.randbytes(12_000_000)
    expect["Saves/video:clip?.mp4"] = big  # name needs sanitising
    open(os.path.join(srcdir, "Saves/video:clip?.mp4"), "wb").write(big)

    s, j = jget("/api/copy", {"vol": "ps5", "path": srcdir + "/Saves", "dvol": vid, "dest": "/Backup"}, "POST")
    check("copy to read-only NTFS refused", s == 403, str(j))
    s, j = jget("/api/mkdir", {"vol": vid, "path": "/x"}, "POST")
    check("mkdir on read-only NTFS refused", s == 403, str(j))

    s, j = jget("/api/writable", {"vol": vid, "on": "1"}, "POST")
    v = [x for x in j["volumes"] if x["id"] == vid][0] if s == 200 else {}
    check("enable writing", s == 200 and v.get("writable") is True, str(j))

    s, j = jget("/api/mkdir", {"vol": vid, "path": "/New Folder/inner"}, "POST")
    check("mkdir on NTFS (with parents)", s == 200, str(j))
    s, j = jget("/api/mkdir", {"vol": vid, "path": "/New Folder"}, "POST")
    check("mkdir existing -> 409", s == 409, str(j))

    s, j = jget("/api/copy", {"vol": "ps5", "path": srcdir + "/Saves", "dvol": vid, "dest": "/Backup/PS5"}, "POST")
    job = wait_job(j["job"], 120) if s == 200 else None
    check("PS5 -> NTFS folder copy", job and job["state"] == "done", str(job or j))

    ok = True
    for rel, data in expect.items():
        name = rel.replace("video:clip?.mp4", "video_clip_.mp4")
        s, h, b = req("GET", "/api/file", {"vol": vid, "path": "/Backup/PS5/" + name})
        if s != 200 or b != data:
            ok = False
            print("   mismatch:", name, s, len(b), len(data))
            break
    check("written files read back identical (401 files)", ok)

    s, j = jget("/api/copy", {"vol": "ps5", "path": srcdir + "/Saves", "dvol": vid, "dest": "/Backup/PS5"}, "POST")
    job = wait_job(j["job"], 120)
    check("re-copy to NTFS skips everything", job["state"] == "done" and job["skipped_files"] == 401, str(job))

    # NTFS -> NTFS on the same drive.
    s, j = jget("/api/copy", {"vol": vid, "path": "/readme.txt", "dvol": vid, "dest": "/New Folder"}, "POST")
    job = wait_job(j["job"])
    check("NTFS -> same NTFS copy", job["state"] == "done", str(job))

    # Interrupted copy resumes from where it stopped.
    s, j = jget("/api/copy", {"vol": vid, "path": "/big.bin", "dvol": vid, "dest": "/Resume"}, "POST")
    jid = j["job"]
    for _ in range(200):
        s, jj = jget("/api/jobs")
        cur = [x for x in jj["jobs"] if x["id"] == jid][0]
        if cur["done_bytes"] > 0 or cur["state"] != "queued" and cur["state"] != "scanning":
            break
        time.sleep(0.01)
    jget("/api/jobs/cancel", {"id": jid}, "POST")
    first = wait_job(jid)
    s, j = jget("/api/copy", {"vol": vid, "path": "/big.bin", "dvol": vid, "dest": "/Resume"}, "POST")
    job = wait_job(j["job"])
    s, h, b = req("GET", "/api/file", {"vol": vid, "path": "/Resume/big.bin"})
    ref = random.Random(9).randbytes(30_000_000)
    check("cancelled copy resumes and completes", job["state"] == "done" and b == ref,
          "%s / %s" % (first and first["state"], job))

    s, j = jget("/api/writable", {"vol": vid, "on": "0"}, "POST")
    v = [x for x in j["volumes"] if x["id"] == vid][0]
    check("make read-only again", v["writable"] is False)
    return expect


def wait_job(jid, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        s, j = jget("/api/jobs")
        for job in j["jobs"]:
            if job["id"] == jid and job["state"] in ("done", "failed", "cancelled"):
                return job
        time.sleep(0.1)
    return None


if __name__ == "__main__":
    main()
