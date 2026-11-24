#!/usr/bin/env python3
"""A drive ejected while a hot-plug scan runs must stay ejected.

vfs_unmount() used to detach the volume first and only then wait for the
running scan (g_scan) to mark the node as rejected. A scan that was busy
with another node then reached the ejected drive's node, found it neither
mounted nor rejected, and mounted it again right after "safe to unplug".

To make the window deterministic, the test puts a FIFO named da0 into the
stand-in /dev (NTFSB_TEST_DEV_DIR): the hot-plug scan opens it and blocks
until the test opens the other end. While the scan hangs there, the drive
at da1 is ejected; then the FIFO is released and the scan goes on to da1.

Linux only (FIFO, /proc). usage: eject_remount_tests.py build/ntfs-browser
"""
import glob, http.client, json, os, shutil, socket, subprocess, sys, tempfile, threading, time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
PORT = 18096
WORK = tempfile.mkdtemp(prefix="ntfsb-ejectrace-")
DEV = os.path.join(WORK, "dev")
FIFO = os.path.join(DEV, "da0")
failures = []


def check(name, cond, detail=""):
    print("%-48s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def req(method, path, params=None, timeout=30):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    c.request(method, path + q, headers={"X-NTFSB": "1"})
    r = c.getresponse()
    b = r.read()
    c.close()
    return r.status, json.loads(b) if b else None


def ntfs_volumes():
    s, j = req("GET", "/api/volumes")
    return [v for v in j["volumes"] if v.get("kind") == "ntfs"]


def blocked_in_open(pid):
    """Is a thread of pid sitting in openat() (on our FIFO)?"""
    for f in glob.glob("/proc/%d/task/*/syscall" % pid):
        try:
            if open(f).read().split()[0] == "257":
                return True
        except (OSError, IndexError):
            pass
    return False


def main():
    os.makedirs(DEV)
    img = os.path.join(DEV, "da1")
    with open(img, "wb") as f:
        f.truncate(32 << 20)
    subprocess.run(["mkntfs", "-F", "-Q", "-L", "race", img], check=True, capture_output=True)
    log = open(os.path.join(WORK, "server.log"), "w")
    env = dict(os.environ, NTFSB_TEST_DEV_DIR=DEV)
    proc = subprocess.Popen([BIN, "-p", str(PORT)], cwd=WORK, env=env, stdout=log, stderr=log)
    writer = None
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        vols = ntfs_volumes()
        check("drive at da1 mounted at start", len(vols) == 1, "%s" % vols)
        if not vols:
            raise SystemExit(1)
        vid = vols[0]["id"]

        # A new node waits 10 s before it is probed, and scans run every 3 s.
        os.mkfifo(FIFO)
        for _ in range(60):
            if blocked_in_open(proc.pid):
                break
            time.sleep(0.5)
        check("hot-plug scan is waiting on the FIFO", blocked_in_open(proc.pid))

        result = {}
        t = threading.Thread(target=lambda: result.update(eject=req("POST", "/api/eject",
                                                                     {"vol": vid}, 60)))
        t.start()
        time.sleep(1.0)
        writer = os.open(FIFO, os.O_WRONLY | os.O_NONBLOCK)  # releases the scan
        os.write(writer, b"not a drive")
        os.close(writer)
        writer = None
        t.join(60)
        s = result.get("eject", (None,))[0]
        check("eject answered 200", s == 200, "HTTP %s" % s)
        time.sleep(1.0)
        check("drive stays ejected after that scan", ntfs_volumes() == [], "%s" % ntfs_volumes())
        time.sleep(4.0)  # one more hot-plug pass
        check("drive stays ejected after the next scan", ntfs_volumes() == [], "%s" % ntfs_volumes())
        check("server still running", proc.poll() is None)
    finally:
        if writer is not None:
            os.close(writer)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
        log.close()
    shutil.rmtree(WORK, ignore_errors=True)
    print("\n%s" % ("ALL PASSED" if not failures else "FAILED: " + ", ".join(failures)))
    sys.exit(1 if failures else 0)


main()
