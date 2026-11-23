#!/usr/bin/env python3
"""Stress test for the job queue: cancel + Clear while the worker starts a job.

The worker used to drop the job-list lock while the job it had picked still
said "queued". jobs_cancel() turns a queued job into "cancelled", and
"Clear" (or the slot reuse in jobs_add) frees every finished job, so a cancel
followed by Clear could free the job under the running worker
(heap-use-after-free in set_state()).

The window is the time the worker needs for vfs_get() and the writable check
at the start of a job. It gets wide when the drive is busy: an upload holds
the drive's lock while it writes, and the UI's volume polling then waits for
that lock with the global lock held, so the worker queues up behind both.
This test creates exactly that load. Run it against the sanitizer build, where
the old code aborts; a plain build may survive by luck.

Needs: root, /dev/fuse, ntfs-3g.
Usage: tests/race_tests.py build/ntfs-browser-asan
"""
import http.client
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser-asan")
PORT = 18087
WORK = tempfile.mkdtemp(prefix="ntfsrace-")
IMG = os.path.join(WORK, "vol.img")
MNT = os.path.join(WORK, "mnt")
ROUNDS = int(os.environ.get("RACE_ROUNDS", "600"))


def sh(*a):
    subprocess.run(a, check=True, capture_output=True)


def req(method, path, params=None, body=None):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=120)
    try:
        c.request(method, path + q, body=body, headers={"X-NTFSB": "1"})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def main():
    with open(IMG, "wb") as f:
        f.truncate(160 << 20)
    sh("mkntfs", "-F", "-Q", "-L", "Race", IMG)
    os.makedirs(MNT)
    sh("ntfs-3g", IMG, MNT)
    try:
        os.makedirs(os.path.join(MNT, "src"))
        for i in range(40):
            with open(os.path.join(MNT, "src", "f%02d.txt" % i), "wb") as f:
                f.write(b"x" * 2000)
    finally:
        sh("umount", MNT)

    # Squeeze the server onto one CPU together with two busy loops: its threads
    # are then pre-empted all the time, which stretches the window between the
    # worker picking a job and starting it from microseconds to milliseconds.
    # (On a quiet machine the old bug can go unnoticed for thousands of rounds.)
    pin = None
    if hasattr(os, "sched_setaffinity"):
        cpu = sorted(os.sched_getaffinity(0))[0]
        pin = lambda: os.sched_setaffinity(0, {cpu})
    hogs = [subprocess.Popen([sys.executable, "-c", "while True: pass"], preexec_fn=pin)
            for _ in range(2 if pin else 0)]
    log = open(os.path.join(WORK, "server.log"), "wb")
    proc = subprocess.Popen([BIN, "-p", str(PORT), IMG], stdout=log, stderr=subprocess.STDOUT,
                            env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0"), preexec_fn=pin)
    ok = False
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        import json
        vid = [v for v in json.loads(req("GET", "/api/volumes")[1])["volumes"] if v["kind"] == "ntfs"][0]["id"]

        stop = threading.Event()

        def writer(tag):
            i = 0
            while not stop.is_set():
                try:
                    req("POST", "/api/upload", {"vol": vid, "path": "/", "name": "w%s%d.bin" % (tag, i % 3)},
                        body=os.urandom(6 << 20) if i < 3 else b"")
                except OSError:
                    return
                i += 1

        def poller():
            while not stop.is_set():
                try:
                    req("GET", "/api/volumes")
                except OSError:
                    return

        threads = [threading.Thread(target=writer, args=(t,)) for t in "ab"]
        threads += [threading.Thread(target=poller) for _ in range(3)]
        for t in threads:
            t.start()
        try:
            for i in range(ROUNDS):
                if proc.poll() is not None:
                    break
                s, b = req("POST", "/api/copy", {"vol": vid, "path": "/src", "dvol": vid, "dest": "/o%d" % (i % 8)})
                if s != 200:
                    continue
                jid = json.loads(b)["job"]
                req("POST", "/api/jobs/cancel", {"id": jid})
                req("POST", "/api/jobs/clear")
        except (OSError, http.client.HTTPException):
            pass
        stop.set()
        for t in threads:
            t.join()
        time.sleep(0.5)
        ok = proc.poll() is None
        if ok:
            try:
                ok = req("GET", "/api/status")[0] == 200
            except (OSError, http.client.HTTPException):
                ok = False
    finally:
        for h in hogs:
            h.kill()
            h.wait()
        if proc.poll() is None:
            proc.terminate()
        proc.wait()
        log.close()
    print("%-52s %s" % ("cancel + clear while the worker starts a job (%d rounds)" % ROUNDS,
                        "PASS" if ok else "FAIL"))
    if not ok:
        text = open(os.path.join(WORK, "server.log"), errors="replace").read()
        i = text.find("ERROR: AddressSanitizer")
        print(text[i:i + 2500] if i >= 0 else text[-2000:])
        sys.exit(1)
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
