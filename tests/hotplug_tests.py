#!/usr/bin/env python3
"""Drive detection: which device nodes are probed, and when.

The desktop build scans the directory named by NTFSB_TEST_DEV_DIR the way the
PS5 build scans /dev. Each "node" here is an NTFS image with its own label:

- da0, present at start: mounted right away;
- da0s1, da1p1, da2.crypt (partition nodes and other views): never probed;
  partitions are found on the whole disk instead;
- da3, plugged in while the server runs: left alone while the console would
  still be attaching it, then mounted.

Needs: mkntfs. Usage: tests/hotplug_tests.py build/ntfs-browser
"""
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
PORT = 18088
WORK = tempfile.mkdtemp(prefix="ntfshot-")
DEV = os.path.join(WORK, "dev")
SETTLE = 10        # seconds, SETTLE_MS in vfs.c
failures = []


def check(name, cond, detail=""):
    print("%-58s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def mkimage(path, label):
    with open(path, "wb") as f:
        f.truncate(16 << 20)
    subprocess.run(["mkntfs", "-F", "-Q", "-L", label, path], check=True, capture_output=True)
    # mkntfs derives the volume serial from the clock, so images made in the
    # same second share it, and the server rightly treats them as one volume.
    # Give each image its own serial (boot sector offset 0x48).
    with open(path, "r+b") as f:
        f.seek(0x48)
        f.write(os.urandom(8))


def labels():
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request("GET", "/api/volumes")
    vols = json.loads(c.getresponse().read())["volumes"]
    c.close()
    return sorted(v["label"] for v in vols if v["kind"] == "ntfs")


def main():
    os.makedirs(DEV)
    mkimage(os.path.join(DEV, "da0"), "Start")
    mkimage(os.path.join(DEV, "da0s1"), "Slice")
    mkimage(os.path.join(DEV, "da1p1"), "GptPart")
    mkimage(os.path.join(DEV, "da2.crypt"), "Crypt")
    hot = os.path.join(WORK, "hot.img")
    mkimage(hot, "Hot")

    env = dict(os.environ, NTFSB_TEST_DEV_DIR=DEV)
    proc = subprocess.Popen([BIN, "-p", str(PORT)], env=env, cwd=WORK,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        check("drive present at start is mounted right away", labels() == ["Start"], str(labels()))

        # "Plug in" da3: the node appears in one step, like a new device node.
        os.rename(hot, os.path.join(DEV, "da3"))
        plugged = time.time()
        time.sleep(5)
        early = labels()
        check("freshly plugged drive is left alone for its first seconds", "Hot" not in early, str(early))

        seen = None
        while time.time() - plugged < SETTLE + 15:
            if "Hot" in labels():
                seen = time.time() - plugged
                break
            time.sleep(0.5)
        check("...and mounted once it has settled",
              seen is not None and SETTLE <= seen <= SETTLE + 7,
              "after %s s" % (None if seen is None else round(seen, 1)))

        final = labels()
        check("partition nodes and .crypt views are never probed", final == ["Hot", "Start"], str(final))
    finally:
        proc.terminate()
        out = proc.communicate(timeout=10)[0].decode(errors="replace")
        if failures:
            print("--- server output ---\n" + out)
    print()
    if failures:
        print("FAILED:", ", ".join(failures))
        sys.exit(1)
    print("All hot-plug tests passed.")
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
