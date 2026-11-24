#!/usr/bin/env python3
"""Connections that stop making progress must not hold a slot forever.

The server has 64 connection slots. Before this was checked:
- a client that sent its request head one line every few seconds was
  never cut off (the 30 s receive timeout applies to each recv() only);
- a download the client stopped reading (a paused browser download, a
  dead peer) blocked its thread in send() for good, together with its
  reference on the drive.

Both cases run in parallel, so the test takes about a minute and a half. It only uses
the console side (vol=ps5), so it needs neither root nor ntfs-3g.
usage: timeout_tests.py build/ntfs-browser
"""
import http.client, os, shutil, socket, subprocess, sys, tempfile, threading, time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
PORT = 18093
WORK = tempfile.mkdtemp(prefix="ntfsb-timeout-")
BIG = os.path.join(WORK, "big.bin")
SIZE = 32 << 20
LIMIT = 30          # the server's idle timeout
failures = []
results = {}


def check(name, cond, detail=""):
    print("%-48s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def slow_head():
    """Send a never-ending request head, one header line every 5 s."""
    s = socket.create_connection(("127.0.0.1", PORT))
    s.sendall(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n")
    t0 = time.time()
    s.settimeout(5)
    closed_after = None
    while time.time() - t0 < 2 * LIMIT + 20:
        try:
            if s.recv(4096) == b"":
                closed_after = time.time() - t0
                break
        except socket.timeout:
            pass
        except OSError:
            closed_after = time.time() - t0
            break
        try:
            s.sendall(b"X-Slow: 1\r\n")
        except OSError:
            closed_after = time.time() - t0
            break
    s.close()
    results["slow_head"] = closed_after


def stalled_download():
    """Ask for a 32 MB file, then don't read for a while."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", PORT))
    q = urllib.parse.urlencode({"vol": "ps5", "path": BIG})
    s.sendall(("GET /api/file?%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % q).encode())
    # send() gives up after LIMIT seconds without any progress; a call that
    # had already sent part of its chunk returns that part first, so the
    # next one is the one that fails: up to twice LIMIT in all.
    time.sleep(2 * LIMIT + 15)
    s.settimeout(10)
    got = 0
    try:
        while True:
            b = s.recv(1 << 20)
            if not b:
                break
            got += len(b)
    except (socket.timeout, OSError):
        pass
    s.close()
    results["stalled_download"] = got


def main():
    with open(BIG, "wb") as f:
        f.write(os.urandom(1 << 20) * 32)
    log = open(os.path.join(WORK, "server.log"), "w")
    proc = subprocess.Popen([BIN, "-p", str(PORT)], cwd=WORK, stdout=log, stderr=log)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        threads = [threading.Thread(target=slow_head), threading.Thread(target=stalled_download)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        c = results.get("slow_head")
        check("slow request head is cut off", c is not None and c <= 2 * LIMIT + 5,
              "still open after %d s" % (2 * LIMIT + 20) if c is None else "after %.0f s" % c)
        got = results.get("stalled_download", 0)
        check("stalled download is given up", got < SIZE,
              "the client still received all %d bytes" % got)
        c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        c.request("GET", "/api/status")
        check("server still answers", c.getresponse().status == 200)
        c.close()
        check("server still running", proc.poll() is None)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(10)
        log.close()
    shutil.rmtree(WORK, ignore_errors=True)
    print("\n%s" % ("ALL PASSED" if not failures else "FAILED: " + ", ".join(failures)))
    sys.exit(1 if failures else 0)


main()
