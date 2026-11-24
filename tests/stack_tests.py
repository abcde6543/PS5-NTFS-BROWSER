#!/usr/bin/env python3
"""Deep folder trees with the console's small default thread stack.

On the console, libkernel gives a thread created without an explicit stack
size 64 KiB (unless the process is of a kind that gets 2 MiB). The job worker
recurses once per folder level, so it needs more than that. glibc takes the
default thread stack size from RLIMIT_STACK, so running the server with a
64 KiB limit gives every thread without its own size the console's default.

The test copies a folder 64 levels deep from the drive to the console, copies
it back onto the drive, and deletes it there (deleting used to count the
files in the 64th folder as a 65th level and stopped there without a reason). All of it must finish, and the
server must still be running afterwards.

Needs root (mkntfs and ntfs-3g), like the other tests.
usage: stack_tests.py build/ntfs-browser
"""
import http.client, json, os, resource, shutil, socket, subprocess, sys, tempfile, time
import urllib.parse

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfs-browser")
PORT = 18089
LEVELS = 64          # deepest folder copy_tree/delete_tree accept below the start folder
STACK = 64 * 1024    # the console's default for threads without an explicit size

WORK = tempfile.mkdtemp(prefix="ntfsb-stack-")
IMG = os.path.join(WORK, "deep.img")
MNT = os.path.join(WORK, "mnt")
OUT = os.path.join(WORK, "console")
failures = []


def sh(*a):
    subprocess.run(a, check=True, capture_output=True)


def check(name, cond, detail=""):
    print("%-44s %s %s" % (name, "PASS" if cond else "FAIL", detail if not cond else ""))
    if not cond:
        failures.append(name)


def chain():
    return "/deep/" + "/".join("level%02d" % i for i in range(1, LEVELS + 1))


def build_image():
    os.makedirs(MNT)
    with open(IMG, "wb") as f:
        f.truncate(64 << 20)
    sh("mkntfs", "-F", "-Q", "-L", "deep", IMG)
    sh("ntfs-3g", IMG, MNT)
    try:
        os.makedirs(MNT + chain())
        d = MNT + "/deep"
        for i in range(LEVELS + 1):
            with open(os.path.join(d, "file.txt"), "w") as f:
                f.write("level %d\n" % i)
            if i < LEVELS:
                d = os.path.join(d, "level%02d" % (i + 1))
    finally:
        sh("umount", MNT)


def req(method, path, params=None):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    c.request(method, path + q, headers={"X-NTFSB": "1"})
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, json.loads(body) if body else None


def run_job(proc, method, path, params):
    try:
        s, j = req(method, path, params)
    except OSError as e:
        return "server gone (%s)" % e
    if s != 200 or not j or "job" not in j:
        return "not started (%s %s)" % (s, j)
    for _ in range(600):
        if proc.poll() is not None:
            return "server died (exit %s)" % proc.returncode
        try:
            s, js = req("GET", "/api/jobs")
        except OSError:
            time.sleep(0.2)
            continue
        mine = [x for x in js["jobs"] if x["id"] == j["job"]]
        if mine and mine[0]["state"] in ("done", "failed", "cancelled"):
            return mine[0]["state"] + (": " + mine[0]["error"] if mine[0]["error"] else "")
        time.sleep(0.1)
    return "timed out"


def count_files(top):
    return sum(len(files) for _, _, files in os.walk(top))


def main():
    build_image()
    os.makedirs(OUT)
    log = open(os.path.join(WORK, "server.log"), "w")

    def small_stack():
        resource.setrlimit(resource.RLIMIT_STACK, (STACK, STACK))

    proc = subprocess.Popen([BIN, "-p", str(PORT), IMG], cwd=WORK, stdout=log,
                            stderr=log, preexec_fn=small_stack)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        vid = "ntfs0"  # the image, the first NTFS volume

        r = run_job(proc, "POST", "/api/copy", {"vol": vid, "path": "/deep", "dest": OUT})
        check("copy 64 levels drive -> console", r == "done", r)
        n = count_files(os.path.join(OUT, "deep"))
        check("all %d files arrived" % (LEVELS + 1), n == LEVELS + 1, "got %d" % n)

        if proc.poll() is None:
            r = run_job(proc, "POST", "/api/copy", {"vol": "ps5", "path": os.path.join(OUT, "deep"),
                                                    "dvol": vid, "dest": "/back"})
            check("copy 64 levels console -> drive", r == "done", r)
        if proc.poll() is None:
            r = run_job(proc, "POST", "/api/delete", {"vol": vid, "path": "/back/deep"})
            check("delete 64 levels on the drive", r == "done", r)
        check("server still running", proc.poll() is None, "exit %s" % proc.returncode)
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(10)
        log.close()

    if proc.returncode is not None and proc.returncode < 0 and failures:
        print("server was killed by signal %d (a stack overflow shows as 11, SIGSEGV)"
              % -proc.returncode)
    if not failures:
        r = subprocess.run(["ntfsfix", "-n", IMG], capture_output=True, text=True)
        check("volume still consistent (ntfsfix -n)", r.returncode == 0, r.stdout[-300:])

    shutil.rmtree(WORK, ignore_errors=True)
    print("\n%s" % ("ALL PASSED" if not failures else "FAILED: " + ", ".join(failures)))
    sys.exit(1 if failures else 0)


main()
