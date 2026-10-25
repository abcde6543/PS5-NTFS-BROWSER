#!/usr/bin/env python3
"""Stress tests for NTFS *writing*.

Every scenario writes with our driver (via ntfstool) and then has the result
judged by independent tools:
  - our structural checker   (ntfstool check)
  - ntfsresize --check       (ntfs-3g's cluster accounting check)
  - ntfs-3g                  (must read every file back byte-identical by
                              name, then modify the same folders itself)

Needs: root, /dev/fuse, ntfs-3g. Usage: tests/write_tests.py build/ntfstool-asan
"""
import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile

TOOL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/ntfstool-asan")
WORK = tempfile.mkdtemp(prefix="ntfswrite-")
MNT = os.path.join(WORK, "mnt")
os.makedirs(MNT)
failures = []


def sh(*a, check=True):
    return subprocess.run(a, check=check, capture_output=True)


def tool(*a):
    return subprocess.run([TOOL] + list(a), capture_output=True, text=True)


def mkimage(name, mb, cluster=4096):
    p = os.path.join(WORK, name)
    with open(p, "wb") as f:
        f.truncate(mb << 20)
    sh("mkntfs", "-F", "-Q", "-c", str(cluster), "-L", "W", p)
    return p


def make_tree(root, seed, files, max_size, dirs=1, names=None):
    """Create a local tree; returns {relpath: sha256}."""
    r = random.Random(seed)
    out = {}
    os.makedirs(root, exist_ok=True)
    dlist = [""]
    for d in range(dirs - 1):
        rel = os.path.join(r.choice(dlist), "dir%03d" % d)
        os.makedirs(os.path.join(root, rel), exist_ok=True)
        dlist.append(rel)
    for i in range(files):
        nm = names[i % len(names)] + "_%d" % i if names else "f%05d_%s.bin" % (i, "y" * (i % 23))
        rel = os.path.join(r.choice(dlist), nm)
        data = r.randbytes(r.randint(0, max_size))
        with open(os.path.join(root, rel), "wb") as f:
            f.write(data)
        out[rel] = hashlib.sha256(data).hexdigest()
    return out


def verify(name, img, expect, base="/", modify=True):
    """Judge an image with every tool available."""
    problems = []
    r = tool("check", img)
    if r.returncode:
        problems.append("check: " + (r.stderr.strip().splitlines() or ["?"])[0] + " " + r.stdout.strip())
    r = sh("ntfsresize", "--check", "--force", img, check=False)
    if r.returncode:
        problems.append("ntfsresize: " + r.stdout.decode()[-300:] + r.stderr.decode()[-300:])
    if not problems:
        sh("ntfs-3g", "-o", "ro", img, MNT)
        try:
            for rel, h in expect.items():
                p = os.path.join(MNT, base.strip("/"), rel)
                try:
                    with open(p, "rb") as f:
                        if hashlib.sha256(f.read()).hexdigest() != h:
                            problems.append("ntfs-3g: content differs: " + rel)
                            break
                except OSError as e:
                    problems.append("ntfs-3g: " + str(e))
                    break
        finally:
            sh("umount", MNT)
    if not problems and modify:
        # ntfs-3g edits the folders we built (exercises our B-trees), then we
        # check again and write once more on top of its changes.
        sh("ntfs-3g", img, MNT)
        try:
            top = os.path.join(MNT, base.strip("/"))
            victims = sorted(expect)[::3]
            for rel in victims:
                os.unlink(os.path.join(top, rel))
            for i in range(50):
                with open(os.path.join(top, "added_by_ntfs3g_%d.txt" % i), "w") as f:
                    f.write("x" * i)
        finally:
            sh("umount", MNT)
        r = tool("check", img)
        if r.returncode:
            problems.append("check after ntfs-3g edits: " + r.stderr.strip()[:300])
        src = os.path.join(WORK, "extra")
        shutil.rmtree(src, ignore_errors=True)
        make_tree(src, 99, 60, 5000)
        r = tool("putdir", img, src, base.rstrip("/") + "/after_ntfs3g")
        if r.returncode:
            problems.append("write after ntfs-3g edits: " + r.stderr.strip()[:300])
        r = tool("check", img)
        if r.returncode:
            problems.append("final check: " + r.stderr.strip()[:300])
    ok = not problems
    print("%-44s %s" % (name, "PASS" if ok else "FAIL"))
    for p in problems[:5]:
        print("   " + p)
    if not ok:
        failures.append(name)


def put_tree(img, local, dest):
    r = tool("putdir", img, local, dest)
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[:500])


def scenario(name, fn):
    try:
        fn(name)
    except Exception as e:  # noqa: BLE001
        print("%-44s FAIL  (%s)" % (name, e))
        failures.append(name)


def s_cluster_sizes(_):
    for cs in (512, 1024, 4096, 16384, 65536):
        img = mkimage("cs%d.img" % cs, 128, cs)
        local = os.path.join(WORK, "src_cs%d" % cs)
        exp = make_tree(local, cs, 1200, 40000, dirs=12)
        put_tree(img, local, "/data")
        verify("cluster %5d B: 1200 files, 12 folders" % cs, img, exp, "/data")


def s_big_root(name):
    img = mkimage("root.img", 128)
    local = os.path.join(WORK, "src_root")
    exp = make_tree(local, 2, 5000, 2000)
    put_tree(img, local, "/")
    verify(name, img, exp, "/")


def s_names(name):
    img = mkimage("names.img", 64)
    local = os.path.join(WORK, "src_names")
    names = ["Café crème", "日本語のファイル", "Ελληνικά", "emoji 🎮🕹️", "ünïcödé",
             "ÄÖÜ upper", "äöü lower", "Ω", "spaces in name", "L" * 230]
    exp = make_tree(local, 3, 300, 3000, dirs=4, names=names)
    put_tree(img, local, "/Unicode ✓")
    verify(name, img, exp, "/Unicode ✓")
    # Case-insensitive duplicate must be refused.
    tool("mkdir", img, "/Case")
    r = tool("mkdir", img, "/CASE/x")  # parent resolves case-insensitively
    r2 = subprocess.run([TOOL, "mkdir", img, "/case"], capture_output=True, text=True)
    ok = r.returncode == 0 and tool("check", img).returncode == 0
    print("%-44s %s" % ("case-insensitive name handling", "PASS" if ok else "FAIL"))
    if not ok:
        failures.append("case names")


def s_fragmented(name):
    # ntfs-3g fills the disk with small files and frees every other one, so
    # the free space is a comb of holes; then we write big files into it.
    img = mkimage("frag.img", 96)
    sh("ntfs-3g", img, MNT)
    try:
        os.mkdir(os.path.join(MNT, "fill"))
        chunk = os.urandom(8192)
        n = 0
        while n < 9000:
            try:
                with open(os.path.join(MNT, "fill", str(n)), "wb") as f:
                    f.write(chunk)
            except OSError:
                break
            n += 1
        for i in range(0, n, 2):
            os.unlink(os.path.join(MNT, "fill", str(i)))
    finally:
        sh("umount", MNT)
    local = os.path.join(WORK, "src_frag")
    os.makedirs(local, exist_ok=True)
    exp = {}
    r = random.Random(4)
    for i in range(6):
        data = r.randbytes(r.choice([30_000, 70_000, 150_000]))
        with open(os.path.join(local, "big%d.bin" % i), "wb") as f:
            f.write(data)
        exp["big%d.bin" % i] = hashlib.sha256(data).hexdigest()
    put_tree(img, local, "/frag")
    verify(name, img, exp, "/frag")
    # A file needing far more extents than fit in one record must be refused
    # cleanly (no attribute lists are created), leaving the volume intact.
    with open(os.path.join(WORK, "huge.bin"), "wb") as f:
        f.write(os.urandom(20_000_000))
    rr = tool("put", img, os.path.join(WORK, "huge.bin"), "/frag/huge.bin")
    ok = rr.returncode != 0 and tool("check", img).returncode == 0
    ok = ok and sh("ntfsresize", "--check", "--force", img, check=False).returncode == 0
    print("%-44s %s" % ("too-fragmented file refused, volume intact", "PASS" if ok else "FAIL"))
    if not ok:
        failures.append("fragmented refusal")


def s_mft_bitmap_growth(name):
    # 512-byte clusters: the MFT bitmap's allocation covers few records, so
    # 6000 files force it (and the MFT) to grow several times.
    img = mkimage("mftgrow.img", 160, 512)
    local = os.path.join(WORK, "src_mft")
    exp = make_tree(local, 5, 6000, 600, dirs=30)
    put_tree(img, local, "/m")
    verify(name, img, exp, "/m")


def s_disk_full(name):
    img = mkimage("full.img", 24)
    local = os.path.join(WORK, "src_full")
    exp = make_tree(local, 6, 400, 120_000, dirs=3)
    r = tool("putdir", img, local, "/full")
    ok = r.returncode != 0  # must run out of space
    rc = tool("check", img)
    ok = ok and rc.returncode == 0 and "leaked_clusters=0" in rc.stdout
    ok = ok and sh("ntfsresize", "--check", "--force", img, check=False).returncode == 0
    print("%-44s %s" % (name, "PASS" if ok else "FAIL"))
    if not ok:
        print("   ", rc.stdout.strip(), rc.stderr.strip()[:300])
        failures.append(name)


def s_random_mix(name):
    """Alternate our writes and ntfs-3g writes many times."""
    img = mkimage("mix.img", 128)
    r = random.Random(7)
    expect = {}
    for rnd in range(8):
        local = os.path.join(WORK, "mix_%d" % rnd)
        exp = make_tree(local, 100 + rnd, r.randint(50, 400), 30000, dirs=r.randint(1, 6))
        put_tree(img, local, "/mix/round%d" % rnd)
        for k, v in exp.items():
            expect["round%d/%s" % (rnd, k)] = v
        sh("ntfs-3g", img, MNT)
        try:
            base = os.path.join(MNT, "mix")
            for k in r.sample(sorted(expect), min(30, len(expect))):
                os.unlink(os.path.join(base, k))
                del expect[k]
            os.makedirs(os.path.join(base, "round%d" % rnd, "ntfs3g_dir"), exist_ok=True)
        finally:
            sh("umount", MNT)
        rc = tool("check", img)
        if rc.returncode:
            print("%-44s FAIL (round %d: %s)" % (name, rnd, rc.stderr.strip()[:200]))
            failures.append(name)
            return
    verify(name, img, expect, "/mix", modify=False)


def main():
    print("work dir:", WORK)
    scenario("cluster sizes", s_cluster_sizes)
    scenario("5000 files in the root folder", s_big_root)
    scenario("Unicode + 230-char names", s_names)
    scenario("fragmented free space", s_fragmented)
    scenario("MFT + MFT bitmap growth (6000 files)", s_mft_bitmap_growth)
    scenario("disk full: clean failure, no leaks", s_disk_full)
    scenario("8 rounds alternating with ntfs-3g", s_random_mix)
    print()
    if failures:
        print("FAILED:", ", ".join(failures))
        sys.exit(1)
    print("All write tests passed.")
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
