/* Host-side test tool for the NTFS driver.
 *
 *   ntfstool info <image>
 *   ntfstool ls   <image> [path]
 *   ntfstool cat  <image> <path>
 *   ntfstool tree <image>          (recursive "type<TAB>size<TAB>path" list)
 *
 * <image> may be a raw partition image or a whole-disk image with an MBR or
 * GPT; the first NTFS partition is used. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/bdev.h"
#include "../src/ntfs.h"
#include "../src/part.h"

static ntfs_vol_t *open_vol(const char *path) {
  bdev_t *b = bdev_open(path);
  if (!b) { perror(path); exit(1); }
  part_t parts[PART_MAX];
  int n = part_scan(b, parts, PART_MAX);
  for (int i = 0; i < n; i++) {
    bdev_t *s = bdev_slice(b, parts[i].offset, parts[i].size);
    if (!s) continue;
    if (!part_is_ntfs(s)) { bdev_close(s); continue; }
    ntfs_vol_t *v;
    char err[128];
    if (ntfs_mount(s, &v, err, sizeof err) == 0) {
      bdev_close(b);
      return v;
    }
    fprintf(stderr, "partition %d: %s\n", parts[i].index, err);
    bdev_close(s);
  }
  fprintf(stderr, "no NTFS volume found\n");
  exit(1);
}

static int ls_cb(void *ctx, const char *name, const ntfs_stat_t *st) {
  (void)ctx;
  printf("%c %12llu %08x %s\n", st->is_dir ? 'd' : '-',
         (unsigned long long)st->size, st->attrs, name);
  return 0;
}

typedef struct tree_ctx {
  ntfs_vol_t *v;
  char path[4096];
  int depth;
} tree_ctx_t;

typedef struct child {
  char *name;
  ntfs_stat_t st;
} child_t;

typedef struct clist {
  child_t *c;
  size_t n, cap;
} clist_t;

static int collect(void *ctx, const char *name, const ntfs_stat_t *st) {
  clist_t *l = ctx;
  if (l->n == l->cap) {
    l->cap = l->cap ? l->cap * 2 : 32;
    l->c = realloc(l->c, l->cap * sizeof *l->c);
  }
  l->c[l->n].name = strdup(name);
  l->c[l->n].st = *st;
  l->n++;
  return 0;
}

static void tree(tree_ctx_t *t, uint64_t ino) {
  clist_t l = {0};
  int rc = ntfs_readdir(t->v, ino, collect, &l);
  if (rc) fprintf(stderr, "readdir %s: %s\n", t->path, strerror(-rc));
  size_t base = strlen(t->path);
  for (size_t i = 0; i < l.n; i++) {
    snprintf(t->path + base, sizeof t->path - base, "/%s", l.c[i].name);
    printf("%c\t%llu\t%s\n", l.c[i].st.is_dir ? 'd' : 'f',
           l.c[i].st.is_dir ? 0ULL : (unsigned long long)l.c[i].st.size,
           t->path);
    if (l.c[i].st.is_dir && !(l.c[i].st.attrs & NTFS_FA_REPARSE) && t->depth < 64) {
      t->depth++;
      tree(t, l.c[i].st.inode);
      t->depth--;
    }
    t->path[base] = 0;
    free(l.c[i].name);
  }
  free(l.c);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s info|ls|cat|tree <image> [path]\n", argv[0]);
    return 2;
  }
  const char *cmd = argv[1];
  ntfs_vol_t *v = open_vol(argv[2]);
  const char *path = argc > 3 ? argv[3] : "/";
  int rc = 0;

  if (!strcmp(cmd, "info")) {
    ntfs_info_t in;
    uint64_t fr = 0;
    ntfs_get_info(v, &in);
    ntfs_free_bytes(v, &fr);
    printf("label=%s\nserial=%016llx\ntotal=%llu\nfree=%llu\ncluster=%u\n"
           "mft_record=%u\nversion=%u.%u\ndirty=%d\n",
           in.label, (unsigned long long)in.serial,
           (unsigned long long)in.total_bytes, (unsigned long long)fr,
           in.cluster_size, in.mft_record_size, in.ver_major, in.ver_minor,
           in.dirty);
  } else if (!strcmp(cmd, "ls")) {
    uint64_t ino;
    if ((rc = ntfs_lookup(v, path, &ino)) == 0) rc = ntfs_readdir(v, ino, ls_cb, NULL);
  } else if (!strcmp(cmd, "cat")) {
    uint64_t ino;
    ntfs_file_t *f;
    if ((rc = ntfs_lookup(v, path, &ino)) == 0 && (rc = ntfs_open(v, ino, &f)) == 0) {
      static uint8_t buf[1 << 20];
      uint64_t off = 0, size = ntfs_file_size(f);
      while (off < size) {
        ssize_t n = ntfs_pread(f, buf, sizeof buf, off);
        if (n <= 0) { rc = n < 0 ? (int)n : -EIO; break; }
        fwrite(buf, 1, (size_t)n, stdout);
        off += (uint64_t)n;
      }
      ntfs_close(f);
    }
  } else if (!strcmp(cmd, "tree")) {
    tree_ctx_t t = {v, "", 0};
    tree(&t, NTFS_ROOT_INODE);
  } else {
    fprintf(stderr, "unknown command %s\n", cmd);
    rc = -EINVAL;
  }
  if (rc) fprintf(stderr, "%s: %s\n", path, strerror(-rc));
  ntfs_umount(v);
  return rc ? 1 : 0;
}
