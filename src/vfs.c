#include "vfs.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/time.h>
#if defined(__linux__)
#include <sys/statfs.h>
#endif
#include <time.h>
#include <unistd.h>

#include "bdev.h"
#include "part.h"

#define MAX_VOLS    32
#define MAX_SOURCES 32
#define MAX_PROBED  64

typedef struct probed {
  char path[300];
  int  rejected;  /* no NTFS found; skip unless forced */
  int  tries;     /* failed opens; a new drive can take a moment to be ready */
} probed_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;   /* volume list */
static pthread_mutex_t g_scan = PTHREAD_MUTEX_INITIALIZER;   /* one scan at a time */
static vol_t   *g_vols[MAX_VOLS];
static char     g_nodes[MAX_VOLS][300];   /* device node each volume came from */
static vol_t    g_native;
static char     g_sources[MAX_SOURCES][300];
static int      g_nsources;
static probed_t g_probed[MAX_PROBED];
static int      g_nprobed;
static unsigned g_next_id;
static unsigned g_gen = 1;

void vfs_init(void) {
  memset(&g_native, 0, sizeof g_native);
  strcpy(g_native.id, "ps5");
  g_native.kind = VOL_NATIVE;
#ifdef __PROSPERO__
  strcpy(g_native.label, "PS5 Storage");
#else
  strcpy(g_native.label, "Local Files");
#endif
  strcpy(g_native.device, "/");
  g_native.refs = 1;
}

unsigned vfs_generation(void) {
  pthread_mutex_lock(&g_lock);
  unsigned g = g_gen;
  pthread_mutex_unlock(&g_lock);
  return g;
}

vol_t *vfs_get(const char *id) {
  if (!strcmp(id, "ps5")) return &g_native;
  vol_t *found = NULL;
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < MAX_VOLS; i++) {
    if (g_vols[i] && !strcmp(g_vols[i]->id, id)) {
      found = g_vols[i];
      found->refs++;
      break;
    }
  }
  pthread_mutex_unlock(&g_lock);
  return found;
}

void vfs_put(vol_t *v) {
  if (!v || v == &g_native) return;
  pthread_mutex_lock(&g_lock);
  int last = --v->refs == 0;
  pthread_mutex_unlock(&g_lock);
  if (last) {
    ntfs_umount(v->ntfs);
    free(v);
  }
}

/* Remove slot i from the list; caller holds g_lock. */
static void detach_locked(int i) {
  vol_t *v = g_vols[i];
  g_vols[i] = NULL;
  g_nodes[i][0] = 0;
  v->detached = 1;
  g_gen++;
  if (--v->refs == 0) {
    ntfs_umount(v->ntfs);
    free(v);
  }
}

void vfs_add_source(const char *path) {
  pthread_mutex_lock(&g_lock);
  if (g_nsources < MAX_SOURCES)
    snprintf(g_sources[g_nsources++], sizeof g_sources[0], "%s", path);
  pthread_mutex_unlock(&g_lock);
}

static int serial_mounted(uint64_t serial) {
  int r = 0;
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < MAX_VOLS; i++)
    if (g_vols[i] && g_vols[i]->serial == serial) r = 1;
  pthread_mutex_unlock(&g_lock);
  return r;
}

static int node_mounted(const char *node) {
  int r = 0;
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < MAX_VOLS; i++)
    if (g_vols[i] && !strcmp(g_nodes[i], node)) r = 1;
  pthread_mutex_unlock(&g_lock);
  return r;
}

/* Mount every NTFS partition found on one device node. Returns 0 if
 * something was mounted, -1 if there is no NTFS here, -2 if the device
 * could not be opened (may succeed later). */
static int probe_node(const char *node, char *err, size_t errlen) {
  bdev_t *b = bdev_open(node);
  if (!b) {
    snprintf(err, errlen, "cannot open %s: %s", node, strerror(errno));
    return -2;
  }
  part_t parts[PART_MAX];
  int n = part_scan(b, parts, PART_MAX), mounted = 0;
  snprintf(err, errlen, "no NTFS partition found on %s", node);

  for (int i = 0; i < n; i++) {
    bdev_t *s = bdev_slice(b, parts[i].offset, parts[i].size);
    if (!s) continue;
    if (!part_is_ntfs(s)) { bdev_close(s); continue; }
    ntfs_vol_t *nv;
    char merr[128];
    if (ntfs_mount(s, &nv, merr, sizeof merr)) {
      snprintf(err, errlen, "%s partition %d: %s", node, parts[i].index, merr);
      bdev_close(s);
      continue;
    }
    ntfs_info_t info;
    ntfs_get_info(nv, &info);
    if (serial_mounted(info.serial)) {
      /* The same volume seen through another node (e.g. da0 and da0s1). */
      ntfs_umount(nv);
      mounted++;
      continue;
    }

    vol_t *v = calloc(1, sizeof *v);
    if (!v) { ntfs_umount(nv); continue; }
    v->kind = VOL_NTFS;
    v->ntfs = nv;
    v->serial = info.serial;
    v->size = info.total_bytes;
    v->partition = parts[i].index;
    v->refs = 1;
    snprintf(v->scheme, sizeof v->scheme, "%s", parts[i].scheme);
    snprintf(v->label, sizeof v->label, "%s", info.label);
    snprintf(v->device, sizeof v->device, "%s", node);

    pthread_mutex_lock(&g_lock);
    int slot = -1;
    for (int k = 0; k < MAX_VOLS && slot < 0; k++)
      if (!g_vols[k]) slot = k;
    if (slot >= 0) {
      snprintf(v->id, sizeof v->id, "ntfs%u", g_next_id++);
      g_vols[slot] = v;
      snprintf(g_nodes[slot], sizeof g_nodes[0], "%s", node);
      g_gen++;
      mounted++;
    }
    pthread_mutex_unlock(&g_lock);
    if (slot < 0) { ntfs_umount(nv); free(v); }
  }
  bdev_close(b);
  return mounted ? 0 : -1;
}

static int cmp_str(const void *a, const void *b) {
  return strcmp((const char *)a, (const char *)b);
}

/* Candidate device nodes, sorted so whole disks come before partitions. */
static int candidates(char (*out)[300], int max) {
  int n = 0;
#ifdef __PROSPERO__
  /* USB mass storage shows up as da<N> plus partition nodes. */
  DIR *d = opendir("/dev");
  if (d) {
    struct dirent *e;
    while ((e = readdir(d)) && n < max) {
      const char *nm = e->d_name;
      if (strncmp(nm, "da", 2) || nm[2] < '0' || nm[2] > '9') continue;
      if (strchr(nm, '.')) continue; /* e.g. encrypted ".crypt" views */
      snprintf(out[n++], 300, "/dev/%s", nm);
    }
    closedir(d);
  }
#endif
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < g_nsources && n < max; i++)
    snprintf(out[n++], 300, "%s", g_sources[i]);
  pthread_mutex_unlock(&g_lock);
  qsort(out, (size_t)n, 300, cmp_str);
  return n;
}

int vfs_rescan(int force) {
  static char cand[MAX_PROBED][300];
  pthread_mutex_lock(&g_scan);
  int nc = candidates(cand, MAX_PROBED);

  /* Drop volumes whose device node is gone. */
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < MAX_VOLS; i++) {
    if (!g_vols[i] || !g_nodes[i][0]) continue;
    struct stat st;
    int present = stat(g_nodes[i], &st) == 0;
    int listed = 0;
    for (int k = 0; k < nc; k++)
      if (!strcmp(cand[k], g_nodes[i])) listed = 1;
    if (!present || !listed) detach_locked(i);
  }
  pthread_mutex_unlock(&g_lock);

  /* Forget probe results for nodes that disappeared. */
  for (int i = 0; i < g_nprobed;) {
    int listed = 0;
    for (int k = 0; k < nc; k++)
      if (!strcmp(cand[k], g_probed[i].path)) listed = 1;
    if (!listed) g_probed[i] = g_probed[--g_nprobed];
    else i++;
  }

  for (int k = 0; k < nc; k++) {
    if (node_mounted(cand[k])) continue;
    probed_t *p = NULL;
    for (int i = 0; i < g_nprobed; i++)
      if (!strcmp(g_probed[i].path, cand[k])) p = &g_probed[i];
    if (p && p->rejected && !force) continue;
    char err[256];
    int rc = probe_node(cand[k], err, sizeof err);
    if (!p && g_nprobed < MAX_PROBED) {
      p = &g_probed[g_nprobed++];
      memset(p, 0, sizeof *p);
      snprintf(p->path, sizeof p->path, "%s", cand[k]);
    }
    if (p) {
      if (rc == -2) p->tries++;
      p->rejected = rc == -1 || (rc == -2 && p->tries >= 5);
      if (!rc) p->tries = 0;
    }
  }

  int count = 0;
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < MAX_VOLS; i++)
    if (g_vols[i]) count++;
  pthread_mutex_unlock(&g_lock);
  pthread_mutex_unlock(&g_scan);
  return count;
}

int vfs_mount_path(const char *path, char *err, size_t errlen) {
  pthread_mutex_lock(&g_scan);
  int rc;
  if (node_mounted(path)) {
    snprintf(err, errlen, "%s is already mounted", path);
    rc = -1;
  } else {
    rc = probe_node(path, err, errlen);
  }
  pthread_mutex_unlock(&g_scan);
  if (!rc) {
    /* Keep it across rescans. */
    int known = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_nsources; i++)
      if (!strcmp(g_sources[i], path)) known = 1;
    pthread_mutex_unlock(&g_lock);
    if (!known) vfs_add_source(path);
  }
  return rc;
}

int vfs_unmount(const char *id) {
  int rc = -ENOENT;
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < MAX_VOLS; i++) {
    if (g_vols[i] && !strcmp(g_vols[i]->id, id)) {
      /* Don't auto-mount it again until the device is replugged. */
      char node[300];
      snprintf(node, sizeof node, "%s", g_nodes[i]);
      for (int s = 0; s < g_nsources; s++)
        if (!strcmp(g_sources[s], node)) {
          memmove(g_sources[s], g_sources[s + 1],
                  (size_t)(g_nsources - s - 1) * sizeof g_sources[0]);
          g_nsources--;
          break;
        }
      detach_locked(i);
      rc = 0;
      pthread_mutex_unlock(&g_lock);
      pthread_mutex_lock(&g_scan);
      int found = 0;
      for (int p = 0; p < g_nprobed; p++)
        if (!strcmp(g_probed[p].path, node)) { g_probed[p].rejected = 1; found = 1; }
      if (!found && g_nprobed < MAX_PROBED) {
        memset(&g_probed[g_nprobed], 0, sizeof g_probed[0]);
        snprintf(g_probed[g_nprobed].path, 300, "%s", node);
        g_probed[g_nprobed++].rejected = 1;
      }
      pthread_mutex_unlock(&g_scan);
      return rc;
    }
  }
  pthread_mutex_unlock(&g_lock);
  return rc;
}

void vfs_volumes_json(buf_t *b) {
  buf_puts(b, "[{\"id\":\"ps5\",\"kind\":\"native\",\"label\":");
  buf_json_str(b, g_native.label);
  buf_puts(b, "}");
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < MAX_VOLS; i++) {
    vol_t *v = g_vols[i];
    if (!v) continue;
    ntfs_info_t in;
    ntfs_get_info(v->ntfs, &in);
    buf_puts(b, ",{\"id\":");
    buf_json_str(b, v->id);
    buf_puts(b, ",\"kind\":\"ntfs\",\"label\":");
    buf_json_str(b, v->label);
    buf_puts(b, ",\"device\":");
    buf_json_str(b, v->device);
    char why[256] = "";
    int rw = ntfs_is_writable(v->ntfs);
    if (!rw) ntfs_can_write(v->ntfs, why, sizeof why);
    buf_printf(b, ",\"writable\":%s,\"write_block\":", rw ? "true" : "false");
    buf_json_str(b, why);
    buf_printf(b, ",\"scheme\":\"%s\",\"partition\":%d,\"size\":%llu,"
                  "\"serial\":\"%016llX\",\"version\":\"%u.%u\",\"dirty\":%s,"
                  "\"cluster\":%u}",
               v->scheme, v->partition, (unsigned long long)v->size,
               (unsigned long long)v->serial, in.ver_major, in.ver_minor,
               in.dirty ? "true" : "false", in.cluster_size);
  }
  pthread_mutex_unlock(&g_lock);
  buf_puts(b, "]");
}

/* ---- Paths --------------------------------------------------------------- */

int vfs_clean_path(const char *in, char *out, size_t outlen) {
  if (outlen < 2) return -1;
  size_t o = 0;
  out[o++] = '/';
  out[o] = 0;
  const char *p = in;
  while (*p) {
    while (*p == '/') p++;
    if (!*p) break;
    const char *e = strchr(p, '/');
    size_t n = e ? (size_t)(e - p) : strlen(p);
    if (n == 1 && p[0] == '.') {
      /* skip */
    } else if (n == 2 && p[0] == '.' && p[1] == '.') {
      if (o > 1) {
        o--;                       /* drop trailing '/' */
        while (o > 1 && out[o - 1] != '/') o--;
        out[o] = 0;
      }
    } else {
      if (o + n + 2 > outlen) return -1;
      memcpy(out + o, p, n);
      o += n;
      out[o++] = '/';
      out[o] = 0;
    }
    p += n;
  }
  if (o > 1) out[--o] = 0; /* no trailing slash except for root */
  return 0;
}

/* ---- Listing ------------------------------------------------------------- */

static int list_push(vlist_t *l, const char *name, ventry_t *e) {
  if (l->n == l->cap) {
    size_t nc = l->cap ? l->cap * 2 : 64;
    ventry_t *ne = realloc(l->e, nc * sizeof *ne);
    if (!ne) return -ENOMEM;
    l->e = ne;
    l->cap = nc;
  }
  e->name = strdup(name);
  if (!e->name) return -ENOMEM;
  l->e[l->n++] = *e;
  return 0;
}

static void from_ntfs(ventry_t *e, const ntfs_stat_t *st) {
  memset(e, 0, sizeof *e);
  e->is_dir = st->is_dir;
  e->is_link = (st->attrs & NTFS_FA_REPARSE) != 0;
  e->hidden = (st->attrs & (NTFS_FA_HIDDEN | NTFS_FA_SYSTEM)) != 0;
  e->size = st->is_dir ? 0 : st->size;
  e->mtime = st->mtime;
  e->attrs = st->attrs;
}

static int ntfs_list_cb(void *ctx, const char *name, const ntfs_stat_t *st) {
  ventry_t e;
  from_ntfs(&e, st);
  return list_push(ctx, name, &e) ? 1 : 0;
}

int vfs_list(vol_t *v, const char *path, vlist_t *out) {
  memset(out, 0, sizeof *out);
  if (v->kind == VOL_NTFS) {
    uint64_t ino;
    int rc = ntfs_lookup(v->ntfs, path, &ino);
    if (!rc) rc = ntfs_readdir(v->ntfs, ino, ntfs_list_cb, out);
    if (rc) vfs_list_free(out);
    return rc;
  }

  DIR *d = opendir(path);
  if (!d) return -errno;
  struct dirent *de;
  char full[2048];
  while ((de = readdir(d))) {
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
    snprintf(full, sizeof full, "%s/%s", strcmp(path, "/") ? path : "", de->d_name);
    ventry_t e;
    memset(&e, 0, sizeof e);
    struct stat st;
    if (lstat(full, &st) == 0) {
      e.is_link = S_ISLNK(st.st_mode);
      if (e.is_link) stat(full, &st); /* describe the target */
      e.is_dir = S_ISDIR(st.st_mode);
      e.size = S_ISREG(st.st_mode) ? (uint64_t)st.st_size : 0;
      e.mtime = st.st_mtime;
    } else {
      e.is_dir = de->d_type == DT_DIR;
    }
    e.hidden = de->d_name[0] == '.';
    if (list_push(out, de->d_name, &e)) {
      closedir(d);
      vfs_list_free(out);
      return -ENOMEM;
    }
  }
  closedir(d);
  return 0;
}

void vfs_list_free(vlist_t *l) {
  for (size_t i = 0; i < l->n; i++) free(l->e[i].name);
  free(l->e);
  memset(l, 0, sizeof *l);
}

int vfs_stat(vol_t *v, const char *path, ventry_t *out) {
  memset(out, 0, sizeof *out);
  if (v->kind == VOL_NTFS) {
    uint64_t ino;
    ntfs_stat_t st;
    int rc = ntfs_lookup(v->ntfs, path, &ino);
    if (!rc) rc = ntfs_stat(v->ntfs, ino, &st);
    if (!rc) from_ntfs(out, &st);
    return rc;
  }
  struct stat st;
  if (stat(path, &st)) return -errno;
  out->is_dir = S_ISDIR(st.st_mode);
  out->size = S_ISREG(st.st_mode) ? (uint64_t)st.st_size : 0;
  out->mtime = st.st_mtime;
  return 0;
}

/* ---- Files --------------------------------------------------------------- */

int vfs_open(vol_t *v, const char *path, vfile_t *f) {
  memset(f, 0, sizeof *f);
  f->vol = v;
  f->fd = -1;
  if (v->kind == VOL_NTFS) {
    uint64_t ino;
    int rc = ntfs_lookup(v->ntfs, path, &ino);
    if (!rc) rc = ntfs_open(v->ntfs, ino, &f->nf);
    if (!rc) f->size = ntfs_file_size(f->nf);
    return rc;
  }
  f->fd = open(path, O_RDONLY);
  if (f->fd < 0) return -errno;
  struct stat st;
  if (fstat(f->fd, &st) || S_ISDIR(st.st_mode)) {
    int e = S_ISDIR(st.st_mode) ? EISDIR : errno;
    close(f->fd);
    f->fd = -1;
    return -e;
  }
  f->size = (uint64_t)st.st_size;
  return 0;
}

ssize_t vfs_pread(vfile_t *f, void *buf, size_t len, uint64_t off) {
  if (f->nf) return ntfs_pread(f->nf, buf, len, off);
  ssize_t n;
  do {
    n = pread(f->fd, buf, len, (off_t)off);
  } while (n < 0 && errno == EINTR);
  return n < 0 ? -errno : n;
}

void vfs_close(vfile_t *f) {
  if (f->nf) ntfs_close(f->nf);
  if (f->fd >= 0) close(f->fd);
  f->nf = NULL;
  f->fd = -1;
}

/* ---- Writing ------------------------------------------------------------- */

int vfs_set_writable(vol_t *v, int on, char *err, size_t errlen) {
  if (v->kind != VOL_NTFS) {
    snprintf(err, errlen, "not an NTFS volume");
    return -EINVAL;
  }
  int rc = 0;
  if (on) rc = ntfs_enable_write(v->ntfs, err, errlen);
  else ntfs_disable_write(v->ntfs);
  pthread_mutex_lock(&g_lock);
  g_gen++;
  pthread_mutex_unlock(&g_lock);
  return rc;
}

/* Split "/a/b/c" into the parent's inode and "c". */
static int ntfs_parent(vol_t *v, const char *path, uint64_t *parent, char *name,
                       size_t nlen) {
  const char *slash = strrchr(path, '/');
  if (!slash || !slash[1]) return -EINVAL;
  snprintf(name, nlen, "%s", slash + 1);
  char dir[1024];
  size_t dl = (size_t)(slash - path);
  if (dl >= sizeof dir) return -ENAMETOOLONG;
  memcpy(dir, path, dl);
  dir[dl] = 0;
  return ntfs_lookup(v->ntfs, dl ? dir : "/", parent);
}

int vfs_mkdir(vol_t *v, const char *path) {
  if (v->kind == VOL_NTFS) {
    uint64_t parent;
    char name[512];
    int rc = ntfs_parent(v, path, &parent, name, sizeof name);
    if (!rc) rc = ntfs_mkdir(v->ntfs, parent, name, (int64_t)time(NULL), NULL);
    return rc;
  }
  return mkdir(path, 0777) ? -errno : 0;
}

int vfs_mkdirs(vol_t *v, const char *path) {
  char tmp[1024];
  snprintf(tmp, sizeof tmp, "%s", path);
  size_t n = strlen(tmp);
  for (size_t i = 1; i <= n; i++) {
    if (tmp[i] != '/' && tmp[i] != 0) continue;
    char c = tmp[i];
    tmp[i] = 0;
    ventry_t st;
    int rc = vfs_stat(v, tmp, &st);
    if (rc == -ENOENT) rc = vfs_mkdir(v, tmp);
    else if (!rc && !st.is_dir) rc = -ENOTDIR;
    if (rc && rc != -EEXIST) return rc;
    tmp[i] = c;
  }
  return 0;
}

int64_t vfs_free_bytes(vol_t *v, const char *path) {
  if (v->kind == VOL_NTFS) {
    uint64_t fr;
    return ntfs_free_bytes(v->ntfs, &fr) ? -1 : (int64_t)fr;
  }
  struct statfs sf;
  if (statfs(path, &sf)) return -1;
  return (int64_t)((uint64_t)sf.f_bavail * (uint64_t)sf.f_bsize);
}

int vfs_wopen(vol_t *v, const char *path, uint64_t size, int64_t mtime,
              vwfile_t *w, uint64_t *done) {
  memset(w, 0, sizeof *w);
  w->vol = v;
  w->fd = -1;
  w->mtime = mtime;
  *done = 0;
  if (v->kind == VOL_NTFS) {
    uint64_t parent, ino;
    char name[512];
    int rc = ntfs_parent(v, path, &parent, name, sizeof name);
    if (rc) return rc;
    if (ntfs_lookup(v->ntfs, path, &ino) == 0) {
      ntfs_stat_t st;
      rc = ntfs_stat(v->ntfs, ino, &st);
      if (rc) return rc;
      if (st.is_dir || st.size != size) return -EEXIST;
      rc = ntfs_wopen(v->ntfs, ino, &w->nw, done);
      if (rc == -ENOTSUP) {
        /* Same size but not ours to continue (e.g. compressed): treat a
         * same-sized file as already there. */
        *done = size;
        return 0;
      }
      return rc;
    }
    return ntfs_create(v->ntfs, parent, name, size, mtime, &w->nw);
  }

  struct stat ds;
  if (stat(path, &ds) == 0) {
    if (S_ISDIR(ds.st_mode)) return -EEXIST;
    if ((uint64_t)ds.st_size == size) { *done = size; return 0; }
  }
  snprintf(w->final, sizeof w->final, "%s", path);
  snprintf(w->tmp, sizeof w->tmp, "%s.part", path);
  w->fd = open(w->tmp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  return w->fd < 0 ? -errno : 0;
}

int vfs_wwrite(vwfile_t *w, const void *buf, size_t len) {
  if (w->nw) return ntfs_wwrite(w->nw, buf, len);
  const uint8_t *p = buf;
  while (len) {
    ssize_t m = write(w->fd, p, len);
    if (m < 0) {
      if (errno == EINTR) continue;
      return -errno;
    }
    p += m;
    len -= (size_t)m;
  }
  return 0;
}

int vfs_wclose(vwfile_t *w, int ok) {
  int rc = 0;
  if (w->nw) {
    rc = ntfs_wclose(w->nw);
    w->nw = NULL;
    return rc;
  }
  if (w->fd < 0) return 0;
  if (close(w->fd) && ok) rc = -errno;
  w->fd = -1;
  if (!ok || rc) {
    unlink(w->tmp);
    return rc;
  }
  if (rename(w->tmp, w->final)) {
    rc = -errno;
    unlink(w->tmp);
    return rc;
  }
  if (w->mtime > 0) {
    struct timeval tv[2] = {{(time_t)w->mtime, 0}, {(time_t)w->mtime, 0}};
    utimes(w->final, tv);
  }
  return 0;
}
