#include "jobs.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/statfs.h>
#endif

#include "vfs.h"

#define MAX_JOBS  64
#define COPY_BUF  (2 * 1024 * 1024)

typedef enum { J_QUEUED, J_SCANNING, J_COPYING, J_DONE, J_FAILED, J_CANCELLED } jstate_t;

static const char *state_names[] = {"queued", "scanning", "copying", "done",
                                    "failed", "cancelled"};

typedef struct job {
  int      id;
  jstate_t state;
  char     vol[16];
  char     dvol[16];     /* destination volume */
  char     src[1024];
  char     dest[1024];
  char     current[1024];
  char     error[256];
  uint64_t total_bytes, done_bytes;
  uint64_t present_bytes; /* already at the destination (resume) */
  uint32_t total_files, done_files, skipped_files;
  int64_t  started, finished;
  volatile int cancel;
} job_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cond = PTHREAD_COND_INITIALIZER;
static job_t *g_jobs[MAX_JOBS];
static int    g_next = 1;

static int64_t now_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void set_state(job_t *j, jstate_t s) {
  pthread_mutex_lock(&g_lock);
  j->state = s;
  pthread_mutex_unlock(&g_lock);
}

static void fail(job_t *j, const char *fmt, const char *arg, int err) {
  pthread_mutex_lock(&g_lock);
  if (!j->error[0]) {
    char msg[200];
    snprintf(msg, sizeof msg, fmt, arg);
    snprintf(j->error, sizeof j->error, "%s%s%s", msg, err ? ": " : "",
             err ? strerror(err) : "");
  }
  pthread_mutex_unlock(&g_lock);
}

static int join(char *out, size_t outlen, const char *a, const char *b) {
  size_t la = strlen(a);
  int n = snprintf(out, outlen, "%s%s%s", a, la && a[la - 1] == '/' ? "" : "/", b);
  return n < 0 || (size_t)n >= outlen ? -1 : 0;
}

/* Make a name valid for Windows-style file systems (NTFS written by us,
 * exFAT/FAT USB drives): no \\ : * ? " < > |, no control characters, no
 * trailing dot or space, and not a reserved device name such as CON. */
static void safe_name(char *dst, size_t len, const char *src) {
  static const char *reserved[] = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3",
                                   "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                                   "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
                                   "LPT7", "LPT8", "LPT9"};
  char tmp[1024];
  snprintf(tmp, sizeof tmp, "%s", src);
  for (char *p = tmp; *p; p++)
    if (strchr("\\:*?\"<>|", *p) || (unsigned char)*p < 0x20) *p = '_';
  size_t n = strlen(tmp);
  while (n && (tmp[n - 1] == '.' || tmp[n - 1] == ' ')) tmp[--n] = '_';
  if (!n) snprintf(tmp, sizeof tmp, "_");
  char stem[16];
  size_t sl = strcspn(tmp, ".");
  if (sl < sizeof stem) {
    memcpy(stem, tmp, sl);
    stem[sl] = 0;
    for (size_t i = 0; i < sizeof reserved / sizeof reserved[0]; i++)
      if (!strcasecmp(stem, reserved[i])) {
        snprintf(dst, len, "_%s", tmp);
        return;
      }
  }
  snprintf(dst, len, "%s", tmp);
}

/* ---- Scan ---------------------------------------------------------------- */

/* Count what will be copied. dst mirrors the destination path so data that
 * is already there (an earlier, interrupted copy) is not counted as needed
 * space. */
static void count_file(job_t *j, vol_t *dv, const char *dst, uint64_t size) {
  ventry_t ds;
  int present = dst && vfs_stat(dv, dst, &ds) == 0 && !ds.is_dir && ds.size == size;
  pthread_mutex_lock(&g_lock);
  j->total_bytes += size;
  j->total_files++;
  if (present) j->present_bytes += size;
  pthread_mutex_unlock(&g_lock);
}

static int scan(job_t *j, vol_t *v, vol_t *dv, const char *path, const char *dst, int depth) {
  if (j->cancel) return -ECANCELED;
  if (depth > 64) return -ELOOP;
  ventry_t st;
  int rc = vfs_stat(v, path, &st);
  if (rc) { fail(j, "cannot read %s", path, -rc); return rc; }
  if (!st.is_dir) {
    count_file(j, dv, dst, st.size);
    return 0;
  }
  vlist_t l;
  if ((rc = vfs_list(v, path, &l))) { fail(j, "cannot list %s", path, -rc); return rc; }
  char child[2048], dchild[2048], nm[1024];
  for (size_t i = 0; i < l.n && !rc; i++) {
    if (l.e[i].is_link && l.e[i].is_dir) continue; /* junctions: avoid loops */
    if (join(child, sizeof child, path, l.e[i].name)) continue;
    safe_name(nm, sizeof nm, l.e[i].name);
    int have_dst = dst && !join(dchild, sizeof dchild, dst, nm);
    if (l.e[i].is_dir) rc = scan(j, v, dv, child, have_dst ? dchild : NULL, depth + 1);
    else count_file(j, dv, have_dst ? dchild : NULL, l.e[i].size);
  }
  vfs_list_free(&l);
  return rc;
}

/* ---- Copy ---------------------------------------------------------------- */

static int copy_file(job_t *j, vol_t *v, vol_t *dv, const char *src,
                     const char *dst, int64_t mtime, uint8_t *buf) {
  pthread_mutex_lock(&g_lock);
  snprintf(j->current, sizeof j->current, "%s", src);
  pthread_mutex_unlock(&g_lock);

  vfile_t f;
  int rc = vfs_open(v, src, &f);
  if (rc) { fail(j, "cannot open %s", src, -rc); return rc; }

  vwfile_t w;
  uint64_t done = 0;
  rc = vfs_wopen(dv, dst, f.size, mtime, &w, &done);
  if (rc) {
    fail(j, rc == -EEXIST ? "a different file already exists at %s" : "cannot create %s",
         dst, rc == -EEXIST ? 0 : -rc);
    vfs_close(&f);
    return rc;
  }
  if (done >= f.size) {
    /* Already there (resume). */
    vfs_wclose(&w, 1);
    vfs_close(&f);
    pthread_mutex_lock(&g_lock);
    j->done_bytes += f.size;
    j->done_files++;
    j->skipped_files++;
    pthread_mutex_unlock(&g_lock);
    return 0;
  }
  pthread_mutex_lock(&g_lock);
  j->done_bytes += done; /* continuing a partly copied file */
  pthread_mutex_unlock(&g_lock);

  uint64_t off = done;
  while (off < f.size) {
    if (j->cancel) { rc = -ECANCELED; break; }
    size_t want = f.size - off < COPY_BUF ? (size_t)(f.size - off) : COPY_BUF;
    ssize_t n = vfs_pread(&f, buf, want, off);
    if (n <= 0) {
      rc = n < 0 ? (int)n : -EIO;
      fail(j, "read error in %s", src, -rc);
      break;
    }
    rc = vfs_wwrite(&w, buf, (size_t)n);
    if (rc) { fail(j, "write error in %s", dst, -rc); break; }
    off += (uint64_t)n;
    pthread_mutex_lock(&g_lock);
    j->done_bytes += (uint64_t)n;
    pthread_mutex_unlock(&g_lock);
  }
  vfs_close(&f);
  int rc2 = vfs_wclose(&w, rc == 0);
  if (!rc && rc2) { rc = rc2; fail(j, "cannot finish %s", dst, -rc); }
  if (rc) return rc;
  pthread_mutex_lock(&g_lock);
  j->done_files++;
  pthread_mutex_unlock(&g_lock);
  return 0;
}

static int copy_tree(job_t *j, vol_t *v, vol_t *dv, const char *src, const char *dst,
                     uint8_t *buf, int depth) {
  if (j->cancel) return -ECANCELED;
  if (depth > 64) return -ELOOP;
  ventry_t st;
  int rc = vfs_stat(v, src, &st);
  if (rc) { fail(j, "cannot read %s", src, -rc); return rc; }
  if (!st.is_dir) return copy_file(j, v, dv, src, dst, st.mtime, buf);

  ventry_t dst_st;
  rc = vfs_stat(dv, dst, &dst_st);
  if (rc == -ENOENT) rc = vfs_mkdir(dv, dst);
  else if (!rc && !dst_st.is_dir) rc = -EEXIST;
  if (rc && rc != -EEXIST) {
    fail(j, "cannot create folder %s", dst, -rc);
    return rc;
  }
  if (rc == -EEXIST && vfs_stat(dv, dst, &dst_st) == 0 && !dst_st.is_dir) {
    fail(j, "a file is in the way of folder %s", dst, 0);
    return rc;
  }
  vlist_t l;
  if ((rc = vfs_list(v, src, &l))) { fail(j, "cannot list %s", src, -rc); return rc; }
  char cs[2048], cd[2048], nm[1024];
  for (size_t i = 0; i < l.n && !rc; i++) {
    if (l.e[i].is_link && l.e[i].is_dir) continue;
    safe_name(nm, sizeof nm, l.e[i].name);
    if (join(cs, sizeof cs, src, l.e[i].name) || join(cd, sizeof cd, dst, nm)) {
      fail(j, "path too long: %s", l.e[i].name, 0);
      rc = -ENAMETOOLONG;
      break;
    }
    rc = l.e[i].is_dir ? copy_tree(j, v, dv, cs, cd, buf, depth + 1)
                       : copy_file(j, v, dv, cs, cd, l.e[i].mtime, buf);
  }
  vfs_list_free(&l);
  return rc;
}

static void run_job(job_t *j) {
  vol_t *v = vfs_get(j->vol);
  if (!v) {
    fail(j, "volume %s is no longer available", j->vol, 0);
    set_state(j, J_FAILED);
    return;
  }
  vol_t *dv = vfs_get(j->dvol);
  if (!dv) {
    vfs_put(v);
    fail(j, "destination drive %s is no longer available", j->dvol, 0);
    set_state(j, J_FAILED);
    return;
  }
  uint8_t *buf = malloc(COPY_BUF);
  int rc = buf ? 0 : -ENOMEM;
  if (!rc && dv->kind == VOL_NTFS && !ntfs_is_writable(dv->ntfs)) {
    fail(j, "writing is not enabled on %s", dv->label[0] ? dv->label : dv->id, 0);
    rc = -EROFS;
  }

  set_state(j, J_SCANNING);
  char top[2048] = "";
  if (!rc) {
    const char *base = strrchr(j->src, '/');
    base = base && base[1] ? base + 1 : "";
    char nm[1024];
    if (!*base) snprintf(nm, sizeof nm, "%s", v->label[0] ? v->label : v->id);
    else snprintf(nm, sizeof nm, "%s", base);
    safe_name(nm, sizeof nm, nm);
    if (join(top, sizeof top, j->dest, nm)) rc = -ENAMETOOLONG;
  }
  if (!rc) rc = scan(j, v, dv, j->src, top, 0);

  if (!rc) {
    int64_t fr = vfs_free_bytes(dv, j->dest);
    if (fr >= 0) {
      uint64_t avail = (uint64_t)fr;
      uint64_t needed = j->total_bytes - j->present_bytes;
      if (avail < needed) {
        char need[64];
        snprintf(need, sizeof need, "%.2f GB needed, %.2f GB free",
                 needed / 1e9, avail / 1e9);
        fail(j, "not enough space: %s", need, 0);
        rc = -ENOSPC;
      }
    }
  }

  if (!rc) {
    /* top is dest + the source's name (a volume root uses its label). */
    set_state(j, J_COPYING);
    rc = copy_tree(j, v, dv, j->src, top, buf, 0);
  }
  free(buf);
  vfs_put(dv);
  vfs_put(v);

  pthread_mutex_lock(&g_lock);
  j->finished = now_ms();
  j->current[0] = 0;
  j->state = rc == -ECANCELED || j->cancel ? J_CANCELLED : rc ? J_FAILED : J_DONE;
  pthread_mutex_unlock(&g_lock);
}

static void *worker(void *arg) {
  (void)arg;
  for (;;) {
    job_t *next = NULL;
    pthread_mutex_lock(&g_lock);
    while (!next) {
      /* Oldest queued job first. */
      for (int i = 0; i < MAX_JOBS; i++)
        if (g_jobs[i] && g_jobs[i]->state == J_QUEUED &&
            (!next || g_jobs[i]->id < next->id))
          next = g_jobs[i];
      if (!next) pthread_cond_wait(&g_cond, &g_lock);
    }
    next->started = now_ms();
    if (next->cancel) {
      next->state = J_CANCELLED;
      pthread_mutex_unlock(&g_lock);
      continue;
    }
    pthread_mutex_unlock(&g_lock);
    run_job(next);
  }
  return NULL;
}

void jobs_init(void) {
  pthread_t t;
  pthread_attr_t at;
  pthread_attr_init(&at);
  pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
  pthread_create(&t, &at, worker, NULL);
  pthread_attr_destroy(&at);
}

int jobs_copy(const char *vol, const char *src, const char *dvol, const char *dest_dir,
              char *err, size_t errlen) {
  vol_t *dv = vfs_get(dvol);
  if (!dv) {
    snprintf(err, errlen, "destination drive not found");
    return -ENOENT;
  }
  ventry_t st;
  int src_ok = vfs_stat(dv, dest_dir, &st) == 0 && st.is_dir;
  int ro = dv->kind == VOL_NTFS && !ntfs_is_writable(dv->ntfs);
  vfs_put(dv);
  if (ro) {
    snprintf(err, errlen, "turn on writing for this drive first");
    return -EROFS;
  }
  if (!src_ok) {
    snprintf(err, errlen, "destination folder does not exist: %s", dest_dir);
    return -ENOENT;
  }
  if (!strcmp(vol, dvol)) {
    /* Same drive: refuse copying a folder into itself. */
    size_t n = strlen(src);
    if (!strncmp(dest_dir, src, n) && (dest_dir[n] == '/' || !dest_dir[n])) {
      snprintf(err, errlen, "cannot copy a folder into itself");
      return -EINVAL;
    }
  }
  job_t *j = calloc(1, sizeof *j);
  if (!j) { snprintf(err, errlen, "out of memory"); return -ENOMEM; }
  snprintf(j->vol, sizeof j->vol, "%s", vol);
  snprintf(j->dvol, sizeof j->dvol, "%s", dvol);
  snprintf(j->src, sizeof j->src, "%s", src);
  snprintf(j->dest, sizeof j->dest, "%s", dest_dir);
  j->state = J_QUEUED;

  pthread_mutex_lock(&g_lock);
  int slot = -1;
  for (int i = 0; i < MAX_JOBS && slot < 0; i++)
    if (!g_jobs[i]) slot = i;
  if (slot < 0) {
    /* Reuse the oldest finished slot. */
    for (int i = 0; i < MAX_JOBS; i++)
      if (g_jobs[i]->state >= J_DONE && (slot < 0 || g_jobs[i]->id < g_jobs[slot]->id))
        slot = i;
    if (slot >= 0) { free(g_jobs[slot]); g_jobs[slot] = NULL; }
  }
  if (slot < 0) {
    pthread_mutex_unlock(&g_lock);
    free(j);
    snprintf(err, errlen, "too many jobs in progress");
    return -EBUSY;
  }
  j->id = g_next++;
  g_jobs[slot] = j;
  pthread_cond_signal(&g_cond);
  pthread_mutex_unlock(&g_lock);
  return j->id;
}

int jobs_cancel(int id) {
  int rc = -ENOENT;
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < MAX_JOBS; i++)
    if (g_jobs[i] && g_jobs[i]->id == id) {
      g_jobs[i]->cancel = 1;
      if (g_jobs[i]->state == J_QUEUED) g_jobs[i]->state = J_CANCELLED;
      rc = 0;
    }
  pthread_mutex_unlock(&g_lock);
  return rc;
}

void jobs_clear_finished(void) {
  pthread_mutex_lock(&g_lock);
  for (int i = 0; i < MAX_JOBS; i++)
    if (g_jobs[i] && g_jobs[i]->state >= J_DONE) {
      free(g_jobs[i]);
      g_jobs[i] = NULL;
    }
  pthread_mutex_unlock(&g_lock);
}

void jobs_json(buf_t *b) {
  int64_t now = now_ms();
  buf_puts(b, "[");
  int first = 1;
  pthread_mutex_lock(&g_lock);
  /* Newest first. */
  job_t *list[MAX_JOBS];
  int n = 0;
  for (int i = 0; i < MAX_JOBS; i++)
    if (g_jobs[i]) list[n++] = g_jobs[i];
  for (int a = 1; a < n; a++)
    for (int k = a; k > 0 && list[k]->id > list[k - 1]->id; k--) {
      job_t *t = list[k]; list[k] = list[k - 1]; list[k - 1] = t;
    }
  for (int i = 0; i < n; i++) {
    job_t *j = list[i];
    if (!first) buf_puts(b, ",");
    first = 0;
    int64_t elapsed = j->started ? (j->finished ? j->finished : now) - j->started : 0;
    buf_printf(b, "{\"id\":%d,\"state\":\"%s\",\"vol\":", j->id, state_names[j->state]);
    buf_json_str(b, j->vol);
    buf_puts(b, ",\"src\":");
    buf_json_str(b, j->src);
    buf_puts(b, ",\"dvol\":");
    buf_json_str(b, j->dvol);
    buf_puts(b, ",\"dest\":");
    buf_json_str(b, j->dest);
    buf_puts(b, ",\"current\":");
    buf_json_str(b, j->current);
    buf_puts(b, ",\"error\":");
    buf_json_str(b, j->error);
    buf_printf(b, ",\"total_bytes\":%llu,\"done_bytes\":%llu,\"total_files\":%u,"
                  "\"done_files\":%u,\"skipped_files\":%u,\"elapsed_ms\":%lld}",
               (unsigned long long)j->total_bytes, (unsigned long long)j->done_bytes,
               j->total_files, j->done_files, j->skipped_files, (long long)elapsed);
  }
  pthread_mutex_unlock(&g_lock);
  buf_puts(b, "]");
}
