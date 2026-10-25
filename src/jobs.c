#include "jobs.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  char     src[1024];
  char     dest[1024];
  char     current[1024];
  char     error[256];
  uint64_t total_bytes, done_bytes;
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

/* Some names that are fine on NTFS are not allowed on exFAT USB drives. */
static void safe_name(char *dst, size_t len, const char *src) {
  snprintf(dst, len, "%s", src);
  for (char *p = dst; *p; p++)
    if (strchr("\\:*?\"<>|", *p) || (unsigned char)*p < 0x20) *p = '_';
}

/* ---- Scan ---------------------------------------------------------------- */

static int scan(job_t *j, vol_t *v, const char *path, int depth) {
  if (j->cancel) return -ECANCELED;
  if (depth > 64) return -ELOOP;
  ventry_t st;
  int rc = vfs_stat(v, path, &st);
  if (rc) { fail(j, "cannot read %s", path, -rc); return rc; }
  if (!st.is_dir) {
    pthread_mutex_lock(&g_lock);
    j->total_bytes += st.size;
    j->total_files++;
    pthread_mutex_unlock(&g_lock);
    return 0;
  }
  vlist_t l;
  if ((rc = vfs_list(v, path, &l))) { fail(j, "cannot list %s", path, -rc); return rc; }
  char child[2048];
  for (size_t i = 0; i < l.n && !rc; i++) {
    if (l.e[i].is_link && l.e[i].is_dir) continue; /* junctions: avoid loops */
    if (join(child, sizeof child, path, l.e[i].name)) continue;
    if (l.e[i].is_dir) rc = scan(j, v, child, depth + 1);
    else {
      pthread_mutex_lock(&g_lock);
      j->total_bytes += l.e[i].size;
      j->total_files++;
      pthread_mutex_unlock(&g_lock);
    }
  }
  vfs_list_free(&l);
  return rc;
}

/* ---- Copy ---------------------------------------------------------------- */

static int copy_file(job_t *j, vol_t *v, const char *src, const char *dst,
                     int64_t mtime, uint8_t *buf) {
  pthread_mutex_lock(&g_lock);
  snprintf(j->current, sizeof j->current, "%s", src);
  pthread_mutex_unlock(&g_lock);

  vfile_t f;
  int rc = vfs_open(v, src, &f);
  if (rc) { fail(j, "cannot open %s", src, -rc); return rc; }

  /* Resume support: an existing file with the same size is skipped. */
  struct stat ds;
  if (stat(dst, &ds) == 0 && S_ISREG(ds.st_mode) && (uint64_t)ds.st_size == f.size) {
    vfs_close(&f);
    pthread_mutex_lock(&g_lock);
    j->done_bytes += f.size;
    j->done_files++;
    j->skipped_files++;
    pthread_mutex_unlock(&g_lock);
    return 0;
  }

  char tmp[2100];
  snprintf(tmp, sizeof tmp, "%s.part", dst);
  int out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (out < 0) {
    rc = -errno;
    fail(j, "cannot create %s", tmp, -rc);
    vfs_close(&f);
    return rc;
  }

  uint64_t off = 0;
  while (off < f.size) {
    if (j->cancel) { rc = -ECANCELED; break; }
    size_t want = f.size - off < COPY_BUF ? (size_t)(f.size - off) : COPY_BUF;
    ssize_t n = vfs_pread(&f, buf, want, off);
    if (n <= 0) {
      rc = n < 0 ? (int)n : -EIO;
      fail(j, "read error in %s", src, -rc);
      break;
    }
    for (ssize_t w = 0; w < n;) {
      ssize_t m = write(out, buf + w, (size_t)(n - w));
      if (m < 0) {
        if (errno == EINTR) continue;
        rc = -errno;
        fail(j, "write error in %s", dst, -rc);
        break;
      }
      w += m;
    }
    if (rc) break;
    off += (uint64_t)n;
    pthread_mutex_lock(&g_lock);
    j->done_bytes += (uint64_t)n;
    pthread_mutex_unlock(&g_lock);
  }
  vfs_close(&f);
  if (close(out) && !rc) { rc = -errno; fail(j, "write error in %s", dst, -rc); }

  if (rc) {
    unlink(tmp);
    return rc;
  }
  if (rename(tmp, dst)) {
    rc = -errno;
    fail(j, "cannot rename to %s", dst, -rc);
    unlink(tmp);
    return rc;
  }
  if (mtime > 0) {
    struct timeval tv[2] = {{(time_t)mtime, 0}, {(time_t)mtime, 0}};
    utimes(dst, tv);
  }
  pthread_mutex_lock(&g_lock);
  j->done_files++;
  pthread_mutex_unlock(&g_lock);
  return 0;
}

static int copy_tree(job_t *j, vol_t *v, const char *src, const char *dst,
                     uint8_t *buf, int depth) {
  if (j->cancel) return -ECANCELED;
  if (depth > 64) return -ELOOP;
  ventry_t st;
  int rc = vfs_stat(v, src, &st);
  if (rc) { fail(j, "cannot read %s", src, -rc); return rc; }
  if (!st.is_dir) return copy_file(j, v, src, dst, st.mtime, buf);

  if (mkdir(dst, 0777) && errno != EEXIST) {
    rc = -errno;
    fail(j, "cannot create folder %s", dst, -rc);
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
    rc = l.e[i].is_dir ? copy_tree(j, v, cs, cd, buf, depth + 1)
                       : copy_file(j, v, cs, cd, l.e[i].mtime, buf);
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
  uint8_t *buf = malloc(COPY_BUF);
  int rc = buf ? 0 : -ENOMEM;

  set_state(j, J_SCANNING);
  if (!rc) rc = scan(j, v, j->src, 0);

  if (!rc) {
    struct statfs sf;
    if (statfs(j->dest, &sf) == 0) {
      uint64_t avail = (uint64_t)sf.f_bavail * (uint64_t)sf.f_bsize;
      if (avail < j->total_bytes) {
        char need[64];
        snprintf(need, sizeof need, "%.1f GB needed, %.1f GB free",
                 j->total_bytes / 1e9, avail / 1e9);
        fail(j, "not enough space: %s", need, 0);
        rc = -ENOSPC;
      }
    }
  }

  if (!rc) {
    set_state(j, J_COPYING);
    const char *base = strrchr(j->src, '/');
    base = base && base[1] ? base + 1 : "";
    char nm[1024], dst[2048];
    if (!*base) {
      /* Copying a volume root: use the volume label as the folder name. */
      snprintf(nm, sizeof nm, "%s", v->label[0] ? v->label : v->id);
      safe_name(nm, sizeof nm, nm);
    } else {
      safe_name(nm, sizeof nm, base);
    }
    if (join(dst, sizeof dst, j->dest, nm)) rc = -ENAMETOOLONG;
    else rc = copy_tree(j, v, j->src, dst, buf, 0);
  }
  free(buf);
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

int jobs_copy(const char *vol, const char *src, const char *dest_dir, char *err,
              size_t errlen) {
  struct stat st;
  if (stat(dest_dir, &st) || !S_ISDIR(st.st_mode)) {
    snprintf(err, errlen, "destination folder does not exist: %s", dest_dir);
    return -ENOENT;
  }
  if (!strcmp(vol, "ps5")) {
    /* Native to native: refuse copying a folder into itself. */
    size_t n = strlen(src);
    if (!strncmp(dest_dir, src, n) && (dest_dir[n] == '/' || !dest_dir[n])) {
      snprintf(err, errlen, "cannot copy a folder into itself");
      return -EINVAL;
    }
  }
  job_t *j = calloc(1, sizeof *j);
  if (!j) { snprintf(err, errlen, "out of memory"); return -ENOMEM; }
  snprintf(j->vol, sizeof j->vol, "%s", vol);
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
