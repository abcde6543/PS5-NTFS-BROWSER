#include "bdev.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__FreeBSD__) || defined(__PROSPERO__)
#include <sys/disk.h>
#elif defined(__linux__)
#include <linux/fs.h>
#endif

#define CACHE_BLOCK   (64 * 1024)  /* bytes per cache block */
#define CACHE_BLOCKS  128          /* 8 MiB per physical device */
#define DIRECT_MIN    (256 * 1024) /* larger aligned reads skip the cache */

typedef struct cblock {
  uint64_t blkno;
  uint64_t stamp;
  int      valid;
  uint8_t *data;
} cblock_t;

struct bdev {
  char      path[300];
  int       fd;             /* -1 for slices */
  bdev_t   *parent;         /* non-NULL for slices */
  uint64_t  base;           /* offset inside parent */
  uint64_t  size;
  uint32_t  sector;
  int       refs;
  int       writable;

  /* cache, physical devices only */
  pthread_mutex_t lock;
  cblock_t  cache[CACHE_BLOCKS];
  uint64_t  clock;
};

static int read_full(int fd, uint64_t off, void *buf, size_t len) {
  uint8_t *p = buf;
  while (len) {
    ssize_t n = pread(fd, p, len, (off_t)off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (n == 0) {
      /* End of an image file that is not a whole number of sectors. */
      memset(p, 0, len);
      return 0;
    }
    p += n; off += (uint64_t)n; len -= (size_t)n;
  }
  return 0;
}

bdev_t *bdev_open(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return NULL;

  struct stat st;
  if (fstat(fd, &st) != 0) { close(fd); return NULL; }

  uint64_t size = 0;
  uint32_t sector = 512;

  if (S_ISREG(st.st_mode)) {
    size = (uint64_t)st.st_size;
  } else {
#if defined(__FreeBSD__) || defined(__PROSPERO__)
    off_t ms = 0; u_int ss = 0;
    if (ioctl(fd, DIOCGMEDIASIZE, &ms) == 0) size = (uint64_t)ms;
    if (ioctl(fd, DIOCGSECTORSIZE, &ss) == 0 && ss) sector = ss;
#elif defined(__linux__)
    unsigned long long ms = 0; int ss = 0;
    if (ioctl(fd, BLKGETSIZE64, &ms) == 0) size = ms;
    if (ioctl(fd, BLKSSZGET, &ss) == 0 && ss > 0) sector = (uint32_t)ss;
#endif
    if (!size) {
      off_t end = lseek(fd, 0, SEEK_END);
      if (end > 0) size = (uint64_t)end;
    }
  }
  if (!size || sector > CACHE_BLOCK || (sector & (sector - 1))) {
    close(fd);
    return NULL;
  }

  bdev_t *b = calloc(1, sizeof *b);
  if (!b) { close(fd); return NULL; }
  strncpy(b->path, path, sizeof b->path - 1);
  b->fd = fd;
  b->size = size;
  b->sector = sector;
  b->refs = 1;
  pthread_mutex_init(&b->lock, NULL);
  return b;
}

bdev_t *bdev_slice(bdev_t *parent, uint64_t offset, uint64_t size) {
  if (offset > parent->size || size > parent->size - offset) return NULL;
  bdev_t *b = calloc(1, sizeof *b);
  if (!b) return NULL;
  bdev_t *root = parent->parent ? parent->parent : parent;
  snprintf(b->path, sizeof b->path, "%.250s@%llu", parent->path,
           (unsigned long long)offset);
  b->fd = -1;
  b->parent = root;
  b->base = offset + parent->base;
  b->size = size;
  b->sector = parent->sector;
  b->refs = 1;
  pthread_mutex_lock(&root->lock);
  root->refs++;
  pthread_mutex_unlock(&root->lock);
  return b;
}

void bdev_close(bdev_t *b) {
  if (!b) return;
  if (b->parent) {
    bdev_t *root = b->parent;
    free(b);
    bdev_close(root);
    return;
  }
  pthread_mutex_lock(&b->lock);
  int left = --b->refs;
  pthread_mutex_unlock(&b->lock);
  if (left > 0) return;
  for (int i = 0; i < CACHE_BLOCKS; i++) free(b->cache[i].data);
  close(b->fd);
  pthread_mutex_destroy(&b->lock);
  free(b);
}

/* Fetch one cache block; caller holds the lock. */
static cblock_t *cache_get(bdev_t *b, uint64_t blkno) {
  cblock_t *victim = &b->cache[0];
  for (int i = 0; i < CACHE_BLOCKS; i++) {
    cblock_t *c = &b->cache[i];
    if (c->valid && c->blkno == blkno) {
      c->stamp = ++b->clock;
      return c;
    }
    if (!c->valid || c->stamp < victim->stamp) victim = c;
  }
  if (!victim->data && !(victim->data = malloc(CACHE_BLOCK))) return NULL;

  uint64_t off = blkno * CACHE_BLOCK;
  size_t len = CACHE_BLOCK;
  if (off + len > b->size) {
    /* Short final block: round up to a whole sector. */
    len = (size_t)(b->size - off);
    len = (len + b->sector - 1) & ~(size_t)(b->sector - 1);
    memset(victim->data, 0, CACHE_BLOCK);
  }
  victim->valid = 0;
  if (read_full(b->fd, off, victim->data, len) != 0) return NULL;
  victim->valid = 1;
  victim->blkno = blkno;
  victim->stamp = ++b->clock;
  return victim;
}

int bdev_read(bdev_t *b, uint64_t off, void *buf, size_t len) {
  if (off > b->size || len > b->size - off) return -1;
  if (!len) return 0;

  bdev_t *root = b;
  if (b->parent) {
    root = b->parent;
    off += b->base;
  }

  uint8_t *out = buf;
  uint32_t ss = root->sector;

  /* Large, aligned reads go straight to the device. */
  if (len >= DIRECT_MIN && !(off % ss) && !(len % ss)) {
    return read_full(root->fd, off, out, len);
  }

  pthread_mutex_lock(&root->lock);
  while (len) {
    uint64_t blkno = off / CACHE_BLOCK;
    size_t inblk = (size_t)(off % CACHE_BLOCK);
    size_t n = CACHE_BLOCK - inblk;
    if (n > len) n = len;
    cblock_t *c = cache_get(root, blkno);
    if (!c) {
      pthread_mutex_unlock(&root->lock);
      return -1;
    }
    memcpy(out, c->data + inblk, n);
    out += n; off += n; len -= n;
  }
  pthread_mutex_unlock(&root->lock);
  return 0;
}

static int write_full(int fd, uint64_t off, const void *buf, size_t len) {
  const uint8_t *p = buf;
  while (len) {
    ssize_t n = pwrite(fd, p, len, (off_t)off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (n == 0) return -1;
    p += n; off += (uint64_t)n; len -= (size_t)n;
  }
  return 0;
}

int bdev_enable_write(bdev_t *b) {
  bdev_t *root = b->parent ? b->parent : b;
  pthread_mutex_lock(&root->lock);
  int rc = 0;
  if (!root->writable) {
    int fd = open(root->path, O_RDWR);
    if (fd < 0) {
      rc = -errno;
    } else {
      /* dup2 swaps the descriptor atomically, so reads running in other
       * threads keep working. */
      if (dup2(fd, root->fd) < 0) rc = -errno;
      else root->writable = 1;
      close(fd);
    }
  }
  pthread_mutex_unlock(&root->lock);
  return rc;
}

int bdev_is_writable(const bdev_t *b) {
  const bdev_t *root = b->parent ? b->parent : b;
  return root->writable;
}

/* Copy freshly written bytes into any cached blocks they overlap. */
static void cache_update(bdev_t *root, uint64_t off, const uint8_t *data, size_t len) {
  for (int i = 0; i < CACHE_BLOCKS; i++) {
    cblock_t *c = &root->cache[i];
    if (!c->valid) continue;
    uint64_t bs = c->blkno * CACHE_BLOCK, be = bs + CACHE_BLOCK;
    uint64_t s = off > bs ? off : bs, e = off + len < be ? off + len : be;
    if (s < e) memcpy(c->data + (s - bs), data + (s - off), (size_t)(e - s));
  }
}

int bdev_write(bdev_t *b, uint64_t off, const void *buf, size_t len) {
  if (off > b->size || len > b->size - off) return -1;
  if (!len) return 0;
  bdev_t *root = b;
  if (b->parent) {
    root = b->parent;
    off += b->base;
  }
  if (!root->writable) return -1;

  int rc = 0;
  uint32_t ss = root->sector;
  pthread_mutex_lock(&root->lock);
  if (!(off % ss) && !(len % ss)) {
    rc = write_full(root->fd, off, buf, len);
    if (!rc) cache_update(root, off, buf, len);
  } else {
    uint64_t a0 = off / ss * ss, a1 = (off + len + ss - 1) / ss * ss;
    size_t span = (size_t)(a1 - a0);
    uint8_t *tmp = malloc(span);
    if (!tmp) rc = -1;
    if (!rc) rc = read_full(root->fd, a0, tmp, span);
    if (!rc) {
      memcpy(tmp + (off - a0), buf, len);
      rc = write_full(root->fd, a0, tmp, span);
    }
    if (!rc) cache_update(root, a0, tmp, span);
    free(tmp);
  }
  pthread_mutex_unlock(&root->lock);
  return rc;
}

int bdev_flush(bdev_t *b) {
  bdev_t *root = b->parent ? b->parent : b;
  if (!root->writable) return 0;
  return fsync(root->fd) ? -1 : 0;
}

uint64_t bdev_size(const bdev_t *b) { return b->size; }
uint32_t bdev_sector_size(const bdev_t *b) { return b->sector; }
const char *bdev_path(const bdev_t *b) { return b->path; }
