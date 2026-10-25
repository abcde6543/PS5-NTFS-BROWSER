/* Block device access with sector alignment and a small LRU read cache.
 *
 * Raw disk devices on FreeBSD (and therefore the PS5) only accept reads whose
 * offset and length are multiples of the sector size. Everything above this
 * layer can read at any byte offset and length. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

typedef struct bdev bdev_t;

/* Open a device node or an image file read-only. Returns NULL on error. */
bdev_t *bdev_open(const char *path);

/* A view of part of another device (a partition). Holds a reference to the
 * parent; closing the view drops it. */
bdev_t *bdev_slice(bdev_t *parent, uint64_t offset, uint64_t size);

void bdev_close(bdev_t *b);

/* Read len bytes at off. Returns 0 on success, -1 on error or past the end. */
int bdev_read(bdev_t *b, uint64_t off, void *buf, size_t len);

uint64_t    bdev_size(const bdev_t *b);
uint32_t    bdev_sector_size(const bdev_t *b);
const char *bdev_path(const bdev_t *b);
