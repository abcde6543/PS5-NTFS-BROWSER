/* Partition table discovery (MBR, extended/logical MBR, GPT). */
#pragma once

#include <stdint.h>
#include "bdev.h"

#define PART_MAX 32

typedef struct part {
  uint64_t offset;  /* bytes from start of disk */
  uint64_t size;    /* bytes */
  int      index;   /* 1-based partition number */
  char     scheme[8]; /* "mbr", "gpt" or "none" */
} part_t;

/* Fill parts[] with the partitions found on b. If there is no partition table
 * the whole device is returned as a single entry. Returns the count. */
int part_scan(bdev_t *b, part_t *parts, int max);

/* Quick check for an NTFS boot sector at the start of b. */
int part_is_ntfs(bdev_t *b);
