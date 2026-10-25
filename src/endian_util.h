/* Little-endian loads from unaligned byte buffers. */
#pragma once

#include <stdint.h>

static inline uint16_t le16(const void *p) {
  const uint8_t *b = p;
  return (uint16_t)(b[0] | b[1] << 8);
}

static inline uint32_t le32(const void *p) {
  const uint8_t *b = p;
  return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 |
         (uint32_t)b[3] << 24;
}

static inline uint64_t le64(const void *p) {
  const uint8_t *b = p;
  return (uint64_t)le32(b) | (uint64_t)le32(b + 4) << 32;
}

static inline void put_le16(void *p, uint16_t v) {
  uint8_t *b = p;
  b[0] = (uint8_t)v;
  b[1] = (uint8_t)(v >> 8);
}
