#include "utf.h"

#include <stdlib.h>

static size_t put_utf8(char *o, uint32_t cp) {
  if (cp < 0x80) { o[0] = (char)cp; return 1; }
  if (cp < 0x800) {
    o[0] = (char)(0xC0 | cp >> 6);
    o[1] = (char)(0x80 | (cp & 0x3F));
    return 2;
  }
  if (cp < 0x10000) {
    o[0] = (char)(0xE0 | cp >> 12);
    o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    o[2] = (char)(0x80 | (cp & 0x3F));
    return 3;
  }
  o[0] = (char)(0xF0 | cp >> 18);
  o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
  o[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
  o[3] = (char)(0x80 | (cp & 0x3F));
  return 4;
}

char *utf16le_to_utf8(const uint8_t *src, size_t n) {
  char *out = malloc(n * 3 + 1); /* a surrogate pair (2 units) -> 4 bytes */
  if (!out) return NULL;
  size_t o = 0;
  for (size_t i = 0; i < n; i++) {
    uint32_t c = (uint32_t)(src[i * 2] | src[i * 2 + 1] << 8);
    if (c >= 0xD800 && c <= 0xDBFF && i + 1 < n) {
      uint32_t d = (uint32_t)(src[i * 2 + 2] | src[i * 2 + 3] << 8);
      if (d >= 0xDC00 && d <= 0xDFFF) {
        c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00);
        i++;
      } else {
        c = 0xFFFD;
      }
    } else if (c >= 0xD800 && c <= 0xDFFF) {
      c = 0xFFFD;
    }
    o += put_utf8(out + o, c);
  }
  out[o] = 0;
  return out;
}

int utf8_seq_len(const unsigned char *s, size_t avail) {
  unsigned char c = s[0];
  if (c < 0x80) return 1;
  int n;
  uint32_t cp;
  if ((c & 0xE0) == 0xC0) { n = 2; cp = c & 0x1F; }
  else if ((c & 0xF0) == 0xE0) { n = 3; cp = c & 0x0F; }
  else if ((c & 0xF8) == 0xF0) { n = 4; cp = c & 0x07; }
  else return 0;
  if ((size_t)n > avail) return 0;
  for (int i = 1; i < n; i++) {
    if ((s[i] & 0xC0) != 0x80) return 0;
    cp = cp << 6 | (s[i] & 0x3F);
  }
  if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) ||
      (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
      (cp >= 0xD800 && cp <= 0xDFFF))
    return 0;
  return n;
}

int utf8_to_utf16(const char *src, uint16_t *out, int max) {
  const unsigned char *s = (const unsigned char *)src;
  size_t avail = 0;
  while (s[avail]) avail++;
  int o = 0;
  while (*s) {
    int n = utf8_seq_len(s, avail);
    uint32_t cp;
    if (!n) { cp = 0xFFFD; n = 1; }
    else if (n == 1) cp = s[0];
    else if (n == 2) cp = (uint32_t)(s[0] & 0x1F) << 6 | (s[1] & 0x3F);
    else if (n == 3)
      cp = (uint32_t)(s[0] & 0x0F) << 12 | (uint32_t)(s[1] & 0x3F) << 6 | (s[2] & 0x3F);
    else
      cp = (uint32_t)(s[0] & 0x07) << 18 | (uint32_t)(s[1] & 0x3F) << 12 |
           (uint32_t)(s[2] & 0x3F) << 6 | (s[3] & 0x3F);
    s += n;
    avail -= (size_t)n;
    if (cp >= 0x10000) {
      if (o + 2 > max) return -1;
      cp -= 0x10000;
      out[o++] = (uint16_t)(0xD800 + (cp >> 10));
      out[o++] = (uint16_t)(0xDC00 + (cp & 0x3FF));
    } else {
      if (o + 1 > max) return -1;
      out[o++] = (uint16_t)cp;
    }
  }
  return o;
}
