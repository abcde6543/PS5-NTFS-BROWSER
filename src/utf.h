/* UTF-16LE <-> UTF-8 conversion. Invalid input becomes U+FFFD. */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Convert nchars UTF-16LE code units (unaligned bytes) to a malloc'd,
 * NUL-terminated UTF-8 string. Returns NULL only when out of memory. */
char *utf16le_to_utf8(const uint8_t *src, size_t nchars);

/* Convert UTF-8 to UTF-16 code units. Returns the unit count, or -1 if the
 * result does not fit in max units. */
int utf8_to_utf16(const char *src, uint16_t *out, int max);

/* Length of the next valid UTF-8 sequence at s (1-4), or 0 if invalid. */
int utf8_seq_len(const unsigned char *s, size_t avail);
