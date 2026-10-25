/* bin2c <input> <output.h> <symbol>: embed a file as a C byte array. */
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: bin2c <input> <output.h> <symbol>\n");
    return 2;
  }
  FILE *in = fopen(argv[1], "rb"), *out = fopen(argv[2], "w");
  if (!in || !out) {
    perror("bin2c");
    return 1;
  }
  fprintf(out, "/* Generated from %s. Do not edit. */\n#pragma once\n", argv[1]);
  fprintf(out, "static const unsigned char %s[] = {", argv[3]);
  unsigned long n = 0;
  int c;
  while ((c = fgetc(in)) != EOF) {
    fprintf(out, "%s0x%02x,", n % 16 ? "" : "\n  ", c);
    n++;
  }
  fprintf(out, "\n};\nstatic const unsigned long %s_len = %lu;\n", argv[3], n);
  fclose(in);
  return fclose(out) ? 1 : 0;
}
