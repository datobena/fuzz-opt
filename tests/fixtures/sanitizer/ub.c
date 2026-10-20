#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

__attribute__((noinline)) int add_lengths(int a, int b) {
  return a + b; /* signed overflow */
}

__attribute__((noinline)) int heap_read(const char *s, size_t n) {
  char *buf = malloc(4);
  memcpy(buf, s, 4);
  int r = buf[n]; /* heap overflow when n >= 4 */
  free(buf);
  return r;
}

int main(int argc, char **argv) {
  if (argc < 2) return 0;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 0;
  char d[16] = {0};
  size_t n = fread(d, 1, sizeof d, f);
  fclose(f);
  if (n && d[0] == 'U') {
    int x = INT_MAX - 1;
    printf("%d\n", add_lengths(x, (int)n));
  } else if (n && d[0] == 'A') {
    printf("%d\n", heap_read(d, (size_t)n + 8));
  }
  return 0;
}
