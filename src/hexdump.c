#include "hexdump.h"
#include "utils.h"

void print_hexdump(Byte* dump, size_t num_bytes) {

  for (uint32_t i = 0; i < num_bytes; i++) {
    if (i && !(i % 16))
      printf("\n");

    printf("%02hhX", dump[i]);

    if (i && !((i-1) % 2))
      printf(" ");
  }

  printf("\n");
}

Byte* hexdump(uint64_t off, uint32_t len, char* filepath) {
  size_t size;
  size_t num_bytes;
  int    fd;

  fd = open(filepath, O_RDONLY, S_IRUSR | S_IRGRP);
  if (fd == -1) {
    perror(filepath);
    return NULL;
  }

  size = lseek(fd, 0, SEEK_END);
  if (size < off+len) {
    printf("The file: \'%s\' does not contain enough bytes for the key to be "
           "at the file offset: 0x%02lX\n", filepath, off);
    close(fd);
    return NULL;
  }

  num_bytes  = len * sizeof(Byte);
  Byte* dump = (Byte*)malloc(num_bytes);
  CHECK(dump, NULL, "Memory allocation failed.")

  lseek(fd, off, SEEK_SET);

  size = read(fd, dump, num_bytes);
  if (size != len) {
    fprintf(stderr, "Failed reading the key from the file: %s: %s\n", filepath, strerror(errno));
    FREE(dump);
    close(fd);
    return NULL;
  }

  close(fd);

  return dump;
}
