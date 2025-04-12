#ifndef GTA4_CRYPTO_UTILS_H
#define GTA4_CRYPTO_UTILS_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include "types.h"

typedef struct {
  size_t size;
  Byte*  data;
} Crypto;

#define FREE(mem) if ((mem) != NULL) { free(mem); }
#define CHECK(ptr, mem, s) if ((ptr) == NULL) { perror((s)); FREE(mem); return NULL; }
#define CHECK2(ptr, s) if ((ptr) == NULL) { perror((s)); return 0; }
#define CHECK_CLOSE(ptr, mem, file, s) if ((ptr) == NULL) { perror(s); fclose(file); FREE(mem); return NULL; }

Crypto* get_file_content(char* filepath);
size_t  write_buffer_to_file(const char* filename, const void* buffer, size_t size);
int     is_hex(char* str);
long    to_hex(char* str);

#endif
