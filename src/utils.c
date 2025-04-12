#include "utils.h"

Crypto* get_file_content(char* filepath) {
  FILE*   file;
  long    file_size;
  Byte*   buffer;
  Crypto* encrypted;
  size_t  ret;

  encrypted = (Crypto*)malloc(1*sizeof(Crypto));
  CHECK(encrypted, NULL, "Memory allocation failed.");

  file = fopen(filepath, "rb");
  CHECK(file, encrypted, filepath);

  fseek(file, 0, SEEK_END);
  file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  buffer = (Byte *)malloc((file_size)*sizeof(Byte));
  CHECK_CLOSE(buffer, encrypted, file, "Memory allocation failed");

  ret = fread(buffer, 1, file_size, file);
  if (ret != (size_t)file_size) {
    fprintf(stderr, "Failed reading from file: %s: %s\n", filepath, strerror(errno));
    FREE(buffer);
    FREE(encrypted)
  }

  encrypted->data = buffer;
  encrypted->size = file_size;

  fclose(file);
  return encrypted;
}

size_t write_buffer_to_file(const char* filename, const void* buffer, size_t size) {
  FILE* file = fopen(filename, "wb");
  CHECK2(file, filename);

  size_t written = fwrite(buffer, 1, size, file);
  fclose(file);

  return written;
}

int is_hex(char* str) {
  if (!strlen(str))
    return 0;

  if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
    str += 2;

  while (*str) {
    if (!isxdigit((unsigned char)*str))
      return 0;
    str++;
  }

  return 1;
}

long to_hex(char* str) {
  char* endptr;
  long  hex;

  errno = 0;
  hex   = strtol(str, &endptr, 16);

  if (*endptr != '\0' || errno)
    fprintf(stderr, "Failed converting: %s to a hexadecimal: %s\n", str, strerror(errno));

  return hex;
}
