#ifndef HEXDUMP_H
#define HEXDUMP_H

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "types.h"

Byte* hexdump(uint64_t off, uint32_t len, char* filepath);
void  print_hexdump(Byte* dump, size_t num_bytes);

#endif
