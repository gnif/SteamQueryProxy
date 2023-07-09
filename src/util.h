#ifndef _H_UTIL_
#define _H_UTIL_

#include <stdbool.h>
#include <stdint.h>

int msleep(long msec);
unsigned short csum(unsigned short *ptr, int nbytes);

bool isInvalidIPv4(uint32_t ip, bool private);
uint32_t jenkinsHash(uint32_t value1, uint32_t value2);

static inline int min(int a, int b) { return a < b ? a : b; }

#endif
