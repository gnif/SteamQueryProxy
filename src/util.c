#include "util.h"

#include <time.h>
#include <errno.h>
#include <stdint.h>

int msleep(long msec)
{
  struct timespec ts;
  int res;

  if (msec < 0)
  {
    errno = EINVAL;
    return -1;
  }

  ts.tv_sec = msec / 1000;
  ts.tv_nsec = (msec % 1000) * 1000000;

  do {
    res = nanosleep(&ts, &ts);
  } while (res && errno == EINTR);

  return res;
}

unsigned short csum(unsigned short *ptr, int nbytes)
{
  register long  sum;
  unsigned short oddbyte;

  sum = 0;
  while(nbytes > 1)
  {
    sum    += *ptr++;
    nbytes -= 2;
  }

  if(nbytes == 1)
  {
    oddbyte                = 0;
    *((uint8_t *)&oddbyte) = *(uint8_t *)ptr;
    sum                   += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  return (short)~sum;
}

typedef struct
{
  uint32_t start;
  uint32_t end;
}
IPv4Range;

static const IPv4Range reservedRanges[] =
{
  // Broadcast (0.0.0.0/24)
  {0x00000000, 0x000000FF},

  // Lookback  (127.0.0.0/8)
  {0x7F000000, 0x7FFFFFFF},

  // Link-Local (169.254.0.0 - 169.254.255.255)
  {0xA9FE0000, 0xA9FEFFFF},

  // Multicast (224.0.0.0 - 239.255.255.255)
  {0xE0000000, 0xEFFFFFFF},

  // Reserved (240.0.0.0 - 255.255.255.255)
  {0xF0000000, 0xFFFFFFFF}
};

static const IPv4Range privateRanges[] =
{
  // Private Networks (172.16.0.0/16, 192.168.0.0/16, 10.0.0.0/8)
  {0xAC100000, 0xAC1FFFFF},
  {0xC0A80000, 0xC0A8FFFF},
  {0x0A000000, 0x0AFFFFFF}
};

bool isInvalidIPv4(uint32_t ip, bool private)
{
  // IPs ending in 0 or 255
  if ((ip & 0xFF) == 0x00 || (ip & 0xFF) == 0xFF)
    return true;

  // check for IPs in the reserved ranges
  for (int i = 0; i < sizeof(reservedRanges) / sizeof(reservedRanges[0]); i++)
    if (ip >= reservedRanges[i].start && ip <= reservedRanges[i].end)
      return true;

  if (private)
  {
    // check for IPs in the private ranges
    for (int i = 0; i < sizeof(privateRanges) / sizeof(privateRanges[0]); i++)
      if (ip >= privateRanges[i].start && ip <= privateRanges[i].end)
        return true;
  }

  return false;
}

uint32_t jenkinsHash(uint32_t value)
{
  value = (value + 0x7ed55d16) + (value << 12);
  value = (value ^ 0xc761c23c) ^ (value >> 19);
  value = (value + 0x165667b1) + (value << 5);
  value = (value + 0xd3a2646c) ^ (value << 9);
  value = (value + 0xfd7046c5) + (value << 3);
  value = (value ^ 0xb55a4f09) ^ (value >> 16);
  return value;
}
