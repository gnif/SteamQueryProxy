#ifndef _H_CLIENT_
#define _H_CLIENT_

#include <stdint.h>
#include <stdbool.h>
#include "locking.h"

typedef struct
{
  Lock      lock;
  uint8_t * data;
  int       size;
  int       packetSize;
  bool      compressed;
  bool      release;
}
Payload;

void client_start(
    const char * ip,
    unsigned int queryPort,
    bool goldSource,
    bool threaded);

bool client_isReady(void);
void client_stop(void);

const Payload * client_getPayload(int id);
void client_releasePayload(const Payload * p);

#endif
