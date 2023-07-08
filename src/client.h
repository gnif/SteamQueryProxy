#ifndef _H_CLIENT_
#define _H_CLIENT_

#include <stdint.h>
#include <stdbool.h>
#include "locking.h"

typedef struct
{
  RWLock    lock;
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

typedef enum
{
  PT_A2S_INFO,
  PT_GS_INFO,
  PT_A2S_PLAYER,
  PT_A2S_RULES,

  PT_MAX
}
PayloadType;

const Payload * client_getPayload(PayloadType type);
void client_releasePayload(const Payload * p);

#endif
