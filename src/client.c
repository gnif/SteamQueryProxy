#include "client.h"
#include "proto.h"
#include "util.h"
#include "challenge.h"
#include "global.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <netinet/in.h>

static Payload g_cache[PT_MAX] = {0};

static int g_sock;
static struct sockaddr_in g_sin;
static bool g_goldSource;

static bool getPayload(Payload * p)
{
  int len;
  static uint8_t data[65535];
  socklen_t slen = sizeof(g_sin);
  if ((len = recvfrom(g_sock, data, sizeof(data), 0,
      (struct sockaddr *)&g_sin, &slen)) == -1)
  {
    perror("recvfrom");
    return false;
  }

  uint32_t * header = (uint32_t *)data;
  if (*header == HEADER_SINGLE)
  {
    p->data       = data;
    p->size       = len;
    p->packetSize = 0;
    p->compressed = false;
    p->release    = false;
    return true;
  }

  if (g_goldSource)
  {
    GoldSourceHeader * h = (GoldSourceHeader *)data;
    uint32_t id      = h->id;
    uint8_t  packets = h->ttl;

    // goldsource packets are all 1400 bytes
    const int packetSize = 1400 - sizeof(*h);
    uint8_t * buffer = malloc(packets * packetSize);

    int copySize = min(packetSize, len - sizeof(*h));
    memcpy(buffer + h->num * packetSize, data + sizeof(*h), copySize);
    p->size = copySize;

    for(int i = 0; i < packets - 1; ++i)
    {
      if ((len = recvfrom(g_sock, data, sizeof(data), 0,
          (struct sockaddr *)&g_sin, &slen)) == -1)
      {
        perror("recvfrom GS");
        free(buffer);
        return false;
      }

      if (h->header != HEADER_MULTI)
      {
        fprintf(stderr, "S Invalid Header\n");
        free(buffer);
        return false;
      }

      if (h->id != id)
      {
        fprintf(stderr, "S Unexpected Packet ID\n");
        free(buffer);
        return false;
      }

      if (h->num >= packets)
      {
        fprintf(stderr, "S Invalid Packet Number\n");
        free(buffer);
        return false;
      }

      int copySize = min(packetSize, len - sizeof(*h));
      memcpy(buffer + h->num * packetSize, data + sizeof(*h), copySize);
      p->size += copySize;
    }

    p->data       = buffer;
    p->packetSize = packetSize;
    p->compressed = false;
    p->release    = true;
  }
  else
  {
    //Source Server
    SourceHeader * h = (SourceHeader *)data;
    uint32_t id         = h->id;
    uint8_t  packets    = h->ttl;
    uint16_t packetSize = h->size;

    uint8_t * buffer = malloc(packets * packetSize);
    int copySize = min(packetSize, len - sizeof(*h));
    memcpy(buffer + h->num * packetSize, data + sizeof(*h), copySize);
    p->size = copySize;

    for(int i = 0; i < packets - 1; ++i)
    {
      if ((len = recvfrom(g_sock, data, sizeof(data), 0,
          (struct sockaddr *)&g_sin, &slen)) == -1)
      {
        perror("recvfrom S");
        free(buffer);
        return false;
      }

      if (h->header != HEADER_MULTI)
      {
        fprintf(stderr, "S Invalid Header\n");
        free(buffer);
        return false;
      }

      if (h->id != id)
      {
        fprintf(stderr, "S Unexpected Packet ID\n");
        free(buffer);
        return false;
      }

      if (h->num >= packets)
      {
        fprintf(stderr, "S Invalid Packet Number\n");
        free(buffer);
        return false;
      }

      int copySize = min(packetSize, len - sizeof(*h));
      memcpy(buffer + h->num * packetSize, data + sizeof(*h), copySize);
      p->size += copySize;
    }

    p->data       = buffer;
    p->packetSize = packetSize;
    p->compressed = (id & 0x80) != 0;
    p->release    = true;
  }

  return true;
}

inline static void freePayload(Payload * p)
{
  if (!p->release)
    return;
  p->release = false;
  free(p->data);
  p->data = NULL;
}

inline static void assignPayload(PayloadType type, Payload * src)
{
  Payload * dst = &g_cache[type];
  rwlock_writeLock(&dst->lock);

  freePayload(dst);

  if (src->release)
  {
    dst->data    = src->data;
    src->release = false;
  }
  else
  {
    dst->data = malloc(src->size);
    memcpy(dst->data, src->data, src->size);
  }

  dst->size       = src->size;
  dst->packetSize = src->packetSize;
  dst->compressed = src->compressed;
  dst->release    = true;

  rwlock_writeUnlock(&dst->lock);
}

static void * clientThread(void * opaque)
{
  enum Stage
  {
    STAGE_INFO,
    STAGE_PLAYER,
    STAGE_RULES,
    STAGE_SLEEP
  };

  g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  struct timeval tv =
  {
    .tv_sec  = 1,
    .tv_usec = 0
  };
  setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  enum Stage stage     = STAGE_INFO;
  uint32_t   challenge = 0xFFFFFFFF;
  Payload    p         = {0};

  for(;;)
  {
    switch(stage)
    {
      case STAGE_INFO:
      {
        challenge_new();
        static QueryInfoMsg m =
        {
          .header    = HEADER_SINGLE,
          .query     = A2S_INFO,
          .payload   = "Source Engine Query"
        };

        m.challenge = challenge;
        sendto(g_sock, &m,
            challenge != 0xFFFFFFFF ? sizeof(m) : sizeof(m) - 4,
            0, (struct sockaddr *)&g_sin, sizeof(g_sin));
        break;
      }

      case STAGE_PLAYER:
      {
        // request the player info
        static QueryMsg m = {
          .header    = HEADER_SINGLE,
          .query     = A2S_PLAYER,
        };

        m.challenge = challenge;
        sendto(g_sock, &m, sizeof(m), 0,
            (struct sockaddr *)&g_sin, sizeof(g_sin));
        break;
      }

      case STAGE_RULES:
      {
        // request the rules
        static QueryMsg m = {
          .header    = HEADER_SINGLE,
          .query     = A2S_RULES,
        };

        m.challenge = challenge;
        sendto(g_sock, &m, sizeof(m), 0,
            (struct sockaddr *)&g_sin, sizeof(g_sin));
        break;
      }

      case STAGE_SLEEP:
        msleep(1000 * 10);
        stage = STAGE_INFO;
        continue;
    }

read:
    if (!getPayload(&p))
    {
      stage = STAGE_SLEEP;
      continue;
    }

    uint8_t * query;

    // some engines have a secondary header when the packet was split
    if (*(uint32_t *)p.data == HEADER_SINGLE)
      query = p.data + 4;
    else
      query = p.data;

    switch(*query)
    {
      case S2C_CHALLENGE:
      {
        challenge = *(uint32_t *)(query + 1);
        if (!g_quiet)
          printf("Got S2C_CHALLENGE: 0x%08x\n", challenge);
        freePayload(&p);
        break;
      }

      case A2S_INFO_REPLY:
        if (!g_quiet)
          printf("Got A2S_INFO_REPLY: %d bytes\n", p.size);
        assignPayload(PT_A2S_INFO, &p);
        stage = STAGE_PLAYER;
        break;

      case GS_INFO_REPLY:
        if (!g_quiet)
          printf("Got GS_INFO_REPLY: %d bytes\n", p.size);
        if (!g_goldSource)
        {
          fprintf(stderr, "ERROR: Server is GoldSource\n");
          exit(1);
        }

        assignPayload(PT_GS_INFO, &p);
        goto read;

      case A2S_PLAYER_REPLY:
        if (!g_quiet)
          printf("Got A2S_PLAYER_REPLY: %d bytes\n", p.size);
        assignPayload(PT_A2S_PLAYER, &p);
        stage = STAGE_RULES;
        break;

      case A2S_RULES_REPLY:
        if (!g_quiet)
          printf("Got A2S_RULES_REPLY: %d bytes\n", p.size);
        assignPayload(PT_A2S_RULES, &p);
        stage = STAGE_SLEEP;
        break;

      default:
        freePayload(&p);
        goto read;
    }
  }

  close(g_sock);
  return NULL;
}

static pthread_t qt;
void client_start(const char * ip, unsigned int queryPort, bool goldSource,
    bool threaded)
{
  g_sin.sin_family = AF_INET;
  inet_pton(AF_INET, ip, &(g_sin.sin_addr));
  g_sin.sin_port = htons(queryPort);
  g_goldSource = goldSource;

  for(int i = 0; i < PT_MAX; ++i)
    rwlock_init(&g_cache[i].lock);

  if (!g_quiet)
    printf("Upstream: %s:%d (Protocol: %sSource)\n",
        ip,
        queryPort,
        goldSource ? "Gold" : "");

  if (threaded)
    pthread_create(&qt, NULL, clientThread, NULL);
  else
    clientThread(NULL);
}

bool client_isReady()
{
  // should we wait for a GS_INFO packet too?
  return
    g_cache[PT_A2S_INFO  ].size &&
    g_cache[PT_A2S_PLAYER].size &&
    g_cache[PT_A2S_RULES ].size;
}

void client_stop()
{
  pthread_join(qt, NULL);
}

const Payload * client_getPayload(PayloadType type)
{
  if (type < 0 || type > PT_MAX)
    return NULL;

  Payload * p = &g_cache[type];
  rwlock_readLock(&p->lock);
  if (!p->data)
  {
    rwlock_readUnlock(&p->lock);
    return NULL;
  }

  return p;
}

void client_releasePayload(const Payload * p)
{
  // cast away const so we can unlock it
  Payload * pp = (Payload *)p;
  rwlock_readUnlock(&pp->lock);
}
