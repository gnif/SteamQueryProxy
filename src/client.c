#include "client.h"
#include "proto.h"
#include "util.h"
#include "challenge.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <netinet/in.h>

Payload a2sInfo   = { 0 };
Payload gsInfo    = { 0 };
Payload a2sPlayer = { 0 };
Payload a2sRules  = { 0 };

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

inline static void assignPayload(Payload * dst, Payload * src)
{
  LOCK(dst->lock);

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

  UNLOCK(dst->lock);
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

  enum Stage stage      = STAGE_INFO;
  bool       haveAnswer = false;
  uint32_t   answer     = -1;
  for(;;)
  {
    switch(stage)
    {
      case STAGE_INFO:
      {
        challenge_new();
        uint8_t buffer[25 + (haveAnswer ? 4 : 0)];
        uint32_t * header  = (uint32_t *)buffer;
        uint8_t  * query   = (uint8_t  *)(header + 1);
        char     * payload = (char     *)(query  + 1);

        if (haveAnswer)
        {
          void * challenge = (void *)(payload + 20);
          memcpy(challenge, &answer, sizeof(answer));
        }

        *header = 0xFFFFFFFF;
        *query  = A2S_INFO;
        memcpy(payload, "Source Engine Query\0", 20);
        sendto(g_sock, buffer, sizeof(buffer), 0,
            (struct sockaddr *)&g_sin, sizeof(g_sin));
        break;
      }

      case STAGE_PLAYER:
      {
        // request the player info
        QueryMsg m = {
          .header = HEADER_SINGLE,
          .query  = A2S_PLAYER,
          .answer = answer
        };

        sendto(g_sock, &m, sizeof(m), 0,
            (struct sockaddr *)&g_sin, sizeof(g_sin));
        break;
      }

      case STAGE_RULES:
      {
        // request the rules
        QueryMsg m = {
          .header = HEADER_SINGLE,
          .query  = A2S_RULES,
          .answer = answer
        };

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
    Payload p = {0};
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
        void * challenge = (void *)(query + 1);
        memcpy(&answer, challenge, sizeof(answer));
        haveAnswer = true;
        printf("Got S2C_CHALLENGE: 0x%08x\n", answer);
        freePayload(&p);
        break;
      }

      case A2S_INFO_REPLY:
        printf("Got A2S_INFO_REPLY: %d bytes\n", p.size);
        assignPayload(&a2sInfo, &p);
        stage = STAGE_PLAYER;
        break;

      case GS_INFO_REPLY:
        printf("Got GS_INFO_REPLY: %d bytes\n", p.size);
        if (!g_goldSource)
        {
          fprintf(stderr, "ERROR: Server is GoldSource\n");
          exit(1);
        }

        assignPayload(&gsInfo, &p);
        goto read;

      case A2S_PLAYER_REPLY:
        printf("Got A2S_PLAYER_REPLY: %d bytes\n", p.size);
        assignPayload(&a2sPlayer, &p);
        stage = STAGE_RULES;
        break;

      case A2S_RULES_REPLY:
        printf("Got A2S_RULES_REPLY: %d bytes\n", p.size);
        assignPayload(&a2sRules, &p);
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

  if (threaded)
    pthread_create(&qt, NULL, clientThread, NULL);
  else
    clientThread(NULL);
}

bool client_isReady()
{
  // should we wait for a GS_INFO packet too?
  return a2sInfo.size && a2sPlayer.size && a2sRules.size;
}

void client_stop()
{
  pthread_join(qt, NULL);
}

const Payload * client_getPayload(int id)
{
  Payload * p;
  switch(id)
  {
    case A2S_INFO  : p = &a2sInfo  ; break;
    case GS_INFO   : p = &gsInfo   ; break;
    case A2S_PLAYER: p = &a2sPlayer; break;
    case A2S_RULES : p = &a2sRules ; break;
    default:
      return NULL;
  }

  if (!p->data)
    return NULL;

  LOCK(p->lock);
  return p;
}

void client_releasePayload(const Payload * p)
{
  // cast away const so we can unlock it
  Payload * pp = (Payload *)p;
  UNLOCK(pp->lock);
}
