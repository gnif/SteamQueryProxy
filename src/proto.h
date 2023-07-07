#ifndef _H_PROTO_
#define _H_PROTO_

#include <stdint.h>
#include <stdbool.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#define HEADER_SINGLE 0xFFFFFFFF
#define HEADER_MULTI  0xFFFFFFFE

#define S2C_CHALLENGE                0x41
#define A2S_PLAYER_REPLY             0x44
#define A2S_RULES_REPLY              0x45
#define A2S_INFO_REPLY               0x49
#define A2S_INFO                     0x54
#define A2S_PLAYER                   0x55
#define A2S_RULES                    0x56
#define A2A_PING                     0x69
#define A2A_PING_REPLY               0x6A
#define A2S_SERVERQUERY_GETCHALLENGE 0x57

#define GS_INFO       0x6D //psuedo entry
#define GS_INFO_REPLY 0x6D

typedef struct __attribute__((packed))
{
  uint32_t header;
  uint32_t id;
  uint8_t ttl: 4;
  uint8_t num: 4;
  uint8_t payload[0];
}
GoldSourceHeader;

typedef struct __attribute__((packed))
{
  uint32_t header;
  uint32_t id        : 31;
  bool     compressed: 1 ;
  uint8_t  ttl;
  uint8_t  num;
  uint16_t size;
  uint8_t  payload[0];
}
SourceHeader;

typedef struct __attribute__((packed))
{
  uint32_t header;
  uint8_t  query;
  uint32_t answer;
}
QueryMsg;

typedef struct __attribute__((packed))
{
  uint32_t header;
  uint8_t  query;
  uint8_t  data[15];
}
QueryPing;

typedef struct __attribute__((packed))
{
  struct iphdr  ip;
  struct udphdr udp;
  uint8_t       payload[0];
}
UDPHeader;

#endif
