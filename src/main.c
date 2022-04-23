#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <limits.h>
#include <linux/types.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

static bool                g_verbose = true;
static int                 g_queryPort;
static struct mnl_socket * nl;
static int                 g_socket;

// retain 60s worth of challenges
static uint32_t  g_challenges[6]  = { 0 };
static int       g_challengeIndex = 0;
static const int g_nChallenges    = sizeof(g_challenges) / sizeof(*g_challenges);


atomic_flag dataLock;
#define LOCK(x) \
  while(atomic_flag_test_and_set_explicit(&(x), memory_order_acquire)) { ; }
#define UNLOCK(x) \
  atomic_flag_clear_explicit(&(x), memory_order_release);

typedef struct
{
  void         * data;
  unsigned int   len;
}
Cache;

Cache a2sInfo   = { 0 };
Cache a2sPlayer = { 0 };
Cache a2sRules  = { 0 };

#define S2C_CHALLENGE                0x41
#define A2S_PLAYER_REPLY             0x44
#define A2S_RULES_REPLY              0x45
#define A2S_INFO_REPLY               0x49
#define A2S_INFO                     0x54
#define A2S_PLAYER                   0x55
#define A2S_RULES                    0x56
#define A2A_PING                     0x69
#define A2S_SERVERQUERY_GETCHALLENGE 0x57

unsigned short csum(unsigned short *ptr,int nbytes)
{
  register long  sum;
  unsigned short oddbyte;

  sum = 0;
  while(nbytes>1)
  {
    sum    += *ptr++;
    nbytes -= 2;
  }

  if(nbytes == 1)
  {
    oddbyte               = 0;
    *((u_char *)&oddbyte) = *(u_char *)ptr;
    sum                  += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  return (short)~sum;
}

static char g_datagram[1400];
static void initDatagram(void)
{
  memset(g_datagram, 0, sizeof(g_datagram));
  struct iphdr  * iph = (struct iphdr *)g_datagram;
  struct udphdr * udp = (struct udphdr *)(iph + 1);

  iph->ihl      = 5;
  iph->version  = 4;
  iph->tos      = IPTOS_DSCP_EF;
  iph->frag_off = htons(IP_DF);
  iph->ttl      = 255;
  iph->protocol = IPPROTO_UDP;
  iph->check    = 0;
  udp->check    = 0;
}

/* NOTE: not thread safe due to the use of g_datagram */
static void sendPacket(
  uint32_t daddr, uint32_t saddr,
  uint16_t dport, uint16_t sport,
  void *   data , uint16_t len)
{
  struct iphdr  * iph = (struct iphdr *)g_datagram;
  struct udphdr * udp = (struct udphdr *)(iph + 1);
  char * payload = (char *)(udp + 1);

  static int id = 0;
  iph->id      = htonl(saddr ^ daddr ^ dport ^ sport ^ id++);
  iph->tot_len = sizeof(*iph) + sizeof(*udp) + len;
  iph->saddr   = saddr;
  iph->daddr   = daddr;
#if 0
  iph->check   = 0;
  iph->check   = csum((unsigned short *)g_datagram, sizeof(*iph));
#endif

  udp->source = sport;
  udp->dest   = dport;
  udp->len    = htons(8 + len);

  memcpy(payload, data, len);
#if 0
  {
    struct pseudo_header
    {
      u_int32_t source_address;
      u_int32_t dest_address;
      u_int8_t  placeholder;
      u_int8_t  protocol;
      u_int16_t udp_length;
    };

    char psuedogram[sizeof(struct pseudo_header) + sizeof(*udp) + len];
    struct pseudo_header * psh = (struct pseudo_header *)psuedogram;
    psh->source_address = saddr;
    psh->dest_address   = daddr;
    psh->placeholder    = 0;
    psh->protocol       = IPPROTO_UDP;
    psh->udp_length     = htons(sizeof(struct udphdr) + len);
    memcpy(psh + 1, udp, sizeof(*udp) + len);

    udp->check = csum((unsigned short *)psuedogram, sizeof(psuedogram));
  }
#endif

  struct sockaddr_in sin =
  {
    .sin_family      = AF_INET,
    .sin_port        = dport,
    .sin_addr.s_addr = daddr
  };

  sendto(g_socket, g_datagram, iph->tot_len, 0,
      (struct sockaddr *)&sin, sizeof(sin));
}

static void newChallenge(void)
{
  int next = g_challengeIndex - 1;
  if (next < 0)
    next = g_nChallenges - 1;

  do
  {
    uint32_t new = rand() % UINT32_MAX;
    if (new == 0 || new == 0xFFFFFFFF)
      continue;

    g_challenges[next] = new;
    g_challengeIndex   = next;
    return;
  }
  while(false);
}

static bool validateChallenge(uint32_t challenge, uint32_t mutate)
{
  if (challenge == 0 || challenge == 0xFFFFFFFF)
    return false;

  challenge ^= mutate;
  int index = g_challengeIndex;
  for(int i = 0; i < g_nChallenges; ++i)
  {
    if (g_challenges[index] == challenge)
      return true;

    if (++index == g_nChallenges)
      index = 0;
  }

  return false;
}

static void sendChallenge(struct iphdr * iph, struct udphdr * udp)
{
  char buffer[9];
  memcpy(buffer, "\xFF\xFF\xFF\xFF\x41", 5);
  void * challenge = (void *)(buffer + 5);

  const uint32_t ch = g_challenges[g_challengeIndex] ^
    (iph->saddr ^ udp->dest);
  memcpy(challenge, &ch, sizeof(ch));

  sendPacket(
    iph->saddr,
    iph->daddr,
    udp->source,
    udp->dest,
    buffer,
    sizeof(buffer));
}

static bool parse_payload(void * payload, uint16_t len)
{
  if (len < sizeof(struct iphdr) + sizeof(struct udphdr) || len > 57)
    return true;

  struct iphdr * iph = (struct iphdr *)payload;
  if (iph->protocol != IPPROTO_UDP)
    return true;

  struct udphdr * udp = (struct udphdr *)(iph + 1);
  payload = (void *)(udp + 1);

#if 0
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &iph->saddr, saddr, sizeof(saddr));
  inet_ntop(AF_INET, &iph->daddr, daddr, sizeof(daddr));
  printf("%s:%d -> %s:%d\n", saddr, ntohs(udp->source), daddr, ntohs(udp->dest));
#endif

  uint32_t * header = (uint32_t *)payload;
  if (*header != 0xFFFFFFFF)
    return true;

  uint32_t challenge;
  uint8_t * query = (uint8_t *)(header + 1);
  switch(*query)
  {
    case A2S_INFO:
    {
      char * data = (char *)(query + 1);
      if (memcmp(data, "Source Engine Query\0", 20) != 0)
        break;

      if (udp->len == 25)
      {
        sendChallenge(iph, udp);
        return false;
      }

      memcpy(&challenge, data + 20, sizeof(challenge));
      if (!validateChallenge(challenge, iph->saddr ^ udp->dest))
      {
        sendChallenge(iph, udp);
        return false;
      }

      LOCK(dataLock);
      sendPacket(
        iph->saddr,
        iph->daddr,
        udp->source,
        udp->dest,
        a2sInfo.data,
        a2sInfo.len);
      UNLOCK(dataLock);

      if (g_verbose)
        printf("A2S_INFO 0x%08x\n", challenge);

      return false;
    }

    case A2S_PLAYER:
    {
      if (udp->len == 9)
      {
        sendChallenge(iph, udp);
        return false;
      }

      memcpy(&challenge, query + 1, sizeof(challenge));
      if (!validateChallenge(challenge, iph->saddr ^ udp->dest))
      {
        sendChallenge(iph, udp);
        return false;
      }

      LOCK(dataLock);
      sendPacket(
        iph->saddr,
        iph->daddr,
        udp->source,
        udp->dest,
        a2sPlayer.data,
        a2sPlayer.len);
      UNLOCK(dataLock);

      if (g_verbose)
        printf("A2S_PLAYER 0x%08x\n", challenge);

      return false;
    }

    case A2S_RULES:
    {
      if (udp->len == 9)
      {
        sendChallenge(iph, udp);
        return false;
      }

      memcpy(&challenge, query + 1, sizeof(challenge));
      if (!validateChallenge(challenge, iph->saddr ^ udp->dest))
      {
        sendChallenge(iph, udp);
        return false;
      }

      LOCK(dataLock);
      sendPacket(
        iph->saddr,
        iph->daddr,
        udp->source,
        udp->dest,
        a2sRules.data,
        a2sRules.len);
      UNLOCK(dataLock);

      if (g_verbose)
        printf("A2S_RULES 0x%08x\n", challenge);

      return false;
    }

    // this is deprecated but implement it anyway for completeness
    case A2A_PING:
    {
      sendPacket(
        iph->saddr,
        iph->daddr,
        udp->source,
        udp->dest,
        "\xFF\xFF\xFF\xFF\x6A" "00000000000000\0",
        20);

      if (g_verbose)
        printf("A2A_PING\n");

      return false;
    }

    // this is deprecated but implement it anyway for completeness
    case A2S_SERVERQUERY_GETCHALLENGE:
    {
      sendChallenge(iph, udp);

      if (g_verbose)
        printf("A2S_SERVERQUERY_GETCHALLENGE\n");

      return false;
    }
  }

  return true;
}

static void nfq_send_verdict(int queue_num, uint32_t id, int verdict)
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr *nlh;

  nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
  nfq_nlmsg_verdict_put(nlh, id, verdict);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }
}

static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
  struct nlattr *attr[NFQA_MAX+1] = {};
  if (nfq_nlmsg_parse(nlh, attr) < 0)
  {
    perror("problems parsing");
    return MNL_CB_ERROR;
  }

  struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
  if (attr[NFQA_PACKET_HDR] == NULL)
  {
    fputs("metaheader not set\n", stderr);
    return MNL_CB_ERROR;
  }

  struct nfqnl_msg_packet_hdr * ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
  uint32_t id = ntohl(ph->packet_id);

  uint16_t plen    = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
  void *   payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
  int      verdict = parse_payload(payload, plen) ? NF_ACCEPT : NF_DROP;

  nfq_send_verdict(ntohs(nfg->res_id), id, verdict);
  return MNL_CB_OK;
}

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

static void * queryThread(void * opaque)
{
  struct sockaddr_in sin =
  {
    .sin_family      = AF_INET,
    .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    .sin_port        = htons(g_queryPort)
  };

  socklen_t slen = sizeof(sin);
  int       sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  struct timeval tv =
  {
    .tv_sec  = 1,
    .tv_usec = 0
  };
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  bool     haveAnswer = false;
  uint32_t answer     = 0;
  for(;;)
  {
    newChallenge();

    // initial query to get the challenge
    {
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
      sendto(sock, buffer, sizeof(buffer), 0,
          (struct sockaddr *)&sin, sizeof(sin));
    }

read:
    {
      uint8_t buffer[1400];
      int len;
      if ((len = recvfrom(sock, buffer, sizeof(buffer), 0,
          (struct sockaddr *)&sin, &slen)) == -1)
      {
        perror("recvfrom A2S_INFO");
        goto loop;
      }

      uint32_t * header  = (uint32_t *)buffer;
      uint8_t  * query   = (uint8_t  *)(header + 1);
      switch(*query)
      {
        case S2C_CHALLENGE:
        {
          void * challenge = (void *)(query + 1);
          memcpy(&answer, challenge, sizeof(answer));
          haveAnswer = true;
          printf("Got S2C_CHALLENGE:: 0x%08x\n", answer);
          continue;
        }

        case A2S_INFO_REPLY:
        {
          LOCK(dataLock);
          if (a2sInfo.data)
            free(a2sInfo.data);

          printf("Got A2S_INFO_REPLY: %d bytes\n", len);
          a2sInfo.data = malloc(len);
          a2sInfo.len  = len;
          memcpy(a2sInfo.data, buffer, len);
          UNLOCK(dataLock);

          // request the player info
          void * challenge = (void *)(query + 1);

          *header    = 0xFFFFFFFF;
          *query     = A2S_PLAYER;
          memcpy(challenge, &answer, sizeof(answer));

          sendto(sock, buffer, 9, 0,
              (struct sockaddr *)&sin, sizeof(sin));
          goto read;
        }

        case A2S_PLAYER_REPLY:
        {
          LOCK(dataLock);
          if (a2sPlayer.data)
            free(a2sPlayer.data);

          printf("Got A2S_PLAYER_REPLY: %d bytes\n", len);
          a2sPlayer.data = malloc(len);
          a2sPlayer.len  = len;
          memcpy(a2sPlayer.data, buffer, len);
          UNLOCK(dataLock);

          // request the rules
          void * challenge = (void *)(query + 1);

          *header    = 0xFFFFFFFF;
          *query     = A2S_RULES;
          memcpy(challenge, &answer, sizeof(answer));

          sendto(sock, buffer, 9, 0,
              (struct sockaddr *)&sin, sizeof(sin));
          goto read;
        }

        case A2S_RULES_REPLY:
        {
          LOCK(dataLock);
          if (a2sRules.data)
            free(a2sRules.data);

          printf("Got A2S_RULES_REPLY: %d bytes\n", len);
          a2sRules.data = malloc(len);
          a2sRules.len  = len;
          memcpy(a2sRules.data, buffer, len);
          UNLOCK(dataLock);
          break;
        }
      }
    }

loop:
    msleep(1000 * 10);
  }

  close(sock);
  return NULL;
}

int main(int argc, char *argv[])
{
  /* largest possible packet payload, plus netlink data overhead: */
  const size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
  char buf[sizeof_buf];
  memset(buf, 0, sizeof_buf);

  struct nlmsghdr *nlh;
  int ret;
  unsigned int portid, queue_num;

  if (argc != 3)
  {
    printf("Usage: %s [queue_num] [query_port]\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  queue_num   = atoi(argv[1]);
  g_queryPort = atoi(argv[2]);

  if (g_queryPort < 1 || g_queryPort > 65535)
  {
    printf("Invalid query port\n");
    exit(EXIT_FAILURE);
  }

  nl = mnl_socket_open(NETLINK_NETFILTER);
  if (nl == NULL)
  {
    perror("mnl_socket_open");
    exit(EXIT_FAILURE);
  }

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
  {
    perror("mnl_socket_bind");
    exit(EXIT_FAILURE);
  }
  portid = mnl_socket_get_portid(nl);

  nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

  nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
  nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

  mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
  mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

  /* ENOBUFS is signalled to userspace when packets were lost
   * on kernel side.  In most cases, userspace isn't interested
   * in this information, so turn it off.
   */
  ret = 1;
  mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

  g_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  srand(time(NULL));

  /* initialie the UDP datagram */
  initDatagram();

  /* pre-populate the challenges */
  for(int i = 0; i < g_nChallenges; ++i)
    newChallenge();

  atomic_flag_clear(&dataLock);
  pthread_t qt;
  pthread_create(&qt, NULL, queryThread, NULL);

  /* wait until we have all the information needed to operate */
  while(!a2sInfo.len || !a2sPlayer.len || !a2sRules.len)
    msleep(200);

  for (;;)
  {
    ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
    if (ret == -1)
    {
      perror("mnl_socket_recvfrom");
      exit(EXIT_FAILURE);
    }

    ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
    if (ret < 0)
    {
      perror("mnl_cb_run");
      exit(EXIT_FAILURE);
    }
  }

  pthread_join(qt, NULL);
  close(g_socket);
  mnl_socket_close(nl);

  return 0;
}
