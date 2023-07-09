#include "global.h"
#include "util.h"
#include "client.h"
#include "proto.h"
#include "locking.h"
#include "challenge.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// the maximum size of packets we are interested in
#define MAX_RECV_SIZE 57

static bool g_goldSource  = false;
static bool g_dropPrivate = false;

typedef struct
{
  bool       enabled;
  int        interval;

  atomic_int packets;
  atomic_int drops;
  atomic_int challenges;
  atomic_int answers;
  atomic_int pass;
}
Stats;

static Stats g_stats = {0};

IPPacket g_udpHeader;
static void initDatagram(void)
{
  memset(&g_udpHeader, 0, sizeof(g_udpHeader));
  g_udpHeader.ip.ihl      = 5;
  g_udpHeader.ip.version  = 4;
  g_udpHeader.ip.tos      = IPTOS_DSCP_EF;
  g_udpHeader.ip.frag_off = 0;
  g_udpHeader.ip.ttl      = 255;
  g_udpHeader.ip.protocol = IPPROTO_UDP;
  g_udpHeader.ip.check    = 0;
  g_udpHeader.udp.check   = 0;
}

static void sendPacket(
  int sock,
  uint32_t daddr, uint32_t saddr,
  uint16_t dport, uint16_t sport,
  const void * data, uint16_t len)
{
  // Largest safe MTU to use is 1500
  uint8_t datagram[1500];

  memcpy(datagram, &g_udpHeader, sizeof(g_udpHeader));
  IPPacket * pkt = (IPPacket *)datagram;

  static atomic_int id = 0;
  uint16_t pktid =
    (saddr >> 16 ^ saddr) ^
    (daddr >> 16 ^ daddr) ^
    dport ^
    sport ^
    atomic_fetch_add(&id, 1);

  pkt->ip.id      = htons(pktid);
  pkt->ip.saddr   = saddr;
  pkt->ip.daddr   = daddr;

  pkt->udp.source = sport;
  pkt->udp.dest   = dport;
  pkt->udp.len    = htons(8 + len);

  struct sockaddr_in sin =
  {
    .sin_family      = AF_INET,
    .sin_port        = dport,
    .sin_addr.s_addr = daddr
  };

  int offset = 0;
  int used   = sizeof(*pkt);
  while(len > 0)
  {
    int available   = sizeof(datagram) - used;
    int payloadSize = min(len, available);
    int packetSize  = used + payloadSize;

    pkt->ip.tot_len  = htons(packetSize);
    pkt->ip.frag_off = htons((len > available ? IP_MF : 0) | (offset >> 3));
    memcpy(datagram + used, data, payloadSize);

    sendto(sock, datagram, packetSize, 0,
        (struct sockaddr *)&sin, sizeof(sin));

    len    -= payloadSize;
    data   += payloadSize;
    offset += payloadSize + (offset ? 0 : sizeof(pkt->udp));
    used    = sizeof(pkt->ip);
  }
}

static void sendPayload(
  int sock,
  uint32_t daddr, uint32_t saddr,
  uint16_t dport, uint16_t sport,
  PayloadType type)
{
  const Payload * p = client_getPayload(type);
  if (!p)
    return;

  // if a single packet, nothing to do except directly transmit it
  if (p->packetSize == 0)
  {
    sendPacket(sock, daddr, saddr, dport, sport, p->data, p->size);
    goto out;
  }

  const int ttlPackets = (p->size + p->packetSize - 1) / p->packetSize;

  if (g_goldSource)
  {
    uint8_t payload[sizeof(GoldSourceHeader) + p->packetSize];
    GoldSourceHeader * h = (GoldSourceHeader *)payload;
    h->header = HEADER_MULTI;
    h->id     = rand() % UINT32_MAX;
    h->ttl    = ttlPackets;

    int remaining = p->size;
    for(int i = 0; i < ttlPackets; ++i)
    {
      int copySize = min(remaining, p->packetSize);
      remaining -= copySize;

      h->num = i;
      memcpy(h->payload, p->data + i * p->packetSize, copySize);
      sendPacket(sock, daddr, saddr, dport, sport, payload,
          sizeof(*h) + copySize);
    }
  }
  else
  {
    uint8_t payload[sizeof(SourceHeader) + p->packetSize];
    SourceHeader * h = (SourceHeader *)payload;
    h->header     = HEADER_MULTI;
    h->id         = rand() % UINT32_MAX;
    h->compressed = p->compressed;
    h->size       = p->packetSize;
    h->ttl        = ttlPackets;

    int remaining = p->size;
    for(int i = 0; i < ttlPackets; ++i)
    {
      int copySize = min(remaining, p->packetSize);
      remaining -= copySize;

      h->num = i;
      memcpy(h->payload, p->data + i * p->packetSize, copySize);
      sendPacket(sock, daddr, saddr, dport, sport, payload,
          sizeof(*h) + copySize);
    }
  }

out:
  client_releasePayload(p);

  if (g_stats.enabled)
    atomic_fetch_add(&g_stats.answers, 1);
}

static void sendChallenge(int sock, IPPacket * h)
{
  const uint32_t ch = challenge_get(h->ip.saddr ^ h->udp.dest);
  QueryMsg m =
  {
    .header    = HEADER_SINGLE,
    .query     = S2C_CHALLENGE,
    .challenge = ch
  };

  sendPacket(sock, h->ip.saddr, h->ip.daddr, h->udp.source, h->udp.dest,
      &m, sizeof(m));

  if (g_stats.enabled)
    atomic_fetch_add(&g_stats.challenges, 1);
}

static bool parse_payload(int sock, void * payload, uint16_t len)
{
  if (g_stats.enabled)
    atomic_fetch_add(&g_stats.packets, 1);

  if (len < sizeof(IPPacket) || len > MAX_RECV_SIZE)
    return true;

  IPPacket * h = (IPPacket *)payload;
  if (h->ip.protocol != IPPROTO_UDP)
    return true;

  // check the IP is even valid to afford some basic flood protection
  uint32_t ip = ntohl(h->ip.saddr);
  if (isInvalidIPv4(ip, g_dropPrivate))
  {
    if (g_stats.enabled)
      atomic_fetch_add(&g_stats.drops, 1);

    if (g_verbose)
    {
      char saddr[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &h->ip.saddr, saddr, sizeof(saddr));
      printf("Drop Bad IP: %s\n", saddr);
    }
    return false;
  }

  payload = h->payload;
  int payloadLen = ntohs(h->udp.len) - sizeof(h->udp);

#if 0
  char saddr[INET_ADDRSTRLEN];
  char daddr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &h->ip.saddr, saddr, sizeof(saddr));
  inet_ntop(AF_INET, &h->ip.daddr, daddr, sizeof(daddr));
  printf("%s:%d -> %s:%d\n", saddr, ntohs(h->udp.source), daddr, ntohs(h->udp.dest));
#endif

  uint32_t * header = (uint32_t *)payload;

  // the query packets should never be multi-packet
  if (*header == HEADER_MULTI)
  {
    if (g_stats.enabled)
      atomic_fetch_add(&g_stats.drops, 1);
    return false;
  }

  // Check the header is incorrect, this may be game traffic to pass though
  if (*header != HEADER_SINGLE)
  {
    if (g_stats.enabled)
      atomic_fetch_add(&g_stats.pass, 1);
    return true;
  }

  uint32_t challenge;
  uint8_t * query = (uint8_t *)(header + 1);
  switch(*query)
  {
    case A2S_INFO:
    {
      char * data = (char *)(query + 1);
      if (memcmp(data, "Source Engine Query\0", 20) != 0)
        break;

      if (payloadLen < 29)
      {
        sendChallenge(sock, h);
        return false;
      }

      memcpy(&challenge, data + 20, sizeof(challenge));
      if (!challenge_validate(challenge, h->ip.saddr ^ h->udp.dest))
      {
        sendChallenge(sock, h);
        return false;
      }

      if (g_goldSource)
        sendPayload(sock, h->ip.saddr, h->ip.daddr, h->udp.source, h->udp.dest,
            PT_GS_INFO);

      sendPayload(sock, h->ip.saddr, h->ip.daddr, h->udp.source, h->udp.dest,
          PT_A2S_INFO);

      if (g_verbose)
        printf("A2S_INFO 0x%08x\n", challenge);
      return false;
    }

    case A2S_PLAYER:
    {
      if (payloadLen < 9)
      {
        sendChallenge(sock, h);
        return false;
      }

      memcpy(&challenge, query + 1, sizeof(challenge));
      if (!challenge_validate(challenge, h->ip.saddr ^ h->udp.dest))
      {
        sendChallenge(sock, h);
        return false;
      }

      sendPayload(sock, h->ip.saddr, h->ip.daddr, h->udp.source, h->udp.dest,
          PT_A2S_PLAYER);
      if (g_verbose)
        printf("A2S_PLAYER 0x%08x\n", challenge);

      return false;
    }

    case A2S_RULES:
    {
      if (payloadLen < 9)
      {
        sendChallenge(sock, h);
        return false;
      }

      memcpy(&challenge, query + 1, sizeof(challenge));
      if (!challenge_validate(challenge, h->ip.saddr ^ h->udp.dest))
      {
        sendChallenge(sock, h);
        return false;
      }

      sendPayload(sock, h->ip.saddr, h->ip.daddr, h->udp.source, h->udp.dest,
          PT_A2S_RULES);
      if (g_verbose)
        printf("A2S_RULES 0x%08x\n", challenge);

      return false;
    }

    // this is deprecated but implement it anyway for completeness
    case A2A_PING:
    {
      static const QueryPing m =
      {
        .header = HEADER_SINGLE,
        .query  = A2A_PING_REPLY,
        .data   = "00000000000000\0"
      };

      sendPacket(sock, h->ip.saddr, h->ip.daddr, h->udp.source, h->udp.dest,
        &m, g_goldSource ? 6 : sizeof(m));

      if (g_stats.enabled)
        atomic_fetch_add(&g_stats.answers, 1);

      if (g_verbose)
        printf("A2A_PING\n");

      return false;
    }

    // this is deprecated but implement it anyway for completeness
    case A2S_SERVERQUERY_GETCHALLENGE:
    {
      sendChallenge(sock, h);

      if (g_verbose)
        printf("A2S_SERVERQUERY_GETCHALLENGE\n");

      return false;
    }

    // assume any other message types are an attack
    default:
      if (g_stats.enabled)
        atomic_fetch_add(&g_stats.drops, 1);
      return false;
  }

  if (g_stats.enabled)
    atomic_fetch_add(&g_stats.pass, 1);
  return true;
}

typedef struct
{
  int sock;
  unsigned int queueNum;
  unsigned int queryPort;
  struct mnl_socket * nl;
}
NLThreadInfo;

static void nfq_send_verdict(NLThreadInfo * ti, int queueNum, uint32_t id, int verdict)
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr *nlh;

  nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queueNum);
  nfq_nlmsg_verdict_put(nlh, id, verdict);

  if (mnl_socket_sendto(ti->nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }
}

static int queue_cb(const struct nlmsghdr *nlh, void * opaque)
{
  NLThreadInfo *ti = (NLThreadInfo *)opaque;

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
  int      verdict =
    parse_payload(ti->sock, payload, plen) ? NF_ACCEPT : NF_DROP;

  nfq_send_verdict(ti, ntohs(nfg->res_id), id, verdict);
  return MNL_CB_OK;
}

void * netlinkThread(void * opaque)
{
  NLThreadInfo *ti = (NLThreadInfo *)opaque;

  const size_t sizeof_buf = MAX_RECV_SIZE + (MNL_SOCKET_BUFFER_SIZE / 2);
  char buf[sizeof_buf];
  memset(buf, 0, sizeof_buf);

  ti->nl = mnl_socket_open(NETLINK_NETFILTER);
  if (ti->nl == NULL)
  {
    perror("mnl_socket_open");
    exit(EXIT_FAILURE);
  }

  if (mnl_socket_bind(ti->nl, 0, MNL_SOCKET_AUTOPID) < 0)
  {
    perror("mnl_socket_bind");
    exit(EXIT_FAILURE);
  }
  unsigned int portid = mnl_socket_get_portid(ti->nl);

  struct nlmsghdr *nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, ti->queueNum);
  nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

  if (mnl_socket_sendto(ti->nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

  nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, ti->queueNum);
  nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, MAX_RECV_SIZE);
  nfq_nlmsg_cfg_put_qmaxlen(nlh, 0xFFFFFFFF);

  mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
  mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

  if (mnl_socket_sendto(ti->nl, nlh, nlh->nlmsg_len) < 0)
  {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

  /* ENOBUFS is signalled to userspace when packets were lost
   * on kernel side.  In most cases, userspace isn't interested
   * in this information, so turn it off.
   */
  int ret = 1;
  mnl_socket_setsockopt(ti->nl, NETLINK_NO_ENOBUFS, &ret, sizeof(ret));
  ti->sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  for (;;)
  {
    int ret = mnl_socket_recvfrom(ti->nl, buf, sizeof_buf);
    if (ret == -1)
    {
      perror("mnl_socket_recvfrom");
      break;
    }

    ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, ti);
    if (ret < 0)
    {
      perror("mnl_cb_run");
      break;
    }
  }

  close(ti->sock);
  mnl_socket_close(ti->nl);
  free(ti);
  return NULL;
}

static void printHelp(void)
{
  printf(
    "Usage: SteamQueryProxy [options]\n"
    "Options:\n"
    "  -p, --query-port <port>   The Game Query UDP Port\n"
    "  -n, --queue-num <num>     The first netfilter queue ID\n"
    "  -t, --queue-threads <num> How many thread queues to process\n"
    "  -g, --goldsource          Set if using the GoldSource protocol\n"
    "  -d, --drop-private        Drop packets originating from private IPs\n"
    "  -v, --verbose             Print verbose information for debugging\n"
    "  -s, --print-stats <num>   Print statistics every <num> seconds\n"
    "  -q, --quiet               Print less information\n"
    "  -h, --help                Print this help\n"
    "\n"
    "You MUST configure netfilter to redirect traffic to this application\n"
    "For example:\n"
    "\n"
    "  iptables -A INPUT -i lo -j ACCEPT\n"
    "  iptables -A INPUT -p udp -m udp --dport 27015 \\\n"
    "    -m length --length 33:57 -j NFQUEUE \\\n"
    "    --queue-balance 0:1 --queue-bypass\n"
    "\n"
    "The first rule is to accept loopback traffic, without this, this\n"
    "application will get into an infinate loop, it MUST be present.\n"
    "\n"
    "The second rule sends packets that match the basic criteria for the \n"
    "Query Protocol to queues 0-1. This example creates 2 queues, as such you\n"
    "MUST use 2 threads to service both queues. Failure to do this correcly\n"
    "will prevent proper operation\n"
    "\n"
    "Once the above rules are in place simply launch this application.\n"
    "For example:\n"
    "\n"
    "  SteamQueryProxy -p 27015 -n 0 -t 2\n"
    "\n"
    "Make sure your port number and thread count are correct per your\n"
    "and game server configuration. Also be sure your game is configured\n"
    "to listen on IP 0.0.0.0 or this application will not function at all.\n"
    "\n"
    "If you find this tool useful please consider supporting my work here:\n"
    "\n"
    "* [GitHub](https://github.com/sponsors/gnif)\n"
    "* [Ko-Fi](https://ko-fi.com/lookingglass)\n"
    "* [Patreon](https://www.patreon.com/gnif)\n"
    "* [Paypal](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=ESQ72XUPGKXRY)\n"
    "* BTC - 14ZFcYjsKPiVreHqcaekvHGL846u3ZuT13\n"
    "* ETH - 0x6f8aEe454384122bF9ed28f025FBCe2Bce98db85\n"
    "\n"
  );
}

int main(int argc, char *argv[])
{
  unsigned int queryPort    = 0;
  unsigned int queueNum     = 0;
  unsigned int queueThreads = 1;

  struct option long_options[] =
  {
    {"query-port"   , required_argument, 0, 'p'},
    {"queue-num"    , required_argument, 0, 'n'},
    {"queue-threads", required_argument, 0, 't'},
    {"goldsource"   , no_argument      , 0, 'g'},
    {"drop-private" , no_argument      , 0, 'd'},
    {"verbose"      , no_argument      , 0, 'v'},
    {"quiet"        , no_argument      , 0, 'q'},
    {"print-stats"  , required_argument, 0, 's'},
    {"help"         , no_argument      , 0, 'h'},
    {0              , 0                , 0,  0 }
  };

  int option;
  int option_index = 0;
  while ((option = getopt_long(argc, argv, "p:n:t:gdvs:qh",
          long_options, &option_index)) != -1)
  {
    switch(option)
    {
      case 'p':
        queryPort = atoi(optarg);
        break;

      case 'n':
        queueNum = atoi(optarg);
        break;

      case 't':
        queueThreads = atoi(optarg);
        break;

      case 'g':
        g_goldSource = true;
        break;

      case 'd':
        g_dropPrivate = true;
        break;

      case 'v':
        g_verbose = true;
        break;

      case 's':
        g_stats.enabled  = true;
        g_stats.interval = atoi(optarg);
        if (g_stats.interval < 1)
        {
          fprintf(stderr, "Invalid stats interval, must be > 0\n");
          printHelp();
          return 1;
        }
        break;

      case 'q':
        g_quiet = true;
        break;

      case 'h':
      case '?':
        printHelp();
        return 1;

      default:
        fprintf(stderr, "Unknown option %c\n", option);
        printHelp();
        return 1;
    }
  }

  if (queryPort < 1 || queryPort > 65535)
  {
    printf("Invalid query port\n");
    printHelp();
    exit(EXIT_FAILURE);
  }

  srand(time(NULL));

  /* initialie the UDP datagram */
  initDatagram();

  challenge_init();
  client_start("127.0.0.1", queryPort, g_goldSource, true);

  /* wait until we have all the information needed to operate */
  while(client_isReady())
    msleep(200);

  pthread_t t[queueThreads];
  for(int i = 0; i < queueThreads; ++i)
  {
    NLThreadInfo * ti = malloc(sizeof(*ti));
    ti->queueNum  = queueNum + i;
    ti->queryPort = queryPort;
    pthread_create(&t[i], NULL, netlinkThread, ti);
  }

  if (g_stats.enabled)
  {
    for(;;)
    {
      msleep(g_stats.interval * 1000);
      int packets    = atomic_exchange(&g_stats.packets   , 0);
      int drops      = atomic_exchange(&g_stats.drops     , 0);
      int challenges = atomic_exchange(&g_stats.challenges, 0);
      int answers    = atomic_exchange(&g_stats.answers   , 0);
      int pass       = atomic_exchange(&g_stats.pass      , 0);

      printf(
          "Stats=Packets: %-7d "
          "Blocked: %-7d "
          "Challenges: %-7d "
          "Answers: %-7d "
          "Passed: %-7d\n",
          packets, drops, challenges, answers, pass);
    }
  }

  for(int i = 0; i < queueThreads; ++i)
    pthread_join(t[i], NULL);

  client_stop();
  return 0;
}
