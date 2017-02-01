/*
 * COPYRIGHT AND LICENSE
 *
 * Copyright (c) 2004-2005, Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *       1.      Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.
 *       2.      Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *       3.      The name of the copyright owner may not be used to
 * endorse or promote products derived from this software without specific
 * prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

static const char __attribute__((unused)) id[] =
      "@(#) $Id: main.c,v 1.1.1.8 2007/05/09 20:42:13 sachin Exp $";

#include <arpa/inet.h>
#include <assert.h>
#include <event.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "amt.h"
#include "memory.h"
#include "pat.h"
#include "prefix.h"
#include "relay.h"

static struct instances instance_head;
static mem_handle mem_rinstance_handle = NULL;

static relay_instance*
relay_instance_alloc(int af)
{
    relay_instance* instance;

    if (!mem_rinstance_handle) {
        mem_rinstance_handle =
              mem_type_init(sizeof(relay_instance), "Relay instance");
    }
    instance = (relay_instance*)mem_type_alloc(mem_rinstance_handle);
    instance->relay_af = af;
    instance->tunnel_af = af;

    /*
     * Insert this instance into the instance list
     */
    TAILQ_INSERT_TAIL(&instance_head, instance, relay_next);

    /*
     * initialize the head of the packet queues
     */
    TAILQ_INIT(&instance->pkt_head[HIGH]);
    TAILQ_INIT(&instance->pkt_head[MEDIUM]);
    TAILQ_INIT(&instance->pkt_head[LOW]);
    TAILQ_INIT(&instance->idle_sgs_list);

    /*
     * Initialize the roots of the radix trees
     */
    instance->relay_root = NULL;
    instance->rif_root = NULL;
    instance->relay_url_port = DEFAULT_URL_PORT;
    instance->agg_qdelay = 0;
    instance->n_qsamples = 0;
    /* Zero all stats */
    bzero(&instance->stats, sizeof(instance->stats));

    /* Capture interface index */
    instance->cap_iface_index = 0;

    return instance;
}

static int
socket_set_non_blocking(int s)
{
    int rc, val;

    val = fcntl(s, F_GETFL, 0);
    if (val < 0) {
        return errno;
    }
    rc = fcntl(s, F_SETFL, val | O_NONBLOCK);
    if (rc < 0) {
        return errno;
    }
    return 0;
}

/* static int
socket_set_blocking(int s)
{
    int rc, val;

    val = fcntl(s, F_GETFL, 0);
    if (val < 0)
        return errno;
    rc = fcntl(s, F_SETFL, val & ~O_NONBLOCK);
    if (rc < 0)
        return errno;
    return 0;
} */

static void
icmp_recv(int fd, short __unused flags, void* uap)
{
    relay_instance* instance = (relay_instance*)uap;
    struct sockaddr_in addr;
    char buf[1024];
    int bytes;
    socklen_t len = sizeof(addr);
    prefix_t* pfx;
    // patext* pat;
    // gw_t* gw;
    const char* res;
    const struct icmphdr* ih;
    const struct iphdr* iph;
    u_int32_t dest;

    bzero(buf, sizeof(buf));
    bytes = recvfrom(instance->icmp_sk, buf, sizeof(buf), 0,
          (struct sockaddr*)&addr, &len);
    if (bytes < 0) {
        if (relay_debug(instance))
            fprintf(stderr, "Failed to receive the ICMP message\n");
        return;
    }

    iph = (const struct iphdr*)buf;
    ih = (const struct icmphdr*)(buf + iph->ihl * 4);

    switch (ih->type) {
        case ICMP_DEST_UNREACH:
        case ICMP_SOURCE_QUENCH:
            iph = (const struct iphdr*)(buf + iph->ihl * 4 +
                                        sizeof(struct icmphdr));
            dest = iph->daddr;
            break;
        default:
            if (relay_debug(instance))
                fprintf(stderr, "Other ICMP message type: %d\n", ih->type);
            return;
    }

    res = inet_ntop(AF_INET, &dest, (char*)buf, 1024);
    if (res == NULL && relay_debug(instance)) {
        fprintf(stderr, "Cannot obtain the ICMP source address\n");
        return;
    }

    if (relay_debug(instance)) {
        fprintf(stderr, "Received a ICMP message from %s\n", buf);
    }

    pfx = prefix_build(AF_INET, &dest, INET_HOST_LEN);
    icmp_delete_gw(instance, pfx);
    prefix_free(pfx);
}

static void
relay_icmp_init(relay_instance* instance)
{
    struct protoent* proto = NULL;

    if ((proto = getprotobyname("ICMP")) == NULL) {
        fprintf(stderr, "failed to get ICMP protocol\n");
        exit(1);
    }

    instance->icmp_sk = socket(AF_INET, SOCK_RAW, proto->p_proto);
    if (instance->icmp_sk < 0) {
        fprintf(stderr, "ICMP socket init failed: %s\n", strerror(errno));
        exit(1);
    }

    if (socket_set_non_blocking(instance->icmp_sk) < 0) {
        fprintf(stderr, "ICMP socket nonblocking failed: %s\n",
              strerror(errno));
        exit(1);
    }

    event_set(&(instance->icmp_sk_ev), instance->icmp_sk,
          EV_READ | EV_PERSIST, icmp_recv, instance);
    if (event_add(&(instance->icmp_sk_ev), NULL)) {
        fprintf(stderr, "ICMP socket event failed\n");
        exit(1);
    }
}

static void
dns_reply(int fd, short __unused flags, void* uap)
{
    char response[100], str_avg_qdelay[100];
    int nbytes;
    relay_instance* instance = (relay_instance*)uap;
    double avg_qdelay;
    struct pcap_stat pstat;
    u_int64_t pcap_lose = 0;

    if (instance->n_qsamples == 0)
        avg_qdelay = 0.0;
    else
        avg_qdelay = 1.0 * instance->agg_qdelay / instance->n_qsamples;

    if (instance->n_qsamples > 0) {
        if (pcap_stats(instance->relay_pcap, &pstat)) {
            pcap_perror(instance->relay_pcap, "Cannot get pcap stats");
        } else {
            pcap_lose = pstat.ps_drop;
        }
    }

    if (relay_debug(instance)) {
        fprintf(stderr, "Send DNS response, avg delay: %f\n", avg_qdelay);
    }

    sprintf(str_avg_qdelay, "%f", avg_qdelay);

    /* Ignore the data sent by the DNS,  send reponse directly */
    if (avg_qdelay >= instance->qdelay_thresh &&
          instance->enable_queuing_delay_test)
        sprintf(response, "HTTP/1.1 500 Internal Server "
                          "Error\r\nContent-Length:%u\r\n\r\n%f",
              (unsigned int)strlen(str_avg_qdelay), avg_qdelay);
    else if (pcap_lose > 0 && instance->enable_pcap_test)
        sprintf(response, "HTTP/1.1 500 Internal Server "
                          "Error\r\nContent-Length:%u\r\n\r\n%f",
              (unsigned int)strlen(str_avg_qdelay), avg_qdelay);
    else
        sprintf(response, "HTTP/1.1 200 OK\r\nContent-Length:%u\r\n\r\n%f",
              (unsigned int)strlen(str_avg_qdelay), avg_qdelay);

    /* Set dns_com_sk to blocking mode */
    /* if(socket_set_blocking(instance->dns_com_sk)) {
        if (relay_debug(instance)) {
            fprintf(stderr, "DNS com socket blocking failed: %s\n",
    strerror(errno));
        }
        close(instance->dns_com_sk);
        return;
    } */

    nbytes = write(instance->dns_com_sk, response, strlen(response));
    if (nbytes < 0) {
        if (relay_debug(instance)) {
            fprintf(stderr, "DNS com socket write failed: %s\n",
                  strerror(errno));
        }
    }

    close(instance->dns_com_sk);

    /* reset */
    instance->agg_qdelay = 0;
    instance->n_qsamples = 0;
}

static void
dns_connect(int fd, short __unused flags, void* uap)
{
    struct sockaddr_in dns_addr;
    socklen_t addrlen = sizeof(dns_addr);
    relay_instance* instance = (relay_instance*)uap;

    if (relay_debug(instance)) {
        fprintf(stderr, "Receive DNS query\n");
    }

    instance->dns_com_sk = accept(
          instance->dns_listen_sk, (struct sockaddr*)&dns_addr, &addrlen);
    if (instance->dns_com_sk < 0) {
        if (relay_debug(instance)) {
            fprintf(stderr, "DNS listen socket accept failed: %s\n",
                  strerror(errno));
        }
        return;
    }

    if (socket_set_non_blocking(instance->dns_com_sk)) {
        if (relay_debug(instance)) {
            fprintf(stderr, "DNS com socket nonblocking failed: %s\n",
                  strerror(errno));
        }
        close(instance->dns_com_sk);
        return;
    }

    event_set(&(instance->sk_read_ev), instance->dns_com_sk, EV_READ,
          dns_reply, instance);
    if (event_add(&(instance->sk_read_ev), NULL)) {
        if (relay_debug(instance)) {
            fprintf(stderr, "DNS com socket event failed: %s\n",
                  strerror(errno));
        }
        close(instance->dns_com_sk);
        return;
    }
}

static void
relay_dns_init(relay_instance* instance)
{
    struct sockaddr_in serv_addr;
    int reuse = 1;

    bzero((char*)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(instance->dns_listen_port);

    instance->dns_listen_sk = socket(AF_INET, SOCK_STREAM, 0);
    if (instance->dns_listen_sk < 0) {
        fprintf(stderr, "DNS listen socket init failed: %s\n",
              strerror(errno));
        exit(1);
    }

    if (setsockopt(instance->dns_listen_sk, SOL_SOCKET, SO_REUSEADDR,
              &reuse, sizeof(reuse)) < 0) {
        fprintf(stderr, "DNS listen socket address reuse failed %s\n",
              strerror(errno));
        exit(1);
    }

    if (bind(instance->dns_listen_sk, (struct sockaddr*)&serv_addr,
              sizeof(serv_addr)) < 0) {
        fprintf(stderr, "DNS listen socket bind failed: %s\n",
              strerror(errno));
        exit(1);
    }

    if (listen(instance->dns_listen_sk, 16) < 0) {
        fprintf(stderr, "DNS socket listen failed: %s\n", strerror(errno));
        exit(1);
    }

    if (socket_set_non_blocking(instance->dns_listen_sk) < 0) {
        fprintf(stderr, "DNS listen socket nonblocking failed: %s\n",
              strerror(errno));
        exit(1);
    }

    event_set(&(instance->sk_listen_ev), instance->dns_listen_sk,
          EV_READ | EV_PERSIST, dns_connect, instance);
    if (event_add(&(instance->sk_listen_ev), NULL)) {
        fprintf(stderr, "DNS listen socket event failed\n");
        exit(1);
    }
}

static void
relay_event_init(relay_instance* instance)
{
    instance->relay_context = event_init();
    if (instance->relay_context == NULL) {
        fprintf(stderr, "event_init failed\n");
        exit(1);
    }
}

static void
relay_mcast_info(int signum)
{
    relay_instance* instance;
    struct pcap_stat relay_pcap_stat;

    instance = TAILQ_FIRST(&instance_head);

    if (relay_debug(instance)) {
        fprintf(stderr, "mcast data recvd: %llu, mcast data sent: %llu\n",
              (unsigned long long)instance->stats.mcast_data_recvd,
              (unsigned long long)instance->stats.mcast_data_sent);
        pcap_stats(instance->relay_pcap, &relay_pcap_stat);
        fprintf(stderr, "pcap data recvd: %u, pcap data dropped: %u\n",
              relay_pcap_stat.ps_recv, relay_pcap_stat.ps_drop);
        fprintf(stderr, "pcap data recvd by relay 1: %llu\n",
              (unsigned long long)instance->stats.pcap_data_recvd1);
        fprintf(stderr, "pcap data recvd by relay 2: %llu\n",
              (unsigned long long)instance->stats.pcap_data_recvd2);
    }

    exit(0);
}

/*
 * relay_signal_init - Add signal handlers
 */
static void
relay_signal_init(relay_instance* instance)
{
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, 0);

    sa.sa_handler = relay_mcast_info;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, 0);
}

static void
usage(char* name)
{
    fprintf(stderr, "usage: %s -a anycast prefix/plen [-u1] [-d] [-q count "
                    "of packets to dequeue at once] [-t queuing delay "
                    "threshold (default 100 msec)] [-g DNS live test "
                    "listening port (default 80)] [-b AMT port (default "
                    "2268)] [--enable-queuing-delay-test enable the DNS "
                    "live test for queuing delay] [--enable-pcap-test "
                    "enable the DNS live test for pcap lost pkts]\n",
          name);
    exit(1);
}

int
relay_socket_shared_init(int family,
      struct sockaddr* bind_addr,
      int bind_addr_len)
{
    int rc, val, len, sock;

    val = TRUE;
    len = sizeof(val);

    sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        fprintf(stderr, "error creating socket: %s\n", strerror(errno));
        exit(1);
    }

    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, len);
    if (rc < 0) {
        fprintf(stderr, "error SO_REUSEADDR socket: %s\n", strerror(errno));
        exit(1);
    }

    if (bind_addr) {
        rc = bind(sock, bind_addr, bind_addr_len);
        if (rc < 0) {
            fprintf(stderr, "error binding socket: %s\n", strerror(errno));
            exit(1);
        }
    }

/*
 * XXX - Update for linux to use IP_PKTINFO,
 * instead of IP_RECVDSTADDR and IP_RECVIF.
 */
#ifdef BSD
    rc = setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR, &val, len);
    if (rc < 0) {
        fprintf(stderr, "error IP_RECVDSTADDR on socket: %s\n",
              strerror(errno));
        exit(1);
    }
    rc = setsockopt(sock, IPPROTO_IP, IP_RECVIF, &val, len);
    if (rc < 0) {
        fprintf(stderr, "error IP_RECVIF on socket: %s\n", strerror(errno));
        exit(1);
    }
#else
    if (family == AF_INET) {
        rc = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &val, len);
        if (rc < 0) {
            fprintf(stderr, "error IP_RECVDSTADDR on socket: %s\n",
                  strerror(errno));
            exit(1);
        }
    } else {
        rc = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, len);
        if (rc < 0) {
            fprintf(stderr, "error IPv6_RECVDSTADDR on socket: %s\n",
                  strerror(errno));
            exit(1);
        }
    }
#endif

    val = fcntl(sock, F_GETFL, 0);
    if (val < 0) {
        return errno;
    }
    rc = fcntl(sock, F_SETFL, val | O_NONBLOCK);
    if (rc < 0) {
        fprintf(
              stderr, "error O_NONBLOCK on socket: %s\n", strerror(errno));
        exit(1);
    }

    return sock;
}

/*
 * Listen for URL requests to come in to display statistics and
 * user/billing information.
 */
void
relay_url_init(relay_instance* instance)
{
    int rc, salen, sock;
    // int val, len;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr* sa = NULL;

    switch (instance->relay_af) {
        case AF_INET:
            salen = sizeof(sin);
            sa = (struct sockaddr*)&sin;
            bzero(sa, salen);
            sin.sin_family = instance->relay_af;
            sin.sin_addr.s_addr = htonl(INADDR_ANY);
            sin.sin_port = htons(instance->relay_url_port);
            break;

        case AF_INET6:
            salen = sizeof(sin6);
            sa = (struct sockaddr*)&sin6;
            bzero(sa, salen);
            sin6.sin6_addr = in6addr_any;
            sin6.sin6_family = instance->relay_af;
            sin6.sin6_port = htons(instance->relay_url_port);
            break;

        default:
            salen = 0;
            assert(instance->relay_af == AF_INET ||
                   instance->relay_af == AF_INET6);
    }

    // val = TRUE;
    // len = sizeof(val);

    sock = socket(instance->relay_af, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        fprintf(stderr, "error creating URL socket: %s\n", strerror(errno));
        exit(1);
    }

    rc = bind(sock, sa, salen);
    if (rc < 0) {
        fprintf(stderr, "error binding url socket: %s\n", strerror(errno));
        exit(1);
    }

    rc = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
        fprintf(
              stderr, "error O_NONBLOCK on socket: %s\n", strerror(errno));
        exit(1);
    }

    rc = listen(sock, 5);
    if (rc < 0) {
        fprintf(
              stderr, "error url listen on socket: %s\n", strerror(errno));
        exit(1);
    }

    event_set(&instance->relay_url_ev, sock, EV_READ | EV_PERSIST,
          relay_accept_url, (void*)instance);
    rc = event_add(&instance->relay_url_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "error url event_add: %s\n", strerror(errno));
        exit(1);
    }
    instance->relay_url_sock = sock;
}

static void
relay_anycast_socket_init(relay_instance* instance,
      struct sockaddr* listen_addr,
      int addr_len)
{
    int rc;

    instance->relay_anycast_sock = relay_socket_shared_init(
          instance->relay_af, listen_addr, addr_len);

    event_set(&instance->relay_anycast_ev, instance->relay_anycast_sock,
          EV_READ | EV_PERSIST, relay_instance_read, (void*)instance);
    rc = event_add(&instance->relay_anycast_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "error anycast event_add: %s\n", strerror(errno));
        exit(1);
    }
}

int
main(int argc, char** argv)
{
    int ch, rc, plen;
    relay_instance* instance;
    struct sockaddr_storage listen_addr;
    char tunnel_addr[MAX_ADDR_STRLEN];
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;
    struct option long_options[] = { { "enable-queuing-delay-test",
                                           no_argument, 0, 'e' },
        { "enable-pcap-test", no_argument, 0, 'f' } };

    /*
     * assume IPv4 for the first release.
     * We'll make it fully address family indepdent later
     */
    TAILQ_INIT(&instance_head);
    instance = relay_instance_alloc(AF_INET);

    BIT_RESET(instance->relay_flags, RELAY_FLAG_DEBUG);
    instance->dequeue_count = 1;
    instance->qdelay_thresh = 100;
    instance->dns_listen_port = 80;
    instance->amt_port = AMT_PORT;
    instance->enable_queuing_delay_test = 0;
    instance->enable_pcap_test = 0;
    instance->pcap_buffer_size = 10 * 1024 * 1024;

    bzero((char*)&listen_addr, sizeof(listen_addr));
#ifdef BSD
    listen_addr.sin_len = sizeof(listen_addr);
#endif
    plen = 0;
    tunnel_addr[0] = '\0';

    while ((ch = getopt_long(argc, argv, "u:a:dp:q:t:g:b:r:n:c:l:s:",
                  long_options, NULL)) != EOF) {
        switch (ch) {
            case 's': {
                strcpy(tunnel_addr, optarg);
                break;
            }
            case 'l': {
                if (strcmp(optarg, "inet") == 0)
                    instance->tunnel_af = AF_INET;
                else if (strcmp(optarg, "inet6") == 0)
                    instance->tunnel_af = AF_INET6;
                else {
                    fprintf(stderr, "bad tunnel (-l) net specification: %s\n", optarg);
                    exit(1);
                }
                break;
            }
            case 'c': {
                instance->cap_iface_index = if_nametoindex(optarg);
                if (instance->cap_iface_index == 0) {
                    perror("bad capture interface name");
                    exit(1);
                }
                strncpy(instance->cap_iface_name, optarg,
                        sizeof(instance->cap_iface_name));
                instance->cap_iface_name[
                    sizeof(instance->cap_iface_name)-1] = 0;
                break;
            }
            case 'n':
                if (strcmp(optarg, "inet") == 0)
                    instance->relay_af = AF_INET;
                else if (strcmp(optarg, "inet6") == 0)
                    instance->relay_af = AF_INET6;
                else {
                    fprintf(stderr, "bad relay (-n) net specification: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'u':
                instance->use_unicast_addr = 1;
                break;
            case 'a': {
                char* pstr = NULL;
                pstr = strsep(&optarg, "/");
                if (pstr == NULL) {
                    fprintf(stderr,
                          "bad anycast prefix: expecting prefix/len\n");
                    exit(1);
                }
                if (optarg == NULL) {
                    fprintf(stderr, "bad anycast prefix length\n");
                    exit(1);
                }

                switch (instance->relay_af) {
                    case AF_INET: {
                        struct in_addr prefix;
                        struct sockaddr_in real_listen_addr;
                        rc = inet_pton(AF_INET, pstr, &prefix);
                        if (rc == 1) {
                            plen = strtol(optarg, NULL, 10);
                            if (plen == 0) {
                                fprintf(stderr,
                                      "bad anycast prefix length\n");
                                exit(1);
                            }
                            if (plen > AMT_HOST_PLEN) {
                                fprintf(stderr,
                                      "anycast prefix length too long\n");
                                exit(1);
                            }
                            real_listen_addr.sin_family = AF_INET;
                            if (instance->use_unicast_addr == 1) {
                                real_listen_addr.sin_addr = inet_makeaddr(
                                      ntohl(prefix.s_addr), 0x0);
                            } else {
                                real_listen_addr.sin_addr = inet_makeaddr(
                                      ntohl(prefix.s_addr), 0x1);
                            }
                            bcopy(&real_listen_addr, &listen_addr,
                                  sizeof(real_listen_addr));
                        } else {
                            fprintf(stderr, "bad anycast prefix\n");
                            exit(1);
                        }
                        break;
                    }
                    case AF_INET6: {
                        struct in6_addr prefix;
                        struct sockaddr_in6 real_listen_addr;
                        rc = inet_pton(AF_INET6, pstr, &prefix);
                        if (rc == 1) {
                            plen = strtol(optarg, NULL, 10);
                            if (plen == 0) {
                                fprintf(stderr,
                                      "bad anycast prefix length\n");
                                exit(1);
                            }
                            if (plen > AMT_HOST6_PLEN) {
                                fprintf(stderr,
                                      "anycast prefix length too long\n");
                                exit(1);
                            }
                            real_listen_addr.sin6_family = AF_INET6;
                            if (instance->use_unicast_addr == 1) {
                                real_listen_addr.sin6_addr = prefix;
                            } else {
                                /* to-do: */
                                real_listen_addr.sin6_addr = prefix;
                            }
                            bcopy(&real_listen_addr, &listen_addr,
                                  sizeof(real_listen_addr));
                        } else {
                            fprintf(stderr, "bad anycast prefix\n");
                            exit(1);
                        }
                        break;
                    }
                }
                break;
            }
            case 'd':
                BIT_SET(instance->relay_flags, RELAY_FLAG_DEBUG);
                break;
            case 'q':
                if (optarg == NULL) {
                    fprintf(stderr, "must specify dequeue length\n");
                    exit(1);
                }
                instance->dequeue_count = strtol(optarg, NULL, 10);
                break;
            case 't':
                if (optarg == NULL) {
                    fprintf(
                          stderr, "must specify the queueing threshold\n");
                    exit(1);
                }
                instance->qdelay_thresh = strtol(optarg, NULL, 10);
                break;
            case 'g':
                if (optarg == NULL) {
                    fprintf(stderr,
                          "must specify the dns live test port number\n");
                    exit(1);
                }
                instance->dns_listen_port = atoi(optarg);
                break;
            case 'b':
                if (optarg == NULL) {
                    fprintf(stderr, "must specify the AMT port number\n");
                    exit(1);
                }
                instance->amt_port = atoi(optarg);
                break;
            case 'e':
                instance->enable_queuing_delay_test = 1;
                break;
            case 'f':
                instance->enable_pcap_test = 1;
                break;
            case 'r':
                instance->pcap_buffer_size = atoi(optarg);
                if (instance->pcap_buffer_size < 64 * 1024) {
                    fprintf(stderr,
                          "pcap buffer size should be bigger than 64KB\n");
                    exit(1);
                }
                break;
            case 'p':
                if (optarg == NULL) {
                    fprintf(stderr, "must specify port number\n");
                    exit(1);
                }
                instance->relay_url_port = strtol(optarg, NULL, 10);
                if (instance->relay_url_port < IPPORT_RESERVED) {
                    fprintf(stderr, "must use port number => %d\n",
                          IPPORT_RESERVED);
                    exit(1);
                }
                break;
            default:
                fprintf(stderr, "unknown argument '%c'\n", ch);
            case '?':
                usage(argv[0]);
        }
    }

    if (instance->relay_af == AF_INET) {
        struct sockaddr_in* paddr = (struct sockaddr_in*)&listen_addr;
        paddr->sin_port = htons(instance->amt_port);
    } else {
        struct sockaddr_in6* paddr = (struct sockaddr_in6*)&listen_addr;
        paddr->sin6_port = htons(instance->amt_port);
    }

    if (plen == 0) {
        fprintf(stderr, "anycast prefix/len must be set with -a\n");
        exit(1);
    }

    if (instance->cap_iface_index == 0) {
        fprintf(stderr, "missing capture interface name\n");
        exit(1);
    }

    // Get tunnel address
    if (strlen(tunnel_addr) == 0) {
        fprintf(stderr, "missing tunnel addr\n");
        exit(1);
    }
    if (instance->tunnel_af == AF_INET) {
        if (inet_pton(instance->tunnel_af, tunnel_addr, &(addr.sin_addr)) !=
              1) {
            fprintf(stderr, "invalid tunnel addr\n");
            exit(1);
        }
        addr.sin_family = AF_INET;
        bcopy(&addr, &instance->tunnel_addr, sizeof(addr));
    } else {
        if (inet_pton(instance->tunnel_af, tunnel_addr, &addr6.sin6_addr) !=
              1) {
            fprintf(stderr, "invalid tunnel addr\n");
            exit(1);
        }
        addr6.sin6_family = AF_INET6;
        bcopy(&addr6, &instance->tunnel_addr, sizeof(addr6));
    }

    relay_event_init(instance);
    relay_signal_init(instance);
    relay_anycast_socket_init(
          instance, (struct sockaddr*)&listen_addr, sizeof(listen_addr));
    relay_url_init(instance);
    relay_dns_init(instance);
    relay_icmp_init(instance);

    rc = event_dispatch();
    fprintf(stderr, "Unexpected exit: %s\n", strerror(rc));

    return rc;
}
