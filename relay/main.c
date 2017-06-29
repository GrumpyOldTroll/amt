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
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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
    bzero(instance, sizeof(*instance));

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
    instance->relay_groot = NULL;
    instance->rif_root = NULL;
    instance->relay_url_port = DEFAULT_URL_PORT;
    instance->agg_qdelay = 0;
    instance->n_qsamples = 0;

    /* Capture interface index */
    instance->cap_iface_index = 0;

    // BIT_RESET(instance->relay_flags, RELAY_FLAG_DEBUG);
    instance->dequeue_count = 10;
    // instance->qdelay_thresh = 100;
    instance->amt_port = AMT_PORT;

    return instance;
}

static void
relay_instance_free(relay_instance* instance)
{
    TAILQ_REMOVE(&instance_head, instance, relay_next);
    if (instance->relay_anycast_ev) {
        event_free(instance->relay_anycast_ev);
        instance->relay_anycast_ev = NULL;
    }
    if (instance->relay_url_ev) {
        event_free(instance->relay_url_ev);
        instance->relay_url_ev = NULL;
    }
    if (instance->relay_pkt_timer) {
        event_free(instance->relay_pkt_timer);
        instance->relay_pkt_timer = NULL;
    }
    if (instance->sk_listen_ev) {
        event_free(instance->sk_listen_ev);
        instance->sk_listen_ev = NULL;
    }
    if (instance->sk_read_ev) {
        event_free(instance->sk_read_ev);
        instance->sk_read_ev = NULL;
    }
    if (instance->icmp_sk_ev) {
        event_free(instance->icmp_sk_ev);
        instance->icmp_sk_ev = NULL;
    }
    patext* pat;
    pat = pat_getnext(&instance->rif_root, NULL, 0);
    while (pat) {
        recv_if* rif = pat2rif(pat);
        pat_delete(&instance->rif_root, pat);
        relay_rif_free(rif);
        pat = pat_getnext(&instance->rif_root, NULL, 0);
    }
    if (instance->event_base) {
        event_base_free(instance->event_base);
        instance->event_base = NULL;
    }
    if (instance->nonraw_ports) {
        free(instance->nonraw_ports);
        instance->nonraw_ports = NULL;
        instance->nonraw_count = 0;
    }

    mem_type_free(mem_rinstance_handle, instance);
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
icmp_recv(int fd, short flags, void* uap)
{
    (void)fd;
    (void)flags;
    relay_instance* instance = (relay_instance*)uap;
    struct sockaddr_in addr;
    char buf[1024];
    int bytes;
    socklen_t len = sizeof(addr);
    prefix_t* pfx;
    // patext* pat;
    // gw_t* gw;
    const char* res;
#ifdef LINUX
#define ICMPHDR icmphdr
#define ICMP_TYPE(ic) ((ic)->type)
#else
#define ICMPHDR icmp
#define ICMP_TYPE(ic) ((ic)->icmp_type)
#endif
    const struct ICMPHDR* ih;
    const struct ip* iph;
    u_int32_t dest;

    bzero(buf, sizeof(buf));
    bytes = recvfrom(instance->icmp_sk, buf, sizeof(buf), 0,
          (struct sockaddr*)&addr, &len);
    if (bytes < 0) {
        if (relay_debug(instance))
            fprintf(stderr, "Failed to receive the ICMP message\n");
        return;
    }

    iph = (const struct ip*)buf;
    ih = (const struct ICMPHDR*)(buf + iph->ip_hl * 4);

    switch (ICMP_TYPE(ih)) {
        case ICMP_UNREACH:
        case ICMP_SOURCEQUENCH:
            iph = (const struct ip*)(buf + iph->ip_hl * 4 +
                                        sizeof(struct ICMPHDR));
            dest = iph->ip_dst.s_addr;
            break;
        default:
            if (relay_debug(instance))
                fprintf(stderr, "Other ICMP message type: %d\n",
                        ICMP_TYPE(ih));
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

    instance->icmp_sk_ev = event_new(instance->event_base,
            instance->icmp_sk, EV_READ | EV_PERSIST, icmp_recv, instance);
    if (event_add(instance->icmp_sk_ev, NULL)) {
        fprintf(stderr, "ICMP socket event failed\n");
        exit(1);
    }
}

static void
relay_event_init(relay_instance* instance)
{
    instance->event_base = event_base_new();
    if (instance->event_base == NULL) {
        fprintf(stderr, "event_base_new failed\n");
        exit(1);
    }
}

static void
relay_mcast_info(int signum)
{
    (void)signum;
    relay_instance* instance;

    instance = TAILQ_FIRST(&instance_head);

    if (relay_debug(instance)) {
        fprintf(stderr, "mcast data recvd: %llu, mcast data sent: %llu\n",
              (unsigned long long)instance->stats.mcast_data_recvd,
              (unsigned long long)instance->stats.mcast_data_sent);
    }

    event_base_loopbreak(instance->event_base);
}

/*
 * relay_signal_init - Add signal handlers
 */
static void
relay_signal_init(relay_instance* instance)
{
    (void)instance;
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

int
relay_socket_shared_init(int family,
      struct sockaddr* bind_addr, int debug)
{
    int rc, val, len, sock;
    char str[MAX_SOCK_STRLEN];

    sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        fprintf(stderr, "error creating socket: %s\n", strerror(errno));
        exit(1);
    }

    val = TRUE; len = sizeof(val);
    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, len);
    if (rc < 0) {
        fprintf(stderr, "error SO_REUSEADDR socket: %s\n", strerror(errno));
        exit(1);
    }

    if (bind_addr) {
        int bind_addr_len = 0;
        if (family == AF_INET) {
            bind_addr_len = sizeof(struct sockaddr_in);
            struct sockaddr_in* psa = (struct sockaddr_in*)bind_addr;
            psa->sin_family = AF_INET;
        } else if (family == AF_INET6) {
            bind_addr_len = sizeof(struct sockaddr_in6);
            struct sockaddr_in6* psa = (struct sockaddr_in6*)bind_addr;
            psa->sin6_family = AF_INET6;
        }
        rc = bind(sock, bind_addr, bind_addr_len);
        if (rc < 0) {
            fprintf(stderr, "error binding socket to %s: %s\n",
                    sock_ntop(family, bind_addr, str, sizeof(str)),
                    strerror(errno));
            exit(1);
        }
        if (debug) {
            fprintf(stderr, "bound udp socket %d %s\n", sock,
                    sock_ntop(family, bind_addr, str, sizeof(str)));
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
    char str[MAX_ADDR_STRLEN];
    void* addrp = 0;
    int family = instance->relay_af;
    uint16_t port = instance->relay_url_port;

    if (instance->relay_url_port == 0) {
        fprintf(stderr, "Not starting RelayUrl socket for stats (RelayUrlPort=0)\n");
        return;
    }

    switch (instance->relay_af) {
        case AF_INET:
            salen = sizeof(sin);
            sa = (struct sockaddr*)&sin;
            bzero(sa, salen);
            sin.sin_family = instance->relay_af;
            sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            sin.sin_port = htons(instance->relay_url_port);
            addrp = &sin.sin_addr;
            break;

        case AF_INET6:
            salen = sizeof(sin6);
            sa = (struct sockaddr*)&sin6;
            bzero(sa, salen);
            sin6.sin6_addr = in6addr_loopback;
            sin6.sin6_family = instance->relay_af;
            sin6.sin6_port = htons(instance->relay_url_port);
            addrp = &sin6.sin6_addr;
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
        fprintf(stderr, "error creating URL socket (%s:%u): %s\n",
                inet_ntop(family, addrp, str, sizeof(str)), htons(port),
                strerror(errno));
        exit(1);
    }

    rc = bind(sock, sa, salen);
    if (rc < 0) {
        fprintf(stderr, "error binding url socket (%s:%u): %s\n",
                inet_ntop(family, addrp, str, sizeof(str)), htons(port),
                strerror(errno));
        exit(1);
    }

    rc = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
        fprintf(stderr, "error O_NONBLOCK on url socket (%s:%u): %s\n",
                inet_ntop(family, addrp, str, sizeof(str)), htons(port),
                strerror(errno));
        exit(1);
    }

    rc = listen(sock, 5);
    if (rc < 0) {
        fprintf(stderr, "error url listen on socket (%s:%u): %s\n",
                inet_ntop(family, addrp, str, sizeof(str)), htons(port),
                strerror(errno));
        exit(1);
    }

    instance->relay_url_ev = event_new(instance->event_base, sock,
            EV_READ | EV_PERSIST, relay_accept_url, (void*)instance);
    rc = event_add(instance->relay_url_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "error url event_add on socket (%s:%u): %s\n",
                inet_ntop(family, addrp, str, sizeof(str)), htons(port),
                strerror(errno));
        exit(1);
    }
    instance->relay_url_sock = sock;
}

static void
relay_anycast_socket_init(relay_instance* instance,
      struct sockaddr* listen_addr)
{
    int rc;

    {
        char str[MAX_ADDR_STRLEN];
        fprintf(stderr, "anycast listen_addr: %s\n",
                sock_ntop(instance->relay_af, &instance->listen_addr,
                    str, sizeof(str)));
        fprintf(stderr, "%p\n%p\n", &instance->listen_addr, listen_addr);
    }
    instance->relay_anycast_sock = relay_socket_shared_init(
          instance->relay_af, listen_addr, relay_debug(instance));

    instance->relay_anycast_ev = event_new(instance->event_base,
            instance->relay_anycast_sock, EV_READ | EV_PERSIST,
            relay_instance_read, (void*)instance);
    rc = event_add(instance->relay_anycast_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "error anycast event_add: %s\n", strerror(errno));
        exit(1);
    }
}

int
main(int argc, char** argv)
{
    relay_instance* instance;
    TAILQ_INIT(&instance_head);
    instance = relay_instance_alloc(AF_INET);

    int rc;
    rc = relay_parse_command_line(instance, argc, argv);
    if (rc) {
        fprintf(stderr, "failure parsing command line args\n");
        exit(1);
    }

    relay_event_init(instance);
    relay_signal_init(instance);

    {
        char str[MAX_ADDR_STRLEN];
        fprintf(stderr, "main listen_addr: %s\n",
                sock_ntop(instance->relay_af, &instance->listen_addr,
                    str, sizeof(str)));
    }
    relay_anycast_socket_init(
          instance, (struct sockaddr*)&instance->listen_addr);
    relay_url_init(instance);
    if (!BIT_TEST(instance->relay_flags, RELAY_FLAG_NOICMP)) {
        relay_icmp_init(instance);
    }
    if (!BIT_TEST(instance->relay_flags, RELAY_FLAG_NONRAW)) {
        relay_raw_socket_init(instance);
    }

    rc = event_base_dispatch(instance->event_base);
    if (rc) {
        fprintf(stderr, "failure calling event_dispatch: %s\n", strerror(rc));
    } else {
        fprintf(stderr, "event_base_dispatch completed\n");
    }
    relay_instance_free(instance);
    mem_shutdown();

    return rc;
}
