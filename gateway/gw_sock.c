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

#include <sys/socket.h>
#include <sys/types.h>
#ifndef BSD
#include <arpa/inet.h>
#endif
#include <event.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <unistd.h>

#ifndef BSD
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#include "amt.h"
#include "gw.h"

int
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

/*
static int
socket_set_reuse(int s)
{
    int rc, val, len;

    val = TRUE; len = sizeof(val);
    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, len);
    return rc;
}
*/

static int
init_shared_gateway_sock(gw_t* gw, int* sock)
{
    int dsock, rc;
    struct sockaddr_storage ss;
    bzero(&ss, sizeof(ss));
    struct sockaddr* sa = (struct sockaddr*)&ss;
    int port;
    void* in_addr;
    socklen_t slen;

    dsock = socket(gw->gateway_family, SOCK_DGRAM, 0);
    if (dsock < 0) {
        fprintf(stderr, "%s: error creating discovery socket: %s\n",
                gw->name, strerror(errno));
        return errno;
    }
    *sock = dsock;

    rc = socket_set_non_blocking(dsock);
    if (rc < 0) {
        return errno;
    }

    if (gw->tunnel_addr_set) {
        switch (gw->gateway_family) {
            case AF_INET:
            {
                struct sockaddr_in* sin = (struct sockaddr_in*)sa;
                bcopy(&gw->tunnel_addr, sin, sizeof(*sin));
                slen = sizeof(*sin);
                in_addr = &sin->sin_addr;
                sin->sin_port = 0;
            }
            break;
            case AF_INET6:
            {
                struct sockaddr_in6* sin = (struct sockaddr_in6*)sa;
                bcopy(&gw->tunnel_addr, sin, sizeof(*sin));
                slen = sizeof(*sin);
                in_addr = &sin->sin6_addr;
                sin->sin6_port = 0;
            }
            break;
            default:
                fprintf(stderr,
                        "%s: internal error: unknown gateway family %d\n",
                        gw->name, gw->gateway_family);
                exit(-1);
        }
    } else {
        switch (gw->gateway_family) {
            case AF_INET:
            {
                struct sockaddr_in* sin = (struct sockaddr_in*)sa;
                slen = sizeof(*sin);
                in_addr = &sin->sin_addr;
                sin->sin_family = gw->gateway_family;
                port = 0;
#ifdef BSD
                sin->sin_len = sizeof(*sin);
#endif
                sin->sin_addr.s_addr = htonl(INADDR_ANY);
                sin->sin_port = 0;
            }
            break;
            case AF_INET6:
            {
                struct sockaddr_in6* sin = (struct sockaddr_in6*)sa;
                slen = sizeof(*sin);
                in_addr = &sin->sin6_addr;
                sin->sin6_family = gw->gateway_family;
                port = 0;
#ifdef BSD
                sin->sin6_len = sizeof(*sin);
#endif
                sin->sin6_addr = in6addr_any;
                sin->sin6_port = 0;
            }
            break;
            default:
                fprintf(stderr,
                        "%s: internal error: unknown gateway family %d\n",
                        gw->name, gw->gateway_family);
                exit(-1);
        }
    }

    rc = bind(dsock, sa, slen);
    if (rc < 0) {
        char str[MAX_ADDR_STRLEN];
        fprintf(stderr, "%s: error binding tunnel to %s(%d): %s\n",
                gw->name, inet_ntop(gw->gateway_family, in_addr, str,
                    sizeof(str)), port, strerror(errno));
        return errno;
    }

    return 0;
}

static int
init_discovery_socket(gw_t* gw)
{
    int rc;
    rc = init_shared_gateway_sock(gw, &gw->disco_sock);
    if (rc) {
        return rc;
    }

    int dsock = gw->disco_sock;

    gw->udp_disco_ev = event_new(gw->event_base, dsock,
            EV_READ | EV_PERSIST, gw_event_udp, (void*)gw);
    rc = event_add(gw->udp_disco_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "%s: error from disco event_add: %s\n", gw->name,
              strerror(errno));
        return errno;
    }

    return 0;
}

int
init_routing_socket(gw_t* gw)
{
    int s;
/*
 * initialize routing socket
 */
#ifdef BSD
    int rc;
    s = socket(AF_ROUTE, SOCK_RAW, 0);
    if (s < 0) {
        fprintf(stderr, "%s: creating routing socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }
    rc = socket_set_non_blocking(s);
    if (rc < 0) {
        return errno;
    }
#else
    if ((s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        fprintf(stderr, "%s: creating routing socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }
#endif
    gw->rt_sock = s;
    gw->seq = random();

    return 0;
}

#if 0
// TBD: should I try to support raw external sockets instead of 
// relying on mcproxy and tunnel interface through kernel routing?
// --jake 2017-06-14
int
init_forwarding_socket(gw_t* gw)
{
    int sock;
    int rc;

    struct ifreq ifreq_v = {0};
    strncpy(ifreq_v.ifr_name, gw->cap_iface_name,
            IFNAMSIZ-1);
    sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        fprintf(stderr, "%s: error creating forwarding socket: %s\n",
                gw->name, strerror(errno));
        exit(1);
    }

    rc = socket_set_non_blocking(sock);
    if (rc) {
        fprintf(stderr, "%s: error setting forwarding nonblocking %s: %s\n",
                gw->name, gw->cap_iface_name, strerror(errno));
        exit(1);
    }

    rc = socket_set_reuse(sock);
    if (rc) {
        fprintf(stderr, "%s: error setting forwarding reuse %s: %s\n",
                gw->name, gw->cap_iface_name, strerror(errno));
        exit(1);
    }

    rc = ioctl(sock, SIOCGIFHWADDR, &ifreq_v);
    if (rc) {
        fprintf(stderr, "%s: error fetching hwaddr from interface %s: %s\n",
                gw->name, gw->cap_iface_name, strerror(errno));
        exit(1);
    }
    bcopy(&ifreq_v.ifr_hwaddr.sa_data, &gw->iface_hwaddr[0],
            sizeof(gw->iface_hwaddr));

    if (gw->debug) {
        fprintf(stderr, "mac address on %s came out as "
            "%02x:%02x:%02x:%02x:%02x:%02x\n", gw->cap_iface_name,
            gw->iface_hwaddr[0], gw->iface_hwaddr[1], gw->iface_hwaddr[2],
            gw->iface_hwaddr[3], gw->iface_hwaddr[4], gw->iface_hwaddr[5]);
    }

    gw->forwarding_sock = sock;
    return 0;
}

int
init_group_membership_socket(gw_t* gw)
{
    int sock;
    int rc;
    switch (gw->data_family) {
        case AF_INET:
        {
            sock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
            if (sock < 0) {
                fprintf(stderr, "%s: error creating group membership "
                        "socket: %s\n", gw->name, strerror(errno));
                exit(1);
            }
        }
        break;
        case AF_INET6:
        {
            sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
            if (sock < 0) {
                fprintf(stderr, "%s: error creating group membership "
                        "socket: %s\n", gw->name, strerror(errno));
                exit(1);
            }

            struct icmp6_filter filter;
            ICMP6_FILTER_SETBLOCKALL(&filter);
            ICMP6_FILTER_SETPASS(MLD_LISTENER_REPORT, &filter);
            // ICMP6_FILTER_SETPASS(ICMP6_MEMBERSHIP_REPORT, &filter);
            rc = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER,
                            (void *)&filter, sizeof(filter));
            if (rc) {
                fprintf(stderr, "%s: error setting sockopt to pass mld "
                        "membership reports: %s\n", gw->name,
                        strerror(errno));
                exit(1);
            }
        }
        break;
        default:
            fprintf(stderr, "%s: internal error: unknown data family %d\n",
                    gw->name, gw->data_family);
            exit(1);
    }

    /*
    rc = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
            gw->cap_iface_name, strlen(gw->cap_iface_name));
    */
    rc = bind(sock, (struct sockaddr*)&gw->query_addr,
            gw->data_family==AF_INET?sizeof(struct sockaddr_in):
                sizeof(struct sockaddr_in6));
    if (rc) {
        fprintf(stderr, "%s: error binding for joins on interface %s: %s\n",
                gw->name, gw->cap_iface_name, strerror(errno));
        exit(1);
    }

    rc = socket_set_non_blocking(sock);
    if (rc) {
        fprintf(stderr, "%s: error non-blocking on interface %s: %s\n",
                gw->name, gw->cap_iface_name, strerror(errno));
        exit(1);
    }

    struct ifreq ifreq_v = {0};
    strncpy(ifreq_v.ifr_name, gw->cap_iface_name,
            IFNAMSIZ-1);
    rc = ioctl(sock, SIOCGIFFLAGS, &ifreq_v);
    if (rc) {
        fprintf(stderr, "%s: error fetching flags from interface %s: %s\n",
                gw->name, gw->cap_iface_name, strerror(errno));
        exit(1);
    }
    if (!(ifreq_v.ifr_flags & IFF_MULTICAST)) {
        fprintf(stderr, "%s: interface %s has multicast disabled.\n",
                gw->name, gw->cap_iface_name);
        exit(1);
    }
    // should I also check IFF_RUNNING and/or IFF_UP? All of these can
    // change after the fact, but multicast, if wrong, is more likely to be
    // misconfigured than unplugged or something, I think.
    // -Jake 2017-05-23

    // join to receive IGMP/MLD reports
    switch (gw->data_family) {
        case AF_INET:
        {
            struct ip_mreqn mreq;
            bzero(&mreq, sizeof(mreq));
            inet_pton(AF_INET, "224.0.0.22", &mreq.imr_multiaddr);
            mreq.imr_ifindex = gw->cap_iface_index;
            bcopy(&((struct sockaddr_in*)&gw->query_addr)->sin_addr,
                    &mreq.imr_address, sizeof(struct in_addr));

            rc = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                    sizeof(mreq));
        }
        break;
        case AF_INET6:
        {
            struct ipv6_mreq mreq;
            bzero(&mreq, sizeof(mreq));
            inet_pton(AF_INET6, "FF02::16", &mreq.ipv6mr_multiaddr);
            mreq.ipv6mr_interface = gw->cap_iface_index;
            rc = setsockopt(sock, IPPROTO_IPV6,
                    IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        }
        break;
        default:
            fprintf(stderr, "%s: internal error 3, unknown family %d\n",
                    gw->name, gw->data_family);
            exit(1);
    }

    if (rc < 0) {
        fprintf(stderr, "%s: error from joining for membership reports: %s\n",
              gw->name, strerror(errno));
        return errno;
    }

    gw->membership_ev = event_new(gw->event_base, sock,
            EV_READ | EV_PERSIST, gw_event_tun, (void*)gw);
    rc = event_add(gw->membership_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "%s: error from membership event_add: %s\n",
              gw->name, strerror(errno));
        return errno;
    }

    gw->membership_sock = sock;
    return 0;
}
#endif

/*
 * Create a UDP socket to communicate with the relay.
 * Determine our local address that we should use for sending packets
 * to the relay.
 * Add our new socket to the event queue.
 */
int
gw_init_udp_sock(gw_t* gw)
{
    socklen_t ss_len;
    struct sockaddr_storage ss;
    int rc;
    rc = init_shared_gateway_sock(gw, &gw->udp_sock);
    if (rc) {
        return rc;
    }

    switch (gw->gateway_family) {
        case AF_INET:
            ss_len = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            ss_len = sizeof(struct sockaddr_in6);
            break;
        default:
            fprintf(stderr, "%s: internal error, unknown gw family %d\n",
                    gw->name, gw->gateway_family);
            return -1;
    }
    int usock = gw->udp_sock;

    rc = connect(usock, (struct sockaddr*)&gw->unicast_relay_addr, ss_len);
    if (rc < 0) {
        fprintf(stderr, "%s: connecting on UDP socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }

    bzero(&ss, sizeof(ss));
    rc = getsockname(usock, (struct sockaddr*)&ss, &ss_len);
    if (rc < 0) {
        fprintf(stderr, "%s: getsockname: %s\n", gw->name, strerror(errno));
        return errno;
    }

    if (gw->tunnel_addr_set) {
        switch (gw->gateway_family) {
            case AF_INET:
                ((struct sockaddr_in*)&gw->tunnel_addr)->sin_port =
                    ((struct sockaddr_in*)&ss)->sin_port;
                break;
            case AF_INET6:
                ((struct sockaddr_in6*)&gw->tunnel_addr)->sin6_port =
                    ((struct sockaddr_in6*)&ss)->sin6_port;
                break;
        }
        if (0 != memcmp(&gw->tunnel_addr, &ss, ss_len)) {
            char str[MAX_SOCK_STRLEN];
            char str2[MAX_SOCK_STRLEN];
            fprintf(stderr, "%s: warning: %s not the expected addr %s\n",
                    gw->name,
                    sock_ntop(gw->gateway_family, &ss, str, sizeof(str)),
                    sock_ntop(gw->gateway_family, &gw->tunnel_addr,
                        str2, sizeof(str2)));

        }
    } else {
        bcopy(&ss, &gw->tunnel_addr, ss_len);
    }
    if (gw->debug) {
        char str[MAX_SOCK_STRLEN];
        char str2[MAX_SOCK_STRLEN];
        fprintf(stderr, "%s: gateway tunnel: %s -> %s\n",
                gw->name,
                sock_ntop(gw->gateway_family, &ss, str, sizeof(str)),
                sock_ntop(gw->gateway_family, &gw->unicast_relay_addr,
                    str2, sizeof(str2)));
    }

    gw->udp_event_ev = event_new(gw->event_base, usock,
            EV_READ | EV_PERSIST, gw_event_udp, (void*)gw);
    rc = event_add(gw->udp_event_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "%s: error from udp event_add: %s\n", gw->name,
              strerror(errno));
        return errno;
    }

    return 0;
}

void
gw_cleanup_udp_sock(gw_t* gw)
{
    int rc;

    rc = event_del(gw->udp_disco_ev);
    if (rc < 0) {
        fprintf(stderr, "%s: error from disco event_del: %s\n", gw->name,
              strerror(errno));
    }
    event_free(gw->udp_disco_ev);
    gw->udp_disco_ev = 0;
    /* Close the discovery socket */
    close(gw->disco_sock);
    gw->disco_sock = 0;
}

int
init_sockets(gw_t* gw)
{
    int rc;

    rc = init_discovery_socket(gw);
    if (rc) {
        return rc;
    }
    return 0;
}

