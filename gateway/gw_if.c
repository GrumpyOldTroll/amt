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

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef BSD
#include <sys/sockio.h>
#endif

#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <time.h>

#ifdef BSD
#include <net/if_dl.h>
#else
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#define _GNU_SOURCE
#include <string.h>
#endif

#include <arpa/inet.h>
#include <net/route.h>

#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "amt.h"
#include "gw.h"

#define NL_BUFSIZE 8192
static const char __attribute__((unused)) id[] =
      "@(#) $Id: gw_if.c,v 1.1.1.9 2007/05/31 17:22:03 sachin Exp $";

/*
 * return TRUE if address a1 and address a2 are on the same network
 * a1 and a2 should be in host byte order
 */
static int
in_addr_net_compare(in_addr_t a1, in_addr_t a2, int plen)
{
    in_addr_t mask = inet_plen2mask(plen);

    return ((a1 & mask) == (a2 & mask));
}

#ifdef BSD
static u_int8_t*
net_rt_iflist(int family, int flags, size_t* lenp)
{
    int mib[6];
    u_int8_t* buf;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = family; /* only addresses of this family */
    mib[4] = NET_RT_IFLIST;
    mib[5] = flags; /* interface index or 0 */
    if (sysctl(mib, 6, NULL, lenp, NULL, 0) < 0)
        return (NULL);

    if ((buf = malloc(*lenp)) == NULL)
        return (NULL);
    if (sysctl(mib, 6, buf, lenp, NULL, 0) < 0) {
        free(buf);
        return (NULL);
    }

    return (buf);
}

/*
 * Round up 'a' to next multiple of 'size', which must be a power of 2
 */
#define ROUNDUP(a, size)                                                   \
    (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))

/*
 * Step to next socket address structure;
 * if sa_len is 0, assume it is sizeof(u_long).
 */
#define NEXT_SA(ap)                                                        \
    ap = (struct sockaddr*)((caddr_t)ap +                                  \
                            (ap->sa_len ? ROUNDUP(ap->sa_len,              \
                                                sizeof(u_long))            \
                                        : sizeof(u_long)))

static void
get_rtaddrs(int addrs, struct sockaddr* sa, struct sockaddr** rti_info)
{
    int i;

    for (i = 0; i < RTAX_MAX; i++) {
        if (addrs & (1 << i)) {
            rti_info[i] = sa;
            NEXT_SA(sa);
        } else {
            rti_info[i] = NULL;
        }
    }
}

static int
gw_if_addr_delete(gw_t* gw)
{
    struct ifreq ifr;

    snprintf(ifr.ifr_name, IFNAMSIZ, "tun%d", gw->tununit);

    bzero(&ifr, sizeof(struct ifreq));

    if (ioctl(gw->disco_sock, SIOCDIFADDR, &ifr) < 0) {
        fprintf(stderr,
              "%s: deleting remnant tunnel interface %s address: %s\n",
              gw->name, ifr.ifr_name, strerror(errno));
        return 1;
    }
    return 0;
}

/*
 * get the first unicast address that isn't on the tunnel interface.
 * delete any AMT anycast prefix addresses on the tunnel interface.
 */
static int
gw_if_addr_get(gw_t* gw)
{
    u_int8_t *buf, *next, *lim;
    struct if_msghdr* ifm = NULL;
    struct ifa_msghdr* ifam;
    struct sockaddr *sa, *rti_info[RTAX_MAX];
    struct sockaddr_dl* sdl;
    size_t len;
    char tunnel[6];
    char name[IFNAMSIZ];
    int tlen, tunnel_index = -1, delete_index = -1;

    snprintf(tunnel, sizeof(tunnel), "tun%d", gw->tununit);
    tlen = strlen(tunnel);

    /*
     * read the interface addresses
     */

    buf = net_rt_iflist(AF_INET, 0, &len);

    lim = buf + len;
    for (next = buf; next < lim; next += ifm->ifm_msglen) {
        ifm = (struct if_msghdr*)next;
        if (ifm->ifm_type == RTM_IFINFO) {
            sa = (struct sockaddr*)(ifm + 1);
            get_rtaddrs(ifm->ifm_addrs, sa, rti_info);
            sa = rti_info[RTAX_IFP];
            if (sa != NULL) {
                if (sa->sa_family == AF_LINK) {
                    sdl = (struct sockaddr_dl*)sa;
                    if (sdl->sdl_nlen > 0) {
                        int nlen;

                        /*
                         * look for tunnel interface
                         */
                        snprintf(name, sizeof(name), "%*s", sdl->sdl_nlen,
                              &sdl->sdl_data[0]);
                        nlen = strlen(name);

                        if (strncmp(name, tunnel, min(tlen, nlen)) == 0) {

                            /*
                             * found the tunnel interface
                             */
                            tunnel_index = sdl->sdl_index;
                        } else {
                            tunnel_index = -1;
                        }
                    }
                }
            }
        } else if (ifm->ifm_type == RTM_NEWADDR) {
            /*
             * Look at the existing addresses on the interface
             */
            fprintf(stderr, "%s: interface %s index %d found address\n",
                  gw->name, name, ifm->ifm_index);
            ifam = (struct ifa_msghdr*)next;
            sa = (struct sockaddr*)(ifam + 1);
            get_rtaddrs(ifam->ifam_addrs, sa, rti_info);

            sa = rti_info[RTAX_IFA];
            if (sa != NULL) {
                struct sockaddr_in* sin;

                switch (sa->sa_family) {

                    case AF_INET:
                        sin = (struct sockaddr_in*)sa;
                        /*
                         * If we have an AMT anycast address on the
                         * interface, mark it and we'll delete it later
                         */
                        if (in_addr_net_compare(gw->subnet_anycast_prefix,
                                  ntohl(sin->sin_addr.s_addr),
                                  gw->subnet_anycast_plen)) {
                            delete_index = tunnel_index;
                        }
#ifndef __linux__
                        /*
                         * Here's an address on a non-tunnel interface
                         * save the first one as our source address for
                         * control packets to the relay as long as its not
                         * a loopback address (127.x.y.z)
                         */
                        else if (!in_addr_net_compare(0x7f000000,
                                       ntohl(sin->sin_addr.s_addr), 8)) {
                            bcopy(sin, &gw->local_addr, sin->sin_len);
                        }
#endif
                        break;

                    default:
                        break;
                }
            }
        }
    }

    /*
     * If we found an address on the tunnel and its in the anycast range,
     * delete it for now.
     * We'll add it back again after we locate a relay address which
     * will bring up the tunnel interface.
     */
    if (delete_index > 0) {
        gw_if_addr_delete(gw);
    }
    return 0;
}

/*
 * set an AMT anycast address on the tunnel interface
 */

int
gw_if_addr_set(gw_t* gw)
{
    struct ifaliasreq ifra;
    struct sockaddr_in* sin;
    char str[16];

    /*
     * Add an address on the anycast subnet to the tunnel interface
     */
    snprintf(ifra.ifra_name, IFNAMSIZ, "tun%d", gw->tununit);

    sin = (struct sockaddr_in*)&ifra.ifra_addr;
    bzero(sin, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_len = sizeof(*sin);
    sin->sin_addr = inet_makeaddr(gw->subnet_anycast_prefix,
          (random() & ~inet_plen2mask(gw->subnet_anycast_plen)));
    bcopy(sin, &gw->tun_addr, sin->sin_len);

    sin = (struct sockaddr_in*)&ifra.ifra_broadaddr;
    bzero(sin, sizeof(*sin));

    sin = (struct sockaddr_in*)&ifra.ifra_mask;
    bzero(sin, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_len = sizeof(*sin);
    sin->sin_addr.s_addr = htonl(inet_plen2mask(gw->subnet_anycast_plen));

    if (ioctl(gw->disco_sock, SIOCAIFADDR, &ifra) < 0) {
        fprintf(stderr,
              "%s: problem setting tunnel interface address %s: %s\n",
              gw->name,
              inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)),
              strerror(errno));
        return 1;
    }
    return 0;
}
#else  /* LINUX_OS */
static int
parse_if_info(struct nlmsghdr* nlHdr, int* if_index, char* interface)
{
    struct rtattr* rtAttr;
    int rtLen;
    struct ifinfomsg* ifInfo;

    ifInfo = (struct ifinfomsg*)NLMSG_DATA(nlHdr);

    rtAttr = (struct rtattr*)IFLA_RTA(ifInfo);
    rtLen = IFLA_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
            case IFLA_IFNAME:
                if (strcmp(interface, (char*)RTA_DATA(rtAttr)) == 0) {
                    *if_index = ifInfo->ifi_index;
                    return 0;
                }
            default:
                break;
        }
    }
    return -1;
}

static int
read_sock(int sockFd, char* bufPtr, int seqNum, int pId)
{
    struct nlmsghdr* nlHdr;
    int readLen = 0, msgLen = 0;

    do {
        /* Receive response from kernel */
        if ((readLen = recv(sockFd, bufPtr, NL_BUFSIZE - msgLen, 0)) < 0) {
            perror("SOCK READ: ");
            return errno;
        }
        nlHdr = (struct nlmsghdr*)bufPtr;
        /* Check if header is valid */
        if (NLMSG_OK(nlHdr, readLen) == 0) {
            return -1;
        }

        /* check for error packet */
        if (nlHdr->nlmsg_type == NLMSG_ERROR) {
            // struct nlmsgerr *errHdr;
            // errHdr = (struct nlmsgerr *) NLMSG_DATA(nlHdr);
            return -1;
        }

        /* Check if its the last message */
        if (nlHdr->nlmsg_type == NLMSG_DONE) {
            break;
        } else {

            /* Move the buffer pointer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
            break;
        }
    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));
    return msgLen;
}

/* Copy the first unicast ipaddress into unicast_addr
 * copy the address on the TUN interface into sin
 */
static int
parse_if_addr(struct nlmsghdr* nlHdr,
      int if_index,
      struct sockaddr_in* sin,
      struct sockaddr_in* unicast_addr)
{
    struct ifaddrmsg* ifAddrs;
    struct rtattr* rtAttr;
    int rtLen;
    static int flag = 0;
    struct in_addr tmp_addr;
    ifAddrs = (struct ifaddrmsg*)NLMSG_DATA(nlHdr);
    rtAttr = (struct rtattr*)IFA_RTA(ifAddrs);
    rtLen = IFA_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
            case IFA_ADDRESS:
                memcpy(&tmp_addr, RTA_DATA(rtAttr), sizeof(struct in_addr));
                if (if_index == ifAddrs->ifa_index) {
                    sin->sin_family = AF_INET;
                    memcpy(&sin->sin_addr, RTA_DATA(rtAttr),
                          sizeof(struct in_addr));
                } else if (!in_addr_net_compare(
                                 0x7f000000, htonl(tmp_addr.s_addr), 8) &&
                           flag == 0) {
                    unicast_addr->sin_family = AF_INET;
                    memcpy(&unicast_addr->sin_addr, RTA_DATA(rtAttr),
                          sizeof(struct in_addr));
                    flag = 1;
                }
                break;
            default:
                break;
        }
    }
    return 0;
}

/* Given the interface name returns the interface index and address */
static int
get_if_addr(int sock,
      char* interface,
      int* if_index,
      struct sockaddr_in* sin,
      struct sockaddr_in* unicast_addr)
{
    // struct ifaddrmsg *addrMsg;
    struct nlmsghdr* nlMsg;
    // struct ifinfomsg *linkMsg;
    char msgBuf[NL_BUFSIZE];
    int len;
    static int msgSeq = 0;

    *if_index = -1;

    memset(msgBuf, 0, NL_BUFSIZE);

    nlMsg = (struct nlmsghdr*)msgBuf;
    // linkMsg = (struct ifinfomsg *)NLMSG_DATA(nlMsg);

    /* For getting interface addresses */
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlMsg->nlmsg_type = RTM_GETLINK;
    nlMsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

    nlMsg->nlmsg_seq = msgSeq++;
    nlMsg->nlmsg_pid = getpid();

    if (write(sock, nlMsg, nlMsg->nlmsg_len) < 0) {
        fprintf(stderr, "amtgwd: Write To Netlink Socket Failed\n");
        return -1;
    }

    if ((len = read_sock(sock, msgBuf, msgSeq, getpid())) < 0) {
        fprintf(stderr, "amtgwd: Read from Netlink Socket Failed\n");
        return -1;
    }

    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        /* For getting interface addresses */
        if (parse_if_info(nlMsg, if_index, interface) == 0) {
            break;
        }
    }

    if (*if_index == -1) {
        return -1;
    }

    memset(msgBuf, 0, NL_BUFSIZE);

    nlMsg = (struct nlmsghdr*)msgBuf;
    // addrMsg = (struct ifaddrmsg *)NLMSG_DATA(nlMsg);

    /* For getting interface addresses */
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlMsg->nlmsg_type = RTM_GETADDR;
    nlMsg->nlmsg_flags = NLM_F_ROOT | NLM_F_REQUEST;
    nlMsg->nlmsg_seq = msgSeq++;
    nlMsg->nlmsg_pid = getpid();

    if (write(sock, nlMsg, nlMsg->nlmsg_len) < 0) {
        fprintf(stderr, "amtgwd: Write To Netlink Socket Failed\n");
        return -1;
    }

    if ((len = read_sock(sock, msgBuf, msgSeq, getpid())) < 0) {
        fprintf(stderr, "amtgwd: Read from Netlink Socket Failed\n");
        return -1;
    }

    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        /* For getting interface addresses */
        parse_if_addr(nlMsg, *if_index, sin, unicast_addr);
    }
    return 0;
}

static void
parse_response(struct nlmsghdr* nlHdr)
{
    struct nlmsgerr* nlErr;

    nlErr = (struct nlmsgerr*)NLMSG_DATA(nlHdr);
    fprintf(stdout, "nlmsgerr:error %d\n", nlErr->error);
}

static int
addattr_l(struct nlmsghdr* n, int maxlen, int type, void* data, int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr* rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
        return -1;
    }

    rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

    return 0;
}

static int
delete_if_addr(int sock, int if_index, struct sockaddr_in* sin, int plen)
{
    struct nlmsghdr* nlMsg;
    struct ifaddrmsg* addrMsg;
    char msgBuf[NL_BUFSIZE];
    int len;
    static int msgSeq = 0;

    memset(msgBuf, 0, NL_BUFSIZE);

    nlMsg = (struct nlmsghdr*)msgBuf;
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlMsg->nlmsg_type = RTM_DELADDR;
    nlMsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlMsg->nlmsg_seq = msgSeq++;
    nlMsg->nlmsg_pid = getpid();

    addrMsg = (struct ifaddrmsg*)NLMSG_DATA(nlMsg);
    addrMsg->ifa_prefixlen = plen;
    addrMsg->ifa_family = AF_INET;
    addrMsg->ifa_index = if_index;

    if (addattr_l(nlMsg, NL_BUFSIZE, IFA_LOCAL, &sin->sin_addr.s_addr, 4) <
          0) {
        fprintf(stderr, "amtgwd: addattr_l failed\n");
        return -1;
    }

    if (write(sock, nlMsg, nlMsg->nlmsg_len) < 0) {
        fprintf(stderr, "amtgwd: Write To Netlink Socket Failed\n");
        return -1;
    }

    len = read_sock(sock, msgBuf, msgSeq, getpid());

    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        /* For getting interface addresses */
        parse_response(nlMsg);
    }
    return 0;
}

static int
set_if_addr(int sock, int if_index, struct sockaddr_in* sin, int plen)
{
    struct nlmsghdr* nlMsg;
    struct ifaddrmsg* addrMsg;
    struct in_addr ifa_local;
    char msgBuf[NL_BUFSIZE];
    int len;
    static int msgSeq = 0;

    memset(msgBuf, 0, NL_BUFSIZE);
    memset(&ifa_local, 0, sizeof(struct in_addr));

    nlMsg = (struct nlmsghdr*)msgBuf;
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlMsg->nlmsg_type = RTM_NEWADDR;
    nlMsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlMsg->nlmsg_seq = msgSeq++;
    nlMsg->nlmsg_pid = getpid();

    addrMsg = (struct ifaddrmsg*)NLMSG_DATA(nlMsg);
    addrMsg->ifa_prefixlen = plen;
    addrMsg->ifa_family = AF_INET;
    addrMsg->ifa_scope = RT_SCOPE_NOWHERE;
    addrMsg->ifa_index = if_index;

    if (addattr_l(nlMsg, NL_BUFSIZE, IFA_LOCAL, &sin->sin_addr.s_addr, 4) <
          0) {
        fprintf(stderr, "amtgwd: addattr_l() failed\n");
        return -1;
    }

    if (addattr_l(nlMsg, NL_BUFSIZE, IFA_ADDRESS, &sin->sin_addr.s_addr,
              sizeof(ifa_local.s_addr)) < 0) {
        fprintf(stderr, "amtgwd: addattr_l() failed\n");
        return -1;
    }

    if (write(sock, nlMsg, nlMsg->nlmsg_len) < 0) {
        fprintf(stderr, "amtgwd: Write To Netlink Socket Failed\n");
        return -1;
    }

    len = read_sock(sock, msgBuf, msgSeq, getpid());

    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        /* For getting interface addresses */
        parse_response(nlMsg);
    }

    return 0;
}
/*
 * get the first unicast address that isn't on the tunnel interface.
 * delete any AMT anycast prefix addresses on the tunnel interface.
 */
static int
gw_if_addr_get(gw_t* gw)
{
    int if_index;
    struct sockaddr_in sin;
    bzero(&gw->local_addr, sizeof(gw->local_addr));
    if (get_if_addr(gw->rt_sock, gw->tunifname, &if_index, &sin,
              &gw->local_addr) < 0) {
        return -1;
    }

    /* Store the interface index in the gateway */
    gw->tunindex = if_index;

    /*
     * If we have an AMT anycast address on the
     * interface, mark it and we'll delete it later
     */
    if (in_addr_net_compare(gw->subnet_anycast_prefix,
              ntohl(sin.sin_addr.s_addr), gw->subnet_anycast_plen)) {
        if (delete_if_addr(gw->rt_sock, if_index, &sin,
                  gw->subnet_anycast_plen) < 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * set an AMT anycast address on the tunnel interface
 */
int
gw_if_addr_set(gw_t* gw)
{
    struct sockaddr_in sin;
    int rc;
    unsigned long host =
          htonl(gw->local_addr.sin_addr.s_addr) >> gw->subnet_anycast_plen;

    srandom(time(NULL));
    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = inet_makeaddr(gw->subnet_anycast_prefix, host);
    bcopy(&sin, &gw->tun_addr, sizeof(sin));

    rc = set_if_addr(
          gw->rt_sock, gw->tunindex, &sin, gw->subnet_anycast_plen);
    return rc;
}
#endif /* LINUX_OS */

int
init_address(gw_t* gw)
{
    int rc;
    struct sockaddr_in* sin;

    /*
     * setup anycast address for discovery
     */
    sin = (struct sockaddr_in*)&gw->anycast_relay_addr;
    bzero(sin, sizeof(*sin));
    sin->sin_family = AF_INET;
#ifdef BSD
    sin->sin_len = sizeof(*sin);
#endif
    sin->sin_port = htons(AMT_PORT);
    sin->sin_addr = inet_makeaddr(gw->relay_anycast_address, 0x0);

    /*
     * get the first unicast address that isn't on the tunnel interface.
     */
    rc = gw_if_addr_get(gw);
    if (rc < 0) {
        return rc;
    }

#ifdef BSD
    if (gw->local_addr.sin_len == 0) {
        fprintf(stderr,
              "%s: no global unicast address on interface to use\n",
              gw->name);
        return -1;
    }
#endif

    return 0;
}

/*
 * determine the local address that is going to be used when
 * communicating with the relay.
 */
/*
int
gw_local_addr_get(gw_t *gw)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
#ifdef BSD
    addr.sin_len = sizeof(addr);
#endif
    addr.sin_addr.s_addr = gw->unicast_relay_addr.sin_addr.s_addr;
    addr.sin_port = htons(AMT_PORT);

    return 0;
}
*/

#ifdef BSD
static int
mcast_add_default(gw_t* gw)
{
    int len, rc;
    struct rt_msghdr* rtm;
    struct sockaddr_in* sin;

    rtm = (struct rt_msghdr*)gw->packet_buffer;
    len = sizeof(struct rt_msghdr) + 3 * sizeof(struct sockaddr_in);
    bzero(rtm, len);

    rtm->rtm_msglen = len;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = RTM_ADD;
    rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    rtm->rtm_pid = gw->pid;
    rtm->rtm_seq = gw->seq++;

    sin = (struct sockaddr_in*)(rtm + 1);
    sin->sin_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_UNSPEC_GROUP);

    sin++;
    sin->sin_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = gw->tun_addr.sin_addr.s_addr;

    sin++;
    sin->sin_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(inet_plen2mask(4));

    rc = write(gw->rt_sock, rtm, rtm->rtm_msglen);
    if (rc < 0) {
        fprintf(stderr, "%s: error setting multicast route: %s\n", gw->name,
              strerror(errno));
    }
    return rc;
}

/*
 * Make sure the 224/4 route is pointing out the tunnel interface
 */
int
gw_mcast_default_set(gw_t* gw)
{
    int i, len, rc, seq, tries, reply;
    struct rt_msghdr* rtm;
    struct sockaddr* sa;
    struct sockaddr_in* sin;

    /*
     * Look in the routing table for 224/4
     */

    reply = FALSE;
    seq = gw->seq++;

    rtm = (struct rt_msghdr*)gw->packet_buffer;
    len = sizeof(struct rt_msghdr) + 2 * sizeof(struct sockaddr_in);
    bzero(rtm, len);

    rtm->rtm_msglen = len;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = RTM_GET;
    rtm->rtm_addrs = RTA_DST | RTA_NETMASK;
    rtm->rtm_pid = gw->pid;
    rtm->rtm_seq = seq;

    sin = (struct sockaddr_in*)(rtm + 1);
    sin->sin_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_UNSPEC_GROUP);

    sin++;
    sin->sin_len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(inet_plen2mask(4));

    rc = write(gw->rt_sock, rtm, rtm->rtm_msglen);
    if (rc < 0) {
        switch (errno) {
            case ESRCH: /* no 224/4 route exists */
                rc = mcast_add_default(gw);
                if (rc < 0) {
                    return rc;
                }
                return 0;

            default:
                fprintf(stderr, "%s: error getting multicast route: %s\n",
                      gw->name, strerror(errno));
                return rc;
        }
    }

    tries = 10000;
    do {
        rc = read(gw->rt_sock, rtm, BUFFER_SIZE);
        if (rc < 0) {
            switch (errno) {
                case EINTR: /* try again */
                    break;
                default:
                    break;
            }
        }
        if ((rtm->rtm_type == RTM_GET) && (rtm->rtm_seq == seq) &&
              (rtm->rtm_pid == gw->pid)) {
            reply = TRUE;
        }
    } while (tries-- && (reply == FALSE));

    if (tries == 0) {
        return -1;
    }

    if (reply == FALSE) {
        return -1;
    }

    /*
     * Got reply back
     */
    sa = (struct sockaddr*)(rtm + 1);
    for (i = 0; i < RTAX_MAX; i++) {
        if (rtm->rtm_addrs & (1 << i)) {
            switch (i) {
                case RTAX_DST: /* exact match, ignore */
                case RTAX_NETMASK:
                    break;

                case RTAX_GATEWAY: /* gateway address should be tunnel */
                    sin = (struct sockaddr_in*)sa;
                    if (gw->tun_addr.sin_addr.s_addr !=
                          sin->sin_addr.s_addr) {
                        fprintf(stderr,
                              "%s: default multicast route "
                              "isn't pointing at tunnel interface\n",
                              gw->name);
                    }
                    break;
            }
            NEXT_SA(sa);
        }
    }

    return 0;
}
#else
static int
set_mcast_default_route(int sock,
      int ifa_index,
      struct sockaddr_in* sin,
      int plen)
{
    struct nlmsghdr* nlMsg;
    char msgBuf[NL_BUFSIZE];
    int len;
    static int msgSeq = 0;
    struct rtmsg* rtMsg;

    memset(msgBuf, 0, NL_BUFSIZE);

    nlMsg = (struct nlmsghdr*)msgBuf;
    rtMsg = (struct rtmsg*)NLMSG_DATA(nlMsg);

    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlMsg->nlmsg_type = RTM_NEWROUTE;
    nlMsg->nlmsg_flags =
          NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE;
    nlMsg->nlmsg_seq = msgSeq;
    nlMsg->nlmsg_pid = getpid();

    rtMsg->rtm_family = AF_INET;
    rtMsg->rtm_dst_len = plen;
    rtMsg->rtm_src_len = 0;
    rtMsg->rtm_tos = 0;
    rtMsg->rtm_table = RT_TABLE_MAIN;
    rtMsg->rtm_protocol = RTPROT_BOOT;
    rtMsg->rtm_scope = 0;
    rtMsg->rtm_type = RTN_UNICAST;
    rtMsg->rtm_flags = 0;

    if (addattr_l(nlMsg, NL_BUFSIZE, RTA_DST, &sin->sin_addr.s_addr,
              sizeof(sin->sin_addr.s_addr)) < 0) {
        fprintf(stderr, "amtgwd: addattr_l() failed\n");
        return -1;
    }

    if (addattr_l(nlMsg, NL_BUFSIZE, RTA_OIF, &ifa_index,
              sizeof(ifa_index)) < 0) {
        fprintf(stderr, "amtgwd: addattr_l() failed\n");
        return -1;
    }

    if (write(sock, nlMsg, nlMsg->nlmsg_len) < 0) {
        fprintf(stderr, "amtgwd: Write To Netlink Socket Failed\n");
        return -1;
    }

    if ((len = read_sock(sock, msgBuf, msgSeq, getpid())) < 0) {
        return -1;
    }

    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        /* For getting interface addresses */
        parse_response(nlMsg);
    }
    return 0;
}
/*
 * Make sure the 224/4 route is pointing out the tunnel interface
 */
int
gw_mcast_default_set(gw_t* gw)
{
    struct sockaddr_in sin;
    int rc;

    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_UNSPEC_GROUP);

    rc = set_mcast_default_route(gw->rt_sock, gw->tunindex, &sin, 4);
    return rc;
}
#endif /* BSD */
