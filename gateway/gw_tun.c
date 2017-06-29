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

#include <errno.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef BSD
#include <sys/linker.h>
#include <sys/module.h>
#endif /* BSD */

#include <net/if.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <unistd.h>
#ifdef BSD
#include <net/if_tun.h>
#else
#include <linux/if_tun.h>
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <event.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <linux/if_packet.h>
// #include <net/ethernet.h> /* the L2 protocols */

#include <netinet/icmp6.h>
#include "mld6.h"  // copied from freebsd 11.0
#include "igmp.h"  // copied from freebsd, linux doesn't have v3 in 2017
#include "amt.h"
#include "gw.h"

#define TUNDEV_MAX 4

static const char __attribute__((unused)) id[] =
      "@(#) $Id: gw_tun.c,v 1.1.1.8 2007/05/09 20:40:55 sachin Exp $";

#ifdef BSD
#if 0
int
init_iftun_device(gw_t* gw)
{
    int unit, fd;
    char name[FILENAME_MAX];

    for (unit = 0; unit != TUNDEV_MAX; unit++) {
        snprintf(name, sizeof(name), "/dev/tun%d", unit);
        fd = open(name, O_RDWR);
        if (fd < 0) {
            switch (errno) {
                case ENXIO:
                case ENOENT:
                    if (modfind("if_tun") < 0) {
                        if (kldload("if_tun") < 0) {
                            fprintf(stderr, "Cannot load if_tun\n");
                        }
                    }
                    break;
            }
        } else {
            int rc, mode;

            gw->tundev = fd;
            gw->tununit = unit;

            mode = IFF_BROADCAST | IFF_MULTICAST;
            rc = ioctl(fd, TUNSIFMODE, &mode);
            if (rc < 0) {
                fprintf(stderr,
                      "%s: coudn't set tunnel mode to broadcast: %s\n",
                      gw->name, strerror(errno));
                return rc;
            }

            rc = socket_set_non_blocking(fd);
            if (rc < 0) {
                fprintf(stderr,
                      "%s: coudn't set tunnel to non-blocking: %s\n",
                      gw->name, strerror(errno));
                return rc;
            }
            event_set(&gw->tun_event_id, fd, EV_READ | EV_PERSIST,
                  gw_event_tun, (void*)gw);
            rc = event_add(&gw->tun_event_id, NULL);
            if (rc < 0) {
                fprintf(stderr, "%s: error from tun event_add: %s\n",
                      gw->name, strerror(errno));
                return errno;
            }
            return fd;
        }
    }
    return fd;
}
#endif   // jake-remove
#else  /* LINUX_OS */
int
init_iftun_device(gw_t* gw)
{
    int fd;
    char name[FILENAME_MAX];
    struct ifreq ifr;

    snprintf(name, sizeof(name), "/dev/net/tun");
    fd = open(name, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "%s: couldn't open %s: %s\n", gw->name, name,
                strerror(errno));
        return -1;
    } else {
        int rc;
        int sd;

        bzero(&ifr, sizeof(struct ifreq));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, gw->cap_iface_name, IFNAMSIZ);
        rc = ioctl(fd, TUNSETIFF, &ifr);
        if (rc < 0) {
            fprintf(stderr,
                  "%s: coudn't set tunnel %s mode to broadcast: %s\n",
                  gw->name, gw->cap_iface_name, strerror(errno));
            close(fd);
            return rc;
        }

        if (strcmp(gw->cap_iface_name, ifr.ifr_ifrn.ifrn_name) != 0) {
            fprintf(stderr,
                    "%s: warning: interface names don't match %s != %s\n",
                    gw->name, gw->cap_iface_name, ifr.ifr_ifrn.ifrn_name);
        }

        sd = socket(gw->data_family, SOCK_DGRAM, 0);
        if (sd < 0) {
            perror("socket failed");
            close(fd);
            return -1;
        }
        rc = ioctl(sd, SIOCGIFFLAGS, &ifr);
        if (rc) {
            fprintf(stderr, "%s: ioctl SIOCGIFFLAGS %s failed: %s\n",
                    gw->name, ifr.ifr_name, strerror(errno));
            close(sd);
            close(fd);
            return -1;
        }
        if (!(ifr.ifr_flags & IFF_UP)) {
            ifr.ifr_flags |= IFF_UP;
            rc = ioctl(sd, SIOCSIFFLAGS, &ifr);
            if (rc) {
                fprintf(stderr, "%s: ioctl SIOCSIFFLAGS %s failed: %s\n",
                        gw->name, ifr.ifr_name, strerror(errno));
                close(sd);
                close(fd);
                return -1;
            }
        }
        close(sd);

        rc = socket_set_non_blocking(fd);
        if (rc < 0) {
            fprintf(stderr, "%s: coudn't set tunnel to non-blocking: %s\n",
                    gw->name, strerror(errno));
            close(fd);
            return rc;
        }
        printf("membership socket added\n");
        gw->membership_ev = event_new(gw->event_base, fd,
                EV_READ | EV_PERSIST, gw_event_tun, (void*)gw);
        rc = event_add(gw->membership_ev, NULL);
        if (rc < 0) {
            fprintf(stderr, "%s: error from tun event_add: %s\n", gw->name,
                  strerror(errno));
            close(fd);
            return errno;
        }
        gw->tundev = fd;
    }
    return fd;
}
#endif /* BSD */

/*
 * ip_get_hl
 *
 * Get the IP header-length.
 */
static int
ip_get_hl(struct ip* ip)
{
    return (ip->ip_hl << 2);
}

int
gw_send_local_membership_query(gw_t* gw)
{
    int rc;
    uint8_t buf[256];
    if (gw->debug) {
        fprintf(stderr, "%s: sending local membership query\n", gw->name);
    }
    int len = build_membership_query(gw->data_family,
            (struct sockaddr*)&gw->local_addr, buf, sizeof(buf));
    if (len < 0) {
        return len;
    }
    rc = write(gw->tundev, buf, len);
    if (rc < 0) {
        fprintf(stderr, "%s: error writing local IGMP query: %s\n",
                gw->name, strerror(errno));
    }
    return rc;
}

static int
gw_receive_tun(gw_t* gw, int fd)
{
    int len, tries;

    tries = 3;
    while (tries--) {
        len = read(fd, gw->packet_buffer, sizeof(gw->packet_buffer));
        if (len < 0) {
            switch (errno) {
                case EINTR: /* interrupted, retry. */
                    break;

                case EAGAIN: /* nothing to read */
                    return -1;

                default:
                    fprintf(stderr, "%s: tunnel read error: %s\n", gw->name,
                          strerror(errno));
                    return -1;
            }
        } else if (len == 0) {
            fprintf(stderr, "%s: zero length read\n", gw->name);
            return 0;
        } else {
#if 0
            {
            uint8_t* cp = gw->packet_buffer;
            printf("gw_receive_tun\n%02x%02x%02x%02x %02x%02x%02x%02x "
                   "%02x%02x%02x%02x %02x%02x%02x%02x\n"
                   "%02x%02x%02x%02x %02x%02x%02x%02x "
                   "%02x%02x%02x%02x %02x%02x%02x%02x\n",
                cp[0],cp[1],cp[2],cp[3],cp[4],cp[5],cp[6],cp[7],
                cp[8],cp[9],cp[10],cp[11],cp[12],cp[13],cp[14],cp[15],
                cp[16],cp[17],cp[18],cp[19],cp[20],cp[21],cp[22],cp[23],
                cp[24],cp[25],cp[26],cp[27],cp[28],cp[29],cp[30],cp[31]);
            }
#endif
            switch (gw->data_family) {
                case AF_INET:
                {
                    struct ip* ip;
                    u_int8_t* cp;
                    int iphlen;
                    int orig_len = len;
                    ip = (struct ip*)gw->packet_buffer;

                    switch (ip->ip_p) {
                        case IPPROTO_IGMP:
                            iphlen = ip_get_hl(ip);
                            cp = ((uint8_t*)ip) + iphlen;
                            switch (*cp) {
                                case IGMP_v1_HOST_MEMBERSHIP_REPORT:
                                case IGMP_v2_HOST_MEMBERSHIP_REPORT:
                                case IGMP_HOST_LEAVE_MESSAGE:
                                case IGMP_v3_HOST_MEMBERSHIP_REPORT:
                                    if (gw->debug) {
                                        fprintf(stderr, "%s: IGMP report type %d "
                                                "len %d from tunnel\n",
                                                gw->name, *cp, len);
                                    }
                                    gw_request_start(gw, (uint8_t*)ip, len);
                                    break;
                                case IGMP_HOST_MEMBERSHIP_QUERY:
                                    if (gw->debug) {
                                        fprintf(stderr, "%s: IGMP query type %d "
                                                "len %d from tunnel\n",
                                                gw->name, *cp, len);
                                    }
                                    break;
                                default:
                                    fprintf(stderr,
                                          "%s: IGMP type %d len %d from tunnel\n",
                                          gw->name, *cp, len);
                            }
                            break;

                        default:
                            fprintf(stderr, "%s: IP Proto %d len %d from tunnel\n",
                                  gw->name, ip->ip_p, len);
                            break;
                    }
                    return orig_len;
                }
                break;
                case AF_INET6:
                {
                    if (len < sizeof(struct ip6_hdr) + 2) {
                        fprintf(stderr, "%s: received packet len %d on %s, ignoring "
                                "(too small for ipv6(hdr=%d)\n", gw->name, len,
                                gw->cap_iface_name, (int)sizeof(struct ip6_hdr));
                        return -1;
                    }
                    struct ip6_hdr* ip;
                    u_int8_t* cp;
                    int orig_len = len;
                    cp = gw->packet_buffer;
                    ip = (struct ip6_hdr*)cp;
                    /*

                    int iphlen;
                    cp += sizeof(struct ip6_hdr);
                    len -= sizeof(struct ip6_hdr);
                    struct ip6_ext* ipe = cp;
                    uint8_t nxt = iph->ip6_nxt;
                    // 0 = next hop (we expect one of these for membership reports)
                    // 58 = ICMPv6 (https://tools.ietf.org/html/rfc2463#section-2.1)
                    // other headers may or may not be present? which should I handle?
                    // https://tools.ietf.org/html/rfc2460#section-4.2
                    // - probably abort on anything with either of top 2 bits set
                    //   (nxt&0xc0) --jake 2017-06-14
                    while (nxt != 58 && (nxt == 0 || nxt == ??)) {
                        int nxtlen = ipe->ip6e_len;
                        if (len < nxtlen + 2) {
                            fprintf(stderr, "%s: received packet len %d on %s, "
                                "ignoring (too small for ipv6(hdr=%d)\n", gw->name,
                                len, gw->cap_iface_name, (int)sizeof(*ip));
                            return -1;
                        }
                        nxt = ipe->ip6e_nxt;
                        cp += nxtlen + 2;
                        len -= nxtlen + 2;
                        ipe = (struct ip6_ext*)cp;
                    }
                    if (nxt != 58) {
                        // ignoring non-icmp packet
                        return -1;
                    }
                    if (len < sizeof(struct icmp6_hdr)) {
                        fprintf(stderr, "%s: received packet len %d on %s, "
                            "ignoring (too small for icmp6_hdr(%d)\n", gw->name,
                            len, gw->cap_iface_name,
                            (int)sizeof(struct icmp6_hdr));
                        return -1;
                    }
                    struct icmp6_hdr* icmp6 = (struct icmp6_hdr*)cp;

                    // forward if it's a membership report
                    // https://tools.ietf.org/html/rfc3810#section-5
                    if (icmp6->icmp6_type == 143)
                    struct mldv2_report* mld_report_hdr = (struct mldv2_report*)cp;
                    */
                   // TBD: above, figure out whether this is a MLD
                   // membership report, and only forward those, (and
                   // filter out link local scopes? non-global scopes?)
                   //
                   // probably better: look at mroute for what's active
                   // with this interface as a source, and generate
                   // a report. (/proc/net/mcfilter or ip show mroute? or
                   // is there some kind of netlink or ioctl that should be
                   // used?)
                   // PS: i think that would provide pim support, with
                   // pimd, as well as keeping igmp/mld support with
                   // mcproxy.
                   // jake 2017-06-14
                    if (gw->debug) {
                        fprintf(stderr, "%s: MLDv2 report (assumed) "
                                "len %d from %s, sending req to relay\n",
                                gw->name, orig_len, gw->cap_iface_name);
                    }
                    gw_request_start(gw, (uint8_t*)ip, orig_len);
                    return orig_len;
                }
                break;
                default:
                    fprintf(stderr, "%s: internal error: unknown data_family in "
                            "receive_tun\n", gw->name);
                    return -1;
                break;
            }
        }
    }
    return -1;
}

void
gw_event_tun(int fd, short __unused flags, void* uap)
{
    int len;
    gw_t* gw;

    gw = (gw_t*)uap;

    do {
        len = gw_receive_tun(gw, fd);
    } while (len > 0);
}

void
gw_forward_tun(gw_t* gw, u_int8_t* cp, int len)
{
    int tries;

#if 0
    // TBD: should I try to support forwarding on a raw socket for an 
    // interface instead of through kernel routing?
    // --jake 2017-06-29
    struct sockaddr_ll dest;
    bzero(&dest, sizeof(dest));

    dest.sll_family = AF_PACKET;
    if (gw->data_family == AF_INET) {
        if (len < sizeof(struct ip)) {
            fprintf(stderr, "%s: dropped packet len %d < ip header size\n",
                    gw->name, len);
            return;
        }
        dest.sll_protocol = htons(0x800);
        struct ip* iph = (struct ip*)cp;
        bcopy(&iph->ip_dst.s_addr, &dest.sll_addr[2], 4);
        if ((dest.sll_addr[2] & 0xe0) != dest.sll_addr[2]) {
            char str[MAX_ADDR_STRLEN];
            fprintf(stderr, "%s: dropped packet non-multicast dest: %s\n",
                    gw->name, inet_ntop(AF_INET, &iph->ip_dst, str,
                        sizeof(str)));
            return;
        }
        // https://tools.ietf.org/html/rfc1112#section-6.4
        dest.sll_addr[0] = 0x1;
        dest.sll_addr[1] = 0;
        dest.sll_addr[2] = 0x5e;
        dest.sll_addr[3] = 0x7f & dest.sll_addr[3];
    } else if (gw->data_family == AF_INET6) {
        if (len < sizeof(struct ip6_hdr)) {
            fprintf(stderr, "%s: dropped packet len %d < ip6 header size\n",
                    gw->name, len);
            return;
        }
        dest.sll_protocol = htons(0x86dd);
        struct ip6_hdr* iph = (struct ip6_hdr*)cp;
        if (iph->ip6_dst.s6_addr[0] != 0xff) {
            char str[MAX_ADDR_STRLEN];
            fprintf(stderr, "%s: dropped packet non-multicast dest: %s\n",
                    gw->name, inet_ntop(AF_INET6, &iph->ip6_dst, str,
                        sizeof(str)));
            return;
        }

        // https://tools.ietf.org/html/rfc2464#section-7
        dest.sll_addr[0] = 0x33;
        dest.sll_addr[1] = 0x33;
        bcopy(&iph->ip6_dst.s6_addr[12], &dest.sll_addr[2], 4);
    }
    dest.sll_ifindex = gw->cap_iface_index;
    dest.sll_pkttype = PACKET_MULTICAST;
    dest.sll_halen = 6;
#endif

    if (gw->debug) {
        static unsigned int npackets = 0;
        if (npackets % 10000 == 0) {
            fprintf(stderr, "%s: data packet %u forwarded on %s\n",
                    gw->name, npackets + 1, gw->cap_iface_name);
        }
        npackets += 1;
    }

    tries = 3;
    while (tries--) {
        ssize_t rc;
        /*
        rc = sendto(gw->forwarding_sock, cp, len, MSG_DONTWAIT, 
                (struct sockaddr*)&dest, sizeof(dest));
                */
        rc = write(gw->tundev, cp, len);
        if (rc < 0) {
            switch (errno) {
                case EINTR:
                case EAGAIN:
                    /* try again */
                    break;

                default:
                    fprintf(stderr, "%s: tunnel interface write: %s\n",
                          gw->name, strerror(errno));
                    return;
            }
        } else if (rc != len) {
            fprintf(stderr,
                  "%s: tunnel interface short write %d out of %d\n",
                  gw->name, (int)rc, len);
            return;
        } else {
            /* success */
            return;
        }
    }
}

