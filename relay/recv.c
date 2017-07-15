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
      "@(#) $Id: //sandbox/pyang/amt/relay/recv.c#12 $";

#include <errno.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#ifdef BSD
#include <net/bpf.h>
#include <sys/ioctl.h>
#endif /* BSD */
#include <assert.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
// #define __USE_GNU 1
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#ifdef BSD
#include <net/if_dl.h>
#include <netinet6/mld6.h>
#else
#include "mld6.h" // copied from FREEBSD 11.0
#endif
#ifdef LINUX
#include <linux/ipv6.h>
#endif
#include <linux/if_packet.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <event.h>

#include <md5.h>

#include "igmp.h"
#include "amt.h"
#include "hmac.h"
#include "memory.h"
#include "pat.h"
#include "prefix.h"
#include "relay.h"
#include "tree.h"

extern void bufferevent_setwatermark(struct bufferevent*,
      short,
      size_t,
      size_t);

#define MIN_SOCKADDR_IN_LEN 8

static mem_handle mem_packet_handle = NULL;
static mem_handle mem_rif_handle = NULL;
static mem_handle mem_url_handle = NULL;

static recv_if*
relay_rif_get(relay_instance* instance)
{
    recv_if* rif;

    if (!mem_rif_handle) {
        mem_rif_handle = mem_type_init(sizeof(recv_if), "Relay Receive IF");
    }
    rif = (recv_if*)mem_type_alloc(mem_rif_handle);
    rif->rif_instance = instance;

    return rif;
}

void
relay_rif_free(recv_if* rif)
{
    if (rif) {
        if (rif->rif_ev) {
            event_free(rif->rif_ev);
            rif->rif_ev = NULL;
        }
        mem_type_free(mem_rif_handle, rif);
    }
}

static inline packet*
relay_pkt_get(relay_instance* instance, u_int offset)
{
    packet* pkt;

    if (!mem_packet_handle) {
        mem_packet_handle = mem_type_init(sizeof(packet) + BUFFER_SIZE,
                "Relay Packet");
    }
    pkt = (packet*)mem_type_alloc(mem_packet_handle);
    pkt->pkt_instance = instance;
    pkt->pkt_offset = offset;
    pkt->pkt_data = &pkt->pkt_space[offset];

    return pkt;
}

static inline void
relay_pkt_free(packet* pkt)
{
    relay_instance* instance = pkt->pkt_instance;

    prefix_free(pkt->pkt_dst);
    prefix_free(pkt->pkt_src);

    if (TAILQ_LINKED(pkt, pkt_next)) {
        TAILQ_REMOVE(&instance->pkt_head[pkt->pkt_queue], pkt, pkt_next);
    }

    mem_type_free(mem_packet_handle, pkt);
}

static url_request*
relay_url_get(relay_instance* instance)
{
    url_request* url;

    if (!mem_url_handle) {
        mem_url_handle = mem_type_init(sizeof(url_request), "URL Request");
    }
    url = (url_request*)mem_type_alloc(mem_url_handle);
    url->url_instance = instance;

    return url;
}

void
relay_url_free(url_request* url)
{
    if (url) {
        mem_type_free(mem_url_handle, url);
    }
}

/*
 * Frees the group record list
 */
static void
free_grecord_list(group_record_list_t* grec_head)
{
    group_record_t* tmprec;
    mcast_source_t* tmpsrc;
    while (!TAILQ_EMPTY(grec_head)) {
        tmprec = TAILQ_FIRST(grec_head);
        switch (tmprec->mt) {
            case MEMBERSHIP_LEAVE:
            case MEMBERSHIP_REPORT:
                while (!TAILQ_EMPTY(&tmprec->src_head)) {
                    tmpsrc = TAILQ_FIRST(&tmprec->src_head);
                    prefix_free(tmpsrc->source);
                    TAILQ_REMOVE(&tmprec->src_head, tmpsrc, src_next);
                    free(tmpsrc);
                }
                prefix_free(tmprec->group);
                break;
            default:
                break;
        }
        TAILQ_REMOVE(grec_head, tmprec, rec_next);
        free(tmprec);
    }
}

/*
 * Parse the group records in the IGMPv3 membership report
 *
 */
static int
parse_igmp_record(relay_instance* instance,
      struct igmp_report* igmp,
      group_record_list_t* grec_head)
{
    u_int32_t mc_addr;
    group_record_t* tmp;
    struct igmp_grouprec* igmp_grec;
    mcast_source_t* gsrc;
    u_int16_t cnt, ngrec, nsrcs;
    membership_type mt = 0;

    ngrec = ntohs(igmp->ir_numgrps);
    igmp_grec = (struct igmp_grouprec*)(igmp + 1);
    while (ngrec--) {
        /* Number of sources in this group record */
        nsrcs = ntohs(igmp_grec->ig_numsrc);

        /* Record Type */
        switch (igmp_grec->ig_type) {
            case IGMP_MODE_IS_INCLUDE:
            case IGMP_CHANGE_TO_INCLUDE_MODE:
                if (nsrcs > 0) {
                    mt = MEMBERSHIP_REPORT;
                } else {
                    mt = MEMBERSHIP_LEAVE;
                }
                break;
            case IGMP_MODE_IS_EXCLUDE:
            case IGMP_CHANGE_TO_EXCLUDE_MODE:
                if (nsrcs > 0) {
                    mt = MEMBERSHIP_LEAVE;
                } else {
                    mt = MEMBERSHIP_REPORT;
                }
                break;
            case IGMP_ALLOW_NEW_SOURCES:
                mt = MEMBERSHIP_REPORT;
                break;
            case IGMP_BLOCK_OLD_SOURCES:
                mt = MEMBERSHIP_LEAVE;
                break;
            default:
                continue;
        }

        /* create a new group record */
        if ((tmp = calloc(1, sizeof(group_record_t))) == NULL) {
            free_grecord_list(grec_head);
            return FALSE;
        }

        /* Set the record type */
        tmp->mt = mt;
        tmp->nsrcs = nsrcs;

        /* Set Multicast group address */
        mc_addr = igmp_grec->ig_group.s_addr;
        if (IN_MULTICAST(ntohl(mc_addr))) {
            tmp->group = prefix_build(AF_INET, &mc_addr, INET_HOST_LEN);
        } else {
            instance->stats.igmp_group_invalid++;
            free(tmp);
            continue;
        }

        /* Add Sources */
        struct in_addr* grec_src = (struct in_addr*)(igmp_grec + 1);
        TAILQ_INIT(&tmp->src_head);
        for (cnt = 0; cnt < nsrcs; cnt++) {
            u_int32_t src = grec_src[cnt].s_addr;
            if ((gsrc = calloc(1, sizeof(mcast_source_t))) == NULL) {
                free_grecord_list(grec_head);
                return FALSE;
            }
            gsrc->source = prefix_build(AF_INET, &src, INET_HOST_LEN);

            /* Add source to the list */
            TAILQ_INSERT_TAIL(&tmp->src_head, gsrc, src_next);
        }

        /* Add the record to the list */
        TAILQ_INSERT_TAIL(grec_head, tmp, rec_next);

        /* Go the the next record */
        igmp_grec = (struct igmp_grouprec*)(((u_int8_t*)igmp_grec) +
                                          sizeof(struct igmp_grouprec) +
                                          igmp_grec->ig_datalen * 4 +
                                          (nsrcs)*4);
    }
    return TRUE;
}

/*
 * return TRUE on success
 */
static membership_type
igmp_decode(relay_instance* instance,
      packet* pkt,
      group_record_list_t* grec_head,
      prefix_t** from_ptr)
{
    int hlen, len, pktlen;
    struct ip* ip;
    struct igmpv3* igmp;
    group_record_t* tmp;
    u_int8_t* cp;
    u_int32_t mc_addr;

    cp = (u_int8_t*)pkt->pkt_data;
    pktlen = pkt->pkt_len;
    cp++; /* type */
    pktlen--;
    cp++; /* reserved */
    pktlen--;
    cp += RESPONSE_MAC_LEN;
    pktlen -= RESPONSE_MAC_LEN;
    cp += sizeof(u_int32_t);
    pktlen -= sizeof(u_int32_t);

    ip = (struct ip*)cp;

    hlen = ip->ip_hl << 2;

    igmp = (struct igmpv3*)((u_int8_t*)ip + hlen);
    len = ntohs(ip->ip_len);

    if (len != pktlen) {
        instance->stats.igmp_len_bad++;
        return MEMBERSHIP_ERROR;
    }

    /*
     * remove ip header length from igmp length
     */
    len -= hlen;
    if (len < IGMP_MINLEN) {
        instance->stats.igmp_short_bad++;
        return MEMBERSHIP_ERROR;
    }

    if (csum((uint8_t*)igmp, len)) {
        instance->stats.igmp_checksum_bad++;
        return MEMBERSHIP_ERROR;
    }

    /*
     * Save the inner IP header source address
     */
    if (from_ptr) {
        *from_ptr = prefix_build(AF_INET, &ip->ip_src.s_addr, INET_HOST_LEN);
    }

    switch (igmp->igmp_type) {
        case IGMP_v1_HOST_MEMBERSHIP_REPORT:
        case IGMP_v2_HOST_MEMBERSHIP_REPORT:
            if ((tmp = calloc(1, sizeof(group_record_t))) == NULL) {
                return FALSE;
            }

            /* Multicast group address */
            mc_addr = igmp->igmp_group.s_addr;
            if (IN_MULTICAST(ntohl(mc_addr))) {
                tmp->group = prefix_build(AF_INET, &mc_addr, INET_HOST_LEN);
            } else {
                instance->stats.igmp_group_invalid++;
                free(tmp);
                return FALSE;
            }
            tmp->mt = MEMBERSHIP_REPORT;
            TAILQ_INSERT_TAIL(grec_head, tmp, rec_next);
            break;
        case IGMP_HOST_LEAVE_MESSAGE:
            if ((tmp = calloc(1, sizeof(group_record_t))) == NULL) {
                return FALSE;
            }

            /* Multicast group address */
            mc_addr = igmp->igmp_group.s_addr;
            if (IN_MULTICAST(ntohl(mc_addr))) {
                tmp->group = prefix_build(AF_INET, &mc_addr, INET_HOST_LEN);
            } else {
                instance->stats.igmp_group_invalid++;
                free(tmp);
                return FALSE;
            }
            tmp->mt = MEMBERSHIP_LEAVE;
            TAILQ_INSERT_TAIL(grec_head, tmp, rec_next);
            break;
        case IGMP_v3_HOST_MEMBERSHIP_REPORT: {
            if (parse_igmp_record(instance, (struct igmp_report*)igmp,
                      grec_head) == FALSE) {
                return FALSE;
            }
            break;
        }
        default:
            instance->stats.igmp_packet_unsupported++;
            return FALSE;
    }
    return TRUE;
}

static int
parse_mld_record(relay_instance* instance,
      struct mldv2_report* mld_report_hdr,
      group_record_list_t* grec_head)
{
    struct mldv2_record* grec;
    u_int16_t cnt, ngrecs, nsrcs;
    group_record_t* tmp;
    membership_type mt = 0;
    struct in6_addr src_addr;
    mcast_source_t* gsrc;

    ngrecs = ntohs(mld_report_hdr->mld_numrecs);
    grec = (struct mldv2_record*)(mld_report_hdr + 1);
    while (ngrecs--) {
        nsrcs = ntohs(grec->mr_numsrc);
        switch (grec->mr_type) {
            case MLD_CHANGE_TO_INCLUDE_MODE:
            case MLD_MODE_IS_INCLUDE: {
                if (nsrcs > 0)
                    mt = MEMBERSHIP_REPORT;
                else
                    mt = MEMBERSHIP_LEAVE;
                break;
            }
            case MLD_MODE_IS_EXCLUDE:
            case MLD_CHANGE_TO_EXCLUDE_MODE: {
                if (nsrcs > 0)
                    mt = MEMBERSHIP_LEAVE;
                else
                    mt = MEMBERSHIP_REPORT;
                break;
            }
            case MLD_ALLOW_NEW_SOURCES:
                mt = MEMBERSHIP_REPORT;
                break;
            case MLD_BLOCK_OLD_SOURCES:
                mt = MEMBERSHIP_LEAVE;
                break;
        }

        /* create a new group record */
        if ((tmp = calloc(1, sizeof(group_record_t))) == NULL) {
            free_grecord_list(grec_head);
            return FALSE;
        }

        /* Set the record type */
        tmp->mt = mt;
        tmp->nsrcs = nsrcs;
#define IN6_MULTICAST(addr) (((addr) & (0xff)) == 0xff)
        if (IN6_MULTICAST(grec->mr_addr.s6_addr[0])) {
            tmp->group = prefix_build(
                  AF_INET6, grec->mr_addr.s6_addr, INET6_HOST_LEN);
        } else {
            instance->stats.mld_group_invalid++;
            free(tmp);
            continue;
        }
        TAILQ_INIT(&tmp->src_head);
        struct in6_addr* grec_src = (struct in6_addr*)(grec + 1);
        for (cnt = 0; cnt < nsrcs; cnt++) {
            src_addr = grec_src[cnt];
            if ((gsrc = calloc(1, sizeof(mcast_source_t))) == NULL) {
                free_grecord_list(grec_head);
                free(tmp);
                return FALSE;
            }
            gsrc->source =
                  prefix_build(AF_INET6, src_addr.s6_addr, INET6_HOST_LEN);
            /* Add source to the list */
            TAILQ_INSERT_TAIL(&tmp->src_head, gsrc, src_next);
        }

        /* Add the record to the list */
        TAILQ_INSERT_TAIL(grec_head, tmp, rec_next);

        /* Go the the next record */
        grec = (struct mldv2_record*)((u_int8_t*)grec + sizeof(*grec) +
                                   (grec->mr_datalen * 4) +
                                   (nsrcs * 16));
    }

    return TRUE;
}

/* Return TRUE on success */
static membership_type
mld_decode(relay_instance* instance,
      packet* pkt,
      group_record_list_t* grec_head,
      prefix_t** from_ptr)
{
    u_int8_t* cp;
    int pktlen, iphlen;
    struct ip6_hdr* ip;
    struct ip6_ext* ext_hdr;
    u_int8_t hdr_type;
    struct mldv2_query* mld_hdr;
    struct mldv2_report* mld_report_hdr;

    pktlen = pkt->pkt_len;

    /* skip AMT headers */
    cp = pkt->pkt_data;
    cp++;
    pktlen--; /* Skip type */
    cp++;
    pktlen--; /* Skip reserved */
    cp += RESPONSE_MAC_LEN;
    pktlen -= RESPONSE_MAC_LEN; /* Skip MAC */
    cp += sizeof(u_int32_t);
    pktlen -= sizeof(u_int32_t); /* Skip nonce */

    /* Process IPv6 header */
    ip = (struct ip6_hdr*)cp;
    iphlen = sizeof(*ip);
    pktlen -= sizeof(*ip);
    hdr_type = ip->ip6_nxt;
    cp += sizeof(*ip);
    while (hdr_type != IPPROTO_ICMPV6 && hdr_type != IPPROTO_NONE) {
        ext_hdr = (struct ip6_ext*)cp;
        hdr_type = ext_hdr->ip6e_nxt;
        iphlen += ((ext_hdr->ip6e_len + 1) << 3);
        cp += ((ext_hdr->ip6e_len + 1) << 3);
    }

    if (hdr_type == IPPROTO_NONE)
        return MEMBERSHIP_ERROR;

    if (ntohs(ip->ip6_plen) != pktlen) {
        instance->stats.mld_len_bad++;
        return MEMBERSHIP_ERROR;
    }

    mld_hdr = (struct mldv2_query*)cp;
    pktlen -= iphlen;
    pktlen += sizeof(*ip); /* compensation */

#define MLD_MIMLEN (sizeof(struct mldv2_report) + sizeof(struct mldv2_record))
    if (pktlen < (int)MLD_MIMLEN) {
        instance->stats.mld_short_bad++;
        return MEMBERSHIP_ERROR;
    }

    if (0 /*to-do: implement ICMP checksum */) {
        instance->stats.mld_checksum_bad++;
        return MEMBERSHIP_ERROR;
    }

    /*
 * Save the inner IP header source address
 */
    if (from_ptr) {
        *from_ptr = prefix_build(AF_INET6, ip->ip6_src.s6_addr, INET6_HOST_LEN);
    }

#ifndef BSD
// linux/bsd compatibility shim. Not there in ubuntu16.04 netinet/icmp6.h
// (though it is in linux/icmpv6.h, but i can't include that one...)
// value = 143
#ifndef MLDV2_LISTENER_REPORT 
#define MLDV2_LISTENER_REPORT 143
#endif

#endif

    /* Process the MLD message */
    switch (mld_hdr->mld_icmp6_hdr.icmp6_type) {
        case MLDV2_LISTENER_REPORT: {
            mld_report_hdr = (struct mldv2_report*)mld_hdr;
            if (parse_mld_record(instance, mld_report_hdr, grec_head) ==
                  FALSE) {
                return FALSE;
            }
            break;
        }
        default:
            instance->stats.mld_packet_unsupported++;
            return FALSE;
    }

    return TRUE;
}

/*
 * return TRUE on success
 */
static int
membership_pkt_decode(relay_instance* instance,
      packet* pkt,
      group_record_list_t* grec_head,
      prefix_t** from_ptr)
{
    switch (instance->tunnel_af) {
        /* switch(instance->relay_af) { */
        case AF_INET:
            return igmp_decode(instance, pkt, grec_head, from_ptr);
            break;
        case AF_INET6:
            return mld_decode(instance, pkt, grec_head, from_ptr);
            break;
        default:
            instance->stats.af_unsupported++;
    }
    return FALSE;
}

static u_int32_t
relay_discovery_nonce_extract(packet* pkt)
{
    u_int8_t* cp;
    int len;
    u_int32_t nonce;

    len = pkt->pkt_len;
    cp = (u_int8_t*)pkt->pkt_data;

    if (len > (int)sizeof(u_int32_t)) {
        cp += sizeof(u_int32_t);
        len -= sizeof(u_int32_t);

        if (len >= (int)sizeof(u_int32_t)) {
            nonce = get_long(cp);
            len -= sizeof(u_int32_t);

            if (len && relay_debug(pkt->pkt_instance)) {
                fprintf(stderr, "AMT Discovery with extra info, %d bytes\n",
                      len);
            }
            return nonce;
        }
    } else {
        if (relay_debug(pkt->pkt_instance)) {
            fprintf(stderr, "short AMT Discovery %d bytes\n", len);
        }
    }
    return 0;
}

static u_int32_t
relay_gw_nonce_extract(packet* pkt)
{
    u_int8_t* cp;
    int len;
    u_int32_t nonce;

    len = pkt->pkt_len;
    cp = (u_int8_t*)pkt->pkt_data;

    if (len > (int)sizeof(u_int32_t)) {
        cp += sizeof(u_int32_t);
        len -= sizeof(u_int32_t);

        if (len >= (int)sizeof(u_int32_t)) {
            nonce = get_long(cp);
            len -= sizeof(u_int32_t);

            if (len && relay_debug(pkt->pkt_instance)) {
                fprintf(stderr, "AMT Request with extra info, %d bytes\n",
                      len);
            }
            return nonce;
        }
    } else {
        if (relay_debug(pkt->pkt_instance)) {
            fprintf(stderr, "short AMT Request %d bytes\n", len);
        }
    }
    return 0;
}

static void
relay_response_mac(packet* pkt, u_int32_t nonce, u_int8_t* digest)
{
    relay_instance* instance;
    data_t data;

    instance = pkt->pkt_instance;

    bzero(&data, sizeof(data_t));
    data.nonce = nonce;
    data.sport = pkt->pkt_sport;

    bcopy(pkt->pkt_src, &data.source, sizeof(prefix_t));

    hmac_md5((u_int8_t*)&data, sizeof(data_t),
          (u_char*)instance->passphrase, strlen(instance->passphrase),
          digest);
}

/*
 * return 0 if the response mac is the same
 */
static int
relay_response_mac_verify(packet* pkt)
{
    u_int8_t *cp, *mac, digest[HMAC_LEN];
    u_int32_t nonce;
    relay_instance* instance;

    instance = pkt->pkt_instance;

    cp = (u_int8_t*)pkt->pkt_data;
    cp++; /* type */
    cp++; /* reserved */
    mac = cp;
    cp += RESPONSE_MAC_LEN;
    nonce = get_long(cp);

    relay_response_mac(pkt, nonce, digest);

    int cmp = memcmp(mac, digest, RESPONSE_MAC_LEN);
    if (relay_debug(instance)) {
        if (cmp) {
            fprintf(stderr, "Received AMT Membership Change nonce %u "
                    "received mac %02x%02x%02x%02x%02x%02x (bad: expected="
                    "%02x%02x%02x%02x%02x%02x)\n",
              nonce, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
              digest[0], digest[1], digest[2], digest[3], digest[4],
              digest[5]);
        } else {
            fprintf(stderr, "Received AMT Membership Change nonce %u "
                    "received mac %02x%02x%02x%02x%02x%02x (matched)\n",
              nonce, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
    }
    if (cmp) {
        // cisco gateway is giving the wrong last 2 bytes in version:
        /*
         * Cisco IOS XE Software, Version 03.16.04a.S - Extended Support Release
         * Cisco IOS Software, CSR1000V Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 15.5(3)S4a, RELEASE SOFTWARE (fc1)
         * Compiled Tue 04-Oct-16 07:07 by mcpre
         */
        // csr1000v-universalk9.03.17.03.S.156-1.S3-std.qcow2
        // md5: d3f8ee319643bde1be817a34a2d03f56
        cmp = memcmp(mac, digest, RESPONSE_MAC_LEN-2);
        if (!cmp && relay_debug(instance)) {
            fprintf(stderr, "Cisco compatibility mode: first 4 mac bytes "
                    "matched, so it's passed\n");
        }
    }
    return cmp;
}

/*
 * Figure out which source address we will use to talk to the gateway
 * given its destination address.
 */
static int
relay_select_src_addr(relay_instance* instance,
      prefix_t* dst,
      u_int16_t dport,
      prefix_t** srcp)
{
    (void)instance;

    /*
    // create a temporary socket, connect it to the remote address, and
    // see what the local socket address is.

    // this is cute, but doesn't work for ipv6 on ubuntu 16.04. Even when
    // I have a route, getsockname is coming back with ::1, not the true
    // source the outbound packet will have, so I'm forcing it to the
    // tunnel addr (which defaults to the discovery addr, but can be
    // set independently with -s/--tunnel-addr/TunnelAddr).
    // --jake 2017-06-20

    int s, rc;
    socklen_t len = 0;

    s = socket(dst->family, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "creating UDP socket: %s\n", strerror(errno));
        return errno;
    }

    len = prefix2sock(dst, (struct sockaddr*)&sin);
    switch(dst->family) {
        case AF_INET:
            ((struct sockaddr_in*)&sin)->sin_port = dport;
            break;
        case AF_INET6:
            ((struct sockaddr_in6*)&sin)->sin6_port = dport;
            break;
        default:
            fprintf(stderr, "internal error: unknown address family %d "
                    "in relay_select_src_addr\n", dst->family);
            exit(1);
            break;
    }

    rc = connect(s, (struct sockaddr*)&sin, len);
    if (rc < 0) {
         // we need to handle the case of no route to destination
         // EADDRNOTAVAIL
        fprintf(stderr, "relay connecting on UDP socket: %s\n",
              strerror(errno));
        close(s);
        return errno;
    }

    struct sockaddr_storage src_sin;
    socklen_t src_len = sizeof(src_sin);
    rc = getsockname(s, (struct sockaddr*)&src_sin, &src_len);
    if (rc < 0) {
        fprintf(stderr, "relay getsockname: %s\n", strerror(errno));
        close(s);
        return errno;
    }
    close(s);

    {
    char str[MAX_SOCK_STRLEN];
    fprintf(stderr, "relay getsockname: %s\n", sock_ntop(dst->family,
                &instance->relay_addr, str, sizeof(str)));
    }
    */

    *srcp = sock2prefix(instance->relay_af,
            (struct sockaddr*)&instance->relay_addr);

    return 0;
}

static void
relay_create_recv_socket(relay_instance* instance, prefix_t* src_pfx)
{
    int rc;
    struct sockaddr_storage src;
    patext* pat;
    recv_if* rif;

    /*
     * If there is a socket already for this interface address,
     * we're done.
     */
    pat = pat_get(
          &instance->rif_root, prefix_keylen(src_pfx), prefix_key(src_pfx));
    if (pat) {
        return;
    }

    /*
     * create a new socket for this interface address
     */
    rif = relay_rif_get(instance);
    bcopy(src_pfx, &rif->rif_pfx, sizeof(prefix_t));
    pat_key_set(&rif->rif_node, prefix_key(&rif->rif_pfx));
    pat_keysize_set(&rif->rif_node, prefix_keylen(&rif->rif_pfx));
    pat_add(&instance->rif_root, &rif->rif_node);

    if (instance->relay_af == AF_INET) {
        prefix2sin(src_pfx, (struct sockaddr_in*)&src);
        ((struct sockaddr_in*)&src)->sin_port = htons(instance->amt_port);
    } else {
        prefix2sin6(src_pfx, (struct sockaddr_in6*)&src);
        ((struct sockaddr_in6*)&src)->sin6_port =
            htons(instance->amt_port);
    }

    rif->rif_sock = relay_socket_shared_init(instance->relay_af,
                  (struct sockaddr*)&src, relay_debug(instance));

    if (relay_debug(instance)) {
        char str[MAX_SOCK_STRLEN];
        fprintf(stderr, "opened relay socket %d on %s\n", rif->rif_sock,
                sock_ntop(instance->relay_af, &src, str, sizeof(str)));
    }

    rif->rif_ev = event_new(instance->event_base, rif->rif_sock,
            EV_READ | EV_PERSIST, relay_instance_read, (void*)instance);
    rc = event_add(rif->rif_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "error rif event_add: %s\n", strerror(errno));
        exit(1);
    }
}

/*
 * Send back an advertisement in response to a received discovery.
 * In order for the advertisement to be received back through NATs
 * and stateful firewalls, we send it back to the address it came
 * from reversing the source and destination addresses as well as
 * source and destination ports. This means the
 * source address of the advertisement is the anycast address.
 * This only happens with the discovery/advertisement since other
 * packets are sent directly to the discovered relay and not the anycast
 * address.
 */
static void
relay_send_advertisement(packet* pkt, u_int32_t nonce, prefix_t* from)
{
    int len, dstlen = 0, tries;
    u_int8_t* cp;
    relay_instance* instance;
    struct sockaddr_in dst;
    struct sockaddr_in6 dst6;
    struct sockaddr* dst_sa = NULL;

    instance = pkt->pkt_instance;

    cp = instance->packet_buffer;    /* shared send buffer */
    *cp++ = AMT_RELAY_ADVERTISEMENT; /* type */
    *cp++ = 0;                       /* reserved */
    *cp++ = 0;                       /* reserved */
    *cp++ = 0;                       /* reserved */

    cp = put_long(cp, nonce);

    /*
     * copy our source address into the packet.
     */
    switch (from->family) {
        case AF_INET:
            bcopy(&from->addr.sin, cp, sizeof(struct in_addr));
            cp += sizeof(struct in_addr);

            /*
             * set the destination port to the received source port
             */
            dst_sa = (struct sockaddr*)&dst;
            dstlen = sizeof(dst);
            prefix2sin(pkt->pkt_src, &dst);
            dst.sin_port = pkt->pkt_sport;
            break;

        case AF_INET6:
            bcopy(&from->addr.sin6, cp, sizeof(struct in6_addr));
            cp += sizeof(struct in6_addr);

            dst_sa = (struct sockaddr*)&dst6;
            dstlen = sizeof(dst6);
            prefix2sin6(pkt->pkt_src, &dst6);
            dst6.sin6_port = pkt->pkt_sport;
            break;

        default:
            assert(from->family == AF_INET || from->family == AF_INET6);
    }

    len = cp - (u_int8_t*)instance->packet_buffer;

    tries = 3;
    while (tries--) {
        ssize_t rc;
        char str[MAX_ADDR_STRLEN], str2[MAX_ADDR_STRLEN],
              str3[MAX_ADDR_STRLEN];

        if (relay_debug(instance)) {
            fprintf(stderr, "Sending %s AMT Advertisement len %d "
                            "from %s(%u) to %s(%u) nonce %u relay %s\n",
                  (pkt->pkt_af == AF_INET) ? "INET" : "INET6", len,
                  prefix2str(pkt->pkt_dst, str, sizeof(str)),
                  ntohs(pkt->pkt_dport),
                  prefix2str(pkt->pkt_src, str2, sizeof(str2)),
                  ntohs(pkt->pkt_sport), nonce,
                  prefix2str(from, str3, sizeof(str3)));
        }

        rc = sendto(instance->relay_anycast_sock, instance->packet_buffer,
              len, MSG_DONTWAIT, dst_sa, dstlen);
        if (rc < 0) {
            switch (errno) {
                case EINTR:
                    /* try again */
                    break;

                default:
                    fprintf(stderr, "send advertisement error: %s",
                          strerror(errno));
                    return;
            }
        } else if (rc != len) {
            fprintf(stderr, "send advertisement short write %d out of %d\n",
                  (int)rc, len);
            return;
        } else {
            /* success */
            return;
        }
    }
}

static void
relay_send_membership_query(packet* pkt, u_int32_t nonce, u_int8_t* digest)
{
    int len, tries, querylen;
    u_int8_t* cp;
    relay_instance* instance;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;

    instance = pkt->pkt_instance;

    cp = instance->packet_buffer; /* shared send buffer */
    *cp++ = AMT_MEMBERSHIP_QUERY; /* type */
    *cp++ = 0;                    /* reserved */

    bcopy(digest, cp, RESPONSE_MAC_LEN);
    cp += RESPONSE_MAC_LEN;

    cp = put_long(cp, nonce);

    len = cp - (u_int8_t*)instance->packet_buffer;
    int space = sizeof(instance->packet_buffer) - len;

    querylen = build_membership_query(instance->tunnel_af,
            (struct sockaddr*)&instance->tunnel_addr, cp, space);
    if (querylen <= 0) {
        fprintf(stderr, "Error adding the IGMP/MLD membership query");
        querylen = 0;
    }

    len += querylen;

    if (pkt->pkt_af == AF_INET) {
        prefix2sin(pkt->pkt_src, &sin);
        sin.sin_port = pkt->pkt_sport;
    } else {
        prefix2sin6(pkt->pkt_src, &sin6);
        sin6.sin6_port = pkt->pkt_sport;
    }

    tries = 3;
    while (tries--) {
        ssize_t rc;
        if (pkt->pkt_af == AF_INET)
            rc = sendto(pkt->pkt_fd, instance->packet_buffer, len,
                  MSG_DONTWAIT, (struct sockaddr*)&sin, sizeof(sin));
        else
            rc = sendto(pkt->pkt_fd, instance->packet_buffer, len,
                  MSG_DONTWAIT, (struct sockaddr*)&sin6, sizeof(sin6));
        if (rc < 0) {
            switch (errno) {
                case EINTR:
                    /* try again */
                    break;

                default:
                    fprintf(stderr, "send response mac error: %s",
                          strerror(errno));
                    return;
            }
        } else if (rc != len) {
            fprintf(stderr, "send response mac short write %d out of %d\n",
                  (int)rc, len);
            return;
        } else {
            /* success */
            return;
        }
    }
}

static void
relay_packet_deq(int fd, short event, void* uap)
{
    (void)fd;
    (void)event;
    membership_type mt;
    relay_instance* instance = (relay_instance*)uap;
    packet_queue_pri queue;
    int finished = TRUE;
    u_int32_t deq_pkt_cnt = 0;

    /*
     * Simple priority scheme
     * We process all High priority packets, then all medium, then all low.
     */
    queue = HIGH;

    while ((queue < NUM_QUEUES)) {
        if (!TAILQ_EMPTY(&instance->pkt_head[queue]) &&
              deq_pkt_cnt < instance->dequeue_count) {
            prefix_t *group, *source;
            group_record_list_t grec_head;
            group_record_t* tmprec;
            mcast_source_t* tmpsrc;
            static packet* pkt;
            char str[MAX_ADDR_STRLEN], str2[MAX_ADDR_STRLEN];
            u_int32_t nonce;

            finished = FALSE;

            pkt = TAILQ_FIRST(&instance->pkt_head[queue]);
            assert(pkt);

            // fprintf(stderr, "dequeued packet, type %d\n", pkt->pkt_amt);
            switch (pkt->pkt_amt) {
                case AMT_RELAY_DISCOVERY:
                    nonce = relay_discovery_nonce_extract(pkt);
                    if (relay_debug(instance)) {
                        fprintf(stderr,
                              "Received %s AMT Discovery len %d from "
                              "%s(%u) to %s(%u) nonce %u\n",
                              (pkt->pkt_af == AF_INET) ? "INET" : "INET6",
                              pkt->pkt_len,
                              prefix2str(pkt->pkt_src, str, sizeof(str)),
                              ntohs(pkt->pkt_sport),
                              prefix2str(pkt->pkt_dst, str2, sizeof(str2)),
                              ntohs(pkt->pkt_dport), nonce);
                    }
                    if (nonce) {
                        prefix_t* src = NULL;

                        /*
                         * the src prefix gets allocated here and copied
                         * to the rif receive socket structure
                         * so we free it here.
                         */
                        if (relay_select_src_addr(instance, pkt->pkt_src,
                                  pkt->pkt_sport, &src)) {
                            if (relay_debug(instance)) {
                                fprintf(stderr,
                                      "Can't select source address for %s",
                                      prefix2str(pkt->pkt_dst, str,
                                            sizeof(str)));
                            }
                            prefix_free(src);
                            break;
                        }
                        /*
                         * If we are going to tell the gateway to use an
                         * address, make sure we have a socket open that is
                         * listening to the AMT port on that address. But
                         * in nat mode, just use the same discover socket
                         * (even though discover might respond with a
                         * different relay address)
                         */
                        if (!BIT_TEST(instance->relay_flags, RELAY_FLAG_NAT_MODE)) {
                            relay_create_recv_socket(instance, src);
                        }

                        relay_send_advertisement(pkt, nonce, src);
                        prefix_free(src);

                    } else {
                        fprintf(stderr,
                              "Invalid Relay Discovery nonce %u\n", nonce);
                    }
                    break;

                case AMT_RELAY_ADVERTISEMENT:
                    instance->stats.relay_advertisement_unexpected++;
                    break;

                case AMT_REQUEST:
                    nonce = relay_gw_nonce_extract(pkt);
                    if (relay_debug(instance)) {
                        fprintf(stderr, "Received %s AMT Request len %d "
                                        "from %s(%u) to %s(%u) nonce %u\n",
                              (pkt->pkt_af == AF_INET) ? "INET" : "INET6",
                              pkt->pkt_len,
                              prefix2str(pkt->pkt_src, str, sizeof(str)),
                              ntohs(pkt->pkt_sport),
                              prefix2str(pkt->pkt_dst, str2, sizeof(str2)),
                              ntohs(pkt->pkt_dport), nonce);
                    }
                    if (nonce) {
                        u_int8_t digest[HMAC_LEN];

                        relay_response_mac(pkt, nonce, digest);
                        relay_send_membership_query(pkt, nonce, digest);
                        if (relay_debug(instance)) {
                            fprintf(stderr, "Sent %s AMT Membership Query "
                                            "len %d from %s(%u) to %s(%u) "
                                            "nonce %u MAC "
                                            "%02x%02x%02x%02x%02x%02x\n",
                                  (pkt->pkt_af == AF_INET) ? "INET"
                                                           : "INET6",
                                  pkt->pkt_len, prefix2str(pkt->pkt_dst,
                                                      str2, sizeof(str2)),
                                  ntohs(pkt->pkt_dport),
                                  prefix2str(
                                        pkt->pkt_src, str, sizeof(str)),
                                  ntohs(pkt->pkt_sport), nonce, digest[0],
                                  digest[1], digest[2], digest[3],
                                  digest[4], digest[5]);
                        }
                    } else {
                        if (relay_debug(instance)) {
                            fprintf(stderr,
                                  "Couldn't extract gateway nonce\n");
                        }
                    }
                    break;

                case AMT_MEMBERSHIP_QUERY:
                    instance->stats.membership_query_unexpected++;
                    break;

                case AMT_MEMBERSHIP_CHANGE:
                    group = NULL;
                    source = NULL;
                    TAILQ_INIT(&grec_head);
                    /*
                     * lookup the relay nonce for the 3-way handshake
                     * if there isn't one, toss it
                     */
                    if (relay_response_mac_verify(pkt)) {
                        instance->stats.relay_response_mac_bad++;
                        break;
                    }

                    mt = membership_pkt_decode(
                          instance, pkt, &grec_head, NULL);
                    if (mt == FALSE) {
                        if (relay_debug(instance)) {
                            fprintf(stderr, "Failed to decode membership pkt\n");
                        }
                        break;
                    }
                    /* TBD: This seems not quite right. A membership report
                     * saying exclude all under group x, for instance, I
                     * think should find all joined, not result in only a
                     * leave for the asm group. Doesn't look to be
                     * there? Somewhere has to figure out the diff between
                     * relay's current picture for this gateway and gateway
                     * latest report, and it seems neither here nor in
                     * membership_tree_refresh.
                     * -Jake 2017-04-02
                     */
                    while (!TAILQ_EMPTY(&grec_head)) {
                        tmprec = TAILQ_FIRST(&grec_head);
                        group = tmprec->group;
                        mt = tmprec->mt;
                        switch (mt) {
                            case MEMBERSHIP_REPORT:
                            case MEMBERSHIP_LEAVE:
                                if (tmprec->nsrcs == 0) {
                                    membership_tree_refresh(instance, mt,
                                          pkt, group, NULL);
                                } else {
                                    while (!TAILQ_EMPTY(&tmprec->src_head)) {
                                        group = tmprec->group;
                                        if (tmprec->nsrcs > 1) {
                                            tmprec->group = prefix_dup(group);
                                            tmprec->nsrcs--;
                                        }
                                        tmpsrc = TAILQ_FIRST(
                                              &tmprec->src_head);
                                        source = tmpsrc->source;
                                        membership_tree_refresh(instance,
                                              mt, pkt, group, source);
                                        TAILQ_REMOVE(&tmprec->src_head,
                                              tmpsrc, src_next);
                                        prefix_free(source);
                                        free(tmpsrc);
                                    }
                                }
                                break;
                            case MEMBERSHIP_ERROR:
                            default:
                                break;
                        }
                        TAILQ_REMOVE(&grec_head, tmprec, rec_next);
                        prefix_free(group);
                        free(tmprec);
                    }
                    break;

                case AMT_MCAST_DATA:
                    if (relay_debug(instance)) {
                        static unsigned int data_pkts_recvd = 0;
                        if (data_pkts_recvd % 1000 == 0) {
                            fprintf(stderr,
                                "%s data packet %u, len %d "
                                "from %s(%u) to %s(%u)\n",
                                (pkt->pkt_af == AF_INET) ? "INET":"INET6",
                                data_pkts_recvd,
                                pkt->pkt_len,
                                prefix2str(pkt->pkt_src, str, sizeof(str)),
                                ntohs(pkt->pkt_sport),
                                prefix2str(pkt->pkt_dst, str2, sizeof(str2)),
                                ntohs(pkt->pkt_dport));
                        }
                        data_pkts_recvd++;
                    }
                    relay_forward(pkt);
                    break;

                default:
                    if (relay_debug(instance)) {
                        fprintf(stderr,
                              "received AMT packet without handler\n");
                    }
            }
            relay_pkt_free(pkt);
            deq_pkt_cnt++;

        } else { // RX - don't switch queue yet; keep dequeing...
                 /*
                  * traverse priority queues
              */
            switch (queue) {
                case HIGH:
                    queue = MEDIUM;
                    break;

                case MEDIUM:
                    queue = LOW;
                    break;

                case LOW:
                default:
                    queue = NUM_QUEUES;
            }
            deq_pkt_cnt = 0;
        }
    }
    if (finished) {
        evtimer_del(instance->relay_pkt_timer);
    } else {
        int rc;
        struct timeval tv;

        timerclear(&tv);
        tv.tv_usec = AMT_PACKET_Q_USEC;
        rc = evtimer_add(instance->relay_pkt_timer, &tv);
        if (rc < 0) {
            fprintf(stderr, "can't re-initialize packet timer: %s\n",
                  strerror(errno));
            exit(1);
        }
    }
}

static void
relay_packet_enq(relay_instance* instance, packet* pkt)
{
    struct timeval time_stamp;

    /*
     * Place the received packet on the input queue for processing
     *
     * Membership reports have the highest priority to reduce
     * join/leave latency (and so that leaves aren't dropped in
     * favor of data).
     *
     * Data packets have the next highest priority to reduce packet
     * forwarding latency.
     *
     * Last, Discovery messages are processed since they aren't time
     * sensitive
     */
    switch (pkt->pkt_amt) {
        case AMT_REQUEST:
        case AMT_MEMBERSHIP_QUERY:
        case AMT_MEMBERSHIP_CHANGE:
            pkt->pkt_queue = HIGH;
            break;

        case AMT_MCAST_DATA:
            pkt->pkt_queue = MEDIUM;
            gettimeofday(&time_stamp, NULL);
            pkt->enq_time =
                  time_stamp.tv_sec * 1000000 + time_stamp.tv_usec;
            instance->stats.mcast_data_recvd++;
            break;

        case AMT_RELAY_DISCOVERY:
        case AMT_RELAY_ADVERTISEMENT:
            pkt->pkt_queue = LOW;
            break;
    }
    TAILQ_INSERT_TAIL(&instance->pkt_head[pkt->pkt_queue], pkt, pkt_next);

    /*
     * Make sure the input queue timer is running so the queue will
     * get drained.
     */
    if (!instance->relay_pkt_timer) {
        instance->relay_pkt_timer = evtimer_new(instance->event_base,
                relay_packet_deq, instance);
    }

    if (!evtimer_pending(instance->relay_pkt_timer, NULL)) {
        int rc;
        struct timeval tv;

        timerclear(&tv);
        tv.tv_usec = AMT_PACKET_Q_USEC;
        // evtimer_set(instance->relay_pkt_timer, relay_packet_deq, instance);
        rc = evtimer_add(instance->relay_pkt_timer, &tv);
        if (rc < 0) {
            fprintf(stderr, "can't initialize packet timer: %s\n",
                  strerror(errno));
            exit(1);
        }
    }
}

static int
relay_socket_read(int fd, struct msghdr* msghdr)
{
    int rc = recvmsg(fd, msghdr, 0);
    if (rc < 0) {

        /* Some kind of error. */

        switch (errno) {
            case EINTR:        /* Interrupted.  Retry. */
            case EHOSTUNREACH: /* Unreachable.  Retry. */
            case ENETUNREACH:  /* Unreachable.  Retry. */
                rc = 0;
                break;

            case EWOULDBLOCK: /* Nothing to read. */
                return rc;

            default:
                fprintf(stderr, "Error on socket (%d) read: %s", fd,
                        strerror(errno));
                return rc;
        }
    }

    /* Bail if anything got truncated. */
    if (msghdr->msg_flags & MSG_TRUNC) {
        u_int len = msghdr->msg_iov[0].iov_len;
        fprintf(stderr, "received packet truncated, buffer size %d too "
                        "small, flags 0x%x\n", len,  msghdr->msg_flags);
        errno = ENOBUFS;
        return -1;
    }

    if (msghdr->msg_control && msghdr->msg_controllen &&
            (msghdr->msg_flags & MSG_CTRUNC)) {
        fprintf(stderr, "packet control truncated, buffer size %d too "
                        "small, flags 0x%x\n", (int)msghdr->msg_controllen,
                        msghdr->msg_flags);
        errno = ENOBUFS;
        return -1;
    }
    return rc;
}

void
relay_instance_read(int fd, short flags, void* uap)
{
    (void)flags;
    int len;
    relay_instance* instance;

    instance = (relay_instance*)uap;

    do {
        // this one is reading a packet from the socket to the
        // gateway.
        packet* pkt = relay_pkt_get(instance, 0);

        struct iovec iovecs[1];
        struct msghdr msghdr;
        uint8_t ctlbuf[CTLLEN];
        struct cmsghdr* cmsgp;
        struct sockaddr_storage src_addr;
        int rc;

        bzero(&iovecs, sizeof(iovecs));
        bzero(&msghdr, sizeof(msghdr));

        msghdr.msg_name = &src_addr;
        msghdr.msg_namelen = sizeof(src_addr);
        msghdr.msg_iov = &iovecs[0];
        msghdr.msg_iovlen = sizeof(iovecs)/sizeof(iovecs[0]);
        msghdr.msg_control = ctlbuf;
        msghdr.msg_controllen = sizeof(ctlbuf);

        iovecs[0].iov_base = pkt->pkt_data;
        iovecs[0].iov_len = BUFFER_SIZE - pkt->pkt_offset;

        pkt->pkt_af = instance->relay_af;
        pkt->pkt_fd = fd;
        rc = relay_socket_read(fd, &msghdr);

        if (rc <= 0) {
            if (errno == EWOULDBLOCK) {
                break;
            }
            fprintf(stderr, "error receiving packet from tunnel: %s\n",
                    strerror(errno));
            relay_pkt_free(pkt);
            break;
        }
        pkt->pkt_len = rc;
        /*
        if (relay_debug(instance)) {
            char str[MAX_SOCK_STRLEN];
            fprintf(stderr, "received packet on tunnel from %s\n",
                    sock_ntop(instance->relay_af, &src_addr, str,
                        sizeof(str)));
        }
        */

        struct sockaddr* sa_src = (struct sockaddr*)&src_addr;
        if (sa_src->sa_family != pkt->pkt_af) {
            fprintf(stderr, "error: wrong address family received on "
                    "data socket (%d != %d)\n", sa_src->sa_family,
                    pkt->pkt_af);
            relay_pkt_free(pkt);
            break;
        }

        switch (pkt->pkt_af) {
        case AF_INET:
        {
            struct sockaddr_in* sin = (struct sockaddr_in*)sa_src;
            pkt->pkt_src = prefix_build(AF_INET, &sin->sin_addr,
                    INET_HOST_LEN);
            pkt->pkt_sport = sin->sin_port;
            cmsgp = CMSG_FIRSTHDR(&msghdr);
            while (cmsgp) {
                if (cmsgp->cmsg_level == IPPROTO_IP) {
                    switch (cmsgp->cmsg_type) {
#if BSD
                    case IP_RECVIF:
                    {
                        struct sockaddr_dl* dl_addr =
                            (struct sockaddr_dl*)CMSG_DATA(cmsgp);
                        pkt->pkt_ifindex = dl_addr->sdl_index;
                    }
                    break;
                    case IP_RECVDSTADDR:
                        pkt->pkt_dst = prefix_build(
                               AF_INET, CMSG_DATA(cmsgp), INET_HOST_LEN);
                    break;
#else  // BSD
                    case IP_PKTINFO:
                    {
                        struct in_pktinfo* pktinfo =
                            (struct in_pktinfo*)CMSG_DATA(cmsgp);
                        pkt->pkt_dst = prefix_build(AF_INET,
                                &pktinfo->ipi_spec_dst, INET_HOST_LEN);
                        pkt->pkt_ifindex = pktinfo->ipi_ifindex;
                    }
                    break;
#endif  // BSD
                    default:
                        break;
                    }
                }
                cmsgp = CMSG_NXTHDR(&msghdr, cmsgp);
            }
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6* sin = (struct sockaddr_in6*)sa_src;
            pkt->pkt_src = prefix_build(AF_INET6, &sin->sin6_addr,
                    INET6_HOST_LEN);
            pkt->pkt_sport = sin->sin6_port;
            cmsgp = CMSG_FIRSTHDR(&msghdr);
            while (cmsgp) {
                if (cmsgp->cmsg_level == IPPROTO_IPV6) {
                    switch (cmsgp->cmsg_type) {
#if BSD
                    case IPV6_RECVIF:
                    {
                        struct sockaddr_dl* dl_addr =
                            (struct sockaddr_dl*)CMSG_DATA(cmsgp);
                        pkt->pkt_ifindex = dl_addr->sdl_index;
                    }
                    break;
                    case IPV6_RECVDSTADDR:
                        pkt->pkt_dst = prefix_build(
                               AF_INET6, CMSG_DATA(cmsgp), INET6_HOST_LEN);
                    break;
#else  // BSD
                    case IPV6_PKTINFO:
                    {
                        struct in6_pktinfo* pktinfo =
                            (struct in6_pktinfo*)CMSG_DATA(cmsgp);
                        pkt->pkt_dst = prefix_build(AF_INET6,
                                &pktinfo->ipi6_addr, INET6_HOST_LEN);
                        pkt->pkt_ifindex = pktinfo->ipi6_ifindex;
                        /*
                        if (relay_debug(instance)) {
                            char str[MAX_ADDR_STRLEN];
                            fprintf(stderr, "read ctlmsg dst ip %s\n",
                                    inet_ntop(AF_INET6, &pktinfo->ipi6_addr,
                                        str, sizeof(str)));
                            fprintf(stderr, "into ctlmsg dst ip %s\n",
                                    inet_ntop(AF_INET6, &pkt->pkt_dst->addr.sin6,
                                        str, sizeof(str)));
                            fprintf(stderr, "%p\n%p\n", &pkt->pkt_dst->addr.sin, &pkt->pkt_dst->addr.sin6);
                        }
                        */
                    }
                    break;
#endif  // BSD
                    default:
                        break;
                    }
                }
                cmsgp = CMSG_NXTHDR(&msghdr, cmsgp);
            }
            break;
        }
        default:
            fprintf(stderr, "internal error: unknown packet family in "
                    "relay_instance_read %d\n", pkt->pkt_af);
        }
        if (!pkt->pkt_dst) {
            fprintf(stderr, "error in relay_recv: unknown destination "
                    "address for packet\n");
            relay_pkt_free(pkt);
            break;
        }
        /*
        if (relay_debug(instance)) {
            char str[MAX_SOCK_STRLEN];
            fprintf(stderr, "                            to %s\n",
                    inet_ntop(instance->relay_af, &pkt->pkt_dst->addr.sin6, str,
                        sizeof(str)));
        }
        */


        uint8_t* cp = pkt->pkt_data;

        switch (*cp) {
            case AMT_RELAY_DISCOVERY:
            case AMT_REQUEST:
            case AMT_MEMBERSHIP_CHANGE:
                pkt->pkt_dport = htons(instance->amt_port);
            /* fall through */

            case AMT_RELAY_ADVERTISEMENT:
            case AMT_MEMBERSHIP_QUERY:
                pkt->pkt_amt = *cp;
                relay_packet_enq(instance, pkt);
                break;

            case AMT_MCAST_DATA:
                /* data from gateway not expected */
                fprintf(stderr,
                      "received data from AMT gateway, not supported\n");
                relay_pkt_free(pkt);
                break;

            default:
                fprintf(stderr, "received unknown AMT type, %u\n", *cp);
                relay_pkt_free(pkt);
                len = 0;
        }
    } while (len > 0);
}

void
relay_close_url(url_request* url)
{
    bufferevent_free(url->url_bufev);
    close(url->url_sock);
    relay_url_free(url);
}

void
relay_show_stats(relay_instance* instance, struct evbuffer* buf)
{
    evbuffer_add_printf(buf, "Address Family not supported: %u\n",
          instance->stats.af_unsupported);
    evbuffer_add_printf(buf, "IGMP packet type not supported: %u\n",
          instance->stats.igmp_packet_unsupported);
    evbuffer_add_printf(buf, "IGMP Checksum bad: %u\n",
          instance->stats.igmp_checksum_bad);
    evbuffer_add_printf(
          buf, "IGMP Length bad: %u\n", instance->stats.igmp_len_bad);
    evbuffer_add_printf(buf, "IGMP length < minimum: %u\n",
          instance->stats.igmp_short_bad);
    evbuffer_add_printf(buf, "Invalid Group Address: %u\n",
          instance->stats.igmp_group_invalid);
    evbuffer_add_printf(buf, "Response MAC mismatch: %u\n",
          instance->stats.relay_response_mac_bad);
    evbuffer_add_printf(buf, "Relay didn't expect Query: %u\n",
          instance->stats.membership_query_unexpected);
    evbuffer_add_printf(buf, "Relay didn't expect Advertisement: %u\n",
          instance->stats.relay_advertisement_unexpected);
}

static void
relay_memory_print(void* arg,
      u_int32_t size,
      u_int32_t alloced,
      u_int32_t freed,
      char* name)
{
    struct evbuffer* buf;

    buf = arg;

    evbuffer_add_printf(
          buf, "%s\t%d\t%u\t%u\n", name, size, alloced, freed);
}

void
relay_show_memory(relay_instance* instance, struct evbuffer* buf)
{
    (void)instance;
    evbuffer_add_printf(buf, "Type\tSize\tAlloced\tFreed\n");
    mem_type_show(relay_memory_print, buf);
}

void
readcb(struct bufferevent* bev, void* uap)
{
    url_request* url;
    relay_instance* instance;

    url = (url_request*)uap;
    instance = url->url_instance;

    if (evbuffer_find(EVBUFFER_INPUT(bev), (u_char*)"\r\n\r\n", 4) !=
          NULL) {
        char* str;
        struct evbuffer *hdrbuf, *databuf = NULL;

        str = evbuffer_readline(EVBUFFER_INPUT(bev));
        if (str) {
            char* cmd;

            cmd = strtok(str, " \t");
            if (strncasecmp(cmd, "GET", 3) == 0) {
                cmd = strtok(NULL, "- \t");
                if (strncasecmp(cmd, "/show", 5) == 0) {
                    cmd = strtok(NULL, "- \t");
                    if (strncasecmp(cmd, "stats", 5) == 0) {
                        databuf = evbuffer_new();
                        relay_show_stats(instance, databuf);
                    } else if (strncasecmp(cmd, "memory", 6) == 0) {
                        databuf = evbuffer_new();
                        relay_show_memory(instance, databuf);
                    } else if (strncasecmp(cmd, "streams", 5) == 0) {
                        databuf = evbuffer_new();
                        relay_show_streams(instance, databuf);
                    } else {
                        /*
                         * return file not found
                         */
                        bufferevent_disable(bev, EV_READ);
                        relay_close_url(url);
                        return;
                    }
#ifdef notyet
                } else if (strncasecmp(cmd, "/clear", 6) == 0) {
#endif /* notyet */
                } else {
                    /*
                     * return file not found
                     */
                    bufferevent_disable(bev, EV_READ);
                    relay_close_url(url);
                    return;
                }
            } else {
                /*
                 * return operation not supported
                 */
                bufferevent_disable(bev, EV_READ);
                relay_close_url(url);
                return;
            }
        }
        bufferevent_disable(bev, EV_READ);
        hdrbuf = evbuffer_new();

        evbuffer_add_printf(hdrbuf, "HTTP/1.1 200 OK\n");
        evbuffer_add_printf(hdrbuf, "Server: amtrelayd\n");
        if (databuf) {
            int len;

            len = EVBUFFER_LENGTH(databuf);
            if (len) {
                evbuffer_add_printf(hdrbuf, "Content-Length: %d\n", len);
            }
        }
        evbuffer_add_printf(hdrbuf, "Connection: close\n");
        evbuffer_add_printf(hdrbuf, "Content-Type: text/x-yaml\n");
        evbuffer_add_printf(hdrbuf, "\n");
        bufferevent_write_buffer(bev, hdrbuf);
        evbuffer_free(hdrbuf);

        if (databuf) {
            bufferevent_write_buffer(bev, databuf);
            evbuffer_free(databuf);
        }
    }
}

void
writecb(struct bufferevent* bev, void* uap)
{
    url_request* url;

    url = (url_request*)uap;

    if (EVBUFFER_LENGTH(bev->output) == 0) {
        relay_close_url(url);
    }
}

void
errorcb(struct bufferevent* bev, short what, void* uap)
{
    (void)bev;
    (void)what;
    url_request* url;

    url = (url_request*)uap;

    relay_close_url(url);
}

void
relay_accept_url(int fd, short flags, void* uap)
{
    (void)flags;
    int newfd;
    socklen_t salen;
    char str[MAX_ADDR_STRLEN];
    const char* strp;
    url_request* url;
    relay_instance* instance;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr* sa = NULL;

    instance = (relay_instance*)uap;

    switch (instance->relay_af) {
        case AF_INET:
            sa = (struct sockaddr*)&sin;
            break;

        case AF_INET6:
            sa = (struct sockaddr*)&sin6;
            break;

        default:
            assert(instance->relay_af == AF_INET ||
                   instance->relay_af == AF_INET6);
    }

    newfd = accept(fd, sa, &salen);
    if (newfd < 0) {
        switch (errno) {
            case EWOULDBLOCK:
            case ECONNABORTED:
            case EINTR:
                if (relay_debug(instance)) {
                    fprintf(stderr, "error accepting URL connection: %s\n",
                          strerror(errno));
                }
                return;

            default:
                fprintf(stderr, "error accepting URL connection: %s\n",
                      strerror(errno));
                return;
        }
    }

    switch (instance->relay_af) {
        case AF_INET:
            strp = inet_ntop(
                  instance->relay_af, &sin.sin_addr, str, sizeof(str));
            break;

        case AF_INET6:
            strp = inet_ntop(
                  instance->relay_af, &sin6.sin6_addr, str, sizeof(str));
            break;

        default:
            strp = NULL;
            assert(instance->relay_af == AF_INET ||
                   instance->relay_af == AF_INET6);
    }

    if (relay_debug(instance)) {
        if (strp) {
            fprintf(stderr, "URL connection from %s\n", strp);
        } else {
            fprintf(stderr, "URL connection with error: %s\n",
                  strerror(errno));
        }
    }

    url = relay_url_get(instance);
    url->url_sock = newfd;
    url->url_instance = instance;
    url->url_bufev = bufferevent_new(newfd, readcb, writecb, errorcb, url);

    if (url->url_bufev == NULL) {
        fprintf(
              stderr, "error url buffer event new: %s\n", strerror(errno));
        exit(1);
    }

    bufferevent_setwatermark(url->url_bufev, EV_READ, (size_t)0, (size_t)0);
}

/*
static void
print_pat(patext* pat)
{
    int i;

    for (i = 0; i < (pat->keysize >> 3); i++) {
        fprintf(stderr, "%c", pat->key[i]);
    }
    fprintf(stderr, " %u\n", pat->keysize);
}
*/

static uint8_t*
relay_packet_insert_before(packet* pkt, const char* desc, unsigned int len)
{
    if (pkt->pkt_offset < len) {
        fprintf(stderr, "not enough offset space ahead of nonraw "
                "packet for %s (%u < %u)\n", desc, pkt->pkt_offset, len);
        exit(1);
    }

    pkt->pkt_len += len;
    pkt->pkt_data -= len;
    pkt->pkt_offset -= len;

    return pkt->pkt_data;
}


static void
nonraw_data_read(int fd, short flags, void* uap)
{
    (void)flags;
    grrecv* gv = (grrecv*)uap;
    grnode* gr = gv->gv_gr;
    relay_instance* instance = gr->gr_instance;
    int rc;

    do {
        // here we're reading a udp payload, but we have to construct
        // from it an amt data packet as the udp payload to send. (amt
        // data payload starts at the ip header).

        // so leave space to fill in a full ipv4 header or a big ip6
        // header, plus 8 bytes of udp header, plus the 2 bytes of amt data
        // header in front of the udp payload data we're reading here.
        // (might we want this bigger for any reason?)

        packet* pkt = relay_pkt_get(instance, 80 + 8 + 2);

        struct iovec iovecs[1];
        struct msghdr msghdr;
        uint8_t ctlbuf[CTLLEN];
        struct cmsghdr* cmsgp;
        struct sockaddr_storage src_addr;
        uint8_t* cp;

        bzero(&iovecs, sizeof(iovecs));
        bzero(&msghdr, sizeof(msghdr));

        msghdr.msg_name = &src_addr;
        msghdr.msg_namelen = sizeof(src_addr);
        msghdr.msg_iov = &iovecs[0];
        msghdr.msg_iovlen = sizeof(iovecs)/sizeof(iovecs[0]);
        msghdr.msg_control = ctlbuf;
        msghdr.msg_controllen = sizeof(ctlbuf);

        iovecs[0].iov_base = pkt->pkt_data;
        iovecs[0].iov_len = BUFFER_SIZE - pkt->pkt_offset;

        pkt->pkt_af = instance->tunnel_af;
        pkt->pkt_ifindex = instance->cap_iface_index;
        rc = relay_socket_read(fd, &msghdr);

        if (rc <= 0) {
            if (errno == EWOULDBLOCK) {
                break;
            }
            fprintf(stderr, "error receiving nonraw data packet: %s\n",
                    strerror(errno));
            relay_pkt_free(pkt);
            break;
        }
        pkt->pkt_len = rc;
        pkt->pkt_amt = AMT_MCAST_DATA;

        struct sockaddr* sa_src = (struct sockaddr*)&src_addr;
        if (sa_src->sa_family != pkt->pkt_af) {
            fprintf(stderr, "error: wrong address family received on "
                    "data socket (%d != %d)\n", sa_src->sa_family,
                    pkt->pkt_af);
            relay_pkt_free(pkt);
            break;
        }

        pkt->pkt_dst = prefix_dup(gr->gr_group);
        pkt->pkt_dport = htons(gv->gv_port);

        switch (pkt->pkt_af) {
        case AF_INET:
        {
            struct sockaddr_in* sin = (struct sockaddr_in*)sa_src;
            pkt->pkt_src = prefix_build(AF_INET, &sin->sin_addr,
                    INET_HOST_LEN);
            pkt->pkt_sport = sin->sin_port;

            // insert headers ahead of data we read
            cp = relay_packet_insert_before(pkt, "udp header",
                    sizeof(struct udphdr));
            struct udphdr* udph = (struct udphdr*)cp;
            UH_SPORT(udph) = pkt->pkt_sport;
            UH_DPORT(udph) = pkt->pkt_dport;
            UH_ULEN(udph) = htons(pkt->pkt_len); // note: changes in insert
            UH_SUM(udph) = 0;
            uint8_t ttl = 50, tos = 0;
            unsigned int opt_size = 0;
            unsigned int opt_len = 0;

            /*
             * Get the incoming interface index for filter comparisons.
             * Get the destination IP address to find anycast packets.
             */
            cmsgp = CMSG_FIRSTHDR(&msghdr);
            while (cmsgp) {
                if (cmsgp->cmsg_level == IPPROTO_IP) {
                    switch (cmsgp->cmsg_type) {
#if BSD
                    case IP_RECVIF:
                    {
                        struct sockaddr_dl* dl_addr =
                            (struct sockaddr_dl*)CMSG_DATA(cmsgp);
                        if (dl_addr->sdl_index !=
                                instance->cap_iface_index) {
                            fprintf(stderr, "data packet received on "
                                    "unexpected interface %d instead of "
                                    "%d\n", dl_addr->sdl_index,
                                    instance->cap_iface_index);
                        }
                        // pkt->pkt_ifindex = dl_addr->sdl_index;
                    }
                    break;
                    case IP_RECVDSTADDR:
                        /* ignore the dest from here, if we're receiving
                         * it here it should be the group's addr.
                         */
                        assert(cmsgp->cmsg_len >= sizeof(struct in_addr));
                        // pkt->pkt_dst = prefix_build(
                        //       AF_INET, CMSG_DATA(cmsgp), INET_HOST_LEN);
                    break;
#else  // BSD
                    case IP_PKTINFO:
                    {
                        struct in_pktinfo* pktinfo =
                            (struct in_pktinfo*)CMSG_DATA(cmsgp);
                        /* ignore the dest from here, it's the interface's
                         * addr instead of the packet's destination
                         * (which is supposed to be this group's addr)
                         */
                        // struct in_addr s_addr = pktinfo->ipi_spec_dst;
                        // pkt->pkt_dst =
                        //   prefix_build(AF_INET, &s_addr, INET_HOST_LEN);
                        if (pktinfo->ipi_ifindex !=
                                instance->cap_iface_index) {
                            fprintf(stderr, "data packet received on "
                                    "unexpected interface %d instead of "
                                    "%d\n", pktinfo->ipi_ifindex,
                                    instance->cap_iface_index);
                        }
                        // pkt->pkt_ifindex = pktinfo->ipi_ifindex;
                    }
                    break;
#endif  // BSD
                    case IP_OPTIONS:
                    {
                        // with IP_RECVOPTS
                        if (opt_size != 0) {
                            fprintf(stderr, "internal error: got "
                                    "IP_OPTIONS multiple times in a "
                                    "packet?\n");
                            break;
                        }
                        opt_len = cmsgp->cmsg_len;
                        opt_size = ((opt_len + 3) / 4) * 4;
                        if (!opt_size) {
                            break;
                        }
                        if (opt_size + 22 > pkt->pkt_offset) {
                            fprintf(stderr, "%d: not enough buffer space "
                                    "for options len %d and ip and amt "
                                    "headers\n", pkt->pkt_offset, opt_len);
                            opt_size = 0;
                            break;
                        }
                        cp = relay_packet_insert_before(pkt,
                                "ip options", opt_size);
                        bcopy(CMSG_DATA(cmsgp), cp, opt_len);
                        if (opt_len != opt_size) {
                            assert(opt_len < opt_size);
                            bzero(cp + opt_len, opt_size - opt_len);
                        }
                    }
                    break;
                    case IP_TOS:
                        // with IP_RECVTOS
                        // do I fwd this or should I force it to my own?
                        tos = *(u_int8_t*)CMSG_DATA(cmsgp);
                    break;
                    case IP_TTL:
                    case IP_RECVTTL:
                    // http://man7.org/linux/man-pages/man7/ip.7.html
                        // with IP_RECVTTL
                        // TBD: should I fwd this or should I force it to
                        // my own?
                        ttl = *(u_int8_t*)CMSG_DATA(cmsgp);
                    break;
                    default:
                        fprintf(stderr, "ignored cmsg_type=%d\n",
                                cmsgp->cmsg_type);
                    }
                }
                cmsgp = CMSG_NXTHDR(&msghdr, cmsgp);
            }

            cp = relay_packet_insert_before(pkt, "ip header",
                    sizeof(struct ip));
            struct ip* iph = (struct ip*)cp;
            iph->ip_hl = (20 + opt_size) / 4;
            iph->ip_v = 4;
            iph->ip_tos = tos;
            iph->ip_len = htons(pkt->pkt_len); // note: changed in insert
            iph->ip_id = instance->next_ip_id++;
            iph->ip_off = 0;
            iph->ip_ttl = ttl;
            iph->ip_p = IPPROTO_UDP;
            iph->ip_sum = 0;
            iph->ip_src = pkt->pkt_src->addr.sin;
            iph->ip_dst = pkt->pkt_dst->addr.sin;

            cp = relay_packet_insert_before(pkt, "amt header", 2);
            *cp = 6;
            *(cp + 1) = 0;

            iph->ip_sum = csum((uint8_t*)iph, 4*iph->ip_hl);
            /*
            // this works, but can just be 0, the udp checksum is
            // optional in ip4.
            // [TBD]: make udp checksum optional separately?
            uint8_t pshdr_v[4];
            pshdr_v[0] = 0;
            pshdr_v[1] = iph->ip_p;
            pshdr_v[2] = uph->uh_ulen >> 8;
            pshdr_v[3] = (uph->uh_ulen) & 0xff;
            struct iovec iov[3];
            unsigned int niovs = sizeof(iov)/sizeof(iov[0]);
            iov[0].iov_base = ((uint8_t*)iph)+12;
            iov[0].iov_len = 8;
            iov[1].iov_base = pshdr_v;
            iov[1].iov_len = 4;
            iov[2].iov_base = uph;
            iov[2].iov_len = ntohs(uph->uh_ulen);
            uph->uh_sum = iov_csum(iov, niovs);
            */
        }
        break;

        case AF_INET6:
        {
            struct sockaddr_in6* sin = (struct sockaddr_in6*)sa_src;
            pkt->pkt_src = prefix_build(AF_INET6, &sin->sin6_addr,
                    INET6_HOST_LEN);
            pkt->pkt_sport = sin->sin6_port;

            // insert headers ahead of data we read
            cp = relay_packet_insert_before(pkt, "udp header",
                    sizeof(struct udphdr));
            struct udphdr* udph = (struct udphdr*)cp;
            UH_SPORT(udph) = pkt->pkt_sport;
            UH_DPORT(udph) = pkt->pkt_dport;
            UH_ULEN(udph) = htons(pkt->pkt_len); // note: changes in insert
            UH_SUM(udph) = 0;
            uint8_t ttl = 50;
            uint8_t tos = 0;
            /*
            unsigned int opt_size = 0;
            unsigned int opt_len = 0;
            */

            /*
             * Get the incoming interface index for filter comparisons.
             * Get the destination IP address to find anycast packets.
             */
            cmsgp = CMSG_FIRSTHDR(&msghdr);
            while (cmsgp) {
                if (cmsgp->cmsg_level == IPPROTO_IPV6) {
                    // TBD: probably get extension headers, if any.
                    // maybe also nexthop and routing? not sure if that's
                    // appropriate or not.
                    // --jake 2017-06-18
                    switch (cmsgp->cmsg_type) {
                    case IPV6_PKTINFO:
                    {
                        struct in6_pktinfo* pktinfo = 
                              (struct in6_pktinfo*)CMSG_DATA(cmsgp);
                        /* ignore the dest from here, if we're receiving
                         * it here it should be the group's addr.
                         */
                        /*
                        struct in6_addr s_addr;
                        bcopy(&pktinfo->ipi6_addr, &s_addr,
                            sizeof(s_addr));
                        pkt->pkt_dst = prefix_build(
                              AF_INET6, &s_addr, INET6_HOST_LEN);
                              */
                        if (pktinfo->ipi6_ifindex !=
                                instance->cap_iface_index) {
                            fprintf(stderr, "data packet received on "
                                    "unexpected interface %d instead of "
                                    "%d\n", pktinfo->ipi6_ifindex,
                                    instance->cap_iface_index);
                        }
                    }
                    break;
                    default:
                        fprintf(stderr, "ignored ncmsg_type=%d\n", cmsgp->cmsg_type);
                    }
                }
                cmsgp = CMSG_NXTHDR(&msghdr, cmsgp);
            }

            cp = relay_packet_insert_before(pkt, "ip6 header",
                    sizeof(struct ip6_hdr));
            struct ip6_hdr* iph = (struct ip6_hdr*)cp;
            bzero(&iph->ip6_ctlun, sizeof(iph->ip6_ctlun));
            iph->ip6_flow = (((uint32_t)0x6) << 28) |
                (((uint32_t)tos)<<20);
            iph->ip6_plen = ntohs(pkt->pkt_len);
            iph->ip6_nxt = 17; // UDP
            iph->ip6_hlim = ttl;
            bcopy(&pkt->pkt_src->addr, &iph->ip6_src,
                    sizeof(iph->ip6_src));
            bcopy(&pkt->pkt_dst->addr, &iph->ip6_dst,
                    sizeof(iph->ip6_dst));

            cp = relay_packet_insert_before(pkt, "amt header", 2);
            *cp = 6;
            *(cp + 1) = 0;

            // udp checksum is required:
            // https://tools.ietf.org/html/rfc2460#section-8.1
            struct pshdr {
                uint32_t uh_len;
                uint8_t pshdr_v[4];
            } pshd;
            pshd.uh_len = ntohl(ntohs(UH_ULEN(udph)));
            pshd.pshdr_v[0] = 0;
            pshd.pshdr_v[1] = 0;
            pshd.pshdr_v[2] = 0;
            pshd.pshdr_v[3] = 17;
            struct iovec iov[3];
            unsigned int niovs = sizeof(iov)/sizeof(iov[0]);
            iov[0].iov_base = &iph->ip6_src;
            iov[0].iov_len = 32;
            iov[1].iov_base = &pshd;
            iov[1].iov_len = 8;
            iov[2].iov_base = udph;
            iov[2].iov_len = ntohs(UH_ULEN(udph));
            UH_SUM(udph) = 0;
            UH_SUM(udph) = iov_csum(iov, niovs);

            /*
            if (relay_debug(pkt->pkt_instance)) {
                static unsigned int data_pkts_recvd = 0;
                data_pkts_recvd += 1;
                char str[MAX_ADDR_STRLEN], str2[MAX_ADDR_STRLEN];
                fprintf(stderr,
                    "Received inet6 data packet %u, len %d "
                    "from %s:%u to %s:%u\n",
                    data_pkts_recvd,
                    pkt->pkt_len,
                    prefix2str(pkt->pkt_src, str, sizeof(str)),
                    ntohs(pkt->pkt_sport),
                    prefix2str(pkt->pkt_dst, str2, sizeof(str2)),
                    ntohs(pkt->pkt_dport));
            }
            */
        }
        break;

        default:
            fprintf(stderr, "internal error: unknown family %d in "
                    "nonraw_data_read\n", pkt->pkt_af);
            exit(1);
        }

        relay_packet_enq(instance, pkt);
    } while (rc > 0);
}

static int
nonraw_socket_init(grrecv* gv)
{
    relay_instance* instance = gv->gv_gr->gr_instance;
    int family = instance->tunnel_af;
    char str[MAX_ADDR_STRLEN];
    struct sockaddr_storage gaddr_buf;
    struct sockaddr* gaddr = (struct sockaddr*)&gaddr_buf;
    int gaddr_len = prefix2sock(gv->gv_gr->gr_group, gaddr);
    int sock;
    int trueval = 1;
    int rc;

    sock = socket(family, SOCK_DGRAM, 0);
    if (relay_debug(instance)) {
        fprintf(stderr, "created data socket: %d, binding %s(:%u)\n",
                sock, sock_ntop(family, gaddr, str, sizeof(str)),
                gv->gv_port);
    }
    if (sock < 0) {
        fprintf(stderr, "error creating data socket: %s\n",
                strerror(errno));
        return -1;
    }

    switch(family) {
    case AF_INET:
    {
        ((struct sockaddr_in*)gaddr)->sin_port =
            htons(gv->gv_port);
        rc = bind(sock, gaddr, gaddr_len);
        if (rc < 0) {
            fprintf(stderr, "error binding data socket: (%s):%u %s\n",
                    sock_ntop(family, gaddr, str, sizeof(str)),
                    gv->gv_port, strerror(errno));
            return -1;
        }
#ifdef BSD
        rc = setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR, &trueval,
                sizeof(int));
        if (rc < 0) {
            fprintf(stderr, "error IP_RECVDSTADDR on socket: %s\n",
                  strerror(errno));
            return -1;
        }
        rc = setsockopt(sock, IPPROTO_IP, IP_RECVIF, &trueval,
                sizeof(int));
        if (rc < 0) {
            fprintf(stderr, "error IP_RECVIF on socket: %s\n", strerror(errno));
            return -1;
        }
#else
        rc = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &trueval,
                sizeof(int));
        if (rc < 0) {
            fprintf(stderr, "error IP_RECVDSTADDR on socket: %s\n",
                  strerror(errno));
            return -1;
        }
#endif
        rc = setsockopt(sock, IPPROTO_IP, IP_RECVOPTS,
              &trueval, sizeof(int));
        if (rc < 0) {
            fprintf(stderr, "error IP_RECVOPTS sg socket: %s\n",
                  strerror(errno));
            return -1;
        }
        rc = setsockopt(sock, IPPROTO_IP, IP_RECVTOS,
              &trueval, sizeof(int));
        if (rc < 0) {
            fprintf(stderr, "error IP_RECVTOS sg socket: %s\n",
                  strerror(errno));
            return -1;
        }
        rc = setsockopt(sock, IPPROTO_IP, IP_RECVTTL,
              &trueval, sizeof(int));
        if (rc < 0) {
            fprintf(stderr, "error IP_RECVTTL sg socket: %s\n",
                  strerror(errno));
            return -1;
        }
    }
    break;
    case AF_INET6:
    {
        ((struct sockaddr_in6*)gaddr)->sin6_port =
            htons(gv->gv_port);
        rc = bind(sock, gaddr, gaddr_len);
        if (rc < 0) {
            fprintf(stderr, "error binding data socket: (%s):%u %s\n",
                    sock_ntop(family, gaddr, str, sizeof(str)),
                    gv->gv_port, strerror(errno));
            return -1;
        }

        rc = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &trueval,
                sizeof(int));
        if (rc < 0) {
            fprintf(stderr, "error IPv6_RECVDSTADDR on socket: %s\n",
                  strerror(errno));
            return -1;
        }
        // TBD: for AF_INET6 do we need more opts? (probably. Should
        // probably handle at least extension headers and maybe routing
        // and hop-by-hop headers, so we can pass them all along.)
        // --jake 2017-06-18
    }
    break;
    default:
        fprintf(stderr, "internal error: unknown family %d\n",
                family);
        return -1;
    }

    rc = fcntl(sock, F_GETFL, 0);
    if (rc < 0) {
        fprintf(stderr, "error in GETFL: %s\n", strerror(errno));
        return -1;
    }
    rc = fcntl(sock, F_SETFL, rc | O_NONBLOCK);
    if (rc < 0) {
        fprintf(stderr, "error O_NONBLOCK on socket: %s\n",
                strerror(errno));
        return -1;
    }
    gv->gv_socket = sock;

    gv->gv_receive_ev = event_new(instance->event_base,
            gv->gv_socket, EV_READ | EV_PERSIST, nonraw_data_read,
            (void*)gv);
    rc = event_add(gv->gv_receive_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "error data socket event_add: %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

// buf must have at least 6 bytes.
static void
group_to_mac_address_v4(struct in_addr* addr, uint8_t* buf)
{
    // https://tools.ietf.org/html/rfc1112#section-6.4
    buf[0] = 0x1;
    buf[1] = 0;
    buf[2] = 0x5e;
    buf[3] = 0x7f & ((uint8_t*)addr)[1];
    buf[4] = ((uint8_t*)addr)[2];
    buf[5] = ((uint8_t*)addr)[3];
}

// buf must have at least 6 bytes.
static void
group_to_mac_address_v6(struct in6_addr* addr, uint8_t* buf)
{
    // https://tools.ietf.org/html/rfc2464#section-7
    buf[0] = 0x33;
    buf[1] = 0x33;
    bcopy(&addr->s6_addr[12], &buf[2], 4);
}

static int
data_group_change(grnode* gr, int operation)
{
    relay_instance* instance = gr->gr_instance;
    // for raw socket (if set), make it listen for the right
    // mac address.
    if (BIT_TEST(instance->relay_flags, RELAY_FLAG_NONRAW)) {
        struct packet_mreq preq;
        bzero(&preq, sizeof(preq));
        preq.mr_ifindex = instance->cap_iface_index;
        preq.mr_type = PACKET_MR_MULTICAST;
        preq.mr_alen = 6;
        patext* patgr;
        int already_have = 0;

        switch(instance->tunnel_af) {
            case AF_INET:
                group_to_mac_address_v4(&gr->gr_addr.addr.sin,
                        (uint8_t*)(&preq.mr_address[0]));
                patgr = pat_getnext(&instance->relay_groot, NULL, 0);
                while (patgr) {
                    grnode* other_gr = pat2gr(patgr);
                    patgr = pat_getnext(&instance->relay_groot, pat_key_get(patgr),
                            pat_keysize_get(patgr));
                    if (gr == other_gr) {
                        continue;
                    }
                    uint8_t buf[6];
                    group_to_mac_address_v4(&other_gr->gr_addr.addr.sin,
                            buf);
                    if (!memcmp(buf, preq.mr_address, 6)) {
                        already_have = 1;
                        break;
                    }
                }
                break;
            case AF_INET6:
                group_to_mac_address_v6(&gr->gr_addr.addr.sin6,
                        (uint8_t*)(&preq.mr_address[0]));
                patgr = pat_getnext(&instance->relay_groot, NULL, 0);
                while (patgr) {
                    grnode* other_gr = pat2gr(patgr);
                    patgr = pat_getnext(&instance->relay_groot, pat_key_get(patgr),
                            pat_keysize_get(patgr));
                    if (gr == other_gr) {
                        continue;
                    }
                    uint8_t buf[6];
                    group_to_mac_address_v6(&other_gr->gr_addr.addr.sin6,
                            buf);
                    if (!memcmp(buf, preq.mr_address, 6)) {
                        already_have = 1;
                        break;
                    }
                }
                break;
            default:
                fprintf(stderr, "internal error: unknown family %d\n",
                        instance->tunnel_af);
                return -1;
        }
        if (!already_have) {
            int rc = setsockopt(instance->relay_data_socket, SOL_PACKET,
                    operation, &preq, sizeof(preq));
            if (rc < 0) {
                char str[MAX_ADDR_STRLEN];
                fprintf(stderr, "error changing packet membership for %s: "
                        "%s\n", inet_ntop(instance->tunnel_af,
                            &gr->gr_addr.addr, str, sizeof(str)),
                        strerror(errno));
                return -1;
            }
        }
    }
    return 0;
}

void
data_group_added(grnode* gr)
{
    relay_instance* instance = gr->gr_instance;

    if (!BIT_TEST(instance->relay_flags, RELAY_FLAG_NONRAW)) {
        // we have a raw socket, so we tell it to listen for the new
        // group's mac address.
        if (data_group_change(gr, PACKET_ADD_MEMBERSHIP)) {
            fprintf(stderr, "error adding membership on raw socket\n");
            exit(1);
        }

        // we also need an ip socket, so we can join and leave at the
        // routing level, but the packets will arrive on the raw socket
        // so we don't actually listen.
        gr->gr_recv[0].gv_socket = instance->relay_joining_socket;
    } else {
        int i;
        for (i = 0; i < instance->nonraw_count; ++i) {
            // receive UDP on all the nonraw ports, and feed it to the
            // function that will spoof an ip header + udp header in front
            // before forwarding to joined gateways.
            grrecv* gv = &gr->gr_recv[i];
            gv->gv_gr = gr;
            gv->gv_port = instance->nonraw_ports[i];

            if (nonraw_socket_init(gv)) {
                fprintf(stderr, "error initializing nonraw socket\n");
                exit(1);
            }
        }
    }
}

void
data_group_removed(grnode* gr)
{
    relay_instance* instance = gr->gr_instance;

    if (!BIT_TEST(instance->relay_flags, RELAY_FLAG_NONRAW)) {
        // we have a raw socket, so we tell it to listen for the new
        // group's mac address.
        if (data_group_change(gr, PACKET_DROP_MEMBERSHIP)) {
            fprintf(stderr, "error adding membership on raw socket\n");
            exit(1);
        }
    }
}

static void
raw_socket_read(int fd, short flags, void* uap)
{
    (void)fd;
    (void)flags;
    int rc;
    relay_instance* instance = (relay_instance*)uap;

    do {
        // here we're reading a AF_PACKET SOCK_DGRAM payload (packet(7))
        // the first bytes start an ip header (v4 or v6). We just have
        // to stick the 2-byte amt data shim in front and pass it along.
        // (except sometimes we have to poke in a correct checksum)

        packet* pkt = relay_pkt_get(instance, 2);

        struct iovec iovecs[1];
        struct msghdr msghdr;
        struct sockaddr_storage src_addr;
        uint8_t* cp;

        bzero(&iovecs, sizeof(iovecs));
        bzero(&msghdr, sizeof(msghdr));

        msghdr.msg_name = &src_addr;
        msghdr.msg_namelen = sizeof(src_addr);
        msghdr.msg_iov = &iovecs[0];
        msghdr.msg_iovlen = sizeof(iovecs)/sizeof(iovecs[0]);

        iovecs[0].iov_base = pkt->pkt_data;
        iovecs[0].iov_len = BUFFER_SIZE - pkt->pkt_offset;

        pkt->pkt_af = instance->tunnel_af;
        pkt->pkt_ifindex = instance->cap_iface_index;
        pkt->pkt_fd = fd;
        rc = relay_socket_read(fd, &msghdr);

        if (rc <= 0) {
            if (errno == EWOULDBLOCK) {
                break;
            }
            fprintf(stderr, "error receiving raw data packet: %s\n",
                    strerror(errno));
            relay_pkt_free(pkt);
            break;
        }
        pkt->pkt_len = rc;
        pkt->pkt_amt = AMT_MCAST_DATA;
        cp = pkt->pkt_data;
        u_int len = pkt->pkt_len;

        switch (pkt->pkt_af) {
        case AF_INET:
        {
            if (len < sizeof(struct ip)) {
                fprintf(stderr, "dropping packet smaller than ip header "
                        "(%u)\n", len);
                relay_pkt_free(pkt);
                continue;
            }
            struct ip* iph = (struct ip*)cp;
            if (iph->ip_v != 4) {
                fprintf(stderr, "dropping non-ip4 packet\n");
                if (relay_debug(instance)) {
                    fprintf(stderr, "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x\n"
                       "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x\n",
                       cp[0],cp[1],cp[2],cp[3],cp[4],cp[5],cp[6],cp[7],
                       cp[8],cp[9],cp[10],cp[11],cp[12],cp[13],cp[14],cp[15],
                       cp[16],cp[17],cp[18],cp[19],cp[20],cp[21],cp[22],cp[23],
                       cp[24],cp[25],cp[26],cp[27],cp[28],cp[29],cp[30],cp[31]);
                }
                relay_pkt_free(pkt);
                continue;
            }
            if (len < ntohs(iph->ip_len)) {
                fprintf(stderr, "dropping packet smaller than ip len "
                        "(%u < %u)\n", len, ntohs(iph->ip_len));
                relay_pkt_free(pkt);
                continue;
            }
            len = ntohs(iph->ip_len);
            if (iph->ip_hl < 5 || iph->ip_hl*4 > len) {
                fprintf(stderr, "dropping packet: bad ip header length "
                        "(%u) in data packet with ip len %u\n", iph->ip_hl,
                        len);
                relay_pkt_free(pkt);
                continue;
            }
            pkt->pkt_src = prefix_build(AF_INET, &iph->ip_src,
                    INET_HOST_LEN);
            pkt->pkt_dst = prefix_build(AF_INET, &iph->ip_dst,
                    INET_HOST_LEN);

            // I can leave pkt_sport and pkt_dport unspecified and
            // they'll be converted to tunnel values when sending over
            // the tunnel. not sure if there's any negative effects besides
            // log messages...  --jake 2017-06-18
            pkt->pkt_sport = 0;
            pkt->pkt_dport = 0;

            /*
             * ok, it turns out that dummy interfaces in debian jessie
             * won't let you turn off tx checksum offload for ipv4,
             * so this is kind of a hack feature to inject checksums.
             *
             * what happens is that because tx checksum offload is on,
             * packets sent on a dummy (or loopback) interface don't
             * get checksums set in kernel, so they're wrong when
             * we receive them here, if they were sent by another
             * process on the same machine, and tx off wasn't set.
             *
             * In ubuntu xenial, this is fixed and you can turn off
             * the checksum offload, which means the kernel fills in
             * correct checksums. it looks like:
             * $ ip link add dev dum0 type dummy
             * $ ip addr add 23.212.185.8 dev dum0
             * $ ip link set up dev dum0
             * $ ip route add 224.0.0.0/4 dev dum0
             * $ ethtool --offload dum0 tx off
             *
             * if that ethtool command doesn't complain, you don't
             * need this when sending from that interface thru relay,
             * but unfortunately in some of our deployed sender kernels
             * it errors and refuses to set.
             *
             * doesn't work:
             *   Linux version 3.16.0-4-amd64
             *     (debian-kernel@lists.debian.org)
             *     (gcc version 4.8.4 (Debian 4.8.4-1) ) #1 SMP
             *     Debian 3.16.43-2+deb8u1 (2017-06-18)
             * works:
             *   Linux version 4.4.0-79-generic (buildd@lcy01-30)
             *     (gcc version 5.4.0 20160609
             *     (Ubuntu 5.4.0-6ubuntu1~16.04.4))
             *     #100-Ubuntu SMP Wed May 17 19:58:14 UTC 2017
             * --jake 2017-06-17
             */
            if (!BIT_TEST(instance->relay_flags, RELAY_FLAG_EXTERNAL)) {
                iph->ip_sum = 0;
                iph->ip_sum = csum((uint8_t*)iph, 4*iph->ip_hl);

                cp += 4 * iph->ip_hl;
                len -= 4 * iph->ip_hl;
                if (iph->ip_p == IPPROTO_UDP) { // 17
                    if (len < sizeof(struct udphdr)) {
                        fprintf(stderr, "dropping packet with payload too "
                            "small for udp (%u < %d)\n", len,
                            (int)sizeof(struct udphdr));
                        relay_pkt_free(pkt);
                        continue;
                    }
                    struct udphdr* uph = (struct udphdr*)cp;
                    if (len < ntohs(UH_ULEN(uph))) {
                        fprintf(stderr, "dropping packet with payload too "
                            "small for udp len (%u < %u)\n", len,
                            ntohs(UH_ULEN(uph)));
                        relay_pkt_free(pkt);
                        continue;
                    }
                    UH_SUM(uph) = 0;
                    pkt->pkt_sport = UH_SPORT(uph);
                    pkt->pkt_dport = UH_SPORT(uph);
                }
            }
        }
        break;
        case AF_INET6:
        {
            if (len < sizeof(struct ip6_hdr)) {
                fprintf(stderr, "dropping packet smaller than ip6 header "
                        "(%u)\n", len);
                relay_pkt_free(pkt);
                continue;
            }
            struct ip6_hdr* iph = (struct ip6_hdr*)cp;
            if ((iph->ip6_vfc & 0xf0) != 0x60) {
                fprintf(stderr, "dropping non-ip6 packet\n");
                if (relay_debug(instance)) {
                    fprintf(stderr, "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x\n"
                       "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x\n",
                       cp[0],cp[1],cp[2],cp[3],cp[4],cp[5],cp[6],cp[7],
                       cp[8],cp[9],cp[10],cp[11],cp[12],cp[13],cp[14],cp[15],
                       cp[16],cp[17],cp[18],cp[19],cp[20],cp[21],cp[22],cp[23],
                       cp[24],cp[25],cp[26],cp[27],cp[28],cp[29],cp[30],cp[31]);
                }
                relay_pkt_free(pkt);
                continue;
            }
            if (len < sizeof(*iph) + ntohs(iph->ip6_plen)) {
                fprintf(stderr, "dropping packet smaller than ip len "
                        "(%u < %u)\n", len, ntohs(iph->ip6_plen));
                relay_pkt_free(pkt);
                continue;
            }
            len = sizeof(*iph) + ntohs(iph->ip6_plen);

            pkt->pkt_src = prefix_build(AF_INET6, &iph->ip6_src,
                    INET6_HOST_LEN);
            pkt->pkt_dst = prefix_build(AF_INET6, &iph->ip6_dst,
                    INET6_HOST_LEN);

            if (!BIT_TEST(instance->relay_flags, RELAY_FLAG_EXTERNAL)) {
                cp += sizeof(*iph);
                len -= sizeof(*iph);
                if (iph->ip6_nxt == IPPROTO_UDP) { // 17
                    if (len < sizeof(struct udphdr)) {
                        fprintf(stderr, "dropping packet with payload too "
                            "small for udp (%u < %d)\n", len,
                            (int)sizeof(struct udphdr));
                        relay_pkt_free(pkt);
                        continue;
                    }
                    struct udphdr* uph = (struct udphdr*)cp;
                    if (len < ntohs(UH_ULEN(uph))) {
                        fprintf(stderr, "dropping packet with payload too "
                            "small for udp len (%u < %u)\n", len,
                            ntohs(UH_ULEN(uph)));
                        relay_pkt_free(pkt);
                        continue;
                    }

                    // udp checksum is required:
                    // https://tools.ietf.org/html/rfc2460#section-8.1
                    struct pshdr {
                        uint32_t uh_len;
                        uint8_t pshdr_v[4];
                    } pshd;
                    pshd.uh_len = ntohl(ntohs(UH_ULEN(uph)));
                    pshd.pshdr_v[0] = 0;
                    pshd.pshdr_v[1] = 0;
                    pshd.pshdr_v[2] = 0;
                    pshd.pshdr_v[3] = 17;
                    struct iovec iov[3];
                    unsigned int niovs = sizeof(iov)/sizeof(iov[0]);
                    iov[0].iov_base = &iph->ip6_src;
                    iov[0].iov_len = 32;
                    iov[1].iov_base = &pshd;
                    iov[1].iov_len = 8;
                    iov[2].iov_base = uph;
                    iov[2].iov_len = ntohs(UH_ULEN(uph));
                    UH_SUM(uph) = 0;
                    UH_SUM(uph) = iov_csum(iov, niovs);

                    pkt->pkt_sport = UH_SPORT(uph);
                    pkt->pkt_dport = UH_DPORT(uph);
                }
            }
        }
        break;
        default:
            fprintf(stderr, "internal error: unknown family %d in "
                    "nonraw_data_read\n", pkt->pkt_af);
            exit(1);
        }

        // insert amt data header before
        cp = relay_packet_insert_before(pkt, "amt header", 2);
        *cp = 6;
        *(cp + 1) = 0;
        cp += 2;

        relay_packet_enq(instance, pkt);
    } while (rc > 0);
}

void
relay_raw_socket_init(relay_instance* instance)
{
    int sock, rc;
    int proto;
    switch(instance->tunnel_af) {
        case AF_INET:
            proto = htons(ETH_P_IP);
            break;
        case AF_INET6:
            proto = htons(ETH_P_IPV6);
            break;
        default:
            fprintf(stderr, "internal error: unknown tunnel_af: %d\n",
                    instance->tunnel_af);
            exit(1);
            return;
    }
    sock = socket(AF_PACKET, SOCK_DGRAM, proto);
    if (sock < 0) {
        fprintf(stderr, "error creating data socket: %s\n",
                strerror(errno));
        exit(1);
    }

    /*
    // this seems to do nothing. using bind instead...
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s",
            instance->cap_iface_name);
    rc = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr,
            sizeof(struct ifreq));
    if (rc < 0) {
        fprintf(stderr, "error binding data sock to interface: (%s) %s\n",
                ifr.ifr_name, strerror(errno));
        exit(1);
    }
    */
    // http://man7.org/linux/man-pages/man7/packet.7.html
    /* "To get packets only from a specific interface use
       bind(2) specifying an address in a struct sockaddr_ll to bind the
       packet socket to an interface.  Fields used for binding are
       sll_family (should be AF_PACKET), sll_protocol, and sll_ifindex."
    */
    struct sockaddr_ll bind_addr;
    bzero(&bind_addr, sizeof(bind_addr));
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = proto;
    bind_addr.sll_ifindex = instance->cap_iface_index;
    rc = bind(sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr));
    if (rc < 0) {
        fprintf(stderr, "error binding data sock to interface: (%s) %s\n",
                instance->cap_iface_name, strerror(errno));
        exit(1);
    }

    rc = fcntl(sock, F_GETFL, 0);
    if (rc < 0) {
        fprintf(stderr, "error in GETFL: %s\n", strerror(errno));
        exit(1);
    }
    rc = fcntl(sock, F_SETFL, rc | O_NONBLOCK);
    if (rc < 0) {
        fprintf(stderr, "error O_NONBLOCK on socket: %s\n",
                strerror(errno));
        exit(1);
    }

    instance->relay_data_socket = sock;
    instance->relay_raw_receive_ev = event_new(instance->event_base,
            instance->relay_data_socket, EV_READ | EV_PERSIST,
            raw_socket_read, (void*)instance);
    rc = event_add(instance->relay_raw_receive_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "error raw socket event_add: %s\n",
                strerror(errno));
        exit(1);
    }

    // we also need an ip socket, so we can join and leave at the
    // routing level, but the packets will arrive on the raw socket
    // so we don't actually listen.
    sock = socket(instance->tunnel_af, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        fprintf(stderr, "error creating joining socket: %s\n",
                strerror(errno));
        exit(1);
    }

    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s",
            instance->cap_iface_name);
    rc = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr,
            sizeof(struct ifreq));
    if (rc < 0) {
        fprintf(stderr, "error binding data socket: (%s) %s\n",
                ifr.ifr_name, strerror(errno));
        exit(1);
    }
    rc = fcntl(sock, F_GETFL, 0);
    if (rc < 0) {
        fprintf(stderr, "error in GETFL: %s\n", strerror(errno));
        exit(1);
    }
    rc = fcntl(sock, F_SETFL, rc | O_NONBLOCK);
    if (rc < 0) {
        fprintf(stderr, "error O_NONBLOCK on socket: %s\n",
                strerror(errno));
        exit(1);
    }
    instance->relay_joining_socket = sock;
}

