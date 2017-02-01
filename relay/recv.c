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

#include <sys/errno.h>
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
#ifdef BSD
#include <net/if_dl.h>
#endif /* BSD */
#define __USE_GNU 1
#include <arpa/inet.h>
#include <linux/igmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <event.h>

#include <md5.h>

#include "amt.h"
#include "hmac.h"
#include "in_cksum.h"
#include "memory.h"
#include "mld.h"
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
        mem_type_free(mem_rif_handle, rif);
    }
}

static inline packet*
relay_pkt_get(relay_instance* instance)
{
    packet* pkt;

    if (!mem_packet_handle) {
        mem_packet_handle = mem_type_init(sizeof(packet), "Relay Packet");
    }
    pkt = (packet*)mem_type_alloc(mem_packet_handle);
    pkt->pkt_buffer = malloc(BUFFER_SIZE);
    pkt->pkt_instance = instance;

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

    free(pkt->pkt_buffer);

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
      struct igmpv3_report* igmp,
      group_record_list_t* grec_head)
{
    u_int32_t mc_addr;
    group_record_t* tmp;
    struct igmpv3_grec* igmp_grec;
    mcast_source_t* gsrc;
    u_int16_t cnt, ngrec, nsrcs;
    membership_type mt = 0;

    ngrec = ntohs(igmp->ngrec);
    igmp_grec = &igmp->grec[0];
    while (ngrec--) {
        /* Number of sources in this group record */
        nsrcs = ntohs(igmp_grec->grec_nsrcs);

        /* Record Type */
        switch (igmp_grec->grec_type) {
            case IGMPV3_MODE_IS_INCLUDE:
            case IGMPV3_CHANGE_TO_INCLUDE:
                if (nsrcs > 0) {
                    mt = MEMBERSHIP_REPORT;
                } else {
                    mt = MEMBERSHIP_LEAVE;
                }
                break;
            case IGMPV3_MODE_IS_EXCLUDE:
            case IGMPV3_CHANGE_TO_EXCLUDE:
                if (nsrcs > 0) {
                    mt = MEMBERSHIP_LEAVE;
                } else {
                    mt = MEMBERSHIP_REPORT;
                }
                break;
            case IGMPV3_ALLOW_NEW_SOURCES:
                mt = MEMBERSHIP_REPORT;
                break;
            case IGMPV3_BLOCK_OLD_SOURCES:
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
        mc_addr = igmp_grec->grec_mca;
        if (IN_MULTICAST(ntohl(mc_addr))) {
            tmp->group = prefix_build(AF_INET, &mc_addr, INET_HOST_LEN);
        } else {
            instance->stats.igmp_group_invalid++;
            free(tmp);
            continue;
        }

        /* Add Sources */
        TAILQ_INIT(&tmp->src_head);
        for (cnt = 0; cnt < nsrcs; cnt++) {
            u_int32_t src = igmp_grec->grec_src[cnt];
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
        igmp_grec = (struct igmpv3_grec*)(((u_int8_t*)igmp_grec) +
                                          sizeof(struct igmpv3_grec) +
                                          igmp_grec->grec_auxwords * 4 +
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
    struct igmphdr* igmp;
    group_record_t* tmp;
    u_int8_t* cp;
    u_int32_t mc_addr;

    cp = (u_int8_t*)pkt->pkt_buffer;
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

    igmp = (struct igmphdr*)((u_int8_t*)ip + hlen);
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

    if (in_cksum((u_short*)igmp, len)) {
        instance->stats.igmp_checksum_bad++;
        return MEMBERSHIP_ERROR;
    }

    /*
     * Save the inner IP header source address
     */
    *from_ptr = prefix_build(AF_INET, &ip->ip_src.s_addr, INET_HOST_LEN);

    switch (igmp->type) {
        case IGMP_HOST_MEMBERSHIP_REPORT:
        case IGMPV2_HOST_MEMBERSHIP_REPORT:
            if ((tmp = calloc(1, sizeof(group_record_t))) == NULL) {
                return FALSE;
            }

            /* Multicast group address */
            mc_addr = igmp->group;
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
            mc_addr = igmp->group;
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
        case IGMPV3_HOST_MEMBERSHIP_REPORT: {
            if (parse_igmp_record(instance, (struct igmpv3_report*)igmp,
                      grec_head) == FALSE) {
                /* TODO: Free membership records */
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
      struct mld2_report* mld_report_hdr,
      group_record_list_t* grec_head)
{
    struct mld2_grec* grec;
    u_int16_t cnt, ngrecs, nsrcs;
    group_record_t* tmp;
    membership_type mt = 0;
    struct in6_addr src_addr;
    mcast_source_t* gsrc;

    ngrecs = ntohs(mld_report_hdr->mld2r_ngrec);
    grec = mld_report_hdr->mld2r_grec;
    while (ngrecs--) {
        nsrcs = ntohs(grec->grec_nsrcs);
        switch (grec->grec_type) {
            case MLD2_CHANGE_TO_INCLUDE:
            case MLD2_MODE_IS_INCLUDE: {
                if (nsrcs > 0)
                    mt = MEMBERSHIP_REPORT;
                else
                    mt = MEMBERSHIP_LEAVE;
                break;
            }
            case MLD2_MODE_IS_EXCLUDE:
            case MLD2_CHANGE_TO_EXCLUDE: {
                if (nsrcs > 0)
                    mt = MEMBERSHIP_LEAVE;
                else
                    mt = MEMBERSHIP_REPORT;
                break;
            }
            case MLD2_ALLOW_NEW_SOURCES:
                mt = MEMBERSHIP_REPORT;
                break;
            case MLD2_BLOCK_OLD_SOURCES:
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
        if (IN6_MULTICAST(grec->grec_mca.s6_addr[0])) {
            tmp->group = prefix_build(
                  AF_INET6, grec->grec_mca.s6_addr, INET6_HOST_LEN);
        } else {
            instance->stats.mld_group_invalid++;
            free(tmp);
            continue;
        }
        TAILQ_INIT(&tmp->src_head);
        for (cnt = 0; cnt < nsrcs; cnt++) {
            src_addr = grec->grec_src[cnt];
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
        grec = (struct mld2_grec*)((u_int8_t*)grec + sizeof(*grec) +
                                   (grec->grec_auxwords << 2) +
                                   (nsrcs << 4));
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
    struct mld_msg* mld_hdr;
    struct mld2_report* mld_report_hdr;

    pktlen = pkt->pkt_len;

    /* skip AMT headers */
    cp = pkt->pkt_buffer;
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

    mld_hdr = (struct mld_msg*)cp;
    pktlen -= iphlen;
    pktlen += sizeof(*ip); /* compensation */

#define MLD_MIMLEN (sizeof(struct mld2_report) + sizeof(struct mld2_grec))
    if (pktlen < MLD_MIMLEN) {
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
    *from_ptr = prefix_build(AF_INET6, ip->ip6_src.s6_addr, INET6_HOST_LEN);

    /* Process the MLD message */
    switch (mld_hdr->mld_type) {
        case ICMPV6_MLD2_REPORT: {
            mld_report_hdr = (struct mld2_report*)mld_hdr;
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
    cp = (u_int8_t*)pkt->pkt_buffer;

    if (len > sizeof(u_int32_t)) {
        cp += sizeof(u_int32_t);
        len -= sizeof(u_int32_t);

        if (len >= sizeof(u_int32_t)) {
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
    cp = (u_int8_t*)pkt->pkt_buffer;

    if (len > sizeof(u_int32_t)) {
        cp += sizeof(u_int32_t);
        len -= sizeof(u_int32_t);

        if (len >= sizeof(u_int32_t)) {
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

    cp = (u_int8_t*)pkt->pkt_buffer;
    cp++; /* type */
    cp++; /* reserved */
    mac = cp;
    cp += RESPONSE_MAC_LEN;
    nonce = get_long(cp);

    relay_response_mac(pkt, nonce, digest);

    if (relay_debug(instance)) {
        fprintf(stderr, "Received AMT Membership Change nonce %u received "
                        "mac %02x%02x%02x%02x%02x%02x true mac "
                        "%02x%02x%02x%02x%02x%02x\n",
              nonce, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
              digest[0], digest[1], digest[2], digest[3], digest[4],
              digest[5]);
    }
    return memcmp(mac, digest, RESPONSE_MAC_LEN);
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
    int s, rc;
    socklen_t len = 0;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr* sa = NULL;

    switch (dst->family) {
        case AF_INET:
            bzero(&sin, sizeof(sin));
            sa = (struct sockaddr*)&sin;
            break;

        case AF_INET6:
            bzero(&sin6, sizeof(sin6));
            sa = (struct sockaddr*)&sin6;
            break;

        default:
            assert(dst->family == AF_INET || dst->family == AF_INET6);
    }

    /*
     * create a temporary socket
     */
    s = socket(dst->family, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "creating UDP socket: %s\n", strerror(errno));
        return errno;
    }

    len = prefix2sock(dst, sa);
    if (dst->family == AF_INET)
        sin.sin_port = dport;
    else
        sin6.sin6_port = dport;

    rc = connect(s, sa, len);
    if (rc < 0) {
        /*
         * we need to handle the case of no route to destination
         * EADDRNOTAVAIL
         * XXX
         */
        fprintf(stderr, "relay connecting on UDP socket: %s\n",
              strerror(errno));
        close(s);
        return errno;
    }

    switch (dst->family) {
        case AF_INET:
            sa = (struct sockaddr*)&sin;
            len = sizeof(sin);
            break;

        case AF_INET6:
            sa = (struct sockaddr*)&sin6;
            len = sizeof(sin6);
            break;

        default:
            assert(dst->family == AF_INET || dst->family == AF_INET6);
    }
    bzero(sa, len);
    rc = getsockname(s, (struct sockaddr*)sa, &len);
    if (rc < 0) {
        fprintf(stderr, "relay getsockname: %s\n", strerror(errno));
        close(s);
        return errno;
    }

    *srcp = sock2prefix(dst->family, sa);

    close(s);

    return 0;
}

static void
relay_create_recv_socket(relay_instance* instance, prefix_t* src_pfx)
{
    int rc, srclen;
    struct sockaddr_in src;
    struct sockaddr_in6 src6;
    struct sockaddr* src_sa = NULL;
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
        src_sa = (struct sockaddr*)&src;
        srclen = sizeof(src);
        prefix2sin(src_pfx, &src);
        src.sin_port = htons(instance->amt_port);
    } else {
        src_sa = (struct sockaddr*)&src6;
        srclen = sizeof(src6);
        prefix2sin6(src_pfx, &src6);
        src6.sin6_port = htons(instance->amt_port);
    }

    rif->rif_sock =
          relay_socket_shared_init(instance->relay_af, src_sa, srclen);

    event_set(&rif->rif_ev, rif->rif_sock, EV_READ | EV_PERSIST,
          relay_instance_read, (void*)instance);
    rc = event_add(&rif->rif_ev, NULL);
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
                            "from %s:%u to %s:%u nonce %u relay %s\n",
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

/* this function generates header checksums */
static unsigned short
csum(unsigned short* buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static int
add_membership_query(relay_instance* instance, packet* pkt, u_int8_t* cp)
{
    char str[MAX_ADDR_STRLEN];
    fprintf(stderr, "select source address for %s\n",
          prefix2str(pkt->pkt_dst, str, sizeof(str)));
    int len = -1;
    switch (instance->tunnel_af) {
        /* switch (pkt->pkt_src->family) { */
        case AF_INET: {
            struct ip* iph;
            struct igmpv3_query* igmpq;
            struct sockaddr_in* src_addr;
            iph = (struct ip*)cp;
            /* Fill IP header */
            iph->ip_hl = 5;
            iph->ip_v = 4;
            iph->ip_tos = 0;
            iph->ip_len =
                  htons(sizeof(struct ip) + sizeof(struct igmpv3_query));
            iph->ip_id = htons(54321);
            iph->ip_off = 0;
            iph->ip_ttl = 1;
            iph->ip_p = 2; /* IGMP */
            iph->ip_sum = 0;
            src_addr = (struct sockaddr_in*)&instance->tunnel_addr;
            iph->ip_src = src_addr->sin_addr;
            iph->ip_dst.s_addr = inet_addr("224.0.0.1");

            /* IGMPv3 membership query */
            igmpq = (struct igmpv3_query*)(cp + sizeof(struct ip));
            igmpq->type = IGMP_HOST_MEMBERSHIP_QUERY;
            igmpq->code = 100;
            igmpq->csum = 0;
            igmpq->group = 0;
            igmpq->qrv = 0;
            igmpq->suppress = 1;
            igmpq->resv = 0;
            igmpq->qqic = QQIC;
            igmpq->nsrcs = 0;
            igmpq->srcs[0] = 0;
            igmpq->csum = csum((unsigned short*)igmpq,
                  (sizeof(struct igmpv3_query)) >> 1);
            iph->ip_sum = csum((unsigned short*)iph,
                  (sizeof(struct ip) + sizeof(struct igmpv3_query)) >> 1);
            len = sizeof(struct ip) + sizeof(struct igmpv3_query);
            break;
        }
        case AF_INET6: {
            struct ip6_hdr* iph;
            struct mld2_query* mld_query_hdr;
            u_int8_t* chdr;
            struct ip6_pseudo* pseudo_hdr;
            struct sockaddr_in6* src_addr;
            u_int8_t r_alert[8] = { IPPROTO_ICMPV6, 0, IP6OPT_ROUTER_ALERT,
                2, 0, 0, IP6OPT_PADN, 0 };

            chdr = (u_int8_t*)malloc(
                  sizeof(struct ip6_pseudo) + sizeof(*mld_query_hdr));
            if (chdr == NULL)
                return 0;

            iph = (struct ip6_hdr*)cp;
            bzero(cp, sizeof(*iph));
            iph->ip6_vfc = (6 << 4);
#define NEXTHDR_HOP 0
            iph->ip6_nxt = NEXTHDR_HOP;
            iph->ip6_hlim = 1;
            src_addr = (struct sockaddr_in6*)&instance->tunnel_addr;
            iph->ip6_src = src_addr->sin6_addr;
            inet_pton(AF_INET6, "ff02::1", &iph->ip6_dst);
            bcopy(r_alert, cp + sizeof(*iph), sizeof(r_alert));

            cp += (sizeof(*iph) + sizeof(r_alert));
            mld_query_hdr = (struct mld2_query*)cp;
            mld_query_hdr->mld2q_type = ICMPV6_MGM_QUERY;
            mld_query_hdr->mld2q_code = 0;
            mld_query_hdr->mld2q_cksum = 0;
            mld_query_hdr->mld2q_mrc = htons(100);
            mld_query_hdr->mld2q_resv1 = 0;
            bzero(&mld_query_hdr->mld2q_mca, sizeof(struct in6_addr));
            mld_query_hdr->mld2q_qrv = 0;
            mld_query_hdr->mld2q_suppress = 1;
            mld_query_hdr->mld2q_qqic = QQIC;
            mld_query_hdr->mld2q_nsrcs = 0;
            mld_query_hdr->mld2q_resv2 = 0;
            cp += sizeof(*mld_query_hdr);

            iph->ip6_plen = htons(cp - (u_int8_t*)iph - sizeof(*iph));

            pseudo_hdr = (struct ip6_pseudo*)chdr;
            bcopy(&iph->ip6_src, &pseudo_hdr->src, sizeof(struct in6_addr));
            bcopy(&iph->ip6_dst, &pseudo_hdr->dst, sizeof(struct in6_addr));
            pseudo_hdr->uplen = htonl(cp - (u_int8_t*)iph - sizeof(*iph));
            pseudo_hdr->nxthdr = htonl(IPPROTO_ICMPV6);
            bcopy(mld_query_hdr, chdr + sizeof(*pseudo_hdr),
                  sizeof(*mld_query_hdr));
            mld_query_hdr->mld2q_cksum = csum((unsigned short*)chdr,
                  (sizeof(*pseudo_hdr) + sizeof(*mld_query_hdr)) >> 1);
            free(chdr);

            len = cp - (u_int8_t*)iph;
            break;
        }
    }

    return len;
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

    querylen = add_membership_query(instance, pkt, cp);
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
            prefix_t *group, *source, *from;
            group_record_list_t grec_head;
            group_record_t* tmprec;
            mcast_source_t* tmpsrc;
            static packet* pkt;
            char str[MAX_ADDR_STRLEN], str2[MAX_ADDR_STRLEN];
            u_int32_t nonce;

            finished = FALSE;

            pkt = TAILQ_FIRST(&instance->pkt_head[queue]);
            assert(pkt);

            switch (pkt->pkt_amt) {
                case AMT_RELAY_DISCOVERY:
                    nonce = relay_discovery_nonce_extract(pkt);
                    if (relay_debug(instance)) {
                        fprintf(stderr,
                              "Received %s AMT Discovery len %d from "
                              "%s:%u to %s:%u nonce %u\n",
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
                         * the src prefix gets allocated here but is
                         * referenced in the rif receive socket structure
                         * so we don't free it here.
                         */
                        if (relay_select_src_addr(instance, pkt->pkt_src,
                                  pkt->pkt_sport, &src)) {
                            if (relay_debug(instance)) {
                                fprintf(stderr,
                                      "Can't select source address for %s",
                                      prefix2str(pkt->pkt_dst, str,
                                            sizeof(str)));
                            }
                            break;
                        }
                        /*
                         * If we are going to tell the gateway to use an
                         * address, make sure we have a socket open that is
                         * listening to the AMT port on that address.
                         */
                        relay_create_recv_socket(instance, src);

                        relay_send_advertisement(pkt, nonce, src);

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
                                        "from %s:%u to %s:%u nonce %u\n",
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
                                            "len %d from %s:%u to %s:%u "
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
                    from = NULL;
                    TAILQ_INIT(&grec_head);
                    /*
                     * lookup the relay gnonce for the 3-way handshake
                     * if there isn't one, toss it
                     */
                    if (relay_response_mac_verify(pkt)) {
                        instance->stats.relay_response_mac_bad++;
                        break;
                    }

                    mt = membership_pkt_decode(
                          instance, pkt, &grec_head, &from);
                    if (mt == FALSE) {
                        if (relay_debug(instance))
                            fprintf(stderr,
                                  "Failed to decode membership pkt\n");
                        break;
                    }
                    while (!TAILQ_EMPTY(&grec_head)) {
                        tmprec = TAILQ_FIRST(&grec_head);
                        group = tmprec->group;
                        mt = tmprec->mt;
                        switch (mt) {
                            case MEMBERSHIP_REPORT:
                            case MEMBERSHIP_LEAVE:
                                if (tmprec->nsrcs == 0) {
                                    membership_tree_refresh(instance, mt,
                                          pkt, group, NULL, from);
                                } else {
                                    while (
                                          !TAILQ_EMPTY(&tmprec->src_head)) {
                                        tmpsrc = TAILQ_FIRST(
                                              &tmprec->src_head);
                                        source = tmpsrc->source;
                                        membership_tree_refresh(instance,
                                              mt, pkt, group, source, from);
                                        TAILQ_REMOVE(&tmprec->src_head,
                                              tmpsrc, src_next);
                                        free(tmpsrc);
                                    }
                                }
                                break;
                            case MEMBERSHIP_ERROR:
                            default:
                                break;
                        }
                        TAILQ_REMOVE(&grec_head, tmprec, rec_next);
                        free(tmprec);
                    }
                    break;

                case AMT_MCAST_DATA:
                    if (relay_debug(instance)) {
                        static unsigned int data_pkts_recvd = 0;
                        if (data_pkts_recvd % 10000 == 0) {
                            fprintf(stderr, "Received %s data packet %u, "
                                            "len %d from %s",
                                  (pkt->pkt_af == AF_INET) ? "INET"
                                                           : "INET6",
                                  data_pkts_recvd, pkt->pkt_len,
                                  prefix2str(
                                        pkt->pkt_src, str, sizeof(str)));
                            /*
                            fprintf(stderr,
                                    "Received %s data packet len %d from
                            %s",
                                    (pkt->pkt_af == AF_INET) ? "INET" :
                            "INET6",
                                    pkt->pkt_len,
                                    prefix2str(pkt->pkt_src, str,
                            sizeof(str)));
                            */
                            if (pkt->pkt_sport) {
                                fprintf(stderr, ":%u ",
                                      ntohs(pkt->pkt_sport));
                            } else {
                                fprintf(stderr, " ");
                            }
                            fprintf(stderr, "to %s",
                                  prefix2str(
                                        pkt->pkt_dst, str2, sizeof(str2)));
                            if (pkt->pkt_dport) {
                                fprintf(
                                      stderr, ":%u", ntohs(pkt->pkt_dport));
                            }
                            fprintf(stderr, "\n");
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
        evtimer_del(&instance->relay_pkt_timer);
    } else {
        int rc;
        struct timeval tv;

        timerclear(&tv);
        tv.tv_usec = AMT_PACKET_Q_USEC;
        rc = evtimer_add(&instance->relay_pkt_timer, &tv);
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
     * Data packets have the highest priority to reduce packet forwarding
     * latency.
     *
     * Next, IGMP joins/leaves to reduce join/leave latency
     *
     * Last, Discovery messages are processed since they aren't time
     * sensitive
     */
    switch (pkt->pkt_amt) {
        case AMT_MCAST_DATA:
            pkt->pkt_queue = HIGH;
            gettimeofday(&time_stamp, NULL);
            pkt->enq_time =
                  time_stamp.tv_sec * 1000000 + time_stamp.tv_usec;
            instance->stats.mcast_data_recvd++;
            break;

        case AMT_REQUEST:
        case AMT_MEMBERSHIP_QUERY:
        case AMT_MEMBERSHIP_CHANGE:
            pkt->pkt_queue = MEDIUM;
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

    if (!evtimer_pending(&instance->relay_pkt_timer, NULL)) {
        int rc;
        struct timeval tv;

        timerclear(&tv);
        tv.tv_usec = AMT_PACKET_Q_USEC;
        evtimer_set(&instance->relay_pkt_timer, relay_packet_deq, instance);
        rc = evtimer_add(&instance->relay_pkt_timer, &tv);
        if (rc < 0) {
            fprintf(stderr, "can't initialize packet timer: %s\n",
                  strerror(errno));
            exit(1);
        }
    }
}

static int
relay_message_read(relay_instance* instance, int fd)
{
    u_int8_t namebuf[NAMELEN];
    u_int8_t ctlbuf[CTLLEN];
    struct iovec iovec;
    struct msghdr msghdr;
    struct sockaddr* srcsock;
    struct sockaddr_in* in;
    struct sockaddr_in6* in6;
    int ctl_left, len, rc;
    u_int8_t *ctlptr, *cp;
    struct cmsghdr* cmsgptr;
    packet* pkt;

    bzero(&iovec, sizeof(iovec));
    bzero(&msghdr, sizeof(msghdr));

    msghdr.msg_name = namebuf;
    msghdr.msg_namelen = NAMELEN;
    msghdr.msg_iov = &iovec;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = ctlbuf;
    msghdr.msg_controllen = CTLLEN;

    pkt = relay_pkt_get(instance);

    iovec.iov_base = pkt->pkt_buffer;
    iovec.iov_len = BUFFER_SIZE;

    rc = recvmsg(fd, &msghdr, 0);
    if (rc < 0) {

        /* Some kind of error. */

        switch (errno) {
            case EINTR:        /* Interrupted.  Retry. */
            case EHOSTUNREACH: /* Unreachable.  Retry. */
            case ENETUNREACH:  /* Unreachable.  Retry. */
                rc = 0;
                break;

            case EWOULDBLOCK: /* Nothing to read. */
                goto fail;

            default:
                fprintf(stderr, "Error on read, family %u: %s",
                      instance->relay_af, strerror(errno));
                goto fail;
        }
    }

    /* Bail if anything got truncated. */

    if (msghdr.msg_flags & MSG_TRUNC) {
        fprintf(stderr, "received packet truncated, buffer size %d too "
                        "small, address family %d, flags 0x%x\n",
              BUFFER_SIZE, instance->relay_af, msghdr.msg_flags);
        goto fail;
    }

    if (msghdr.msg_flags & MSG_CTRUNC) {
        fprintf(stderr, "packet control info truncated, buffer size %d too "
                        "small, address family %d, flags 0x%x\n",
              CTLLEN, instance->relay_af, msghdr.msg_flags);
        goto fail;
    }

    pkt->pkt_len = rc;
    pkt->pkt_fd = fd;

    /*
     * Find the address family
     */
    srcsock = (struct sockaddr*)namebuf;
    assert(srcsock);
    pkt->pkt_af = srcsock->sa_family;
    switch (pkt->pkt_af) {
        case AF_INET:
            in = (struct sockaddr_in*)srcsock;
            len = msghdr.msg_namelen;
            if (len < MIN_SOCKADDR_IN_LEN) {
                goto fail;
            }
#ifdef BSD
            if (in->sin_len < MIN_SOCKADDR_IN_LEN) {
                goto fail;
            }
#endif
            pkt->pkt_src = prefix_build(
                  AF_INET, &in->sin_addr.s_addr, INET_HOST_LEN);
            pkt->pkt_sport = in->sin_port;

            /*
             * Get the incoming interface index for filter comparisons.
             * Get the destination IP address to find anycast packets.
             */
            ctlptr = ctlbuf;
            ctl_left = msghdr.msg_controllen;
            while (ctl_left > (int)sizeof(struct cmsghdr)) {
                cmsgptr = (struct cmsghdr*)ctlptr;
#ifdef BSD
                if (cmsgptr->cmsg_level == IPPROTO_IP &&
                      cmsgptr->cmsg_type == IP_RECVIF &&
                      cmsgptr->cmsg_len >=
                            offsetof(struct sockaddr_dl, sdl_data[0])) {

                    dl_addr = (struct sockaddr_dl*)(ctlptr +
                                                    sizeof(struct cmsghdr));
                    pkt->pkt_ifindex = dl_addr->sdl_index;
                } else if (cmsgptr->cmsg_level == IPPROTO_IP &&
                           cmsgptr->cmsg_type == IP_RECVDSTADDR &&
                           cmsgptr->cmsg_len >= sizeof(struct in_addr)) {

                    pkt->pkt_dst = prefix_build(
                          AF_INET, CMSG_DATA(cmsgptr), INET_HOST_LEN);
                }
#else
                if (cmsgptr->cmsg_level == SOL_IP &&
                      cmsgptr->cmsg_type == IP_PKTINFO) {
                    struct in_pktinfo* pktinfo =
                          (struct in_pktinfo*)CMSG_DATA(cmsgptr);
                    struct in_addr s_addr = pktinfo->ipi_spec_dst;
                    pkt->pkt_dst =
                          prefix_build(AF_INET, &s_addr, INET_HOST_LEN);
                    pkt->pkt_ifindex = pktinfo->ipi_ifindex;
                }
#endif
                ctl_left -= cmsgptr->cmsg_len;
                ctlptr += cmsgptr->cmsg_len;
            }
            break;

        case AF_INET6: {
            in6 = (struct sockaddr_in6*)srcsock;
            len = msghdr.msg_namelen;
            if (len < sizeof(*in6))
                goto fail;

            pkt->pkt_src = prefix_build(
                  AF_INET6, in6->sin6_addr.s6_addr, INET6_HOST_LEN);
            pkt->pkt_sport = in6->sin6_port;

            /*
         * Get the incoming interface index for filter comparisons.
         * Get the destination IP address to find anycast packets.
         */
            ctlptr = ctlbuf;
            ctl_left = msghdr.msg_controllen;
            while (ctl_left > (int)sizeof(struct cmsghdr)) {
                cmsgptr = (struct cmsghdr*)ctlptr;
                if (cmsgptr->cmsg_level == SOL_IPV6 &&
                      cmsgptr->cmsg_type == IPV6_PKTINFO) {
                    struct in6_pktinfo* pktinfo = 
                          (struct in6_pktinfo*)CMSG_DATA(cmsgptr);
                    struct in6_addr s_addr = pktinfo->ipi6_addr;
                    pkt->pkt_dst = prefix_build(
                          AF_INET6, s_addr.s6_addr, INET6_HOST_LEN);
                    pkt->pkt_ifindex = pktinfo->ipi6_ifindex;
                }
                ctl_left -= cmsgptr->cmsg_len;
                ctlptr += cmsgptr->cmsg_len;
            }

            break;
        }

        default:
            assert(pkt->pkt_af == AF_INET || pkt->pkt_af == AF_INET6);
    }

    /*
     * Figure out the type of packet and use this later for queueing
     */
    cp = pkt->pkt_buffer;

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
            /* data from gateway not yet supported */
            fprintf(stderr,
                  "received data from AMT gateway, not supported\n");
            break;

        default:
            fprintf(stderr, "received unknown AMT type, %d\n", *cp);
            rc = 0;
    }

fail:

    if (rc <= 0) {
        relay_pkt_free(pkt);
    }
    return rc;
}

void
relay_instance_read(int fd, short __unused flags, void* uap)
{
    int len;
    relay_instance* instance;

    instance = (relay_instance*)uap;

    do {
        len = relay_message_read(instance, fd);
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
    url_request* url;

    url = (url_request*)uap;

    relay_close_url(url);
}

void
relay_accept_url(int fd, short __unused flags, void* uap)
{
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

void
relay_pcap_read(u_char* uap,
      const struct pcap_pkthdr* pkthdr,
      const u_int8_t* cp)
{
    int len;
    packet* pkt;
    relay_instance* instance;
    struct ether_header* ether;
    struct ip* ip;
    struct ip6_hdr* ip6;
    u_int8_t* ap;
    prefix_t* pfx;
    patext* pat;
    int enq = 0;
    char src[MAX_ADDR_STRLEN], dst[MAX_ADDR_STRLEN];

    ip = NULL;
    instance = (relay_instance*)uap;

    instance->stats.pcap_data_recvd1++;

    /*
    if (relay_debug(instance)) {
        fprintf(stderr, "got dispatch callback, caplen %u, pktlen %u\n",
              pkthdr->caplen, pkthdr->len);
    }
    */
    if (pkthdr->caplen != pkthdr->len) {
        if (relay_debug(instance))
            fprintf(stderr, "Received short packet over pcap %u of %u\n",
                  pkthdr->caplen, pkthdr->len);
        return;
    }
    len = pkthdr->len;

    switch (instance->relay_datalink) {
        case DLT_NULL:
            cp += 4;
            len -= 4;
            break;

        case DLT_EN10MB:
            ether = (struct ether_header*)cp;
            if (ntohs(ether->ether_type) != ETHERTYPE_IP) {
                if (relay_debug(instance))
                    fprintf(stderr, "Wrong Ethernet type %d\n",
                          ntohs(ether->ether_type));
                return;
            }
            cp += 14;
            len -= 14;
            break;

        case DLT_SLIP:
        case DLT_PPP:
            cp += 24;
            len -= 24;
            break;
        case DLT_LINUX_SLL:
            cp += 16;
            len -= 16;
            break;
        default:
            if (relay_debug(instance))
                fprintf(stderr, "pcap receive, unknown datalink type %d\n",
                      instance->relay_datalink);
            return;
    }

    if (len == 0) {
        if (relay_debug(instance))
            fprintf(stderr, "AMT DATA packet too small\n");
        return;
    }
    if (len > BUFFER_SIZE) {
        if (relay_debug(instance))
            fprintf(stderr, "AMT DATA packet too big\n");
        return;
    }

    /*
    if (relay_debug(instance)) {
        printf("%02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x\n"
               "%02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x\n",
               cp[0],cp[1],cp[2],cp[3],cp[4],cp[5],cp[6],cp[7],
               cp[8],cp[9],cp[10],cp[11],cp[12],cp[13],cp[14],cp[15],
               cp[16],cp[17],cp[18],cp[19],cp[20],cp[21],cp[22],cp[23],
               cp[24],cp[25],cp[26],cp[27],cp[28],cp[29],cp[30],cp[31]);
    }
    */

    pkt = relay_pkt_get(instance);
    pkt->pkt_af = instance->tunnel_af;
    // pkt->pkt_af = instance->relay_af;
    pkt->pkt_amt = AMT_MCAST_DATA;

    /*
     * leave space for the AMT header at the beginning of the packet
     */
    ap = pkt->pkt_buffer;
    *ap++ = AMT_MCAST_DATA;
    *ap++ = 0; /* reserved */

    /* Draft-07 changes */
    bcopy(cp, ap, len);

    len += sizeof(u_int16_t);

    pkt->pkt_len = len;

    switch (instance->tunnel_af) {
        case AF_INET:
            ip = (struct ip*)cp;
            if (ip->ip_ttl == 1) {
                if (relay_debug(instance))
                    fprintf(stderr, "IP packet with ttl 1\n");
                relay_pkt_free(pkt);
                return;
            }
            pkt->pkt_src =
                  prefix_build(AF_INET, &ip->ip_src.s_addr, INET_HOST_LEN);
            pkt->pkt_dst =
                  prefix_build(AF_INET, &ip->ip_dst.s_addr, INET_HOST_LEN);
            break;

        case AF_INET6:
            ip6 = (struct ip6_hdr*)cp;
            if (ip6->ip6_hops == 1) {
                if (relay_debug(instance))
                    fprintf(stderr, "IP6 packet with ttl 1\n");
                relay_pkt_free(pkt);
                return;
            }
            pkt->pkt_src = prefix_build(
                  AF_INET6, ip6->ip6_src.s6_addr, INET6_HOST_LEN);
            pkt->pkt_dst = prefix_build(
                  AF_INET6, ip6->ip6_dst.s6_addr, INET6_HOST_LEN);
            break;
        default:
            if (relay_debug(instance))
                fprintf(stderr, "Unknown IP version\n");
            relay_pkt_free(pkt);
            return;
    }

    /* count the number of pcap packets */
    instance->stats.pcap_data_recvd2++;

    /* enqueue only needed pkts */
    pfx = prefix_dup(pkt->pkt_dst);
    pat = pat_get(
          &instance->relay_root, prefix_keylen(pfx), prefix_key(pfx));
    if (pat) {
        enq = 1;
    } else {
        pfx = prefix_build_mcast(pkt->pkt_dst, pkt->pkt_src);
        pat = pat_get(
              &instance->relay_root, prefix_keylen(pfx), prefix_key(pfx));
        if (pat)
            enq = 1;
    }

    if (enq == 1) {
        /*
        if (relay_debug(instance)) {
            fprintf(stderr, "pkt queued: %s -> %s\n",
                  prefix2str(pkt->pkt_src, src, MAX_ADDR_STRLEN),
                  prefix2str(pkt->pkt_dst, dst, MAX_ADDR_STRLEN));
        }
        */
        relay_packet_enq(instance, pkt);
    } else {
        if (relay_debug(instance))
            fprintf(stderr, "pkt not subscribed: %s -> %s\n",
                  prefix2str(pkt->pkt_src, src, MAX_ADDR_STRLEN),
                  prefix2str(pkt->pkt_dst, dst, MAX_ADDR_STRLEN));
        relay_pkt_free(pkt);
    }

    prefix_free(pfx);
#define BLOCKING_DISPATCH 1

#if BLOCKING_DISPATCH
    // workaround for bug in dispatch:
    // https://github.com/the-tcpdump-group/libpcap/issues/493
    // That bug was conflicting with a race condition from using
    // nonblocking, so i'd rarely get any packets on a slow iperf.
    pcap_breakloop(instance->relay_pcap);
#endif
}

static u_int pcap_errs = 0;
static u_int pcap_packets = 0;
static void
relay_pcap_event_read(int fd, short __unused flags, void* uap)
{
    int rc;
    relay_instance* instance;
    // char msg[16] = {0};

    instance = (relay_instance*)uap;

    do {
        rc = pcap_dispatch(instance->relay_pcap, 1, relay_pcap_read, uap);
        if (rc > 0) {
            pcap_packets += rc;
        }
    } while (rc > 0);
    if (rc == -1) {
        if (relay_debug(instance)) {
            fprintf(stderr, "pcap error (%u err/%u rx): %s\n", pcap_errs,
                    pcap_packets, pcap_geterr(instance->relay_pcap));
        }
        pcap_errs += 1;
    }
    /*
    else if (rc == -2) {
        if (relay_debug(instance)) {
            fprintf(stderr, "pcap breakloop (%u err/%u rx)\n", pcap_errs,
                    pcap_packets);
        }
    } else {
        if (rc != 0) {
            snprintf(msg, sizeof(msg), "(%d) ", rc);
        }
    }
    if (relay_debug(instance)) {
        struct pcap_stat relay_pcap_stat;

        pcap_stats(instance->relay_pcap, &relay_pcap_stat);
        fprintf(stderr, "pcap_dispatch finished %s(%u err/%u rx): "
                "%u rx, %u drp, %u ifdrp\n",
                msg, pcap_errs, pcap_packets,
                relay_pcap_stat.ps_recv, relay_pcap_stat.ps_drop,
                relay_pcap_stat.ps_ifdrop);
    }
    */
}

int
relay_pcap_create(relay_instance* instance)
{
    int rc;
#ifdef BSD
    int val;
#endif /* BSD */
    u_int32_t localnet, netmask;
    char* device = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;

    if (relay_debug(instance)) {
        fprintf(stderr, "relay_pcap_create call\n");
    }

#if 0
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
	fprintf(stderr, "error getting pcap device: %s\n", errbuf);
	exit(1);
    }
#endif
    if (strlen(instance->cap_iface_name) != 0) {
        device = instance->cap_iface_name;
    }
    if (relay_debug(instance)) {
        fprintf(stderr, "opening pcap on %s\n", device?device:"(NULL)");
    }
    pd = pcap_create(device, errbuf);
    // pd = pcap_open_live(device, 1500, 0, 0, errbuf);
    if (pd == NULL) {
        fprintf(stderr, "error opening pcap device %s: %s\n",
                device?device:"(NULL)", errbuf);
        exit(1);
    }

    if (pcap_set_snaplen(pd, 1500) != 0) {
        fprintf(
              stderr, "error setting pcap snaplen: %s\n", pcap_geterr(pd));
        exit(1);
    }

    if (pcap_set_promisc(pd, 0) != 0) {
        fprintf(stderr, "error setting pcap to non-promisc: %s\n",
              pcap_geterr(pd));
        exit(1);
    }

    if (pcap_set_timeout(pd, 0) != 0) {
        fprintf(
              stderr, "error setting pcap timeout: %s\n", pcap_geterr(pd));
        exit(1);
    }

    if (pcap_set_buffer_size(pd, instance->pcap_buffer_size) != 0) {
        fprintf(stderr, "error setting pcap buffer size: %s\n",
              pcap_geterr(pd));
        exit(1);
    }

    if (pcap_activate(pd) != 0) {
        fprintf(
              stderr, "error setting pcap activate: %s\n", pcap_geterr(pd));
        exit(1);
    }

#if defined(BSD) && defined(BIOCIMMEDIATE)
    val = TRUE;
    /*
     * Turn on immediate mode in the Berkeley Packet Filter (bpf)
     */
    rc = ioctl(pcap_fileno(pd), BIOCIMMEDIATE, &val);
    if (rc < 0) {
        fprintf(stderr, "error setting BPF immediate mode: %s\n",
              strerror(errno));
        exit(1);
    }
#endif /* BSD && BIOCIMMEDIATE */

    localnet=0;
    netmask = PCAP_NETMASK_UNKNOWN;
    fprintf(stderr, "localnet: %08x, netmask: %08x\n", localnet, netmask);

    /*
    rc = pcap_lookupnet(device, &localnet, &netmask, errbuf);
    if (rc < 0) {
        fprintf(stderr, "error lookupnet pcap: %s\n", errbuf);
        exit(1);
    }

    rc = pcap_compile(pd, &instance->relay_fcode,
          "ip multicast or ip6 multicast", 0, netmask);
    if (rc < 0) {
        fprintf(stderr, "error compiling pcap expression: %s\n",
              pcap_geterr(pd));
        exit(1);
    }

    rc = pcap_setfilter(pd, &instance->relay_fcode);
    if (rc < 0) {
        fprintf(stderr, "error setting pcap filter: %s\n", pcap_geterr(pd));
        exit(1);
    }
    */

    instance->relay_datalink = pcap_datalink(pd);
    if (instance->relay_datalink < 0) {
        fprintf(
              stderr, "error getting pcap datalink: %s\n", pcap_geterr(pd));
        exit(1);
    }

    rc = pcap_setnonblock(pd, !BLOCKING_DISPATCH, errbuf);
    if (rc < 0) {
        fprintf(stderr, "error setting non block on pcap: %s\n",
              pcap_geterr(pd));
        exit(1);
    }

    instance->relay_pcap = pd;
    event_set(&instance->relay_pcap_ev, pcap_fileno(pd),
          EV_READ | EV_PERSIST, relay_pcap_event_read, (void*)instance);
    rc = event_add(&instance->relay_pcap_ev, NULL);
    if (rc < 0) {
        fprintf(stderr, "error pcap event_add: %s\n", strerror(errno));
        exit(1);
    }

    return 0;
}

int
relay_pcap_destroy(relay_instance* instance)
{
    int rc;

    /*
     * Don't listen for traffic on this socket any more
     */
    if (relay_debug(instance)) {
        fprintf(stderr, "relay_pcap_destroy call\n");
    }

    rc = event_del(&instance->relay_pcap_ev);
    if (rc < 0) {
        fprintf(stderr, "error from event_del on pcap: %s\n",
              strerror(errno));
        exit(1);
    }
    pcap_freecode(&instance->relay_fcode);
    pcap_close(instance->relay_pcap);
    instance->relay_pcap = NULL;

    return 0;
}
