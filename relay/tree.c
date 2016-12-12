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
      "@(#) $Id: tree.c,v 1.1.1.8 2007/05/09 20:42:13 sachin Exp $";

#include <arpa/inet.h>
#include <assert.h>
#include <event.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stddef.h>
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
#include "tree.h"

static mem_handle mem_sgnode_handle = NULL;
static mem_handle mem_gw_handle = NULL;
static int sgcount = 0;

static sgnode*
relay_sgnode_get(relay_instance* instance)
{
    sgnode* sg;

    if (!mem_sgnode_handle) {
        mem_sgnode_handle =
              mem_type_init(sizeof(sgnode), "Relay (S,G) node");
    }
    sg = (sgnode*)mem_type_alloc(mem_sgnode_handle);
    sg->sg_instance = instance;

    return sg;
}

static void
relay_sgnode_free(sgnode* sg)
{
    if (sg) {
        mem_type_free(mem_sgnode_handle, sg);
    }
}

static gw_t*
relay_gw_get(sgnode* sg)
{
    gw_t* gw;

    if (!mem_gw_handle) {
        mem_gw_handle =
              mem_type_init(sizeof(gw_t), "Relay learned gateway");
    }
    gw = (gw_t*)mem_type_alloc(mem_gw_handle);
    gw->gw_sg = sg;

    return gw;
}

static void
relay_gw_free(gw_t* gw)
{
    if (gw) {
        mem_type_free(mem_gw_handle, gw);
    }
}

/*
 * Leave the group and delete the socket if there are no other sources
 */
static int
membership_leave(sgnode* sg)
{
    int rc = 0;
    struct ip_mreq imr;
    // relay_instance *instance;

    // instance = sg->sg_instance;

    /*
   * Drop the source/group membership
   */
    if (!sg->sg_source) {
        bcopy(prefix_key(sg->sg_group), &imr.imr_multiaddr.s_addr,
              sizeof(struct in_addr));
        imr.imr_interface.s_addr = 0;
        rc = setsockopt(sg->sg_socket, IPPROTO_IP, IP_DROP_MEMBERSHIP,
              (char*)&imr, sizeof(struct ip_mreq));
        if (rc < 0) {
            fprintf(stderr, "error IP_DROP_MEMBERSHIP sg socket: %s\n",
                  strerror(errno));
            exit(1);
        }
    }

    close(sg->sg_socket);
    sg->sg_socket = 0;

    return 0;
}

/*
 * Create a socket to receive data for this group on and join the group
 */
static int
membership_join(sgnode* sg)
{
    int rc;
    struct ip_mreq imr;
    struct ip_mreq_source imr_src;
    relay_instance* instance;

    instance = sg->sg_instance;

    bzero(&imr, sizeof(struct ip_mreq));
    /*
   * set the socket to non-blocking, etc.
   */
    sg->sg_socket = relay_socket_shared_init(instance->relay_af, NULL, 0);

    if (sg->sg_source) {
        bzero(&imr_src, sizeof(struct ip_mreq_source));
        bcopy(prefix_key(sg->sg_source), &imr_src.imr_sourceaddr.s_addr,
              sizeof(struct in_addr));
        bcopy(prefix_key(sg->sg_group), &imr_src.imr_multiaddr.s_addr,
              sizeof(struct in_addr));
        imr_src.imr_interface.s_addr = INADDR_ANY;
        rc = setsockopt(sg->sg_socket, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
              (char*)&imr_src, sizeof(struct ip_mreq_source));
    } else {
        bcopy(prefix_key(sg->sg_group), &imr.imr_multiaddr.s_addr,
              sizeof(struct in_addr));
        imr.imr_interface.s_addr = INADDR_ANY;
        rc = setsockopt(sg->sg_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
              (char*)&imr, sizeof(struct ip_mreq));
    }
    if (rc < 0) {
        fprintf(stderr, "error IP_ADD_MEMBERSHIP sg socket: %s\n",
              strerror(errno));
        exit(1);
    }

    return rc;
}

static gw_t*
gw_find(sgnode* sg, prefix_t* pfx)
{
    patext* pat;

    pat = pat_get(&sg->sg_gwroot, prefix_keylen(pfx), prefix_key(pfx));
    if (pat) {
        return pat2gw(pat);
    }
    return NULL;
}

static void
gw_delete(gw_t* gw)
{
    sgnode* sg;

    sg = gw->gw_sg;

    pat_delete(&sg->sg_gwroot, &gw->gw_node);
    relay_gw_free(gw);
}

/*
 * We keep a tree of gateway's that we receive joins from in each sgnode
 */
static gw_t*
gw_add(sgnode* sg, prefix_t* pfx)
{
    gw_t* gw;
    patext* pat;

    pat = pat_get(&sg->sg_gwroot, prefix_keylen(pfx), prefix_key(pfx));
    if (pat) {
        gw = pat2gw(pat);
    } else {
        gw = relay_gw_get(sg);
        gw->gw_sg = sg;
        bcopy(pfx, &gw->gw_dest, sizeof(prefix_t));
        pat_key_set(&gw->gw_node, prefix_key(&gw->gw_dest));
        pat_keysize_set(&gw->gw_node, prefix_keylen(&gw->gw_dest));
        pat_add(&sg->sg_gwroot, &gw->gw_node);
    }

    return gw;
}

static void
gw_update(gw_t* gw,
      int sock,
      u_int16_t sport,
      prefix_t* pkt_dst,
      u_int16_t dport)
{
    bcopy(pkt_dst, &gw->gw_src, sizeof(prefix_t));
    gw->gw_dport = sport;
    gw->gw_sport = dport;
    gw->gw_socket = sock;
}

static void
gateway_print(struct evbuffer* buf, gw_t* gw)
{
    char str[MAX_ADDR_STRLEN];

    evbuffer_add_printf(buf, "\t%s:%d\t%u\t%u\n",
          prefix2str(&gw->gw_dest, str, sizeof(str)), gw->gw_sport,
          gw->gw_packets, gw->gw_bytes);
}

static void
stream_print(struct evbuffer* buf, sgnode* sg)
{
    char str[MAX_ADDR_STRLEN];
    patext* pat;

    evbuffer_add_printf(buf, "%s\t%u\t%u\n",
          prefix2str(sg->sg_group, str, sizeof(str)), sg->sg_packets,
          sg->sg_bytes);

    evbuffer_add_printf(buf, "\tGateway\tPackets\tBytes\n");

    pat = pat_getnext(&sg->sg_gwroot, NULL, 0);
    while (pat) {
        gateway_print(buf, pat2gw(pat));

        pat = pat_getnext(
              &sg->sg_gwroot, pat_key_get(pat), pat_keysize_get(pat));
    }
}

void
relay_show_streams(relay_instance* instance, struct evbuffer* buf)
{
    patext* pat;

    evbuffer_add_printf(buf, "Group\tPackets\tBytes\n");
    pat = pat_getnext(&instance->relay_root, NULL, 0);
    while (pat) {
        stream_print(buf, pat2sg(pat));
        pat = pat_getnext(&instance->relay_root, pat_key_get(pat),
              pat_keysize_get(pat));
    }
}

void
membership_tree_refresh(relay_instance* instance,
      membership_type mt,
      packet* pkt,
      prefix_t* group,
      prefix_t* source,
      prefix_t* from __unused)
{
    patext* pat;
    sgnode* sg = NULL;
    gw_t* gw;
    prefix_t* pfx;
    char str1[MAX_ADDR_STRLEN], str2[MAX_ADDR_STRLEN];

    /*
   * combine group/source into a single prefix
   */
    if (source) {
        pfx = prefix_build_mcast(group, source);
    } else {
        pfx = prefix_dup(group);
    }

    pat = pat_get(
          &instance->relay_root, prefix_keylen(pfx), prefix_key(pfx));
    if (pat) {
        sg = pat2sg(pat);
        /* sg node already has source and group prefix so free them */
        prefix_free(source);
        prefix_free(group);
    }

    switch (mt) {
        case MEMBERSHIP_REPORT:
            if (!sg) {
                /*
             * create the data link receive socket when the first
             * sgnode is created.
             */
                if (sgcount++ == 0) {
                    if (relay_pcap_create(instance)) {
                        fprintf(stderr, "error initializing libpcap: %s\n",
                              strerror(errno));
                        exit(1);
                    }
                }

                sg = relay_sgnode_get(instance);
                sg->sg_instance = instance;
                sg->sg_group = group;
                sg->sg_source = source;
                bcopy(pfx, &sg->sg_addr, sizeof(prefix_t));
                pat_key_set(&sg->sg_node, prefix_key(&sg->sg_addr));
                pat_keysize_set(&sg->sg_node, prefix_keylen(&sg->sg_addr));
                pat_add(&instance->relay_root, &sg->sg_node);
                sg->sg_gwroot = NULL;
            }
            if (relay_debug(instance)) {
                fprintf(stderr, "Report for %s from %s\n",
                      prefix2str(sg->sg_group, str1, sizeof(str1)),
                      prefix2str(pkt->pkt_src, str2, sizeof(str2)));
            }
            gw = gw_find(sg, pkt->pkt_src);
            if (!gw) {
                gw = gw_add(sg, pkt->pkt_src);
            }

            /*
           * Make sure we keep the latest address and port info
           * so that data can come back through a firewall
           */
            gw_update(gw, pkt->pkt_fd, pkt->pkt_sport, pkt->pkt_dst,
                  pkt->pkt_dport);

            if (!sg->sg_socket) {
                membership_join(sg);
            }
            break;

        case MEMBERSHIP_LEAVE:
            if (sg) {
                if (relay_debug(instance)) {
                    fprintf(stderr, "Leave for %s from %s\n",
                          prefix2str(sg->sg_group, str1, sizeof(str1)),
                          prefix2str(pkt->pkt_src, str2, sizeof(str2)));
                }
                gw = gw_find(sg, pkt->pkt_src);
                if (gw) {
                    gw_delete(gw);

                    if (pat_empty(&sg->sg_gwroot)) {
                        membership_leave(sg);
                        pat_delete(&instance->relay_root, &sg->sg_node);
                        relay_sgnode_free(sg);
                        /*
                 * remove the data link receive socket when the last
                 * sgnode is destroyed
                 */
                        if (--sgcount == 0) {
                            if (relay_pcap_destroy(instance)) {
                                fprintf(stderr,
                                      "error destroying libpcap: %s\n",
                                      strerror(errno));
                                exit(1);
                            }
                        }
                    }
                } else {
                    if (relay_debug(instance)) {
                        fprintf(stderr,
                              "Leave for group not joined by gateway\n");
                    }
                }
            } else {
                if (relay_debug(instance)) {
                    fprintf(stderr, "Leave for group not joined\n");
                }
            }
            break;

        default:
            assert(mt == MEMBERSHIP_REPORT || mt == MEMBERSHIP_LEAVE);
    }
    prefix_free(pfx);
}

static void
relay_forward_gw(sgnode* sg, gw_t* gw, packet* pkt)
{
    int rc, salen, tries;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr* sa;
    relay_instance* instance;

    instance = sg->sg_instance;

    salen = 0;
    sa = NULL;
    switch (instance->relay_af) {
        case AF_INET:
            sa = (struct sockaddr*)&sin;
            salen = sizeof(struct sockaddr_in);
            break;

        case AF_INET6:
            sa = (struct sockaddr*)&sin6;
            salen = sizeof(struct sockaddr_in6);
            break;

        default:
            assert(instance->relay_af == AF_INET ||
                   instance->relay_af == AF_INET6);
    }

    prefix2sock(&gw->gw_dest, sa);
    sin.sin_port = gw->gw_dport;

    tries = 3;
    while (tries--) {
        rc = sendto(gw->gw_socket, pkt->pkt_buffer, pkt->pkt_len,
              MSG_DONTWAIT, sa, salen);
        if (rc < 0) {
            switch (errno) {
                case EINTR:
                    /* try again */
                    break;

                default:
                    fprintf(stderr, "forward packet error: %s",
                          strerror(errno));
                    return;
            }
        } else if (rc != pkt->pkt_len) {
            fprintf(stderr, "forward packet short write %d out of %d\n", rc,
                  pkt->pkt_len);
            return;
        } else {
            /* success */
            return;
        }
    }
}

static void
forward_mcast_data(packet* pkt, patext* pat)
{
    sgnode* sg;
    sg = pat2sg(pat);
    pat = pat_getnext(&sg->sg_gwroot, NULL, 0);
    if (pat) {
        sg->sg_packets++;
        sg->sg_bytes += pkt->pkt_len;
    }
    while (pat) {
        gw_t* gw;

        gw = pat2gw(pat);

        gw->gw_packets++;
        gw->gw_bytes += pkt->pkt_len;

        relay_forward_gw(sg, gw, pkt);
        pat = pat_getnext(
              &sg->sg_gwroot, pat_key_get(pat), pat_keysize_get(pat));
    }
}
/*
 * FreeBSD currently does not support IGMPv3 so all memberships
 * will just use the group address and not the source.
 * In the future, support will be added for group and source forwarding.
 */
void
relay_forward(packet* pkt)
{
    patext* pat;
    relay_instance* instance;
    prefix_t* pfx;

    instance = pkt->pkt_instance;
    /* Cater SSM requests if any */
    pfx = prefix_build_mcast(pkt->pkt_dst, pkt->pkt_src);
    pat = pat_get(
          &instance->relay_root, prefix_keylen(pfx), prefix_key(pfx));
    if (pat) {
        forward_mcast_data(pkt, pat);
    }
    prefix_free(pfx);

    /* Otherwise cater ASM requests */
    pat = pat_get(&instance->relay_root, prefix_keylen(pkt->pkt_dst),
          prefix_key(pkt->pkt_dst));
    if (pat) {
        forward_mcast_data(pkt, pat);
    }
}
