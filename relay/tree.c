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
#include <stddef.h>
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

#include "../libprefix/prefix.h"
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
        if (sg->sg_source) {
            prefix_free(sg->sg_source);
        }
        if (sg->sg_group) {
            prefix_free(sg->sg_group);
        }
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
        if (gw->idle_timer) {
            event_free(gw->idle_timer);
            gw->idle_timer = NULL;
        }
        mem_type_free(mem_gw_handle, gw);
    }
}

static int
family2level(int family)
{
    switch (family) {
        case AF_INET:
            return IPPROTO_IP;
        case AF_INET6:
            return IPPROTO_IPV6;
        default:
            return -1;
    }
}

/*
 * Leave the group and delete the socket if there are no other sources
 */
static int
membership_leave(sgnode* sg)
{
    int rc = 0;
    relay_instance* instance;

    instance = sg->sg_instance;

    if (relay_debug(instance)) {
        char src_addr[MAX_ADDR_STRLEN], group_addr[MAX_ADDR_STRLEN];
        if (sg->sg_source)
            fprintf(stderr, "Sending leave msg: %s/%s\n",
                  prefix2str(sg->sg_source, src_addr, MAX_ADDR_STRLEN),
                  prefix2str(sg->sg_group, group_addr, MAX_ADDR_STRLEN));
        else
            fprintf(stderr, "Sending leave msg: %s\n",
                  prefix2str(sg->sg_group, group_addr, MAX_ADDR_STRLEN));
    }

    /*
     * Drop the source/group membership
     */
    if (!sg->sg_source) {
        struct group_req greq;
        greq.gr_interface = instance->cap_iface_index;
        switch (instance->tunnel_af)
        /* switch(instance->relay_af) */
        {
            case AF_INET: {
                struct sockaddr_in group_addr;
                bzero(&group_addr, sizeof(group_addr));
                group_addr.sin_family = AF_INET;
                bcopy(prefix_key(sg->sg_group), &group_addr.sin_addr.s_addr,
                      sizeof(struct in_addr));
                bcopy(&group_addr, &greq.gr_group, sizeof(group_addr));
                break;
            }
            case AF_INET6: {
                struct sockaddr_in6 group_addr;
                bzero(&group_addr, sizeof(group_addr));
                group_addr.sin6_family = AF_INET6;
                bcopy(prefix_key(sg->sg_group),
                      group_addr.sin6_addr.s6_addr,
                      sizeof(struct in6_addr));
                bcopy(&group_addr, &greq.gr_group, sizeof(group_addr));
                break;
            }
        }

        rc = setsockopt(sg->sg_socket, family2level(instance->tunnel_af)
              /* family2level(instance->relay_af) */,
              MCAST_LEAVE_GROUP, &greq, sizeof(greq));

        if (rc < 0) {
            fprintf(stderr, "error MCAST_LEAVE_GROUP sg socket: %s\n",
                  strerror(errno));
            exit(1);
        }
    } else {
        /* SSM */
        struct group_source_req gsreq;
        bzero(&gsreq, sizeof(gsreq));
        gsreq.gsr_interface = instance->cap_iface_index;
        switch (instance->tunnel_af)
        /* switch(instance->relay_af) */
        {
            case AF_INET: {
                struct sockaddr_in addr;
                bzero(&addr, sizeof(addr));
                addr.sin_family = AF_INET;
                bcopy(prefix_key(sg->sg_source), &addr.sin_addr.s_addr,
                      sizeof(struct in_addr));
                bcopy(&addr, &gsreq.gsr_source, sizeof(addr));
                bcopy(prefix_key(sg->sg_group), &addr.sin_addr.s_addr,
                      sizeof(struct in_addr));
                bcopy(&addr, &gsreq.gsr_group, sizeof(addr));
                break;
            }
            case AF_INET6: {
                struct sockaddr_in6 addr;
                bzero(&addr, sizeof(addr));
                addr.sin6_family = AF_INET6;
                bcopy(prefix_key(sg->sg_source), addr.sin6_addr.s6_addr,
                      sizeof(struct in6_addr));
                bcopy(&addr, &gsreq.gsr_source, sizeof(addr));
                bcopy(prefix_key(sg->sg_group), addr.sin6_addr.s6_addr,
                      sizeof(struct in6_addr));
                bcopy(&addr, &gsreq.gsr_group, sizeof(addr));
                break;
            }
        }

        rc = setsockopt(sg->sg_socket, family2level(instance->tunnel_af)
              /* family2level(instance->relay_af) */,
              MCAST_LEAVE_SOURCE_GROUP, &gsreq, sizeof(gsreq));

        if (rc < 0) {
            fprintf(stderr,
                  "error MCAST_LEAVE_SOURCE_GROUP sg socket: %s\n",
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
static void
membership_join(sgnode* sg)
{
    int rc;
    relay_instance* instance;

    instance = sg->sg_instance;

    if (relay_debug(instance)) {
        char src_addr[MAX_ADDR_STRLEN], group_addr[MAX_ADDR_STRLEN];
        if (sg->sg_source) {
            fprintf(stderr, "Sending join msg: %s/%s\n",
                  prefix2str(sg->sg_source, src_addr, MAX_ADDR_STRLEN),
                  prefix2str(sg->sg_group, group_addr, MAX_ADDR_STRLEN));
        } else {
            fprintf(stderr, "Sending join msg: %s\n",
                  prefix2str(sg->sg_group, group_addr, MAX_ADDR_STRLEN));
        }
    }

    relay_socket_init(sg);
    if (sg->sg_source) {
        /* SSM */
        struct group_source_req gsreq;
        bzero(&gsreq, sizeof(gsreq));
        gsreq.gsr_interface = instance->cap_iface_index;
        switch (instance->tunnel_af)
        {
            case AF_INET: {
                struct sockaddr_in addr;
                bzero(&addr, sizeof(addr));
                addr.sin_family = AF_INET;
                bcopy(prefix_key(sg->sg_source), &addr.sin_addr.s_addr,
                      sizeof(struct in_addr));
                bcopy(&addr, &gsreq.gsr_source, sizeof(addr));
                bcopy(prefix_key(sg->sg_group), &addr.sin_addr.s_addr,
                      sizeof(struct in_addr));
                bcopy(&addr, &gsreq.gsr_group, sizeof(addr));
                break;
            }
            case AF_INET6: {
                struct sockaddr_in6 addr;
                bzero(&addr, sizeof(addr));
                addr.sin6_family = AF_INET6;
                bcopy(prefix_key(sg->sg_source), addr.sin6_addr.s6_addr,
                      sizeof(struct in6_addr));
                bcopy(&addr, &gsreq.gsr_source, sizeof(addr));
                bcopy(prefix_key(sg->sg_group), addr.sin6_addr.s6_addr,
                      sizeof(struct in6_addr));
                bcopy(&addr, &gsreq.gsr_group, sizeof(addr));
                break;
            }
        }

        rc = setsockopt(sg->sg_socket, family2level(instance->tunnel_af),
              MCAST_JOIN_SOURCE_GROUP, &gsreq, sizeof(gsreq));

        if (rc < 0) {
            fprintf(stderr, "error MCAST_JOIN_SOURCE_GROUP sg socket: %s\n",
                  strerror(errno));
            exit(1);
        }
    } else {
        struct group_req greq;
        greq.gr_interface = instance->cap_iface_index;
        switch (instance->tunnel_af)
        {
            case AF_INET: {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                bcopy(prefix_key(sg->sg_group), &addr.sin_addr.s_addr,
                      sizeof(struct in_addr));
                bcopy(&addr, &greq.gr_group, sizeof(addr));
                break;
            }
            case AF_INET6: {
                struct sockaddr_in6 addr;
                addr.sin6_family = AF_INET6;
                bcopy(prefix_key(sg->sg_group), addr.sin6_addr.s6_addr,
                      sizeof(struct in6_addr));
                bcopy(&addr, &greq.gr_group, sizeof(addr));
                break;
            }
        }

        rc = setsockopt(sg->sg_socket, family2level(instance->tunnel_af),
              MCAST_JOIN_GROUP, &greq, sizeof(greq));
        if (rc < 0) {
            fprintf(stderr, "error MCAST_JOIN_GROUP sg socket: %s\n",
                  strerror(errno));
            exit(1);
        }
    }
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

/*int found = 0;
static gw_t *find_gw = NULL;

static void
for_each_sg(patext *ext)
{
    sgnode *sg = pat2sg(ext);
    if (gw_find(sg, &(find_gw->gw_dest)) != NULL)
        ++found;
}

static int
gw_num(gw_t *gw)
{
    sgnode *sg = gw->gw_sg;
    relay_instance *instance = sg->sg_instance;
    find_gw = gw;
    found = 0;

    if(!pat_empty(&(instance->relay_root)))
        pat_walk(&(instance->relay_root), for_each_sg);
    return found;
}*/

static void
gw_delete(gw_t* gw)
{
    sgnode* sg;
    sg = gw->gw_sg;

    /* Delete this gw from the tree */
    pat_delete(&sg->sg_gwroot, &gw->gw_node);
    /* Canncel the idle timer for this gw */
    evtimer_del(gw->idle_timer);

    relay_gw_free(gw);
}

static prefix_t* find_pfx = NULL;

static void
for_each_sg_del(patext* ext)
{
    sgnode* sg = pat2sg(ext);
    relay_instance* instance = sg->sg_instance;
    gw_t* gw;

    if ((gw = gw_find(sg, find_pfx)) != NULL)
        gw_delete(gw);

    if (pat_empty(&sg->sg_gwroot))
        TAILQ_INSERT_TAIL(&(instance->idle_sgs_list), sg, idle_next);
}

void
icmp_delete_gw(relay_instance* instance, prefix_t* pfx)
{
    char str1[MAX_ADDR_STRLEN];
    sgnode *sg, *tmp_sg;

    find_pfx = pfx;

    if (relay_debug(instance)) {
        fprintf(stderr, "Delete gw %s due to the ICMP message\n",
              prefix2str(pfx, str1, MAX_ADDR_STRLEN));
    }

    /* Delete the gw from sg tree */
    if (!pat_empty(&(instance->relay_root))) {

        pat_walk(&(instance->relay_root), for_each_sg_del);
        for (sg = TAILQ_FIRST(&(instance->idle_sgs_list)); sg != NULL;
              sg = tmp_sg) {
            tmp_sg = TAILQ_NEXT(sg, idle_next);
            TAILQ_REMOVE(&(instance->idle_sgs_list), sg, idle_next);

            membership_leave(sg);
            pat_delete(&instance->relay_root, &sg->sg_node);
            int rc;
            rc = event_del(sg->sg_receive_ev);
            if (rc < 0) {
                fprintf(stderr, "error deleting sg event: %s\n",
                        strerror(errno));
                exit(1);
            }
            event_free(sg->sg_receive_ev);
            relay_sgnode_free(sg);
            /*
             * remove the data link receive socket when the last
             * sgnode is destroyed
             */
            if (--sgcount == 0) {
                // XXX: do I need something when out of sgs?
            }
        }
    }
}

/*
 *  Delete a gw after some idle time
 */
void
idle_delete(int fd, short event, void* arg)
{
    (void)fd;
    (void)event;
    gw_t* gw = (gw_t*)arg;
    sgnode* sg;
    relay_instance* instance;
    char str1[MAX_ADDR_STRLEN];

    if (gw) {
        sg = gw->gw_sg;
        instance = sg->sg_instance;

        if (relay_debug(instance)) {
            fprintf(stderr, "Delete idle gw %s\n",
                  prefix2str(&(gw->gw_dest), str1, MAX_ADDR_STRLEN));
        }

        gw_delete(gw);

        if (pat_empty(&sg->sg_gwroot)) {
            membership_leave(sg);
            pat_delete(&instance->relay_root, &sg->sg_node);
            int rc;
            rc = event_del(sg->sg_receive_ev);
            if (rc < 0) {
                fprintf(stderr, "error deleting sg event: %s\n",
                        strerror(errno));
                exit(1);
            }
            event_free(sg->sg_receive_ev);
            relay_sgnode_free(sg);
            /*
             * remove the data link receive socket when the last
             * sgnode is destroyed
             */
            if (--sgcount == 0) {
                // XXX: do i need something when out of sgs?
            }
        }
    }
}

/*
 * We keep a tree of gateways that we receive joins from in each sgnode
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
        if (relay_debug(sg->sg_instance)) {
            char str[MAX_ADDR_STRLEN];
            fprintf(stderr, "Added pat gateway sg=%p key=%s keylen=%u\n",
                    sg, prefix2str(&gw->gw_dest, str, sizeof(str)),
                    prefix_keylen(&gw->gw_dest));
        }
        /* Set the timer */
        gw->idle_timer = evtimer_new(sg->sg_instance->event_base,
                idle_delete, gw);
        /*
        // add is always followed by update, set happens there.
        struct timeval tv;
        int rc;
        tv.tv_sec = GW_IDLE;
        tv.tv_usec = 0;
        rc = evtimer_add(gw->idle_timer, &tv);
        */
        if (!gw->idle_timer) {
            fprintf(stderr, "can't initialize gw idle timer(add): %s\n",
                  strerror(errno));
            exit(1);
        }
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
    struct timeval tv;
    int rc;

    bcopy(pkt_dst, &gw->gw_src, sizeof(prefix_t));
    gw->gw_dport = sport;
    gw->gw_sport = dport;
    gw->gw_socket = sock;

    if (evtimer_pending(gw->idle_timer, NULL)) {
        evtimer_del(gw->idle_timer);
    }

    tv.tv_sec = GW_IDLE;
    tv.tv_usec = 0;
    // evtimer_set(gw->idle_timer, idle_delete, gw);
    rc = evtimer_add(gw->idle_timer, &tv);
    if (rc < 0) {
        fprintf(stderr, "can't initialize gw idle timer(update): %s\n",
              strerror(errno));
        exit(1);
    }
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
      prefix_t* source)
{
    patext* pat;
    sgnode* sg = NULL;
    gw_t* gw;
    prefix_t* pfx;
    char str1[MAX_ADDR_STRLEN], str2[MAX_ADDR_STRLEN],
          str3[MAX_ADDR_STRLEN], str4[MAX_ADDR_STRLEN];

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
                    // XXX: do I need something on first sg?
                }

                sg = relay_sgnode_get(instance);
                sg->sg_instance = instance;
                sg->sg_group = group;
                sg->sg_source = source;
                bcopy(pfx, &sg->sg_addr, sizeof(prefix_t));
                if (relay_debug(instance)) {
                    fprintf(stderr, "Set %s prefix filter for %s/%u\n",
                      (instance->tunnel_af == AF_INET) ? "INET" : "INET6",
                      prefix2str(pfx, str1, sizeof(str1)),
                      prefix_keylen(pfx));
                }
                pat_key_set(&sg->sg_node, prefix_key(&sg->sg_addr));
                pat_keysize_set(&sg->sg_node, prefix_keylen(&sg->sg_addr));
                pat_add(&instance->relay_root, &sg->sg_node);
                sg->sg_gwroot = NULL;
            }
            if (relay_debug(instance)) {
                fprintf(stderr, "Received %s membership report for %s/%s "
                                "from %s:%u to %s:%u\n",
                      (instance->tunnel_af == AF_INET) ? "INET" : "INET6",
                      prefix2str(sg->sg_group, str1, sizeof(str1)),
                      (sg->sg_source == NULL)
                            ? "None"
                            : prefix2str(sg->sg_source, str2, sizeof(str2)),
                      prefix2str(pkt->pkt_src, str3, sizeof(str3)),
                      ntohs(pkt->pkt_sport),
                      prefix2str(pkt->pkt_dst, str4, sizeof(str4)),
                      ntohs(pkt->pkt_dport));
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
                    fprintf(stderr, "Recevied %s leave message for %s/%s "
                                    "from %s:%u to %s:%u\n",
                          (instance->tunnel_af == AF_INET)
                                /* (pkt->pkt_af == AF_INET)*/
                                ? "INET"
                                : "INET6",
                          prefix2str(sg->sg_group, str1, sizeof(str1)),
                          (sg->sg_source == NULL)
                                ? "None"
                                : prefix2str(
                                        sg->sg_source, str2, sizeof(str2)),
                          prefix2str(pkt->pkt_src, str3, sizeof(str3)),
                          ntohs(pkt->pkt_sport),
                          prefix2str(pkt->pkt_dst, str4, sizeof(str4)),
                          ntohs(pkt->pkt_dport));
                }
                gw = gw_find(sg, pkt->pkt_src);
                if (gw) {
                    gw_delete(gw);

                    if (pat_empty(&sg->sg_gwroot)) {
                        membership_leave(sg);
                        pat_delete(&instance->relay_root, &sg->sg_node);
                        int rc;
                        rc = event_del(sg->sg_receive_ev);
                        if (rc < 0) {
                            fprintf(stderr, "error deleting sg event: %s\n",
                                    strerror(errno));
                            exit(1);
                        }
                        event_free(sg->sg_receive_ev);
                        relay_sgnode_free(sg);
                        /*
                         * remove the data link receive socket when the last
                         * sgnode is destroyed
                         */
                        if (--sgcount == 0) {
                            // XXX: do i need something when out of sgs?
                        }
                    } else {
                        prefix_free(source);
                        prefix_free(group);
                    }
                } else {
                    if (relay_debug(instance)) {
                        fprintf(stderr, "Leave for group %s/%s not joined "
                                        "by gateway %s:%u\n",
                              prefix2str(sg->sg_group, str1, sizeof(str1)),
                              (sg->sg_source == NULL)
                                    ? "None"
                                    : prefix2str(sg->sg_source, str2,
                                            sizeof(str2)),
                              prefix2str(pkt->pkt_src, str3, sizeof(str3)),
                              ntohs(pkt->pkt_sport));
                    }
                    prefix_free(source);
                    prefix_free(group);
                }
            } else {
                if (relay_debug(instance)) {
                    fprintf(stderr, "Leave for group %s/%s not joined\n",
                          prefix2str(group, str1, sizeof(str1)),
                          (source == NULL)
                                ? "None"
                                : prefix2str(source, str2, sizeof(str2)));
                }
                prefix_free(source);
                prefix_free(group);
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
    char str1[MAX_ADDR_STRLEN], str2[MAX_ADDR_STRLEN],
          str3[MAX_ADDR_STRLEN];
    struct timeval time_stamp;
    u_int64_t now;

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
    if (instance->relay_af == AF_INET)
        sin.sin_port = gw->gw_dport;
    else
        sin6.sin6_port = gw->gw_dport;

    /* calculate the queueing delay */
    gettimeofday(&time_stamp, NULL);
    now = time_stamp.tv_sec * 1000000 + time_stamp.tv_usec;
    instance->agg_qdelay += (now - pkt->enq_time);
    instance->n_qsamples += 1;

    /*
    uint8_t* cp = pkt->pkt_data;
    if (relay_debug(instance)) {
        printf("%02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x\n"
               "%02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x (len=%u gw_forward %p)\n",
               cp[0],cp[1],cp[2],cp[3],cp[4],cp[5],cp[6],cp[7],
               cp[8],cp[9],cp[10],cp[11],cp[12],cp[13],cp[14],cp[15],
               cp[16],cp[17],cp[18],cp[19],cp[20],cp[21],cp[22],cp[23],
               cp[24],cp[25],cp[26],cp[27],cp[28],cp[29],cp[30],cp[31],
               pkt->pkt_len, gw);
    }
    */

    tries = 3;
    while (tries--) {
        if (relay_debug(instance)) {
            static unsigned int data_pkts_sent = 0;
            if (data_pkts_sent % 1000 == 0) {
                fprintf(stderr, "Sending %s data packet %u len %d from "
                                "%s:%u to %s:%u\n",
                      (pkt->pkt_af == AF_INET) ? "INET" : "INET6",
                      data_pkts_sent, pkt->pkt_len,
                      prefix2str(pkt->pkt_src, str1, sizeof(str1)),
                      ntohs(pkt->pkt_sport),
                      prefix2str(pkt->pkt_dst, str2, sizeof(str2)),
                      ntohs(pkt->pkt_dport));

                fprintf(stderr, "ts: %llu mcast data recvd: %llu, mcast "
                                "data sent: %llu\n",
                      (unsigned long long)time_stamp.tv_sec,
                      (unsigned long long)instance->stats.mcast_data_recvd,
                      (unsigned long long)instance->stats.mcast_data_sent);
            }
            data_pkts_sent++;
        }
        rc = sendto(gw->gw_socket, pkt->pkt_data, pkt->pkt_len,
              MSG_DONTWAIT, sa, salen);
        if (rc < 0) {
            switch (errno) {
                case EINTR:
                    /* try again */
                    if (relay_debug(instance))
                        fprintf(stderr, "forwarding mcast data to %s got "
                                        "interrupted\n",
                              prefix2str(
                                    &(gw->gw_src), str3, MAX_ADDR_STRLEN));
                    break;

                default:
                    if (relay_debug(instance))
                        fprintf(stderr, "forward packet error: %s to %s\n",
                              strerror(errno),
                              prefix2str(
                                    &(gw->gw_src), str3, MAX_ADDR_STRLEN));
                    return;
            }
        } else if ((unsigned int)rc != pkt->pkt_len) {
            if (relay_debug(instance))
                fprintf(stderr,
                      "forward packet short write %d out of %d to %s\n", rc,
                      pkt->pkt_len,
                      prefix2str(&(gw->gw_src), str3, MAX_ADDR_STRLEN));
            return;
        } else {
            /* success */
            instance->stats.mcast_data_sent++;
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
    } else {
        if (relay_debug(sg->sg_instance)) {
            fprintf(stderr, "forward_mcast_data: no gateway for %p\n", sg);
        }
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
        /*
        if (relay_debug(instance)) {
            sgnode* sg = pat2sg(pat);
            char str[MAX_ADDR_STRLEN], str2[MAX_ADDR_STRLEN];
            fprintf(stderr, "forwarding s,g %s -> %s (%p)\n",
                    prefix2str(pkt->pkt_src, str, sizeof(str)),
                    prefix2str(pkt->pkt_dst, str2, sizeof(str2)), sg);
        }
        */
        forward_mcast_data(pkt, pat);
    } else {
        /* Otherwise cater ASM requests */
        pat = pat_get(&instance->relay_root, prefix_keylen(pkt->pkt_dst),
              prefix_key(pkt->pkt_dst));
        /*
        if (relay_debug(instance)) {
            sgnode* sg = 0;
            if (pat) {
                sg = pat2sg(pat);
            }
            char str[MAX_ADDR_STRLEN], str2[MAX_ADDR_STRLEN];
            fprintf(stderr, "forwarding g %s -> %s (%p)\n",
                    prefix2str(pkt->pkt_src, str, sizeof(str)),
                    prefix2str(pkt->pkt_dst, str2, sizeof(str2)), sg);
        }
        */
        if (pat) {
            forward_mcast_data(pkt, pat);
        }
    }
    prefix_free(pfx);

}

