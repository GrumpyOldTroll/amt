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

/*
 * AMT gateway declarations
 * $Id: gw.h,v 1.1.1.9 2007/05/31 17:22:03 sachin Exp $
 */

#ifndef AMT_GATEWAY_GW_H
#define AMT_GATEWAY_GW_H

#define GW_PID_FILE_PATH "/tmp"
#define GW_DISCOVERY_OFFSET 1    /* seconds */
#define GW_DISCOVERY_INTERVAL 20 /* seconds */

#define GW_REQUEST_MAX 7 /* try 7 times (127 secs) */

#define AMT_IGMP_QQIC_TO_QQI(Qqic)                                         \
    ((Qqic < 128) ? (Qqic) : (((Qqic & 0x0f) | 0x10)                       \
                                   << (((Qqic & 0x70) >> 4) + 3)))

#define AMT_IGMP_MRC_TO_MRT(Mrc) (AMT_IGMP_QQIC_TO_QQI(Mrc) / 10)

typedef enum {
    RELAY_NOT_FOUND = 0,
    RELAY_FOUND = 1,
    RELAY_DISCOVERY_INPROGRESS = 2
} relay_status;

TAILQ_HEAD(requests, _request_t);
TAILQ_HEAD(dbg_clients, _debug_client_t);

typedef struct _gw_t
{
    pid_t pid;                             /* current process id */
    void* gw_context;                      /* event context */
    int disco_sock;                        /* discovery socket */
    int udp_sock;                          /* udp send/recv socket */
    int rt_sock;                           /* routing socket */
    int seq;                               /* routing socket seq # */
    int tundev;                            /* descriptor to tunnel */
    int tununit;                           /* unit # of device */
    int tunindex;                          /* index of device */
    char tunifname[FILENAME_MAX];          /* TUN interface name */
    struct event udp_disco_id;             /* discovery read event */
    struct event udp_event_id;             /* udp read event */
    struct event tun_event_id;             /* tun read event */
    struct event discovery_timer;          /* send relay discoverys */
    u_int32_t anycast_relay_nonce;         /* relay discovery nonce */
    in_addr_t subnet_anycast_prefix;       /* ipv4 anycast subnet (host)*/
    int subnet_anycast_plen;               /* ipv4 subnet prefix length*/
    in_addr_t relay_anycast_address;       /* ipv4 anycast subnet (relay)*/
    struct sockaddr_in anycast_relay_addr; /* discovery address */
    struct sockaddr_in unicast_relay_addr; /* relay to send to */
    struct sockaddr_in local_addr;         /* local unicast address */
    struct sockaddr_in tun_addr;           /* local tunnel address */
    struct requests request_head;          /* list head for request list */
    char name[NAME_MAX];                   /* program name */
    u_int8_t packet_buffer[BUFFER_SIZE];   /* transmit/recv buffer */

    relay_status relay;                 /* Relay discovery status */
    struct event query_timer;           /* send periodic amt requests */
    u_int32_t query_len;                /* igmp/mld query len */
    u_int8_t query_buffer[BUFFER_SIZE]; /* igmp/mld query buffer */

    /* Debug */
    u_int8_t debug;               /* debug flag */
    u_int16_t dbg_port;           /* debug port */
    int dbg_sock;                 /* debug socket */
    struct event dbg_event_id;    /* debug read event */
    struct dbg_clients dbg_head;  /* list head 4 dbg clients */
    u_int32_t amt_req_sent;       /* # of AMT requests sent */
    u_int32_t data_pkt_rcvd;      /* # of MCast Data recvd */
    u_int32_t data_pkt_sent;      /* # of MCast Data sent */
    struct timeval last_req_time; /* Timestamp of last AMT req */

} gw_t;

typedef struct _request_t
{
    TAILQ_ENTRY(_request_t) rq_next; /* list of request structs */
    u_int32_t rq_nonce;              /* gateway nonce sent */
    struct event rq_timer;           /* request timer */
    gw_t* rq_gw;                     /* gateway back pointer */
    int rq_count;                    /* number of attempts that failed */
    int rq_buffer_len;               /* size of original packet */
    u_int8_t rq_buffer[0];           /* original packet to send */
} request_t;

typedef struct _debug_client_t
{
    TAILQ_ENTRY(_debug_client_t)
    dc_next;                        /* list of debug clients structs */
    int clientfd;                   /* Client socket FD */
    struct sockaddr_in client_addr; /* Client socket address */
    gw_t* dc_gw;                    /* Gateway instance */
    struct event client_event_id;   /* read event for the dbg client */
} debug_client_t;

int init_sockets(gw_t*);
int init_iftun_device(gw_t*);
int init_address(gw_t*);
int gw_mcast_default_set(gw_t*);
int gw_if_addr_set(gw_t*);
int gw_init_udp_sock(gw_t*);
int init_routing_socket(gw_t*);
void gw_cleanup_udp_sock(gw_t*);
int socket_set_non_blocking(int);
void gw_send_discovery(int, short, void*);
void gw_event_udp(int, short, void*);
void gw_event_tun(int, short, void*);
void gw_request_start(gw_t*, u_int8_t*, int);
void gw_forward_tun(gw_t*, u_int8_t*, int);
void gw_age_relay(gw_t*);
int gw_init_dbg_sock(gw_t*);

#endif  // AMT_GATEWAY_GW_H
