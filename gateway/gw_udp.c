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

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <assert.h>
#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "igmp.h"  // copied from freebsd--linux doesn't have v3 in 2017
#include "amt.h"
#include "gw.h"

static const char __attribute__((unused)) id[] =
      "@(#) $Id: gw_udp.c,v 1.1.1.9 2007/05/31 17:22:04 sachin Exp $";

static request_t*
gw_request_get(int len)
{
    request_t* rq;

    rq = (request_t*)calloc(1, sizeof(request_t) + len);

    return rq;
}

static void
gw_request_free(request_t* rq)
{
    gw_t* gw;

    assert(rq);
    gw = rq->rq_gw;

    /*
     * stop the request timer
     */
    if (rq->rq_tev) {
        if (evtimer_pending(rq->rq_tev, NULL)) {
            evtimer_del(rq->rq_tev);
        }
        event_free(rq->rq_tev);
        rq->rq_tev = 0;
    }

    /*
     * remove it from the request list
     */
    TAILQ_REMOVE(&gw->request_head, rq, rq_next);

    free(rq);
}

static void
gw_send_request(gw_t* gw, request_t* rq)
{
    int tries, len;
    u_int8_t* cp;

    if (!gw->udp_sock) {
        fprintf(stderr, "%s: no socket to send request\n", gw->name);
        return;
    }

    cp = (u_int8_t*)gw->packet_buffer;

    *cp++ = AMT_REQUEST;
    *cp++ = 0; /* reserved */
    *cp++ = 0; /* reserved */
    *cp++ = 0; /* reserved */

    /*
     * save gateway nonce with Group Membership report for later
     */

    cp = put_long(cp, rq->rq_nonce);
    len = cp - (u_int8_t*)gw->packet_buffer;

    tries = 3;
    while (tries--) {
        ssize_t rc;

        rc = send(gw->udp_sock, gw->packet_buffer, len, MSG_DONTWAIT);
        if (rc < 0) {
            switch (errno) {
                case EINTR:
                    /* try again */
                    break;

                case EHOSTDOWN:
                case EHOSTUNREACH:
                case ECONNREFUSED:
                    /*
                     * There are problems communicating with the relay
                     */
                    fprintf(stderr,
                          "%s: send relay communication trouble: %s\n",
                          gw->name, strerror(errno));
                    gw_age_relay(gw);
                    return;

                default:
                    fprintf(stderr, "%s: request send: %s\n", gw->name,
                          strerror(errno));
                    return;
            }
        } else if (rc != len) {
            fprintf(stderr, "%s: request short write %d out of %d\n",
                  gw->name, (int)rc, len);
            return;
        } else {
            /* success */
            gw->amt_req_sent++;
            gettimeofday(&gw->last_req_time, NULL);
            return;
        }
    }
}

static void
gw_request_timeout(int fd, short __unused event, void* uap)
{
    int rc;
    gw_t* gw;
    request_t* rq;
    struct timeval tv;

    rq = (request_t*)uap;
    if (!rq) {
        fprintf(stderr, "AMT: No request to resend\n");
        return;
    }

    gw = rq->rq_gw;
    if (!gw) {
        fprintf(stderr, "AMT: No gateway instance to send request\n");
        return;
    }

    if (++rq->rq_count == GW_REQUEST_MAX) {
        fprintf(stderr, "%s: exceeded max tries to send membership\n",
              gw->name);
        /*
         * Mark that the relay discovery is in progress
         */
        gw->relay = RELAY_DISCOVERY_INPROGRESS;
        TAILQ_FOREACH(rq, &gw->request_head, rq_next)
        {
            if (rq->rq_tev && evtimer_pending(rq->rq_tev, NULL)) {
                gw_request_free(rq);
            }
        }
        /*
         * start a periodic relay discovery timer
         */
        if (!gw->discovery_tev) {
            gw->discovery_tev = evtimer_new(gw->event_base,
                    gw_send_discovery, gw);
        } else {
            if (evtimer_pending(gw->discovery_tev, NULL)) {
                evtimer_del(gw->discovery_tev);
            }
        }
        timerclear(&tv);
        tv.tv_sec = GW_DISCOVERY_OFFSET;
        rc = evtimer_add(gw->discovery_tev, &tv);
        if (rc < 0) {
            fprintf(stderr, "%s: can't initialize discovery timer: %s\n",
                  gw->name, strerror(errno));
            exit(1);
        }

        return;
    }

    /*
     * Use binary exponential backoff to retry request
     */
    timerclear(&tv);

    tv.tv_sec = 1 << (rq->rq_count - 1);
    rc = evtimer_add(rq->rq_tev, &tv);
    if (rc < 0) {
        fprintf(stderr, "%s: can't reset request timer: %s\n", gw->name,
              strerror(errno));
        exit(1);
    }

    gw_send_request(gw, rq);
}

void
gw_relay_found(gw_t* gw)
{
    int rc;
    struct timeval tv;
    request_t* rq;

    /* Set the status that we found the relay */
    gw->relay = RELAY_FOUND;

    /*
     * stop the discovery timer
     */
    if (evtimer_pending(gw->discovery_tev, NULL)) {
        evtimer_del(gw->discovery_tev);
    }

    /*
     * Open a connected socket to the newly discovered relay so we get
     * notified if it stops listening to us.
     */
    gw_init_udp_sock(gw);

    /*
     * Send pending requests
     */
    TAILQ_FOREACH(rq, &gw->request_head, rq_next)
    {
        /* Reset the request retry count */
        rq->rq_count = 0;

        timerclear(&tv);
        tv.tv_sec = 0; /* expire immediately */
        if (!rq->rq_tev) {
            rq->rq_tev = evtimer_new(gw->event_base, gw_request_timeout, rq);
        }
        rc = evtimer_add(rq->rq_tev, &tv);
        if (rc < 0) {
            fprintf(stderr, "%s: can't initialize request timer: %s\n",
                  gw->name, strerror(errno));
            exit(1);
        }
    }
}

void
gw_send_discovery(int fd, short event, void* uap)
{
    gw_t* gw;
    int rc, tries, len;
    u_int8_t* cp;
    u_int32_t nonce;
    struct timeval tv;
    int sin_len = 0;

    gw = (gw_t*)uap;
    if (!gw) {
        fprintf(stderr, "AMT: No gateway instance to send discovery\n");
        return;
    }

    gw->relay = RELAY_DISCOVERY_INPROGRESS;

    if (!gw->disco_sock) {
        fprintf(stderr, "%s: no socket to send discovery\n", gw->name);
        return;
    }

    if (!gw->discovery_tev) {
        gw->discovery_tev = evtimer_new(gw->event_base,
                gw_send_discovery, gw);
    } else {
        if (evtimer_pending(gw->discovery_tev, NULL)) {
            evtimer_del(gw->discovery_tev);
        }
    }

    timerclear(&tv);
    tv.tv_sec = GW_DISCOVERY_INTERVAL;
    rc = evtimer_add(gw->discovery_tev, &tv);
    if (rc < 0) {
        fprintf(stderr, "can't re-initialize discovery timer: %s\n",
              strerror(errno));
        exit(1);
    }

    cp = (u_int8_t*)gw->packet_buffer;

    *cp++ = AMT_RELAY_DISCOVERY;
    *cp++ = 0; /* reserved */
    *cp++ = 0; /* reserved */
    *cp++ = 0; /* reserved */

    nonce = random();                /* 32-bit random number */
    gw->anycast_relay_nonce = nonce; /* save for response */

    cp = put_long(cp, nonce); /* host byte order */

    len = cp - (u_int8_t*)gw->packet_buffer;

    if (gw->gateway_family == AF_INET) {
        sin_len = sizeof(struct sockaddr_in);
    } else if (gw->gateway_family == AF_INET6) {
        sin_len = sizeof(struct sockaddr_in6);
    }

    tries = 3;
    while (tries--) {
        ssize_t size;

        size = sendto(gw->disco_sock, gw->packet_buffer, len, MSG_DONTWAIT,
              (struct sockaddr*)&gw->discovery_addr, sin_len);
        if (size < 0) {
            switch (errno) {
                case EINTR:
                    /* try again */
                    break;

                default:
                {
                    char str[MAX_SOCK_STRLEN];
                    fprintf(stderr, "%s: discovery sendto(%d -> %s): %s\n",
                            gw->name, gw->disco_sock,
                            sock_ntop(gw->gateway_family,
                                &gw->discovery_addr, str, sizeof(str)),
                            strerror(errno));
                    return;
                }
            }
        } else if (size != len) {
            fprintf(stderr, "%s: discovery short write %d out of %d\n",
                  gw->name, (int)size, len);
            return;
        } else {
            /* success */
            return;
        }
    }
}

/*
 * record the relay unicast address for encapsulating
 */

static void
gw_recv_advertisement(gw_t* gw, u_int8_t* cp, int len)
{
    u_int32_t nonce;

    /*
     * If the discovery timer isn't running, then ignore the advertisement
     */
    if (!gw->discovery_tev || !evtimer_pending(gw->discovery_tev, NULL)) {
        fprintf(stderr,
              "%s: received advertisement but no discovery active.\n",
              gw->name);
        return;
    }

    cp += sizeof(u_int32_t); /* skip type and reserved */
    len -= sizeof(u_int32_t);

    nonce = get_long(cp);
    cp += sizeof(u_int32_t);
    len -= sizeof(u_int32_t);

    /*
     * save relay address if the nonce matches our request
     * XXX v4 specific, make family independent
     */
    if (gw->anycast_relay_nonce == nonce) {
        if (gw->gateway_family == AF_INET) {
            if (len < sizeof(struct in_addr)) {
                fprintf(stderr, "%s: advertisement too short. "
                        "(%d bytes for %d-byte addr)\n", gw->name, len,
                        (int)sizeof(struct in_addr));
                return;
            }
            struct sockaddr_in* sin =
                (struct sockaddr_in*)&gw->unicast_relay_addr;
            bzero(sin, sizeof(struct sockaddr_in));
            sin->sin_family = AF_INET;
#ifdef BSD
            sin->sin_len = sizeof(struct sockaddr_in);
#endif
            sin->sin_port = htons(AMT_PORT);
            bcopy(cp, &sin->sin_addr, sizeof(struct in_addr));
            cp += sizeof(struct in_addr);
            len -= sizeof(struct in_addr);
        } else if (gw->gateway_family == AF_INET6) {
            if (len < sizeof(struct in6_addr)) {
                fprintf(stderr, "%s: advertisement too short. "
                        "(%d bytes for %d-byte addr)\n", gw->name, len,
                        (int)sizeof(struct in6_addr));
                return;
            }
            struct sockaddr_in6* sin =
                (struct sockaddr_in6*)&gw->unicast_relay_addr;
            bzero(sin, sizeof(struct sockaddr_in6));
            sin->sin6_family = AF_INET6;
#ifdef BSD
            sin->sin6_len = sizeof(struct sockaddr_in6);
#endif
            sin->sin6_port = htons(AMT_PORT);
            bcopy(cp, &sin->sin6_addr, sizeof(struct in6_addr));
            cp += sizeof(struct in6_addr);
            len -= sizeof(struct in6_addr);
        }

        if (len) {
            fprintf(stderr,
                  "%s: warning: extra %d octets at end of advertisement.\n",
                  gw->name, len);
        }

        gw_relay_found(gw);
    } else {
        fprintf(stderr,
              "AMT Advertisement: got nonce %u, expected nonce %u\n", nonce,
              gw->anycast_relay_nonce);
    }
}

/*
 * Send a membership report/leave to the relay
 */
static void
gw_send_membership(gw_t* gw, request_t* rq, u_int8_t* mac)
{
    int tries, len;
    u_int8_t* cp;

    if (!gw->udp_sock) {
        fprintf(stderr, "%s: no socket to send membership\n", gw->name);
        return;
    }

    cp = (u_int8_t*)gw->packet_buffer;

    *cp++ = AMT_MEMBERSHIP_CHANGE;
    *cp++ = 0; /* reserved */

    /*
     * relay mac
     */
    bcopy(mac, cp, RESPONSE_MAC_LEN);
    cp += RESPONSE_MAC_LEN;

    /*
     * gateway nonce
     */
    cp = put_long(cp, rq->rq_nonce);

    /*
     * copy IGMP packet
     */
    bcopy(&rq->rq_buffer, cp, rq->rq_buffer_len);
    cp += rq->rq_buffer_len;

    len = cp - (u_int8_t*)gw->packet_buffer;

    tries = 3;
    while (tries--) {
        ssize_t rc;

        rc = send(gw->udp_sock, gw->packet_buffer, len, MSG_DONTWAIT);
        if (rc < 0) {
            switch (errno) {
                case EINTR:
                    /* try again */
                    break;

                case EHOSTDOWN:
                case EHOSTUNREACH:
                case ECONNREFUSED:
                    /*
                     * There are problems communicating with the relay
                     */
                    fprintf(stderr,
                          "%s: send relay communication trouble: %s\n",
                          gw->name, strerror(errno));
                    gw_age_relay(gw);
                    return;

                default:
                    fprintf(stderr, "%s: membership change: %s\n", gw->name,
                          strerror(errno));
                    return;
            }
        } else if (rc != len) {
            fprintf(stderr,
                  "%s: membership change short write %d out of %d\n",
                  gw->name, (int)rc, len);
            return;
        } else {
            /* success */
            return;
        }
    }
}

/*
 * Handles the query timeout. Send IGMP/MLD query over the TUN
 */
#if 1
static void
gw_query_timeout(int fd, short __unused event, void* uap)
{
    gw_t* gw = (gw_t*)uap;

    /* Send the query over TUN */
    // gw_forward_tun(gw, gw->query_buffer, gw->query_len);
    gw_send_local_membership_query(gw);
}
#endif

/*
 * process the query from the relay and send back a membership report
 */

static void
gw_recv_query(gw_t* gw, u_int8_t* cp, int len)
{
    request_t* rq;
    u_int32_t nonce;
    u_int8_t mac[RESPONSE_MAC_LEN];

    if (len < 2) {
        fprintf(stderr,
              "%s: short query received, missing reserved fields\n",
              gw->name);
        return;
    }

    cp++; /* skip type and reserved */
    cp++; /* skip type and reserved */
    len -= 2;

    if (len < RESPONSE_MAC_LEN) {
        fprintf(stderr, "%s: short query received, missing relay mac\n",
              gw->name);
        return;
    }
    bcopy(cp, mac, RESPONSE_MAC_LEN);
    cp += RESPONSE_MAC_LEN;
    len -= RESPONSE_MAC_LEN;

    if (len < sizeof(u_int32_t)) {
        fprintf(stderr, "%s: short query received, missing gateway nonce\n",
              gw->name);
        return;
    }
    nonce = ntohl(get_long_native(cp));
    cp += sizeof(u_int32_t);
    len -= sizeof(u_int32_t);

    /*
     * find the correct request
     */
    TAILQ_FOREACH(rq, &gw->request_head, rq_next)
    {
        if (rq->rq_nonce == nonce) {
            break;
        }
    }

    if (rq == NULL) {
        fprintf(stderr, "%s: received query from relay for unknown nonce\n",
              gw->name);
        return;
    }

    /*
     * Start a timer based on QQIC. If the timer has already started then
     * dont do anything.
     */
    if (len > 0 &&
            (!gw->query_tev || !evtimer_pending(gw->query_tev, NULL))) {
        int qqi = 5, mrt = 1;
        int rc;
        switch (gw->data_family) {
            case AF_INET:
            {
                struct ip* iph;
                struct igmpv3* igmpq = NULL;
                int plen, hlen;

                iph = (struct ip*)cp;
                hlen = iph->ip_hl << 2;
                plen = ntohs(iph->ip_len);
                if (plen != len) {
                    fprintf(stderr, "%s: warning: ip len %d in query != "
                            "packet len %d from ip\n", gw->name, plen, len);
                }

                switch (iph->ip_p) {
                    case IPPROTO_IGMP:
                        igmpq = (struct igmpv3*)((u_int8_t*)iph + hlen);
                        switch (igmpq->igmp_type) {
                            case IGMP_HOST_MEMBERSHIP_QUERY:
                                qqi = AMT_IGMP_QQIC_TO_QQI(igmpq->igmp_qqi);
                                mrt = AMT_IGMP_MRC_TO_MRT(igmpq->igmp_code);

                                break;
                            default:
                                fprintf(stderr,
                                      "%s: Unknown IGMP message in AMT query\n",
                                      gw->name);
                                return;
                        }
                        break;

                    default:
                        fprintf(stderr,
                              "%s: Unknown payload in the AMT membership query\n",
                              gw->name);
                        return;
                }
            }
            break;
            case AF_INET6:
            {
                // TBD: parse the qqi and mrt properly to decide when
                // to send a query.
            }
            break;
            default:
                fprintf(stderr, "%s: internal error: unknown data family "
                        "in recv_query\n", gw->name);
                return;
        }

        if (len > sizeof(gw->query_buffer)) {
            fprintf(stderr, "%s: query packet len %d too large to buffer "
                    "(%d)\n", gw->name, len, (int)sizeof(gw->query_buffer));
            return;
        }
        bcopy(cp, gw->query_buffer, len);
        gw->query_len = len;

        /*
         *	set an early timeout so that we can send the
         *	AMT request in time
         */
        struct timeval tv;
        timerclear(&tv);
        tv.tv_sec = qqi - mrt;
        if (!gw->query_tev) {
            gw->query_tev = evtimer_new(gw->event_base,
                    gw_query_timeout, gw);
        }
        rc = evtimer_add(gw->query_tev, &tv);
        if (rc < 0) {
            fprintf(stderr,
                  "%s: can't reset query timer: %s\n",
                  gw->name, strerror(errno));
            exit(1);
        }
    }

    /*
     * send the membership report/leave
     */
    gw_send_membership(gw, rq, mac);

    /*
     * free the request
     */
    gw_request_free(rq);
}

static int
gw_receive_udp(gw_t* gw, int fd)
{
    u_int8_t* cp;
    int tries;
    struct sockaddr_storage from;
    socklen_t fromlen;
    ssize_t recv_len = -1;

    tries = 3;
    while (tries-- && (recv_len < 0)) {

        /*
         * The 'from' address should be the anycast discovery address we
         * sent the discovery to. This is to get back through a firewall.
         * The real 'from' address is the relay address inside the packet.
         */
        fromlen = sizeof(from);
        recv_len = recvfrom(fd, gw->packet_buffer,
              sizeof(gw->packet_buffer), 0, (struct sockaddr*)&from, &fromlen);
        if (recv_len < 0) {
            switch (errno) {
                case EINTR: /* interrupted. retry. */
                    break;

                case EAGAIN:
                    return -1;

                case EHOSTDOWN:
                case EHOSTUNREACH:
                case ECONNREFUSED:
                    /*
                     * There are problems communicating with the relay
                     */
                    fprintf(stderr,
                          "%s: recv relay communication trouble: %s\n",
                          gw->name, strerror(errno));
                    gw_age_relay(gw);
                    return -1;

                default:
                    fprintf(stderr, "%s: UDP recvfrom: %s\n", gw->name,
                          strerror(errno));
                    return -1;
            }
        }

        if (recv_len == 0) {
            fprintf(stderr, "%s: UDP length 0\n", gw->name);
            return 0;
        }
    }

    /*
     * Read succeeded, validate packet and determine type
     */

    cp = gw->packet_buffer;

    switch (*cp) {

        case AMT_RELAY_ADVERTISEMENT:
            gw_recv_advertisement(gw, cp, recv_len);
            break;

        case AMT_MEMBERSHIP_QUERY:
            gw_recv_query(gw, cp, recv_len);
            break;


        case AMT_MCAST_DATA:
            /* Draft 07 changes */
            /* skip over AMT type and reserved */
            cp += sizeof(u_int16_t);
            recv_len -= sizeof(u_int16_t);

            gw_forward_tun(gw, cp, recv_len);

            gw->data_pkt_rcvd++;

            break;

        case AMT_RELAY_DISCOVERY:
        case AMT_REQUEST:
        case AMT_MEMBERSHIP_CHANGE:
            fprintf(stderr, "%s: gateway received unexpected AMT type %d\n",
                  gw->name, *cp);
            break;

        default:
            fprintf(stderr, "%s: gateway received unknown AMT type %d\n",
                  gw->name, *cp);
            break;
    }
    return recv_len;
}

void
gw_event_udp(int fd, short __unused flags, void* uap)
{
    gw_t* gw;

    gw = (gw_t*)uap;

    gw_receive_udp(gw, fd);
}

void
gw_request_start(gw_t* gw, u_int8_t* cp, int len)
{
    request_t* rq;
    int rc;
    struct timeval tv;

    rq = gw_request_get(len);

    rq->rq_nonce = random(); /* 32-bit random request identifier */
    rq->rq_gw = gw;          /* back pointer to the gateway */
    rq->rq_buffer_len = len; /* len of packet data */
    bcopy(cp, &rq->rq_buffer, len);

    /*
     * Insert this in the request list so we can look it up when we get
     * the query back.
     */
    TAILQ_INSERT_TAIL(&gw->request_head, rq, rq_next);

    /*
     * If the discovery timer is running,
     * then schedule the request to be sent out after relay is discovered
     */
    if (!gw->discovery_tev) {
        gw->discovery_tev = evtimer_new(gw->event_base,
                gw_send_discovery, gw);
    }
    if (evtimer_pending(gw->discovery_tev, NULL) ||
          gw->relay == RELAY_DISCOVERY_INPROGRESS) {
        return;
    }

    /*
     * If the relay has not been discovered yet,
     * then send periodic discoveries until we receive a relay advertisement
     */
    if (gw->relay == RELAY_NOT_FOUND) {
        gw_age_relay(gw);
        return;
    }

    /*
     * if the request timer isn't already running,
     * create a timer to send the initial request and subsequent retries
     */
    if (!rq->rq_tev) {
        rq->rq_tev = evtimer_new(gw->event_base, gw_request_timeout, rq);
    }
    if (!evtimer_pending(rq->rq_tev, NULL)) {
        timerclear(&tv);
        tv.tv_sec = 0; /* expire immediately */

        rc = evtimer_add(rq->rq_tev, &tv);
        if (rc < 0) {
            fprintf(stderr, "%s: can't initialize request timer: %s\n",
                  gw->name, strerror(errno));
            exit(1);
        }
    }
}

