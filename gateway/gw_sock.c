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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef BSD
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#include "amt.h"
#include "gw.h"

static const char __attribute__((unused)) id[] =
      "@(#) $Id: gw_sock.c,v 1.1.1.8 2007/05/09 20:40:55 sachin Exp $";

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

static int
init_discovery_socket(gw_t* gw)
{
    int s, rc;
    struct sockaddr_in sin;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "%s: creating discovery socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }
    gw->disco_sock = s;

    rc = socket_set_non_blocking(s);
    if (rc < 0) {
        return errno;
    }

    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
#ifdef BSD
    sin.sin_len = sizeof(sin);
#endif
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);

    rc = bind(s, (struct sockaddr*)&sin, sizeof(sin));
    if (rc < 0) {
        fprintf(stderr, "%s: binding any on UDP socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }

    event_set(&gw->udp_disco_id, s, EV_READ | EV_PERSIST, gw_event_udp,
          (void*)gw);
    rc = event_add(&gw->udp_disco_id, NULL);
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

/*
 * Create a UDP socket to communicate with the relay.
 * Determine our local address that we should use for sending packets
 * to the relay.
 * Add our new socket to the event queue.
 */
int
gw_init_udp_sock(gw_t* gw)
{
    int s, rc, sin_len;
    socklen_t len;
    struct sockaddr_in sin;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "%s: creating UDP socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }
    gw->udp_sock = s;

    rc = socket_set_non_blocking(s);
    if (rc < 0) {
        return errno;
    }

    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);

    rc = bind(s, (struct sockaddr*)&sin, sizeof(sin));
    if (rc < 0) {
        fprintf(stderr, "%s: binding any on UDP socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }

    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin_len = sizeof(sin);
#ifdef BSD
    sin.sin_len = sizeof(sin);
#endif
    sin.sin_addr.s_addr = gw->unicast_relay_addr.sin_addr.s_addr;
    sin.sin_port = htons(AMT_PORT);

    rc = connect(s, (struct sockaddr*)&sin, sizeof(sin));
    if (rc < 0) {
        /*
         * we need to handle the case of no route to destination
         * XXX
         */
        if (errno == EADDRNOTAVAIL) {
        }
        fprintf(stderr, "%s: connecting on UDP socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }

    len = sizeof(sin);
    bzero(&sin, len);
    rc = getsockname(s, (struct sockaddr*)&sin, &len);
    if (rc < 0) {
        fprintf(stderr, "%s: getsockname: %s\n", gw->name, strerror(errno));
        return errno;
    }

    bcopy(&sin, &gw->local_addr, sin_len);

    event_set(&gw->udp_event_id, s, EV_READ | EV_PERSIST, gw_event_udp,
          (void*)gw);
    rc = event_add(&gw->udp_event_id, NULL);
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

    rc = event_del(&gw->udp_disco_id);
    if (rc < 0) {
        fprintf(stderr, "%s: error from disco event_del: %s\n", gw->name,
              strerror(errno));
    }
    bzero(&gw->udp_disco_id, sizeof(struct event));
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

static char dbg_buffer[1024];
void
gw_event_dbg_client(int fd, short __unused flags, void* uap)
{
    debug_client_t* dc;
    gw_t* gw;
    int rc, len = 30;

    dc = (debug_client_t*)uap;
    gw = dc->dc_gw;

    rc = read(fd, dbg_buffer, len);
    if (rc <= 0) {
        fprintf(stderr, "%s: read error from debug client: %s\n", gw->name,
              strerror(errno));
        return;
    } else if (rc == 0) {
        rc = write(fd, "[amtgwd]# ", 10);
        if (rc < 0) {
            fprintf(stderr, "%s: write error(1) from debug client: %s\n",
                  gw->name, strerror(errno));
        }
    } else {
        char* pstr = dbg_buffer;
        int nbytes = 0;
        /*
         * Take action on the command
         */
        if (strncmp(dbg_buffer, "exit", 4) == 0) {
            event_del(&dc->client_event_id);
            close(fd);
            TAILQ_REMOVE(&gw->dbg_head, dc, dc_next);
            free(dc);
            return;
        } else if (strncmp(dbg_buffer, "stat", 4) == 0) {
            nbytes += sprintf(pstr, "~~~~~~~~~~~~~~~ AMT Gateway "
                                    "Statistics ~~~~~~~~~~~~~~~\n");
            nbytes += sprintf(pstr + nbytes,
                  "\tNumber of AMT requests sent: %d\n", gw->amt_req_sent);
            nbytes += sprintf(pstr + nbytes,
                  "\tNumber of MCast data pkts rcvd: %d\n",
                  gw->data_pkt_rcvd);
            if (gw->last_req_time.tv_sec) {
                nbytes += sprintf(pstr + nbytes,
                      "\tTimestamp of last amt req: %s",
                      ctime((time_t*)&gw->last_req_time.tv_sec));
            } else {
                nbytes += sprintf(
                      pstr + nbytes, "\tTimestamp of last amt req: NA\n");
            }

            switch (gw->relay) {
                case RELAY_NOT_FOUND:
                    nbytes += sprintf(
                          pstr + nbytes, "\tRelay: Not yet discovered\n");
                    break;
                case RELAY_DISCOVERY_INPROGRESS:
                    nbytes += sprintf(pstr + nbytes,
                          "\tRelay: Discovery in Progress\n");
                    break;
                case RELAY_FOUND:
                    switch (gw->unicast_relay_addr.sin_family) {
                        char addr[164];
                        case AF_INET:
                            nbytes += sprintf(pstr + nbytes,
                                  "\tRelay: %s:%d\n",
                                  inet_ntop(AF_INET,
                                        &gw->unicast_relay_addr.sin_addr,
                                        addr, 164),
                                  AMT_PORT);
                            break;
                        case AF_INET6:
                            break;
                        default:
                            break;
                    }
                    break;
                default:
                    break;
            }
        } else if (strncmp(dbg_buffer, "discover", 8) == 0) {
            nbytes += sprintf(pstr, "Discovering a Relay...\n");
            gw_age_relay(gw);
        } else if (strncmp(dbg_buffer, "help", 4) == 0) {
            nbytes += sprintf(pstr,
                  "\thelp: Prints this message\n"
                  "\tstat: Prints out the gateway statistics\n"
                  "\tdiscover: Discovers a relay\n"
                  "\texit: Ends the debug session\n");
        } else {
            nbytes += sprintf(pstr, "Unknown Command\n");
        }
        nbytes += sprintf(pstr + nbytes, "[amtgwd]# ");
        rc = write(fd, pstr, nbytes);
        if (rc < 0) {
            fprintf(stderr, "%s: write error from debug client: %s\n",
                  gw->name, strerror(errno));
        }
    }
}

void
gw_event_debug(int fd, short __unused flags, void* uap)
{
    int rc;
    debug_client_t* dc;
    gw_t* gw;
    struct sockaddr_in sin;
    socklen_t socklen;
    int s;

    bzero(&sin, sizeof(sin));

    gw = (gw_t*)uap;

    s = accept(fd, (struct sockaddr*)&sin, &socklen);
    if (s < 0) {
        fprintf(stderr, "%s: accepting debug client socket: %s\n", gw->name,
              strerror(errno));
        return;
    }

    rc = write(s, "[amtgwd]# ", 10);
    if (rc < 0) {
        fprintf(stderr, "%s: event write error from debug client: %s\n",
              gw->name, strerror(errno));
    }

    rc = socket_set_non_blocking(s);
    if (rc < 0) {
        close(s);
        return;
    }

    dc = (debug_client_t*)calloc(1, sizeof(debug_client_t));
    dc->clientfd = s;
    bcopy(&sin, &dc->client_addr, sizeof(struct sockaddr_in));
    dc->dc_gw = gw;
    /*
     * Insert this in the debug client list
     */
    TAILQ_INSERT_TAIL(&gw->dbg_head, dc, dc_next);

    /*
     * Set the read event for this socket
     */
    event_set(&dc->client_event_id, s, EV_READ | EV_PERSIST,
          gw_event_dbg_client, (void*)dc);
    rc = event_add(&dc->client_event_id, NULL);
    if (rc < 0) {
        fprintf(stderr, "%s: error from debug client event_add: %s\n",
              gw->name, strerror(errno));
        close(s);
        TAILQ_REMOVE(&gw->dbg_head, dc, dc_next);
        free(dc);
        return;
    }
}

/*
 * Create a TCP socket to communicate with the debug clients.
 * Add our new socket to the event queue.
 */
int
gw_init_dbg_sock(gw_t* gw)
{
    int s, rc;
    struct sockaddr_in sin;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        fprintf(stderr, "%s: creating debug socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }
    gw->dbg_sock = s;

    rc = socket_set_non_blocking(s);
    if (rc < 0) {
        return errno;
    }

    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(gw->dbg_port);

    rc = bind(s, (struct sockaddr*)&sin, sizeof(sin));
    if (rc < 0) {
        fprintf(stderr, "%s: binding any on debug socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }

    rc = listen(s, 5);
    if (rc < 0) {
        fprintf(stderr, "%s: listening on debug socket: %s\n", gw->name,
              strerror(errno));
        return errno;
    }

    event_set(&gw->dbg_event_id, s, EV_READ | EV_PERSIST, gw_event_debug,
          (void*)gw);
    rc = event_add(&gw->dbg_event_id, NULL);
    if (rc < 0) {
        fprintf(stderr, "%s: error from debug event_add: %s\n", gw->name,
              strerror(errno));
        return errno;
    }

    return 0;
}
