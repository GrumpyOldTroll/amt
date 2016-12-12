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

static const char __attribute__((unused)) id[] = "@(#) $Id: main.c,v 1.1.1.8 2007/05/09 20:42:13 sachin Exp $";

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event.h>
#include <pcap.h>

#include "memory.h"
#include "prefix.h"
#include "pat.h"
#include "amt.h"
#include "relay.h"

static struct instances instance_head;
static mem_handle mem_rinstance_handle = NULL;

static relay_instance *
relay_instance_alloc(int af)
{
    relay_instance *instance;

    if (!mem_rinstance_handle) {
	mem_rinstance_handle = mem_type_init(sizeof(relay_instance),
					     "Relay instance");
    }
    instance = (relay_instance *) mem_type_alloc(mem_rinstance_handle);
    instance->relay_af = af;

    /*
     * Insert this instance into the instance list
     */
    TAILQ_INSERT_TAIL(&instance_head, instance, relay_next);

    /*
     * initialize the head of the packet queues
     */
    TAILQ_INIT(&instance->pkt_head[HIGH]);
    TAILQ_INIT(&instance->pkt_head[MEDIUM]);
    TAILQ_INIT(&instance->pkt_head[LOW]);

    /*
     * Initialize the roots of the radix trees
     */
    instance->relay_root = NULL;
    instance->rif_root = NULL;
    instance->relay_url_port = DEFAULT_URL_PORT;

    return instance;
}

static void
relay_event_init(relay_instance *instance)
{
    instance->relay_context = event_init();
    if (instance->relay_context == NULL) {
	fprintf(stderr, "event_init failed\n");
	exit(1);
    }
}

/*
 * relay_signal_init - Add signal handlers
 */
static void
relay_signal_init (relay_instance *instance)  
{
    struct sigaction sa; 
   
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);   
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, 0);
}

static void
usage(char *name)
{
    fprintf(stderr, "usage: %s -a anycast prefix/plen [-d]\n", name);
    exit(1);
}

int
relay_socket_shared_init(int family, struct sockaddr *bind_addr,
			 int bind_addr_len)
{
    int rc, val, len, sock;

    val = TRUE;
    len = sizeof(val);

    sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
	fprintf(stderr, "error creating socket: %s\n", strerror(errno));
	exit(1);
    }

    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, len);
    if (rc < 0) {
	fprintf(stderr, "error SO_REUSEADDR socket: %s\n",
		strerror(errno));
	exit(1);
    }

    if (bind_addr) {
	rc = bind(sock, bind_addr, bind_addr_len);
	if (rc < 0) {
	    fprintf(stderr, "error binding socket: %s\n", strerror(errno));
	    exit(1);
	}
    }

    /*
     * XXX - Update for linux to use IP_PKTINFO,
     * instead of IP_RECVDSTADDR and IP_RECVIF.
     */
#ifdef BSD
    rc = setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR, &val, len);
    if (rc < 0) {
	fprintf(stderr, "error IP_RECVDSTADDR on socket: %s\n",
		strerror(errno));
	exit(1);
    }
    rc = setsockopt(sock, IPPROTO_IP, IP_RECVIF, &val, len);
    if (rc < 0) {
	fprintf(stderr, "error IP_RECVIF on socket: %s\n",
		strerror(errno));
	exit(1);
    }
#else
    rc = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &val, len);
    if (rc < 0) {
	fprintf(stderr, "error IP_RECVDSTADDR on socket: %s\n",
		strerror(errno));
	exit(1);
    }
#endif

    val = fcntl(sock, F_GETFL, 0);
    if (val < 0) {
	    return errno;
    }
    rc = fcntl(sock, F_SETFL, val | O_NONBLOCK);
    if (rc < 0) {
	    fprintf(stderr, "error O_NONBLOCK on socket: %s\n",
		        strerror(errno));
    	exit(1);
    }

    return sock;
}

/*
 * Listen for URL requests to come in to display statistics and
 * user/billing information.
 */
void
relay_url_init(relay_instance *instance)
{
    int rc, salen, sock;
    // int val, len;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr *sa = NULL;

    switch (instance->relay_af) {
	case AF_INET:
	    salen = sizeof(sin);
	    sa = (struct sockaddr *) &sin;
	    bzero(sa, salen);
	    sin.sin_family = instance->relay_af;
	    sin.sin_addr.s_addr = htonl(INADDR_ANY);
	    sin.sin_port = htons(instance->relay_url_port);
	    break;

	case AF_INET6:
	    salen = sizeof(sin6);
	    sa = (struct sockaddr *) &sin6;
	    bzero(sa, salen);
	    break;

        default:
	    salen = 0;
            assert(instance->relay_af == AF_INET ||
		   instance->relay_af == AF_INET6);
    }


    // val = TRUE;
    // len = sizeof(val);

    sock = socket(instance->relay_af, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
	fprintf(stderr, "error creating URL socket: %s\n", strerror(errno));
	exit(1);
    }

    rc = bind(sock, sa, salen);
    if (rc < 0) {
	fprintf(stderr, "error binding url socket: %s\n", strerror(errno));
	exit(1);
    }

    rc = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (rc < 0) {
	fprintf(stderr, "error O_NONBLOCK on socket: %s\n",
		strerror(errno));
	exit(1);
    }

    rc = listen(sock, 5);
    if (rc < 0) {
	fprintf(stderr, "error url listen on socket: %s\n", strerror(errno));
	exit(1);
    }

    event_set(&instance->relay_url_ev, sock, EV_READ|EV_PERSIST,
	      relay_accept_url, (void *) instance);
    rc = event_add(&instance->relay_url_ev, NULL);
    if (rc < 0) {
	fprintf(stderr, "error url event_add: %s\n", strerror(errno));
	exit(1);
    }
    instance->relay_url_sock = sock;
}

static void
relay_anycast_socket_init(relay_instance *instance,
			  struct sockaddr *listen_addr, int addr_len)
{
    int rc;

    instance->relay_anycast_sock = relay_socket_shared_init(instance->relay_af,
						     listen_addr, addr_len);

    event_set(&instance->relay_anycast_ev, instance->relay_anycast_sock,
	      EV_READ|EV_PERSIST, relay_instance_read, (void *) instance);
    rc = event_add(&instance->relay_anycast_ev, NULL);
    if (rc < 0) {
	fprintf(stderr, "error anycast event_add: %s\n", strerror(errno));
	exit(1);
    }
}

int
main (int argc, char **argv)
{
    int ch, rc, plen;
    relay_instance *instance;
    struct sockaddr_in listen_addr;

    /*
     * assume IPv4 for the first release.
     * We'll make it fully address family indepdent later
     */
    TAILQ_INIT(&instance_head);
    instance = relay_instance_alloc(AF_INET);

    BIT_RESET(instance->relay_flags, RELAY_FLAG_DEBUG);

    bzero((char *) &listen_addr, sizeof(listen_addr));
#ifdef BSD
    listen_addr.sin_len = sizeof(listen_addr);
#endif    
    listen_addr.sin_port = htons(AMT_PORT);
    plen = 0;

    while ((ch = getopt(argc, argv, "u:a:dp:")) != EOF) {
	char *pstr = NULL;
	in_addr_t prefix;
        switch (ch) {
        case 'u':
            instance->use_unicast_addr = 1;
	case 'a':
            pstr = strsep(&optarg, "/");
            if (pstr == NULL) {
                fprintf(stderr, "bad anycast prefix: expecting prefix/len\n");
                exit(1);
            }
            if (optarg == NULL) {
                fprintf(stderr, "bad anycast prefix length\n");
                exit(1);
            }
            rc = inet_pton(AF_INET, pstr, &prefix);
            if (rc == 1) {
                plen = strtol(optarg, NULL, 10);
                if (plen == 0) {
                    fprintf(stderr, "bad anycast prefix length\n");
                    exit(1);
                }
                if (plen > AMT_HOST_PLEN) {
                    fprintf(stderr, "anycast prefix length too long\n");
                    exit(1);
                }

		listen_addr.sin_family = AF_INET;
                if(instance->use_unicast_addr == 1) {
		    listen_addr.sin_addr = inet_makeaddr(ntohl(prefix), 0x0);
                }
                else {
             	    listen_addr.sin_addr = inet_makeaddr(ntohl(prefix), 0x1);
                }
            } else {
                fprintf(stderr, "bad anycast prefix\n");
                exit(1);
            }
            break;

        case 'd':
	    BIT_SET(instance->relay_flags, RELAY_FLAG_DEBUG);
            break;

	case 'p':
	    if (optarg == NULL) {
		fprintf(stderr, "must specify port number\n");
		exit(1);
	    }
	    instance->relay_url_port = strtol(optarg, NULL, 10);
	    if (instance->relay_url_port < IPPORT_RESERVED) {
		fprintf(stderr, "must use port number => %d\n",
			IPPORT_RESERVED);
		exit(1);
	    }
        default:
        case '?':
	    usage(argv[0]);
        }
    }

    if (plen == 0) {
	fprintf(stderr, "anycast prefix/len must be set with -a\n");
	exit(1);
    }
    relay_event_init(instance);
    relay_signal_init(instance);
    relay_anycast_socket_init(instance, (struct sockaddr *) &listen_addr,
			      sizeof(listen_addr));
    relay_url_init(instance);

    rc = event_dispatch();
    fprintf(stderr, "Unexpected exit: %s\n", strerror(rc));

    return rc;
}

