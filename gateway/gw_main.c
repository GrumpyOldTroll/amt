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

#include <arpa/inet.h>
#include <event.h>
#include <libgen.h>
#include <netinet/in.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "amt.h"
#include "gw.h"

static const char __attribute__((unused)) id[] =
      "@(#) $Id: gw_main.c,v 1.1.1.9 2007/05/31 17:22:04 sachin Exp $";

static void
usage(char* name)
{
    fprintf(stderr, "usage: %s -a relay anycast prefix -s subnet anycast "
                    "prefix/plen [-d] [-n] [-v]\n",
          name);
    exit(1);
}

/*
 * Only allow one instance of the AMT gateway to run at a time.
 * Use the PID lockfile method to detect another instance.
 */
static int
init_pid_lockfile(gw_t* gw)
{
    char pidpath[PATH_MAX];
    FILE* fp;

    snprintf(pidpath, MAXPATHLEN, "%s/%s.pid", GW_PID_FILE_PATH, gw->name);
    fp = fopen(pidpath, "r");
    if (fp) {
        char pid_string[11];

        /* PID lock file exists */
        if (fgets(pid_string, sizeof(pid_string), fp) != NULL) {
            int oldpid;

            oldpid = (int)strtol(pid_string, (char**)NULL, 10);
            if (oldpid) {
                if (kill(oldpid, 0) == 0) {
                    /* gateway process already running */
                    return oldpid;
                }
            }
        }
        fclose(fp);
        unlink(pidpath);
    }

    /*
     * create new pid lock file
     */
    gw->pid = getpid();
    fp = fopen(pidpath, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "%d\n", gw->pid);
    fclose(fp);

    return 0;
}

static void
gw_reconfig(int sig)
{
    /* XXX */
}

static void
gw_shutdown(int sig)
{
    /* XXX */
    char pidpath[PATH_MAX];
    fprintf(stderr, "Terminating amtgwd\n");
    snprintf(pidpath, MAXPATHLEN, "%s/%s.pid", GW_PID_FILE_PATH, "amtgwd");
    unlink(pidpath);
}

static void
init_signal_handler(gw_t* gw)
{
    if (signal(SIGHUP, gw_reconfig) == SIG_ERR) {
        fprintf(stderr, "%s: couldn't install SIGHUP handler\n", gw->name);
        exit(1);
    }

    if (signal(SIGTERM, gw_shutdown) == SIG_ERR) {
        fprintf(stderr, "%s: couldn't install SIGTERM handler\n", gw->name);
        exit(1);
    }
}

static int
gw_debug_server(gw_t* gw)
{
    char* pstr = NULL;
    pstr = getenv("AMT_DEBUG_PORT");
    if (pstr == NULL) {
        gw->dbg_port = AMT_DEFAULT_DEBUG_PORT;
    } else {
        gw->dbg_port = strtoul(pstr, NULL, 10);
    }
    gw_init_dbg_sock(gw);
    return 0;
}

int
main(int argc, char** argv)
{
    int ch, rc, parent, nofork = FALSE;
    gw_t gw;

    bzero(&gw, sizeof(gw_t));

    while ((ch = getopt(argc, argv, "a:s:dnv")) != EOF) {
        char* pstr = NULL;
        in_addr_t prefix;

        switch (ch) {
            case 'a':
                if (optarg == NULL) {
                    fprintf(stderr, "no anycast address\n");
                    exit(1);
                }
                rc = inet_pton(AF_INET, optarg, &prefix);
                if (rc == 1) {
                    gw.relay_anycast_address = ntohl(prefix);
                } else {
                    fprintf(stderr, "bad anycast address\n");
                    exit(1);
                }
                break;

            case 's':
                pstr = strsep(&optarg, "/");
                if (pstr == NULL) {
                    fprintf(stderr, "bad anycast subnet prefix\n");
                    exit(1);
                }
                if (optarg == NULL) {
                    fprintf(stderr, "bad anycast subnet prefix length\n");
                    exit(1);
                }
                rc = inet_pton(AF_INET, pstr, &prefix);
                if (rc == 1) {
                    gw.subnet_anycast_prefix = ntohl(prefix);
                    gw.subnet_anycast_plen = strtol(optarg, NULL, 10);
                    if (gw.subnet_anycast_plen == 0) {
                        fprintf(stderr, "bad anycast prefix length\n");
                        exit(1);
                    }
                    if (gw.subnet_anycast_plen > AMT_HOST_PLEN) {
                        fprintf(stderr, "anycast prefix length too long\n");
                        exit(1);
                    }
                } else {
                    fprintf(stderr, "bad anycast prefix\n");
                    exit(1);
                }
                break;
            case 'd': {
                gw.debug = TRUE;
                break;
            }
            case 'n':
                nofork = TRUE;
                break;
            case 'v':
                fprintf(
                      stderr, "AMT Gateway Version: %s\n", AMT_GW_VERSION);
                exit(1);
            case '?':
            default:
                usage(argv[0]);
                break;
        }
    }

    /*
     * save name
     */
    snprintf(gw.name, sizeof(gw.name), "%s", basename(argv[0]));

    if (gw.relay_anycast_address == 0) {
        fprintf(stderr,
              "%s: relay anycast prefix/len must be set with -a\n",
              gw.name);
        exit(1);
    }
    if (gw.subnet_anycast_prefix == 0) {
        fprintf(stderr,
              "%s: subnet anycast prefix/len must be set with -s\n",
              gw.name);
        exit(1);
    }

    if (nofork == FALSE) {
        parent = fork();
        if (parent < 0) {
            fprintf(stderr, "%s: Unable to fork background process.\n",
                  gw.name);
            exit(1);
        }
        if (parent) { /* parent */
            exit(0);
        }
    }

    rc = init_pid_lockfile(&gw);
    if (rc < 0) {
        fprintf(stderr, "%s: Can't create pid lockfile.\n", gw.name);
        exit(1);
    } else if (rc) {
        /* already running */
        fprintf(stderr, "%s: already running, pid %d\n", gw.name, rc);
        exit(1);
    }

    /* child or foreground */

    rc = chdir(_PATH_VARTMP);
    if (rc < 0) {
        fprintf(stderr, "%s: Can't chdir(%s): %s.\n", gw.name, _PATH_VARTMP,
              strerror(errno));
        exit(1);
    }

    gw.gw_context = event_init();
    if (gw.gw_context == NULL) {
        fprintf(stderr, "event_init failed\n");
        exit(1);
    }

    /*
     * Start the debug server
     */
    if (gw.debug == TRUE) {
        TAILQ_INIT(&gw.dbg_head);
        gw_debug_server(&gw);
    }

    if (init_iftun_device(&gw) < 0) {
        fprintf(stderr, "%s: Couldn't open tunnel device for writing.\n",
              gw.name);
        exit(1);
    }

    init_signal_handler(&gw);

    /*
     * Open the routing socket for manipulating routing table and interfaces
     */
    rc = init_routing_socket(&gw);
    if (rc) {
        fprintf(stderr, "%s: Couldn't open routing socket\n", gw.name);
        exit(1);
    }

    /*
     * read interface configuration and clean up any existing anycast
     * addresses on the tunnel interface.
     * Determine a local source address to use.
     * Determine the index of the tunnel interface
     */
    rc = init_address(&gw);
    if (rc) {
        exit(1);
    }

    /*
     * Add anycast prefix address to tunnel interface
     */
    gw_if_addr_set(&gw);

    TAILQ_INIT(&gw.request_head);

/*
 * Make sure the default multicast interface points to the tunnel if
 */
#if 0    
    if (gw_mcast_default_set(&gw)) {
    }
#endif

    rc = event_dispatch();
    fprintf(stderr, "%s: Unexpected exit: %s\n", gw.name, strerror(errno));

    exit(rc);
}

/*
 * we lost communication with the relay
 * flush all pending transactions
 * and try to locate another relay
 */
static void
gw_discover_relay(gw_t* gw)
{
    int rc;
    struct timeval tv;
    request_t* rq;

    gw->relay = RELAY_NOT_FOUND;

    /*
     * Cleanup Discovery state
     */
    if (gw->disco_sock) {
        gw_cleanup_udp_sock(gw);
    }

    /*
     * close relay socket
     */
    if (gw->udp_sock) {
        rc = event_del(&gw->udp_event_id);
        bzero(&gw->udp_event_id, sizeof(struct event));
        close(gw->udp_sock);
        gw->udp_sock = 0;
    }

    /*
     * stop all the request timers
     */
    TAILQ_FOREACH(rq, &gw->request_head, rq_next)
    {
        if (evtimer_pending(&rq->rq_timer, NULL)) {
            evtimer_del(&rq->rq_timer);
        }
    }

    /*
     * stop the discovery timer
     */
    if (evtimer_pending(&gw->discovery_timer, NULL)) {
        evtimer_del(&gw->discovery_timer);
    }

#if 0
    /*
     * stop the query timer
     */
    if (evtimer_pending(&gw->query_timer, NULL)) {
	evtimer_del(&gw->query_timer);
    }
#endif

    /*
     * open discovery socket
     */
    rc = init_sockets(gw);
    if (rc) {
        fprintf(stderr, "%s: Trouble opening discovery socket: %s.\n",
              gw->name, strerror(rc));
        exit(1);
    }

    timerclear(&tv);
    tv.tv_sec = GW_DISCOVERY_OFFSET;
    evtimer_set(&gw->discovery_timer, gw_send_discovery, gw);
    rc = evtimer_add(&gw->discovery_timer, &tv);
    if (rc < 0) {
        fprintf(stderr, "%s: can't initialize discovery timer: %s\n",
              gw->name, strerror(errno));
        exit(1);
    }
}

/*
 * We're having trouble communicating with the relay.
 * This may be a temporary situation so let's not search for
 * a new relay until some time has passed and we're sure.
 */
void
gw_age_relay(gw_t* gw)
{
    gw_discover_relay(gw);
}
