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

/*
 * Only allow one instance of the AMT gateway to run at a time.
 * Use the PID lockfile method to detect another instance.
 */
// TBD: change the lockfile to permit multiple gateways talking to
// different relays for different sources. --jake 2017-06-29
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
    exit(0);
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

static void
gw_send_query_timer(int fd, short event, void* uap)
{
    (void)fd;
    (void)event;
    int rc;
    struct timeval tv;
    gw_t* gw = (gw_t*)uap;

    gw_send_local_membership_query(gw);

    timerclear(&tv);
    tv.tv_sec = 5;
    rc = evtimer_add(gw->local_query_tev, &tv);
    if (rc) {
        fprintf(stderr, "%s: error rescheduling query timer: %s\n",
                gw->name, strerror(errno));
    }
}

int
main(int argc, char** argv)
{
    int rc;
    gw_t gw;

    bzero(&gw, sizeof(gw_t));
    rc = gateway_parse_command_line(&gw, argc, argv);
    /*
     * save name
     */
    snprintf(gw.name, sizeof(gw.name), "%s", basename(argv[0]));

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

    gw.event_base = event_base_new();


    fprintf(stderr, "%p == event_base\n", gw.event_base);
    if (init_iftun_device(&gw) < 0) {
        fprintf(stderr, "%s: Couldn't open tunnel device for writing.\n",
              gw.name);
        exit(1);
    }

    init_signal_handler(&gw);


    rc = init_routing_socket(&gw);
    if (rc) {
        fprintf(stderr, "%s: Couldn't open routing socket\n", gw.name);
        exit(1);
    }

    TAILQ_INIT(&gw.request_head);

    rc = init_sockets(&gw);
    if (rc < 0) {
        fprintf(stderr, "%s: can't initialize sockets: %s\n",
              gw.name, strerror(errno));
        exit(1);
    }

    gw.local_query_tev = evtimer_new(gw.event_base,
            gw_send_query_timer, &gw);
    struct timeval tv;
    timerclear(&tv);
    tv.tv_sec = 0;
    rc = evtimer_add(gw.local_query_tev, &tv);
    if (rc < 0) {
        fprintf(stderr, "%s: can't initialize query timer: %s\n",
              gw.name, strerror(errno));
        exit(1);
    }

    rc = event_base_dispatch(gw.event_base);
    fprintf(stderr, "%s: Unexpected exit from event_base_dispatch: %s\n",
            gw.name, strerror(errno));

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
        rc = event_del(gw->udp_event_ev);
        event_free(gw->udp_event_ev);
        gw->udp_event_ev = 0;
        close(gw->udp_sock);
        gw->udp_sock = 0;
    }

    /*
     * stop all the request timers
     */
    TAILQ_FOREACH(rq, &gw->request_head, rq_next)
    {
        if (rq->rq_tev) {
            if (evtimer_pending(rq->rq_tev, NULL)) {
                evtimer_del(rq->rq_tev);
            }
        }
    }

    /*
     * stop the discovery timer
     */
    if (gw->discovery_tev) {
        if (evtimer_pending(gw->discovery_tev, NULL)) {
            evtimer_del(gw->discovery_tev);
        }
    }

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
    if (!gw->discovery_tev) {
        gw->discovery_tev = evtimer_new(gw->event_base, gw_send_discovery,
                gw);
    }
    rc = evtimer_add(gw->discovery_tev, &tv);
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
