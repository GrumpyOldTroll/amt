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
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/param.h>

#ifdef BSD
#include <sys/linker.h>
#include <sys/module.h>
#endif /* BSD */

#include <sys/uio.h>
#include <sys/queue.h>
#include <unistd.h>
#include <net/if.h>
#ifdef BSD
#include <net/if_tun.h>
#else
#include <linux/if_tun.h>
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <linux/igmp.h>
#include <netinet/igmp.h>


#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <event.h>

#include "amt.h"
#include "gw.h"

#define TUNDEV_MAX      4

static const char __attribute__((unused)) id[] = "@(#) $Id: gw_tun.c,v 1.1.1.8 2007/05/09 20:40:55 sachin Exp $";

#ifdef BSD
int
init_iftun_device(gw_t *gw)
{
    int unit, fd;
    char name[FILENAME_MAX];

    for (unit = 0; unit != TUNDEV_MAX; unit++) {
	snprintf(name, sizeof(name), "/dev/tun%d", unit);
	fd = open(name, O_RDWR);
	if (fd < 0) {
	    switch(errno) {
		case ENXIO:
		case ENOENT:
			if (modfind("if_tun") < 0) {
			    if (kldload("if_tun") < 0) {
				fprintf(stderr, "Cannot load if_tun\n");
			    }
			}
			break;
	    }
	} else {
	    int rc, mode;

	    gw->tundev = fd;
	    gw->tununit = unit;

	    mode = IFF_BROADCAST | IFF_MULTICAST;
	    rc = ioctl(fd, TUNSIFMODE, &mode);
	    if (rc < 0) {
		fprintf(stderr,
			"%s: coudn't set tunnel mode to broadcast: %s\n",
			gw->name, strerror(errno));
		return rc;
	    }

	    rc = socket_set_non_blocking(fd);
	    if (rc < 0) {
		fprintf(stderr,
			"%s: coudn't set tunnel to non-blocking: %s\n",
			gw->name, strerror(errno));
		return rc;
	    }
	    event_set(&gw->tun_event_id, fd, EV_READ|EV_PERSIST, gw_event_tun,
		      (void *) gw);
	    rc = event_add(&gw->tun_event_id, NULL);
	    if (rc < 0) {
		fprintf(stderr, "%s: error from tun event_add: %s\n", gw->name,
			strerror(errno));
		return errno;
	    }
	    return fd;
	}
    }
    return fd;
}
#else /* LINUX_OS */
int
init_iftun_device(gw_t *gw)
{
    int fd;
    char name[FILENAME_MAX];
    struct ifreq ifr;
        
    snprintf(name, sizeof(name), "/dev/net/tun");
    fd = open(name, O_RDWR);
    if (fd < 0) {
    	perror("open");
	return -1;
    } else {
	int rc;
	int sd;
		
	gw->tundev = fd;
	gw->tununit = 0;

	bzero(&ifr, sizeof(struct ifreq));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	rc = ioctl(fd, TUNSETIFF, &ifr);
	if (rc < 0) {
	    fprintf(stderr, "%s: coudn't set tunnel mode to broadcast: %s\n",
		    gw->name, strerror(errno));
  	    return rc;
	}

	strcpy(gw->tunifname, ifr.ifr_ifrn.ifrn_name);

	sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
	    perror("socket failed");
	    return -1;
	}
	strcpy(ifr.ifr_name, gw->tunifname);
	rc = ioctl(sd, SIOCGIFFLAGS, &ifr);
	if (rc) {
	    perror("ioctl SIOCGIFFLAGS failed");
	    close(sd);
	    return -1;
	}
	if (!(ifr.ifr_flags & IFF_UP)) {
	    ifr.ifr_flags |= IFF_UP;
	    rc = ioctl(sd, SIOCSIFFLAGS, &ifr);
	    if (rc) {
	        perror("ioctl SIOCSIFFLAGS failed");
	        close(sd);
	        return -1;
	    }
	}
	close(sd);
	
	rc = socket_set_non_blocking(fd);
	if (rc < 0) {
	    fprintf(stderr, "%s: coudn't set tunnel to non-blocking: %s\n",
		    gw->name, strerror(errno));
	    return rc;
	}
	event_set(&gw->tun_event_id, fd, EV_READ|EV_PERSIST, gw_event_tun,
      		  (void *) gw);
	rc = event_add(&gw->tun_event_id, NULL);
	if (rc < 0) {
	    fprintf(stderr, "%s: error from tun event_add: %s\n", gw->name,
	 	    strerror(errno));
	    return errno;
	}
	return fd;
    }
    return fd;
}
#endif /* BSD */

/*
 * ip_get_hl
 *
 * Get the IP header-length.
 */
static int
ip_get_hl (struct ip *ip)
{
    return (ip->ip_hl << 2);
}

static int
gw_receive_tun(gw_t *gw, int fd)
{
    int len, tries;

    tries = 3;
    while (tries--) {
	len = read(fd, gw->packet_buffer, sizeof(gw->packet_buffer));
	if (len < 0) {
	    switch (errno) {
		case EINTR:		/* interrupted, retry. */
		    break;

		case EAGAIN:		/* nothing to read */
		    return -1;

		default:
		    fprintf(stderr, "%s: tunnel read error: %s\n", gw->name,
			    strerror(errno));
		    return -1;
	    }
	} else if (len == 0) {
	    fprintf(stderr, "%s: zero length read\n", gw->name);
	    return 0;
	} else {
	    struct ip *ip;
	    u_int8_t *cp;
	    int iphlen;

	    ip = (struct ip *) (gw->packet_buffer);
	    switch (ip->ip_p) {
		case IPPROTO_IGMP:
		    iphlen = ip_get_hl(ip);
		    cp = gw->packet_buffer + iphlen;
		    switch (*cp) {
			case IGMP_V1_MEMBERSHIP_REPORT:
			case IGMP_V2_MEMBERSHIP_REPORT:
			case IGMP_V2_LEAVE_GROUP:
			case IGMPV3_HOST_MEMBERSHIP_REPORT:
			    gw_request_start(gw, gw->packet_buffer, len);
			    break;
			case IGMP_HOST_MEMBERSHIP_QUERY:
			    break;
			default:
			    fprintf(stderr,
				    "%s: IGMP type %d len %d from tunnel\n",
				    gw->name, *cp, len);
		    }
		    break;

		default:
		    fprintf(stderr,
			    "%s: IP Proto %d len %d from tunnel\n",
			    gw->name, ip->ip_p, len);
		    break;
	    }
	    return len;
	}
    }
    return -1;
}

void
gw_event_tun(int fd, short __unused flags, void *uap)
{
    int len;
    gw_t *gw;

    gw = (gw_t *) uap;

    do {
	len = gw_receive_tun(gw, fd);
    } while (len > 0);
}

void
gw_forward_tun(gw_t *gw, u_int8_t *cp, int len)
{
    int tries;

    tries = 3;
    while (tries--) {
	ssize_t rc;

	rc = write(gw->tundev, cp, len);
	if (rc < 0) {
	    switch (errno) {
	    case EINTR:
		/* try again */
		break;

	    default:
		fprintf(stderr, "%s: tunnel interface write: %s\n", gw->name,
			strerror(errno));
		return;
	    }
	} else if (rc != len) {
	    fprintf(stderr, "%s: tunnel interface short write %d out of %d\n",
		    gw->name, (int) rc, len);
	    return;
	} else {
	    /* success */
	    return;
	}
    }
}
