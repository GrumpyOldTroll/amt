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

#include <errno.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef BSD
#include <sys/sockio.h>
#endif

#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#include <sys/time.h>
#include <time.h>

#ifdef BSD
#include <net/if_dl.h>
#else
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#define _GNU_SOURCE
#include <string.h>
#endif

#include <arpa/inet.h>
#include <net/route.h>

#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "amt.h"
#include "gw.h"

#define NL_BUFSIZE 8192
static const char __attribute__((unused)) id[] =
      "@(#) $Id: gw_if.c,v 1.1.1.9 2007/05/31 17:22:03 sachin Exp $";

#ifdef BSD
static u_int8_t*
net_rt_iflist(int family, int flags, size_t* lenp)
{
    int mib[6];
    u_int8_t* buf;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = family; /* only addresses of this family */
    mib[4] = NET_RT_IFLIST;
    mib[5] = flags; /* interface index or 0 */
    if (sysctl(mib, 6, NULL, lenp, NULL, 0) < 0)
        return (NULL);

    if ((buf = malloc(*lenp)) == NULL)
        return (NULL);
    if (sysctl(mib, 6, buf, lenp, NULL, 0) < 0) {
        free(buf);
        return (NULL);
    }

    return (buf);
}

/*
 * Round up 'a' to next multiple of 'size', which must be a power of 2
 */
#define ROUNDUP(a, size)                                                   \
    (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))

/*
 * Step to next socket address structure;
 * if sa_len is 0, assume it is sizeof(u_long).
 */
#define NEXT_SA(ap)                                                        \
    ap = (struct sockaddr*)((caddr_t)ap +                                  \
                            (ap->sa_len ? ROUNDUP(ap->sa_len,              \
                                                sizeof(u_long))            \
                                        : sizeof(u_long)))

static void
get_rtaddrs(int addrs, struct sockaddr* sa, struct sockaddr** rti_info)
{
    int i;

    for (i = 0; i < RTAX_MAX; i++) {
        if (addrs & (1 << i)) {
            rti_info[i] = sa;
            NEXT_SA(sa);
        } else {
            rti_info[i] = NULL;
        }
    }
}

#else  /* LINUX_OS */
#endif /* LINUX_OS */

