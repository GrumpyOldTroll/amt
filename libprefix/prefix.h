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
 * $Id: prefix.h,v 1.1.1.8 2007/05/09 20:41:57 sachin Exp $
 */

#ifndef AMT_LIBPREFIX_PREFIX_H
#define AMT_LIBPREFIX_PREFIX_H

#include <netinet/in.h>
#include <string.h>
#include <assert.h>

#define BIT_TEST(f, b) ((f) & (b))

#ifndef NBBY
#define NBBY 8 /* number of bits in a byte */
#endif

#define INET_HOST_LEN 32
#define INET6_HOST_LEN 128

#define INET_MAX_ADDR_STRLEN 16
#define INET6_MAX_ADDR_STRLEN 40
#define MAX_ADDR_STRLEN INET6_MAX_ADDR_STRLEN

typedef struct inm_addr
{
    struct in_addr g_addr;
    struct in_addr s_addr;
} inm_addr;

typedef struct inm6_addr
{
    struct in6_addr g_addr;
    struct in6_addr s_addr;
} inm6_addr;

typedef struct _prefix_t
{
    u_int16_t family; /* AF_INET | AF_INET6 */
    u_int16_t bitlen;
    union
    {
        struct in_addr sin;
        struct in6_addr sin6;
        struct inm_addr sinm;
        struct inm6_addr sinm6;
    } addr;
} prefix_t;

prefix_t* prefix_build(int, void*, int);
prefix_t* prefix_dup(prefix_t*);
void prefix_free(prefix_t*);
prefix_t* prefix_build_mcast(prefix_t*, prefix_t*);
u_int8_t* prefix_key(prefix_t*);
u_int16_t prefix_keylen(prefix_t*);
const char* prefix2str(prefix_t*, char*, int);

static inline void
prefix2sin6(prefix_t* pfx, struct sockaddr_in6* sin6)
{
    bzero(sin6, sizeof(struct sockaddr_in6));
    sin6->sin6_family = pfx->family;
    sin6->sin6_addr = pfx->addr.sin6;
}

static inline void
prefix2sin(prefix_t* pfx, struct sockaddr_in* sin)
{
    bzero(sin, sizeof(struct sockaddr_in));

#ifdef BSD
    sin->sin_len = sizeof(struct sockaddr_in);
#endif
    sin->sin_family = pfx->family;
    sin->sin_addr = pfx->addr.sin; /* struct copy */
}

static inline int
prefix2sock(prefix_t* pfx, struct sockaddr* sa)
{
    int len = 0;

    switch (pfx->family) {
        case AF_INET:
            prefix2sin(pfx, (struct sockaddr_in*)sa);
            len = sizeof(struct sockaddr_in);
            break;

        case AF_INET6:
            prefix2sin6(pfx, (struct sockaddr_in6*)sa);
            len = sizeof(struct sockaddr_in6);
            break;

        default:
            assert(pfx->family == AF_INET || pfx->family == AF_INET6);
    }
    return len;
}

static inline prefix_t*
sock2prefix(int family, struct sockaddr* sa)
{
    struct sockaddr_in* sin;
    struct sockaddr_in6* sin6;
    prefix_t* pfx = NULL;

    switch (family) {
        case AF_INET:
            sin = (struct sockaddr_in*)sa;
            pfx = prefix_build(
                  family, &sin->sin_addr, sizeof(struct in_addr) * NBBY);
            break;

        case AF_INET6:
            sin6 = (struct sockaddr_in6*)sa;
            pfx = prefix_build(family, sin6->sin6_addr.s6_addr,
                  sizeof(struct in6_addr) * NBBY);
            break;

        default:
            assert(pfx->family == AF_INET || pfx->family == AF_INET6);
    }
    return pfx;
}

#endif  // AMT_LIBPREFIX_PREFIX_H
