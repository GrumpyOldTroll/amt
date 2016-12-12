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
      "@(#) $Id: prefix.c,v 1.1.1.8 2007/05/09 20:41:57 sachin Exp $";

#include "prefix.h"
#include "memory.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

static mem_handle mem_prefix_handle = NULL;

/* these routines support continuous mask only */

static prefix_t*
prefix_alloc(int family)
{
    prefix_t* prefix;

    if (!mem_prefix_handle) {
        mem_prefix_handle = mem_type_init(sizeof(prefix_t), "Prefix");
    }

    prefix = (prefix_t*)mem_type_alloc(mem_prefix_handle);
    prefix->family = family;
    prefix->bitlen = 0;

    return prefix;
}

/*
 * This allocates dynamic storage and the user must free the prefix later.
 */
prefix_t*
prefix_build(int family, void* addr, int bitlen)
{
    int nbytes;
    prefix_t* prefix;

    if (family != AF_INET && family != AF_INET6) {
        return NULL;
    }

    nbytes = bitlen / NBBY;
    if (bitlen % NBBY) {
        nbytes++;
    }
    prefix = prefix_alloc(family);
    prefix->bitlen = bitlen;
    bcopy(addr, &prefix->addr.sin, nbytes);

    return prefix;
}

prefix_t*
prefix_dup(prefix_t* prefix)
{
    return prefix_build(prefix->family, &prefix->addr.sin, prefix->bitlen);
}

void
prefix_free(prefix_t* prefix)
{
    if (prefix) {
        mem_type_free(mem_prefix_handle, prefix);
    }
}

/*
 * Here we build a new prefix that combines the group and source
 * addresses. This allows us to find all sources associated with
 * a particular group.
 * This allocates dynamic storage and the user must free the prefix later.
 * assumptions:
 *	The group prefix must be of host prefix length.
 *      This is reasonable since noone currently does group prefix
 *aggregation.
 *	There is no such restriction on the source prefix.
 */

prefix_t*
prefix_build_mcast(prefix_t* group, prefix_t* source)
{
    int nbytes;
    u_int8_t* cp;
    prefix_t* prefix;

    if (!group) {
        return NULL;
    }

    /*
     * make sure both prefixes are from the same address family
     */
    if (source) {
        assert(group->family == source->family);

        if (group->family != AF_INET && group->family != AF_INET6) {
            return NULL;
        }
    }

    /*
     * calculate the length of the group prefix
     * and copy it to the new prefix
     */
    nbytes = group->bitlen / NBBY;
    if (group->bitlen % NBBY) {
        nbytes++;
    }
    assert(nbytes);
    prefix = prefix_alloc(group->family);
    prefix->bitlen = group->bitlen;
    cp = (u_int8_t*)&prefix->addr.sin;
    bcopy(&group->addr.sin, cp, nbytes);
    cp += nbytes;

    /*
     * If there is a source prefix, copy this in.
     */
    if (source) {
        nbytes = source->bitlen / NBBY;
        if (source->bitlen % NBBY) {
            nbytes++;
        }

        if (nbytes) {
            prefix->bitlen += source->bitlen;
            bcopy(&source->addr.sin, cp, nbytes);
        }
    }
    return prefix;
}

u_int8_t*
prefix_key(prefix_t* pfx)
{
    return (u_int8_t*)&pfx->addr.sin;
}

u_int16_t
prefix_keylen(prefix_t* pfx)
{
    return pfx->bitlen;
}

/*
 * convert a prefix to a dotted quad v4 string or a ::v6 string
 */
const char*
prefix2str(prefix_t* pfx, char* str, int len)
{
    return inet_ntop(pfx->family, &pfx->addr.sin, str, len);
}
