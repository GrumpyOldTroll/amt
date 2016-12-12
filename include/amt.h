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
 * AMT declarations
 * $Id: amt.h,v 1.1.1.9 2007/05/31 17:29:50 sachin Exp $
 */

#ifndef AMT_INCLUDE_AMT_H
#define AMT_INCLUDE_AMT_H

#define AMT_GW_VERSION "1.1.7"

#define TRUE 1
#define FALSE 0

#define BIT_TEST(f, b) ((f) & (b))
#define BIT_SET(f, b) ((f) |= (b))
#define BIT_RESET(f, b) ((f) &= (~b))

#define AMT_PORT 2268
/* XXX video packets are > 1300 Bytes */
#define BUFFER_SIZE 1400

#define max(a, b) ((a) >= (b) ? (a) : (b))
#define min(a, b) ((a) <= (b) ? (a) : (b))

typedef enum _amt_msg_t {
    AMT_RELAY_DISCOVERY = 1,
    AMT_RELAY_ADVERTISEMENT = 2,
    AMT_REQUEST = 3,
    AMT_MEMBERSHIP_QUERY = 4,
    AMT_MEMBERSHIP_CHANGE = 5,
    AMT_MCAST_DATA = 6
} amt_msg_t;

#define AMT_HOST_PLEN 32
#define AMT_SUBNET_RELAY_OCTET 0x01

#define HMAC_LEN 16        /* bytes */
#define RESPONSE_MAC_LEN 6 /* bytes */

#define AMT_DEFAULT_DEBUG_PORT 59999

#ifndef __unused
#define __unused
#endif

static in_addr_t inet_mask[] = {
    0x00000000, /* 0.0.0.0 */
    0x80000000, /* 128.0.0.0 */
    0xC0000000, /* 192.0.0.0 */
    0xE0000000, /* 224.0.0.0 */
    0xF0000000, /* 240.0.0.0 */
    0xF8000000, /* 248.0.0.0 */
    0xFC000000, /* 252.0.0.0 */
    0xFE000000, /* 254.0.0.0 */
    0xFF000000, /* 255.0.0.0 */
    0xFF800000, /* 255.128.0.0 */
    0xFFC00000, /* 255.192.0.0 */
    0xFFE00000, /* 255.224.0.0 */
    0xFFF00000, /* 255.240.0.0 */
    0xFFF80000, /* 255.248.0.0 */
    0xFFFC0000, /* 255.252.0.0 */
    0xFFFE0000, /* 255.254.0.0 */
    0xFFFF0000, /* 255.255.0.0 */
    0xFFFF8000, /* 255.255.128.0 */
    0xFFFFC000, /* 255.255.192.0 */
    0xFFFFE000, /* 255.255.224.0 */
    0xFFFFF000, /* 255.255.240.0 */
    0xFFFFF800, /* 255.255.248.0 */
    0xFFFFFC00, /* 255.255.252.0 */
    0xFFFFFE00, /* 255.255.254.0 */
    0xFFFFFF00, /* 255.255.255.0 */
    0xFFFFFF80, /* 255.255.255.128 */
    0xFFFFFFC0, /* 255.255.255.192 */
    0xFFFFFFE0, /* 255.255.255.224 */
    0xFFFFFFF0, /* 255.255.255.240 */
    0xFFFFFFF8, /* 255.255.255.248 */
    0xFFFFFFFC, /* 255.255.255.252 */
    0xFFFFFFFE, /* 255.255.255.254 */
    0xFFFFFFFF  /* 255.255.255.255 */
};

static inline in_addr_t
inet_plen2mask(int plen)
{
    return inet_mask[plen];
}

static inline u_int8_t*
put_short(u_int8_t* cp, u_int16_t value)
{
    *cp++ = (u_int8_t)value >> 8;
    *cp++ = (u_int8_t)value & 0xff;

    return cp;
}

/*
 * copy 32 bits in host byte order into continuous memory
 */
static inline u_int8_t*
put_long(u_int8_t* cp, u_int32_t value)
{
    *cp++ = (value >> 24) & 0xFF;
    *cp++ = (value >> 16) & 0xFF;
    *cp++ = (value >> 8) & 0xFF;
    *cp++ = value & 0xFF;

    return cp;
}

static inline u_int16_t
get_short(u_int8_t* cp)
{
    u_int16_t value;

    value = *cp++;
    value = (value << 8) | *cp;

    return value;
}

static inline u_int32_t
get_long(u_int8_t* cp)
{
    u_int32_t value;

    value = (*cp++ << 24) & 0xFF000000;
    value |= (*cp++ << 16) & 0xFF0000;
    value |= (*cp++ << 8) & 0xFF00;
    value |= *cp++ & 0xFF;

    return value;
}

static inline u_long
get_long_native(const void* ptr)
{
    const u_char* cp;
    u_char* valp;
    u_long val;

    cp = ptr;
    valp = (u_char*)&val;
    *valp++ = *cp++;
    *valp++ = *cp++;
    *valp++ = *cp++;
    *valp = *cp;
    return (val);
}

#ifndef offsetof
#define offsetof(type, member) ((size_t) & ((type*)0)->member)
#endif /* offsetof */

#endif  // AMT_INCLUDE_AMT_H
