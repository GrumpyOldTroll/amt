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
 * Patricia Tree package
 *
 * $Id: pat.h,v 1.1.1.8 2007/05/09 20:41:46 sachin Exp $
 *
 * This package allows the use of variable length keys to be stored
 * in a patricia tree.
 *
 * It is based on code in gated-3.5R11 from Cornell University in the
 * mid 1990's written by Dennis Ferguson. It was extracted and put in
 * a library by Tom Pusateri in 1997.
 *
 * To use this package, just embed an "patext" element in your data
 * structure. This will contain the size of the key and a pointer to
 * the key. It can be placed anywhere in the user's data structure.
 * The user is responsible for allocating storage for the key itself.
 *
 *	typedef struct _mynode {
 *	    ...
 *	    patext	my_extkey;
 *	    ...
 *	} mynode;
 *
 * A routine like the following can be used to map between a
 * patext and the user's data structure.
 *
 *	static inline mynode *
 *	pat2my (patext *ext)
 *	{
 *	    return((mynode *)((int) ext - offsetof(mynode, my_extkey)));
 *	}
 *
 * The following routines can be used to set/get key info.
 *
 *  void    pat_key_set(patext *keynode, u_char *key)
 *  u_char *pat_key_get(patext *keynode)
 *  void    pat_keysize_set(patext *keynode, u_int keysize)
 *  u_int   pat_keysize_get(patext *keynode)
 */

#ifndef AMT_LIBPATRICIA_PAT_H
#define AMT_LIBPATRICIA_PAT_H

#include <sys/types.h>

#ifndef offsetof
#define offsetof(type, member) ((size_t) & ((type*)0)->member)
#endif

#define BIT_TEST(f, b) ((f) & (b))
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef NBBY
#define NBBY 8 /* number of bits in a byte */
#endif

typedef struct _patnode patnode;
typedef patnode* pat_handle;

typedef struct _patext
{
    patnode* patnodeptr;
    u_int keysize;
    u_char* key;
} patext;

static inline u_char*
pat_key_get(patext* keynode)
{
    return keynode->key;
}

static inline void
pat_key_set(patext* keynode, u_char* key)
{
    keynode->key = key;
}

static inline u_int
pat_keysize_get(patext* keynode)
{
    return keynode->keysize;
}

static inline void
pat_keysize_set(patext* keynode, u_int keysize)
{
    keynode->keysize = keysize;
}

void pat_add(pat_handle*, patext*);
void pat_delete(pat_handle*, patext*);
patext* pat_get(pat_handle*, u_int, u_char*);
patext* pat_getnext(pat_handle*, u_char*, u_int);
void pat_walk(pat_handle*, void (*func)(patext*));
int pat_empty(pat_handle*);

#endif  // AMT_LIBPATRICIA_PAT_H
