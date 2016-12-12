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
      "@(#) $Id: test-patricia.c,v 1.1.1.8 2007/05/09 20:42:30 sachin Exp "
      "$";

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "pat.h"

typedef struct _mynode
{
    u_int ref_cnt;
    patext extkey;
} mynode;

/*
 * Map from external key to mynode
 */
static inline mynode*
pat2my(patext* ext)
{
    return ((mynode*)((intptr_t)ext - offsetof(mynode, extkey)));
}

void
my_print(patext* ext)
{
    mynode* n = pat2my(ext);
    u_char* k = pat_key_get(ext);
    int bytes, size;

    size = pat_keysize_get(ext);
    bytes = size / NBBY;
    fprintf(stderr, "ref cnt: %u, keysize %d\n", n->ref_cnt, size);
    while (bytes--) {
        fprintf(stderr, "0x%0x ", *k++);
    }
    fprintf(stderr, "\n");
}

int main(argc, argv) int argc;
char* argv[];
{
    pat_handle root = NULL;
    patext* ext;
    mynode *n, *n2, *n3, *new;
    u_char idxs[5] = { 0x10, 0x22, 0x87, 0x94, 0x33 };
    u_char idxs2[4] = { 0x10, 0x22, 0x85, 0x95 };
    u_char idxs3[6] = { 0x10, 0x22, 0x85, 0x95, 0x33, 0x33 };

    fprintf(stderr, "adding keys\n");
    n = (mynode*)calloc(3, sizeof(mynode));

    n->ref_cnt = 1;
    pat_key_set(&n->extkey, idxs);
    pat_keysize_set(&n->extkey, sizeof(idxs) * NBBY);

    pat_add(&root, &n->extkey);

    n2 = n + 1;
    n2->ref_cnt = 1;
    pat_key_set(&n2->extkey, idxs2);
    pat_keysize_set(&n2->extkey, sizeof(idxs2) * NBBY);

    pat_add(&root, &n2->extkey);

    n3 = n2 + 1;
    n3->ref_cnt = 1;
    pat_key_set(&n3->extkey, idxs3);
    pat_keysize_set(&n3->extkey, sizeof(idxs3) * NBBY);

    pat_add(&root, &n3->extkey);

    fprintf(stderr, "\nWalking tree with pat_walk\n");
    pat_walk(&root, my_print);

    new = pat2my(pat_get(&root, sizeof(idxs) * NBBY, idxs));

    fprintf(stderr, "\nLooking up idxs\n");
    if (new) {
        my_print(&new->extkey);
    } else {
        fprintf(stderr, "Can't find idxs\n");
    }

    fprintf(stderr, "\nWalking tree with getnext\n");

    ext = pat_getnext(&root, NULL, 0);
    while (ext) {
        my_print(ext);
        ext = pat_getnext(&root, pat_key_get(ext), pat_keysize_get(ext));
    }
    return 0;
}
