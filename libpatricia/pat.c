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

static const char __attribute__((unused)) id[] = "@(#) $Id: pat.c,v 1.1.1.8 2007/05/09 20:41:46 sachin Exp $";

#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>
#include "memory.h"
#include "pat.h"

#define	TRUE		1
#define	FALSE		0

static mem_handle mem_patnode_handle = NULL;

struct _patnode {
    struct _patnode	*pat_left;
    struct _patnode	*pat_right;
    struct _patnode	*pat_parent;
    u_short		pat_bit;	/* length of key in bits */
    u_char		pat_tbyte;	/* byte to test in key */
    u_char		pat_tbit;	/* bit to test in byte */
    patext		*pat_ext;
};


#define RNSHIFT		3
#define RNBIT(x)        (0x80 >> ((x) & (NBBY-1)))
#define RNBYTE(x)       ((x) >> RNSHIFT)        
#define RN_BYTELEN(x)   ((unsigned) ((x) + NBBY - 1) >> RNSHIFT)



const u_char first_bit_set[256] = {
    /* 0 - 15 */
    8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4,
    /* 16 - 31 */
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    /* 32 - 63 */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    /* 64 - 127 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    /* 128 - 255 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static inline patnode *
patnode_get(void)
{
    if (!mem_patnode_handle) {
	mem_patnode_handle = mem_type_init(sizeof(patnode), "Patricia node");
    }
    return mem_type_alloc(mem_patnode_handle);
} 
 
static inline void
patnode_free (patnode *node)
{
    if (node) {
	mem_type_free(mem_patnode_handle, node);
    }
}

/*
 *	Get the node for the given destination
 */
patext *
pat_get(pat_handle *handle, u_int bitlen, u_char *ap)
{
    patnode *rn = *handle;
    u_char *ap2;
    patext *ext;

    /*
     * If there is no table, or nothing to do, assume nothing found.
     */
    if (!rn) {
	return NULL;
    }

    /*
     * Search down the tree until we find a node which
     * has a bit number the same as ours.
     */

    while (rn->pat_bit < bitlen) {
	if (rn->pat_tbit & ap[rn->pat_tbyte]) {
	    rn = rn->pat_right;
	} else {
	    rn = rn->pat_left;
	}
	if (!rn) {
	    break;
	}
    }

    /*
     * If we didn't find an exact bit length match, we're gone.
     * If there is no external entry on this node, we're gone too.
     */
    if (!rn || rn->pat_bit != bitlen || !(ext = rn->pat_ext)) {
	return NULL;
    }

    /*
     * So far so good.  Fetch the address and see if we have an
     * exact match.
     */
    ap2 = ext->key;
    bitlen = RN_BYTELEN(bitlen);
    while (bitlen--) {
	if (*ap++ != *ap2++) {
	    return NULL;
	}
    }
    return ext;
}

/*
 *	Insert this head into the tree
 */
void
pat_add(pat_handle *handle, patext *ext)
{
    patnode *rn, *rn_prev, *rn_add, *rn_new;
    u_short bitlen, bits2chk, dbit;
    u_char *addr, *his_addr;
    u_int i;

    /*
     * Compute the bit length of the mask.
     */
    bitlen = ext->keysize;
    assert(bitlen != (u_short) -1);

    rn_prev = *handle;

    /*
     * If there is no existing root node, this is it.  Catch this
     * case now.
     */
    if (!rn_prev) {
	rn = patnode_get();
	*handle = ext->patnodeptr = rn;
	rn->pat_bit = bitlen;
	rn->pat_tbyte = RNBYTE(bitlen);
	rn->pat_tbit = RNBIT(bitlen);
	rn->pat_ext = ext;
	return;
    }

    /*
     * Search down the tree as far as we can, stopping at a node
     * with a bit number >= ours which has an ext attached.  It
     * is possible we won't get down the tree this far, however,
     * so deal with that as well.
     */
    addr = ext->key;
    rn = rn_prev;
    while (rn->pat_bit < bitlen || !(rn->pat_ext)) {
	if (BIT_TEST(addr[rn->pat_tbyte], rn->pat_tbit)) {
	    if (!(rn->pat_right)) {
		break;
	    }
	    rn = rn->pat_right;
	} else {
	    if (!(rn->pat_left)) {
		break;
	    }
	    rn = rn->pat_left;
	}
    }

    /*
     * Now we need to find the number of the first bit in our address
     * which differs from his address.
     */
    bits2chk = MIN(rn->pat_bit, bitlen);
    his_addr = rn->pat_ext->key;
    for (dbit = 0; dbit < bits2chk; dbit += NBBY) {
	i = dbit >> RNSHIFT;
	if (addr[i] != his_addr[i]) {
	    dbit += first_bit_set[addr[i] ^ his_addr[i]];
	    break;
	}
    }

    /*
     * If the different bit is less than bits2chk we will need to
     * insert a split above him.  Otherwise we will either be in
     * the tree above him, or attached below him.
     */
    if (dbit > bits2chk) {
	dbit = bits2chk;
    }
    rn_prev = rn->pat_parent;
    while (rn_prev && rn_prev->pat_bit >= dbit) {
	rn = rn_prev;
	rn_prev = rn->pat_parent;
    }

    /*
     * Okay.  If the node rn points at is equal to our bit number, we
     * may just be able to attach the ext to him.  Check this since it
     * is easy.
     */
    if (dbit == bitlen && rn->pat_bit == bitlen) {
	assert(!(rn->pat_ext));
	rn->pat_ext = ext;
	ext->patnodeptr = rn;
	return;
    }

    /*
     * Allocate us a new node, we are sure to need it now.
     */
    rn_add = patnode_get();
    rn_add->pat_bit = bitlen;
    rn_add->pat_tbyte = RNBYTE(bitlen);
    rn_add->pat_tbit = RNBIT(bitlen);
    rn_add->pat_ext = ext;
    ext->patnodeptr = rn_add;

    /*
     * There are a couple of possibilities.  The first is that we
     * attach directly to the thing pointed to by rn.  This will be
     * the case if his bit is equal to dbit.
     */
    if (rn->pat_bit == dbit) {
	assert(dbit < bitlen);
	rn_add->pat_parent = rn;
	if (BIT_TEST(addr[rn->pat_tbyte], rn->pat_tbit)) {
	    assert(!(rn->pat_right));
	    rn->pat_right = rn_add;
	} else {
	    assert(!(rn->pat_left));
	    rn->pat_left = rn_add;
	}
	return;
    }

    /*
     * The other case where we don't need to add a split is where
     * we were on the same branch as the guy we found.  In this case
     * we insert rn_add into the tree between rn_prev and rn.  Otherwise
     * we add a split between rn_prev and rn and append the node we're
     * adding to one side of it.
     */
    if (dbit == bitlen) {
	if (BIT_TEST(his_addr[rn_add->pat_tbyte], rn_add->pat_tbit)) {
	    rn_add->pat_right = rn;
	} else {
	    rn_add->pat_left = rn;
	}
	rn_new = rn_add;
    } else {
	rn_new = patnode_get();
	rn_new->pat_bit = dbit;
	rn_new->pat_tbyte = RNBYTE(dbit);
	rn_new->pat_tbit = RNBIT(dbit);
	rn_add->pat_parent = rn_new;
	if (BIT_TEST(addr[rn_new->pat_tbyte], rn_new->pat_tbit)) {
	    rn_new->pat_right = rn_add;
	    rn_new->pat_left = rn;
	} else {
	    rn_new->pat_left = rn_add;
	    rn_new->pat_right = rn;
	}
    }
    rn->pat_parent = rn_new;
    rn_new->pat_parent = rn_prev;

    /*
     * If rn_prev is NULL this is a new root node, otherwise it
     * is attached to the guy above in the place where rn was.
     */
    if (!rn_prev) {
	*handle = rn_new;
    } else if (rn_prev->pat_right == rn) {
	rn_prev->pat_right = rn_new;
    } else {
	assert(rn_prev->pat_left == rn);
	rn_prev->pat_left = rn_new;
    }
}


/*
 *	Remove this node from the tree
 */
void
pat_delete(pat_handle *handle, patext *ext)
{
    patnode *rn, *rn_next, *rn_prev;

    rn = (patnode *) ext->patnodeptr;
    ext->patnodeptr = NULL;

    /*
     * Catch the easy case.  If this guy has nodes on both his left
     * and right, he stays in the tree.
     */
    if (rn->pat_left && rn->pat_right) {
	rn->pat_ext = NULL;
	return;
    }

    /*
     * If this guy has no successor he's a goner.  The guy above
     * him will be too, unless he's got external stuff attached to
     * him.
     */
    if (!(rn->pat_left) && !(rn->pat_right)) {
	rn_prev = rn->pat_parent;
	patnode_free(rn);

	if (!rn_prev) {
	    /*
	     * Last guy in the tree, remove the root node pointer
	     */
	    *handle = NULL;
	    return;
	}

	if (rn_prev->pat_left == rn) {
	    rn_prev->pat_left = NULL;
	} else {
	    assert(rn_prev->pat_right == rn);
	    rn_prev->pat_right = NULL;
	}

	if (rn_prev->pat_ext) {
	    return;
	}
	rn = rn_prev;
    }

    /*
     * Here we have a one-way brancher with no external stuff attached
     * (either we just removed the external stuff or one of his child
     * nodes).  Remove him, promoting his one remaining child.
     */
    rn_prev = rn->pat_parent;
    if (rn->pat_left) {
	rn_next = rn->pat_left;
    } else {
	rn_next = rn->pat_right;
    }
    rn_next->pat_parent = rn_prev;

    if (!rn_prev) {
	/*
	 * Our guy's a new root node, put him in.
	 */
	*handle = rn_next;
    } else {
	/*
	 * Find the pointer to our guy in the parent and replace
	 * it with the pointer to our former child.
	 */
	if (rn_prev->pat_left == rn) {
	    rn_prev->pat_left = rn_next;
	} else {
	    assert(rn_prev->pat_right == rn);
	    rn_prev->pat_right = rn_next;
	}
    }

    /*
     * Done, blow this one away as well.
     */
    patnode_free(rn);

    return;
}

void
pat_walk(pat_handle *handle, void (*func)(patext *))
{
    patnode *rn = *handle;

    for (;;) { 
	if ((rn->pat_ext)) {
	    (*func)(rn->pat_ext);
	}
                    
        if (rn->pat_left) {
            rn = rn->pat_left;
        } else if (rn->pat_right) { 
            rn = rn->pat_right;     
        } else {
            patnode *rn_next;
            do {
                rn_next = rn;
                rn = rn->pat_parent;
                if (!rn) {
                    return;
                }
            } while (!(rn->pat_right) || rn->pat_right == rn_next); 
            rn = rn->pat_right;     
        }
    }
}

/*
 * pat_getnext
 *
 * return a route which is after the given route in lexigraphic order.
 * The code assumes that "lexigraphic order" means that you return an
 * address which sorts larger than the given address, or the same address
 * but with a longer mask. If the dest is NULL it assumes he wants the
 * first entry in the table.
 */
patext *
pat_getnext(pat_handle *handle, u_char *ap, u_int bitlen)
{
    patnode *rn = *handle;
    u_char *ap2;
    u_short bits2chk, dbit;

    /*
     * If there is no table, or nothing to do, assume nothing found.
     */
    if (!rn) {
	return NULL;
    }

    /*
     * The first job here is to find a node in the tree which is
     * known to be after the given key/bitlen in lexigraphic order.
     */
    if (ap) {
	/*
	 * Search down the tree as far as we can until we find a node
	 * which has a bit number the same or larger than ours which has
	 * an external node attached.
	 */
	while (rn->pat_bit < bitlen || rn->pat_ext == NULL) {
	    if (rn->pat_tbit & ap[rn->pat_tbyte]) {
		if (!(rn->pat_right)) {
		    break;
		}
		rn = rn->pat_right;
	    } else {
		if (!(rn->pat_left)) {
		    break;
		}
		rn = rn->pat_left;
	    }
	}

	/*
	 * Determine the bit position of the first bit which differs between
	 * the destination we found and the one we were given, as this will
	 * suggest where we should search.  Often this will be an exact
	 * match.
	 */
	bits2chk = MIN(rn->pat_bit, bitlen);
	ap2 = rn->pat_ext->key;
	for (dbit = 0; dbit < bits2chk; dbit += NBBY) {
	    int i = dbit >> RNSHIFT;
	    if (ap[i] != ap2[i]) {
		dbit += first_bit_set[ap[i] ^ ap2[i]];
		break;
	    }
	}

	/*
	 * If we got an exact match, this is either our node (if his mask
	 * is longer than ours) or we only need to find the next node in
	 * the tree.  Do this now since this may be the normal case and
	 * is fairly easy.
	 */
	if (dbit >= bits2chk) {
	    if (rn->pat_bit <= bitlen) {
		if (rn->pat_left) {
		    rn = rn->pat_left;
		} else if (rn->pat_right) {
		    rn = rn->pat_right;
		} else {
		    patnode *rn_next;
		    do {
			rn_next = rn;
			rn = rn->pat_parent;
			if (!rn) {
			    return NULL;
			}
		    } while (!(rn->pat_right) || rn->pat_right == rn_next);
		    rn = rn->pat_right;
		}
	    }
	} else {
	    patnode *rn_next;

	    /*
	     * Here we found a node which differs from our target destination
	     * in the low order bits.  We need to determine whether our guy
	     * is too big, or too small, for the branch we are in.  If
	     * he is too big, walk up until we find a node with a smaller
	     * bit number than dbit where we branched left and search to
	     * the right of this.  Otherwise all the guys in this branch
	     * will be larger than us, so walk up the tree to the first
	     * node we a bit number > dbit and search from there
	     */
	    if (ap[RNBYTE(dbit)] & RNBIT(dbit)) {
		do {
		    rn_next = rn;
		    rn = rn_next->pat_parent;
		    if (!rn) {
			return NULL;
		    }
		    assert(rn->pat_bit != dbit);
		} while (rn->pat_bit > dbit || (!(rn->pat_right)
		    || rn->pat_right == rn_next));
		rn = rn->pat_right;
	    } else {
		rn_next = rn->pat_parent;
		while (rn_next && rn_next->pat_bit > dbit) {
		    rn = rn_next;
		    rn_next = rn_next->pat_parent;
		}
	    }
	}
    }

    /*
     * If we have a pointer to a radix node which is in an area of the
     * tree where the address/masks are larger than our own.  Walk the
     * tree from here, checking each node with an external node attached until
     * we find one which matches our criteria.
     */
    for (;;) {
	if (rn->pat_ext) {
	    break;
	}

	if (rn->pat_left) {
	    rn = rn->pat_left;
	} else if (rn->pat_right) {
	    rn = rn->pat_right;
	} else {
	    patnode *rn_next;
	    do {
		rn_next = rn;
		rn = rn->pat_parent;
		if (!rn) {
		    return NULL;
		}
	    } while (!(rn->pat_right) || rn->pat_right == rn_next);
	    rn = rn->pat_right;
	}
    }

    return rn->pat_ext;
}

int
pat_empty(pat_handle *root)
{
    patext *ext;

    ext = pat_getnext(root, NULL, 0);
    if (ext) {
	return FALSE;
    }
    return TRUE;
}
