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
      "@(#) $Id: memory.c,v 1.1.1.8 2007/05/09 20:41:35 sachin Exp $";

#include "memory.h"
#include "memory_private.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

static struct mem_list mem_head;

mem_handle
mem_type_init(int size, const char* name)
{
    static int inited = FALSE;
    mem_bits_t* mb;

    if (!inited) {
        TAILQ_INIT(&mem_head);
        inited = TRUE;
    }
    mb = calloc(1, sizeof(mem_bits_t));
    assert(mb);

    TAILQ_INSERT_TAIL(&mem_head, mb, m_next);

    mb->m_size = size;
    strncpy(mb->m_name, name, MAX_MEM_NAME-1);
    mb->m_name[MAX_MEM_NAME-1] = 0;

    return mb;
}

void*
mem_type_alloc(mem_handle handle)
{
    mem_bits_t* mb;

    mb = handle;

    assert(mb->m_size > 0);

    mb->m_alloced++;
    return calloc(1, mb->m_size);
}

void
mem_type_free(mem_handle handle, void* mem)
{
    mem_bits_t* mb;

    mb = (mem_bits_t*)handle;

    assert(mb->m_size > 0);

    mb->m_freed++;
    free(mem);
}

void
mem_type_show(mem_print print, void* arg)
{
    mem_bits_t* mb;

    TAILQ_FOREACH(mb, &mem_head, m_next)
    {
        (*print)(arg, mb->m_size, mb->m_alloced, mb->m_freed, mb->m_name);
    }
}

void
mem_shutdown()
{
    mem_bits_t* mb = TAILQ_FIRST(&mem_head);
    while (mb) {
        TAILQ_REMOVE(&mem_head, mb, m_next);
        free(mb);
        mb = TAILQ_FIRST(&mem_head);
    }
}

