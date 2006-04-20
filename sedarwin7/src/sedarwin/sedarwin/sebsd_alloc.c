/*-
 * Copyright (c) 2005, 2006 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS").
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <mach/mach_types.h>
#include <kern/kalloc.h>
#include <sys/param.h>
#include <sys/malloc.h>

void *
sebsd_malloc(size_t size, int type, int flags)
{
	size_t *vs, nsize;

	nsize = size + sizeof(size_t);
	vs = (flags & M_NOWAIT) ?
	    (size_t *)kalloc_noblock(nsize) : (size_t *)kalloc(nsize);
	if (vs != NULL) {
		*vs++ = nsize;
		if (flags & M_ZERO)
			bzero(vs, size);
	}
	return (vs);
}

void
sebsd_free(void *v, int type)
{
	size_t *vs = v;

	if (vs != NULL) {
		vs--;
		kfree((vm_offset_t)vs, *vs);
	}
}
