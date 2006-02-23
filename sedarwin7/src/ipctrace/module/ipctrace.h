
/*-
 * Copyright (c) 2005 SPARTA, Inc.
 * Copyright (c) 2004 Networks Associates Technology, Inc.
 * All rights reserved.
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

#define IT_TASKLEN 124

struct ipctrace_rec
{
	int  action;
	char task[IT_TASKLEN];	/* task performing action */

	char ttask[IT_TASKLEN]; /* task that held the first right */
	int  portn;		/* port serial number */
	int  kotype;		/* type of kernel port */
	int  count;		/* number of occurrences */
};

#define ITA_SEND       1
#define ITA_RECV       2
#define ITA_MAKE_SEND 11
#define ITA_COPY_SEND 12
#define ITA_MOVE_RECV 13

#define	IPCTRACE_LABEL_NAME		"ipctrace"
#define	IPCTRACE_LABEL_NAME_COUNT	1

/* system calls */

#define IT_CALL_GET 1

struct ipctrace_call_get
{
	vm_offset_t buffer;
	vm_size_t   size;
};
