
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

#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include "ipctrace.h"
#include <sys/mac.h>
#include "ikotnames.h"

static const char *
ita_name(int a)
{
	switch (a) {
	case ITA_SEND:
		return ("send");

	case ITA_MOVE_RECV:
		return ("move_recv");

	case ITA_MAKE_SEND:
		return ("make_send");

	case ITA_COPY_SEND:
		return ("copy_send");
	}

	return ("unknown");
}

int
main(int argc, const char *argv[])
{
	mach_port_t kport;
	kern_return_t kr;
	struct ipctrace_call_get args;
	struct ipctrace_rec *p;
	struct ipctrace_rec *end;

	kr = task_for_pid(mach_task_self(), 0, &kport);
	if (kr) {
		printf("can't get kernel port: %d\n", kr);
		return (1);
	}

	if (mac_syscall("ipctrace", IT_CALL_GET, &args)) {
		printf("error calling ipctrace_get\n");
		return (1);
	}

	p = (struct ipctrace_rec *)args.buffer;
	end = (struct ipctrace_rec *)(args.buffer + args.size);

	printf("%d trace records:\n", end-p);

	for (; p < end; p++) {
		if (!strcmp (p->ttask, "mach_kernel"))
			sprintf(p->ttask + strlen("mach_kernel"),
				":%s", ikot_names[p->kotype]);

		printf("%-9s %-66s | %-66s:%5d %6d\n", ita_name(p->action),
		       p->task, p->ttask, p->portn, p->count);
	}

	return (0);
}
