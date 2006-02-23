
/*-
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

#include <stdio.h>
#include <mach/port.h>
#include <mach/task.h>
#include <mach/security.h>

/*
        mgetpmac - Print the label of a task, and the label of its task port.
        Since the task port is required to read the label, the specified
        process must be accessible (e.g. process has same owner as issuer, or
	issuer is root).
*/

int
main(int argc, const char *argv[])
{
	mach_port_t tp;
	char label[512];
	char *policies = "?sebsd,?ipctrace,?mls";

	if (argc > 1)
		task_for_pid(mach_task_self(), strtol(argv[1], NULL, 10), &tp);
	else
		tp = mach_task_self();

	if (argc > 2)
		policies = argv[2];

	if (tp == MACH_PORT_NULL) {
		printf("null port\n");
		return (1);
	}

	if (KERN_SUCCESS == mach_get_task_label_text(tp, policies, label))
		printf("task: %s\n", label);

	if (KERN_SUCCESS == mach_get_label_text(mach_task_self(), tp, policies, label))
		printf("port: %s\n", label);

	return (0);
}
