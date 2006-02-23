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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mac.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stacktrace_syscalls.h"

/*
 * User command that captures a security stack trace created by the
 * mac_stacktrace security policy module and writes it to a binary disk file.
 */
int
main(int argc, char **argv)
{
	struct stacktrace_buf_head *sbhp;
	struct stacktrace_user_args stu;
	char *storagep;
	int error;
	FILE *fp;

	if (argc != 2) {
		printf("usage:  %s path\n", argv[0]);
		exit(1);
	}
	if (strcmp(argv[1], "-on") == 0) {
		stu.param = STACKTRACE_ON;
		stu.version = STACKTRACE_INTERFACE_VERSION;
		error = mac_syscall("stacktrace", STACKTRACECALL_ORDER, &stu);
		exit(0);
	} else if (strcmp(argv[1], "-off") == 0) {
		stu.param = STACKTRACE_OFF;
		stu.version = STACKTRACE_INTERFACE_VERSION;
		error = mac_syscall("stacktrace", STACKTRACECALL_ORDER, &stu);
		exit(0);
	} else if (strcmp(argv[1], "-wrap") == 0) {
		stu.param = FULLBUFF_RESET;
		stu.version = STACKTRACE_INTERFACE_VERSION;
		error = mac_syscall("stacktrace", STACKTRACECALL_ORDER, &stu);
		exit(0);
	} else if (strcmp(argv[1], "-stop") == 0) {
		stu.param = FULLBUFF_STOP;
		stu.version = STACKTRACE_INTERFACE_VERSION;
		error = mac_syscall("stacktrace", STACKTRACECALL_ORDER, &stu);
		exit(0);
	}

	/*
	 * TODO: Find out size from syscall.
	 */
	storagep = malloc(RBSIZE);
	if (storagep == NULL) {
		printf("%s: error from malloc\n", argv[0]);
		exit(1);
	}
	stu.userbuffp = storagep;
	stu.bufmaxsize = RBSIZE;
	stu.version = STACKTRACE_INTERFACE_VERSION;
	error = mac_syscall("stacktrace", STACKTRACECALL_GETBUF, &stu);
	if (error != 0) {
		printf("%s: error from syscall %d\n", argv[0], error);
		exit(1);
	}

	sbhp = (struct stacktrace_buf_head *)storagep;
	if (sbhp->version != STACKTRACE_INTERFACE_VERSION) {
		fprintf(stderr, "%s: this program is for version %d data, "
		    "input is version %d\n", argv[0],
		    STACKTRACE_INTERFACE_VERSION, sbhp->version);
		exit(1);
	}
	printf("%ld calls %ld wraps, max depth %d\n", sbhp->ncalls,
	    sbhp->bufwraps, sbhp->maxdepth);

	/*
	 * Open the output binary file.
	 *
	 * TODO: Print time of last trace and reset.
	 * TODO: Add logic to append to an exiting trace file.
	 */
	fp = fopen(argv[1], "w");
	if (fp == NULL) {
		printf("%s: error from open %s\n", argv[0], argv[1]);
		exit(1);
	}
	fwrite(storagep, RBSIZE, 1, fp);
	fclose(fp);

	exit(0);
}
