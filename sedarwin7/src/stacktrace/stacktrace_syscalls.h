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

#ifndef _STACKTRACE_SYSCALLS_H_
#define	_STACKTRACE_SYSCALLS_H_

#define	STACKTRACECALL_ORDER	10
#define	STACKTRACECALL_GETBUF	8

#define	STACKTRACE_ON	98
#define	STACKTRACE_OFF	99
#define	FULLBUFF_STOP	97
#define	FULLBUFF_RESET	96
#define	STACKTRACE_FULL	95

#define	STACKTRACE_INTERFACE_VERSION	1

#define	RBSIZE	14000000

/*
 * Input args to stacktrace syscall
 */
struct stacktrace_user_args {
	char	*userbuffp;
	long	 bufmaxsize;
	short	 param;
	short	 version;
};

/*
 * Buffer header
 *
 * TODO: Add timestamps of last call, last reset, kernel compile ... also
 * global_fullbuffer_action, global_enable, and buffersize.
 */
struct stacktrace_buf_head {
	long	 ncalls;
	long	 bufwraps;
	short	 maxdepth;
	short	 version;
	char	 next;
};

/*
 * Trace header in the buffer
 */
struct tracehead {
	short	 function;
	short	 ntracelines;
	char	 tracelines;
};

/*
 * Trace line in the buffer
 */
struct traceline {
	long	 stackloc;
	long	 codeloc;
	char	 nexttraceline;
};

#endif /* _STACKTRACE_SYSCALLS_H_ */
