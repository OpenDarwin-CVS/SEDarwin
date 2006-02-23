/*
 * Copyright (c) 2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the TrustedBSD Project by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.  This work was supported
 * by the National Security Agency.
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

/*
 * Implement BSD-layer condition variables using Mach-layer wait queues.
 */

#include <kern/lock.h>
#include <kern/wait_queue.h>

struct cv {
	wait_queue_t		 cv_wait_queue;
	mutex_t			*cv_mutex;		/* Debugging only. */
	const char		*cv_description;
};

struct uthread;
void	cv_init(struct cv *cvp, const char *desc);
void	cv_destroy(struct cv *cvp);
void	cv_wait(struct cv *cvp, mutex_t *mp);
int	cv_wait_sig(struct cv *cvp, mutex_t *mp);
int	cv_timedwait(struct cv *cvp, mutex_t *mp, int timo);
int	cv_timedwait_sig(struct cv *cvp, mutex_t *mp, int timo);
void	cv_signal(struct cv *cvp);
void	cv_broadcast(struct cv *cvp);
void	cv_waitq_remove(struct uthread *td);
int	cv_waitq_empty(struct cv *cvp);
const char	*cv_wmesg(struct cv *cvp);
