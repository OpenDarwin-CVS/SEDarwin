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

#include <sys/types.h>
#include <sys/condvar.h>

#include <kern/lock.h>

void
cv_init(struct cv *cvp, const char *desc)
{

	bzero(cvp, sizeof(*cvp));
	cvp->cv_wait_queue = wait_queue_alloc(SYNC_POLICY_FIFO);
	if (cvp->cv_wait_queue == WAIT_QUEUE_NULL)
		panic("cv_init: wait_queue_alloc failed");
}

void
cv_destroy(struct cv *cvp)
{

#if 0
	/*
	 * TBD/CDV this method is marked both
	 * __APPLE_API_PRIVATE and MACH_KERNEL_PRIVATE
	 */
	if (!wait_queue_is_queue(cvp->cv_wait_queue))
		panic("cv_destroy: !wait_queue_is_queue");
#endif
	wait_queue_free(cvp->cv_wait_queue);
	bzero(cvp, sizeof(*cvp));
}

void
cv_wait(struct cv *cvp, mutex_t *mp)
{
	int ret;

	mutex_unlock(mp);
	ret = wait_queue_assert_wait(cvp->cv_wait_queue, 0, THREAD_UNINT);
	if (ret != THREAD_WAITING)
		panic("cv_wait: wait_queue_assert_wait failed");
	ret = thread_block(THREAD_CONTINUE_NULL);
	if (ret != THREAD_AWAKENED)
		panic("cv_wait: thread_block failed");
	mutex_lock(mp);
}

int
cv_wait_sig(struct cv *cvp, mutex_t *mp)
{
	int ret;

	mutex_unlock(mp);
	ret = wait_queue_assert_wait(cvp->cv_wait_queue, 0,
	    THREAD_INTERRUPTIBLE);
	if (ret != THREAD_WAITING)
		panic("cv_wait: wait_queue_assert_wait failed");
	ret = thread_block(THREAD_CONTINUE_NULL);
	if (ret != THREAD_AWAKENED)
		panic("cv_wait: thread_block failed");
	mutex_lock(mp);
}

/*
 * Not supported in Darwin right now.
 */
int
cv_timedwait(struct cv *cvp, mutex_t *mp, int timo)
{

	panic("cv_timedwait: not currently supported");
}

/*
 * Not supported in Darwin right now.
 */
int
cv_timedwait_sig(struct cv *cvp, mutex_t *mp, int timo)
{

	panic("cv_timedwait: not currently supported");
}

void
cv_signal(struct cv *cvp)
{

	wait_queue_wakeup_one(cvp->cv_wait_queue, 0, THREAD_AWAKENED);
}

void
cv_broadcast(struct cv *cvp)
{

	wait_queue_wakeup_all(cvp->cv_wait_queue, 0, THREAD_AWAKENED);
}

/*
 * Not supported in Darwin right now.
 */
void
cv_waitq_remove(struct uthread *td)
{

	panic("cv_waitq_remove: not currently supported");
}

#if 0
int
cv_waitq_empty(struct cv *cvp)
{

	/*
	 * TBD/CDV wait_queue_empty() should probably be used, but
	 * it's marked both __APPLE_API_PRIVATE and MACH_KERNEL_PRIVATE
	 *
	 */
	return (wait_queue_empty(cvp->cv_wait_queue));
}
#endif

const char *
cv_wmesg(struct cv *cvp)
{

	return (cvp->cv_description);
}
