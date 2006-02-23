
/*-
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001, 2002, 2003, 2004 Networks Associates Technology, Inc.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
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
 *
 */

#include <string.h>
#include <security/mac_internal.h>
#include <sys/ucred.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/vnode.h>

extern struct mac_label_element_list_t mac_label_element_list;

struct label *
mac_cred_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	MAC_PERFORM(init_cred_label, label);
	MAC_DEBUG_COUNTER_INC(&nmaccreds);
	return (label);
}

void
mac_init_cred(struct ucred *cred)
{

	cred->cr_label = mac_cred_label_alloc();
}

static struct label *
mac_proc_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	MAC_PERFORM(init_proc_label, label);
	MAC_DEBUG_COUNTER_INC(&nmacprocs);
	return (label);
}

void
mac_init_proc(struct proc *p)
{

	p->p_label = mac_proc_label_alloc();
}

void
mac_cred_label_free(struct label *label)
{

	MAC_PERFORM(destroy_cred_label, label);
	mac_labelzone_free(label);
	MAC_DEBUG_COUNTER_DEC(&nmaccreds);
}

int
mac_get_cred_audit_labels(struct proc *p, struct mac *mac)
{
	struct ucred *cr;
	int error = 0;
	int count;

	PROC_LOCK(p);
	cr = p->p_ucred;
	crhold(cr);
	PROC_UNLOCK(p);

	MAC_EXTERNALIZE_REGISTERED_LABELS(cred_audit, cr->cr_label, 
		mac->m_string, mac->m_buflen, count);

	crfree(cr);
	return (error);
}

void
mac_destroy_cred(struct ucred *cred)
{

	mac_cred_label_free(cred->cr_label);
	cred->cr_label = NULL;
}

static void
mac_proc_label_free(struct label *label)
{

	MAC_PERFORM(destroy_proc_label, label);
	mac_labelzone_free(label);
	MAC_DEBUG_COUNTER_DEC(&nmacprocs);
}

void
mac_destroy_proc(struct proc *p)
{

	mac_proc_label_free(p->p_label);
	p->p_label = NULL;
}

int
mac_externalize_cred_label(struct label *label, char *elements,
    char *outbuf, size_t outbuflen, int flags)
{
	int error = 0;

	if (elements[0] == '*') {
		int count;
		MAC_EXTERNALIZE_REGISTERED_LABELS(cred, label, outbuf, 
		    outbuflen, count);
	} else
		MAC_EXTERNALIZE_LIST(cred, label, elements, outbuf, outbuflen);

	return (error);
}

int
mac_internalize_cred_label(struct label *label, char *string)
{
	int error;

	MAC_INTERNALIZE_LIST(cred, label, string);

	return (error);
}

/*
 * Initialize MAC label for the first kernel process, from which other
 * kernel processes and threads are spawned.
 */
void
mac_create_proc0(struct ucred *cred)
{

	MAC_PERFORM(create_proc0, cred);
}

/*
 * Initialize MAC label for the first userland process, from which other
 * userland processes and threads are spawned.
 * 
 * On Darwin, proc0 forks and the child process becomes init, though
 * indirectly.  The kernel starts /sbin/mach_init, which subsequently
 * forks and the *parent* execs /sbin/init.  This leaves proc1 as
 * /sbin/init and proc2 as /sbin/mach_init.
 */
void
mac_create_proc1(struct ucred *cred)
{

	MAC_PERFORM(create_proc1, cred);
}

/*
 * When a new process is created, its label must be initialized.  Generally,
 * this involves inheritence from the parent process, modulo possible
 * deltas.  This function allows that processing to take place.
 */
void
mac_create_cred(struct ucred *parent_cred, struct ucred *child_cred)
{
	MAC_PERFORM(create_cred, parent_cred, child_cred);
}

int
mac_execve_enter(struct mac *mac_p, struct label *execlabelstorage)
{
	struct mac mac;
	char *buffer;
	int error;
	size_t dummy;

	if (mac_p == NULL)
		return (0);

	error = copyin(mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	buffer = _MALLOC(mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, buffer, mac.m_buflen, &dummy);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}

	error = mac_internalize_cred_label(execlabelstorage, buffer);
	FREE(buffer, M_MACTEMP);
	return (error);
}

/*
 * When the subject's label changes, it may require revocation of privilege
 * to mapped objects.  This can't be done on-the-fly later with a unified
 * buffer cache.
 */
void
mac_relabel_cred(struct ucred *cred, struct label *newlabel)
{

	MAC_PERFORM(relabel_cred, cred, newlabel);
}

int
mac_check_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	int error;

	MAC_CHECK(check_cred_relabel, cred, newlabel);

	return (error);
}

int
mac_check_cred_visible(struct ucred *u1, struct ucred *u2)
{
	int error;

	if (!mac_enforce_process)
		return (0);

	MAC_CHECK(check_cred_visible, u1, u2);

	return (error);
}

int
mac_check_proc_debug(struct ucred *cred, struct proc *proc)
{
	int error;

	PROC_LOCK_ASSERT(proc, MA_OWNED);

	if (!mac_enforce_process)
		return (0);

	MAC_CHECK(check_proc_debug, cred, proc);

	return (error);
}

int
mac_check_proc_sched(struct ucred *cred, struct proc *proc)
{
	int error;

	PROC_LOCK_ASSERT(proc, MA_OWNED);

	if (!mac_enforce_process)
		return (0);

	MAC_CHECK(check_proc_sched, cred, proc);

	return (error);
}

int
mac_check_proc_signal(struct ucred *cred, struct proc *proc, int signum)
{
	int error;

	PROC_LOCK_ASSERT(proc, MA_OWNED);

	if (!mac_enforce_process)
		return (0);

	MAC_CHECK(check_proc_signal, cred, proc, signum);

	return (error);
}

int
mac_check_proc_wait(struct ucred *cred, struct proc *proc)
{
	int error;

	PROC_LOCK_ASSERT(proc, MA_OWNED);

	if (!mac_enforce_process)
		return (0);

	MAC_CHECK(check_proc_wait, cred, proc);

	return (error);
}


/*
 * Login Context
 */

int
mac_check_proc_setlcid (struct proc *p0, struct proc *p,
			pid_t pid, pid_t lcid)
{
	int error;

	if (!mac_enforce_process)
		return (0);

	MAC_CHECK(check_proc_setlcid, p0, p, pid, lcid);
	return (error);
}

int
mac_check_proc_getlcid (struct proc *p0, struct proc *p, pid_t pid)
{
	int error;

	if (!mac_enforce_process)
		return (0);

	MAC_CHECK(check_proc_getlcid, p0, p, pid);
	return (error);
}

void
mac_proc_create_lctx (struct proc *p, struct lctx *l)
{
	MAC_PERFORM(proc_create_lctx, p, l);
}

void
mac_proc_join_lctx (struct proc *p, struct lctx *l)
{
	MAC_PERFORM(proc_join_lctx, p, l);
}

void
mac_proc_leave_lctx (struct proc *p, struct lctx *l)
{
	MAC_PERFORM(proc_leave_lctx, p, l);
}

struct label *
mac_lctx_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(M_WAITOK);
	MAC_PERFORM(init_lctx_label, label);
	return (label);
}

void
mac_lctx_label_free(struct label *label)
{

	MAC_PERFORM(destroy_lctx_label, label);
	mac_labelzone_free(label);
}

int
mac_externalize_lctx_label(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error;

	MAC_EXTERNALIZE_LIST(lctx, label, elements, outbuf, outbuflen);

	return (error);
}

int
mac_internalize_lctx_label(struct label *label, char *string)
{
	int error;

	MAC_INTERNALIZE_LIST(lctx, label, string);

	return (error);
}

void
mac_relabel_lctx(struct lctx *l, struct label *newlabel)
{

	MAC_PERFORM(relabel_lctx, l, newlabel);
}

int
mac_check_lctx_relabel(struct lctx *l, struct label *newlabel)
{
	int error;

	MAC_CHECK(check_lctx_relabel, l, newlabel);

	return (error);
}
