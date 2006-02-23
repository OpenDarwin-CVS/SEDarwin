/*-
 * Copyright (c) 2003-2005 Networks Associates Technology, Inc.
 * All rights reserved.
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
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mac.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <security/mac_internal.h>
#include <sys/posix_sem.h>
#include <sys/mac_policy.h>

static int	mac_enforce_posix_sem = 1;
SYSCTL_INT(_security_mac, OID_AUTO, enforce_posix_sem, CTLFLAG_RW,
    &mac_enforce_posix_sem, 0, "Enforce MAC policy on Posix Semaphores");
TUNABLE_INT("security.mac.enforce_posix_sem", &mac_enforce_posix_sem);

#ifdef MAC_DEBUG
static unsigned int nmac_psem;
SYSCTL_UINT(_security_mac_debug_counters, OID_AUTO, posix_sem, CTLFLAG_RD,
    &nmac_psem, 0, "number of posix semaphore identifiers in use");
#endif

static struct label *
mac_posix_sem_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	MAC_PERFORM(init_posix_sem_label, label);
	MAC_DEBUG_COUNTER_INC(&nmac_psem);
	return (label);
}

void
mac_init_posix_sem(struct pseminfo *psem)
{

	psem->psem_label = mac_posix_sem_label_alloc();
}

static void
mac_posix_sem_label_free(struct label *label)
{

	MAC_PERFORM(destroy_posix_sem_label, label);
	mac_labelzone_free(label);
	MAC_DEBUG_COUNTER_DEC(&nmac_psem);
}

void
mac_destroy_posix_sem(struct pseminfo *psem)
{

	mac_posix_sem_label_free(psem->psem_label);
	psem->psem_label = NULL;
}

void
mac_create_posix_sem(struct ucred *cred, struct pseminfo *psem,
    const char *name)
{

	MAC_PERFORM(create_posix_sem, cred, psem, psem->psem_label, name);
}

int
mac_check_posix_sem_create(struct ucred *cred, const char *name)
{
	int error;

	if (!mac_enforce_posix_sem)
		return (0);

	MAC_CHECK(check_posix_sem_create, cred, name);

	return (error);
}

int
mac_check_posix_sem_open(struct ucred *cred, struct pseminfo *psem)
{
	int error;

	if (!mac_enforce_posix_sem)
		return (0);

	MAC_CHECK(check_posix_sem_open, cred, psem,
	    psem->psem_label);

	return (error);
}

int
mac_check_posix_sem_post(struct ucred *cred, struct pseminfo *psem)
{
	int error;

	if (!mac_enforce_posix_sem)
		return (0);

	MAC_CHECK(check_posix_sem_post, cred, psem, psem->psem_label);

	return (error);
}

int
mac_check_posix_sem_unlink(struct ucred *cred, struct pseminfo *psem,
    const char *name)
{
	int error;

	if (!mac_enforce_posix_sem)
		return (0);

	MAC_CHECK(check_posix_sem_unlink, cred, psem, psem->psem_label, name);

	return (error);
}

int
mac_check_posix_sem_wait(struct ucred *cred, struct pseminfo *psem)
{
	int error;

	if (!mac_enforce_posix_sem)
		return (0);

	MAC_CHECK(check_posix_sem_wait, cred, psem, psem->psem_label);

	return (error);
}
