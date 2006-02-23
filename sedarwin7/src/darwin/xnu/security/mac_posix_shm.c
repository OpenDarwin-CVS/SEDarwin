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
#include <sys/posix_shm.h>
#include <sys/mac.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/mac_policy.h>
#include <security/mac_internal.h>

static int	mac_enforce_pshm = 1;
SYSCTL_INT(_security_mac, OID_AUTO, enforce_posix_shm, CTLFLAG_RW,
    &mac_enforce_pshm, 0, "Enforce MAC policy on Posix Shared memory");
TUNABLE_INT("security.mac.enforce_posix_shm", &mac_enforce_posix_shm);

#ifdef MAC_DEBUG
static unsigned int nmac_pshm;
SYSCTL_UINT(_security_mac_debug_counters, OID_AUTO, posix_shm, CTLFLAG_RD,
    &nmac_pshm, 0, "number of posix shared memory identifiers in use");
#endif

static struct label *
mac_posix_shm_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	MAC_PERFORM(init_posix_shm_label, label);
	MAC_DEBUG_COUNTER_INC(&nmac_pshm);
	return (label);
}

void
mac_init_posix_shm(struct pshminfo *pshm)
{

	pshm->pshm_label = mac_posix_shm_label_alloc();
}

static void
mac_posix_shm_label_free(struct label *label)
{

	MAC_PERFORM(destroy_posix_shm_label, label);
	mac_labelzone_free(label);
	MAC_DEBUG_COUNTER_DEC(&nmac_pshm);
}

void
mac_destroy_posix_shm(struct pshminfo *pshm)
{

	mac_posix_shm_label_free(pshm->pshm_label);
	pshm->pshm_label = NULL;
}

void
mac_create_posix_shm(struct ucred *cred, struct pshminfo *pshm,
    const char *name)
{

	MAC_PERFORM(create_posix_shm, cred, pshm, pshm->pshm_label, name);
}

int
mac_check_posix_shm_create(struct ucred *cred, const char *name)
{
	int error = 0;

	if (!mac_enforce_pshm)
		return 0;

	MAC_CHECK(check_posix_shm_create, cred, name);

	return error;
}

int
mac_check_posix_shm_open(struct ucred *cred, struct pshminfo *shm)
{
	int error;

	if (!mac_enforce_pshm)
		return (0);

	MAC_CHECK(check_posix_shm_open, cred, shm, shm->pshm_label);

	return (error);
}

int
mac_check_posix_shm_mmap(struct ucred *cred, struct pshminfo *shm,
    int prot, int flags)
{
	int error;

	if (!mac_enforce_pshm)
		return (0);

	MAC_CHECK(check_posix_shm_mmap, cred, shm, shm->pshm_label,
            prot, flags);

	return (error);
}

int
mac_check_posix_shm_stat(struct ucred *cred, struct pshminfo *shm)
{
	int error;

	if (!mac_enforce_pshm)
		return (0);

	MAC_CHECK(check_posix_shm_stat, cred, shm, shm->pshm_label);

	return (error);
}

int
mac_check_posix_shm_truncate(struct ucred *cred, struct pshminfo *shm,
    size_t size)
{
	int error;

	if (!mac_enforce_pshm)
		return (0);

	MAC_CHECK(check_posix_shm_truncate, cred, shm, shm->pshm_label, size);

	return (error);
}

int
mac_check_posix_shm_unlink(struct ucred *cred, struct pshminfo *shm,
    const char *name)
{
	int error;

	if (!mac_enforce_pshm)
		return (0);

	MAC_CHECK(check_posix_shm_unlink, cred, shm, shm->pshm_label, name);

	return (error);
}
