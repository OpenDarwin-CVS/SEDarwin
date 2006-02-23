
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

#include <security/mac_internal.h>
#include <sys/vnode.h>

int
mac_check_system_acct(struct ucred *cred, struct vnode *vp)
{
	int error;

	if (vp != NULL) {
		ASSERT_VOP_LOCKED(vp, "mac_check_system_acct");
	}

	if (!mac_enforce_system)
		return (0);

	MAC_CHECK(check_system_acct, cred, vp,
	    vp != NULL ? vp->v_label : NULL);

	return (error);
}

int
mac_check_system_nfsd(struct ucred *cred)
{
	int error;

	if (!mac_enforce_system)
		return (0);

	MAC_CHECK(check_system_nfsd, cred);

	return (error);
}

int
mac_check_system_reboot(struct ucred *cred, int howto)
{
	int error;

	if (!mac_enforce_system)
		return (0);

	MAC_CHECK(check_system_reboot, cred, howto);

	return (error);
}

int
mac_check_system_settime(struct ucred *cred)
{
	int error;

	if (!mac_enforce_system)
		return (0);

	MAC_CHECK(check_system_settime, cred);

	return (error);
}

int
mac_check_system_swapon(struct ucred *cred, struct vnode *vp)
{
	int error;

	ASSERT_VOP_LOCKED(vp, "mac_check_system_swapon");

	if (!mac_enforce_system)
		return (0);

	MAC_CHECK(check_system_swapon, cred, vp, vp->v_label);
	return (error);
}

int
mac_check_system_swapoff(struct ucred *cred, struct vnode *vp)
{
	int error;

	ASSERT_VOP_LOCKED(vp, "mac_check_system_swapoff");

	if (!mac_enforce_system)
		return (0);

	MAC_CHECK(check_system_swapoff, cred, vp, vp->v_label);
	return (error);
}

int
mac_check_system_sysctl(struct ucred *cred, int *name, u_int namelen,
    void *old, size_t *oldlenp, int inkernel, void *new, size_t newlen)
{
	int error;

	/*
	 * XXXMAC: We're very much like to assert the SYSCTL_LOCK here,
	 * but since it's not exported from kern_sysctl.c, we can't.
	 */
	if (!mac_enforce_system)
		return (0);

	MAC_CHECK(check_system_sysctl, cred, name, namelen, old, oldlenp,
	    inkernel, new, newlen);

	return (error);
}

