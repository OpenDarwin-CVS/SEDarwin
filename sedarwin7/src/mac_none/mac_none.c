/*-
 * Copyright (c) 1999-2002 Robert N. M. Watson
 * Copyright (c) 2001-2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
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
 * $FreeBSD: src/sys/security/mac_none/mac_none.c,v 1.31 2004/02/22 00:33:12 rwatson Exp $
 */

/*
 * Developed by the TrustedBSD Project.
 *
 * Modified for use with the Darwin MAC framework.
 *
 * Sample policy implementing no entry points; for performance measurement
 * purposes only.  If you're looking for a stub policy to base new policies
 * on, try mac_stub.
 */

#include <sys/types.h>
#include <sys/extattr.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <sys/sysctl.h>
#include <sys/libkern.h>
#include <sys/ucred.h>
#include <sys/mac_policy.h>

#include <vm/vm_kern.h>
#include <kern/kalloc.h>
#include <mach/kmod.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <sys/fcntl.h>

#include <string.h>

/*
 * SYSCTL entry points
 */

SYSCTL_DECL(_security_mac);

SYSCTL_NODE(_security_mac, OID_AUTO, none, CTLFLAG_RW, 0,
    "MAC None policy controls");

static int	mac_none_enabled = 1;
SYSCTL_INT(_security_mac_none, OID_AUTO, enabled, CTLFLAG_RW,
    &mac_none_enabled, 0, "Enforce none policy");

static void
mac_none_init_bsd(struct mac_policy_conf *conf)
{

	sysctl_register_oid(&sysctl__security_mac_none);
	sysctl_register_oid(&sysctl__security_mac_none_enabled);
}

static struct mac_policy_ops mac_none_ops =
{
	.mpo_init_bsd                       = mac_none_init_bsd,
};

struct mac_policy_conf mac_none_mac_policy_conf = {
	"mac_none",				/* policy name */
	"MAC None Policy",			/* full name */
	NULL,					/* label namespace */
	0,					/* namespace count */
	&mac_none_ops,				/* policy operations */
	0,					/* loadtime flags*/
	NULL,  					/* security field */
	0					/* runtime flags */
};

#ifdef KEXT
static kern_return_t
kmod_start(kmod_info_t *ki, void *xd)
{
	return (mac_policy_register (&mac_none_mac_policy_conf));
}

static kern_return_t
kmod_stop(kmod_info_t *ki, void *xd)
{
	return (mac_policy_unregister (&mac_none_mac_policy_conf));
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(security.mac_none,  "1.0",  _start, _stop)
kmod_start_func_t *_realmain = kmod_start;
kmod_stop_func_t *_antimain = kmod_stop;
int _kext_apple_cc = __APPLE_CC__ ;
#endif /* KEXT */
