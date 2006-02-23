/*-
 * Copyright (c) 2005 SPARTA, Inc.
 * Copyright (c) 2001-2005 Networks Associates Technology, Inc.
 * Copyright (c) 1999-2002 Robert N. M. Watson
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
 * $FreeBSD: src/sys/security/mac_counters/mac_counters.c,v 1.30 2003/08/21 17:28:45 rwatson Exp $
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/conf.h>
//#include <sys/extattr.h>
#include <sys/kernel.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/mbuf.h>
#include <sys/mac_policy.h>

#define COUNT_NAMESPACE_COUNT 1
#define COUNT_LABEL_NAMESPACE "count"

//SYSCTL_NODE(, OID_AUTO, security, CTLFLAG_RW, 0, 
//    "Security Controls");

//SYSCTL_NODE(_security, OID_AUTO, mac, CTLFLAG_RW, 0,
//    "TrustedBSD MAC policy controls");

//extern struct sysctl_oid_list sysctl__security_mac_children;
//SYSCTL_NODE(_security_mac, OID_AUTO, count, CTLFLAG_RW, 0,
//    "Function counters");

#define MAKE_COUNTER(n) \
	static int n ## _c; \
	SYSCTL_INT(_security_mac_count, OID_AUTO, n ## _c, CTLFLAG_RD, \
		&n ## _c, 0, #n "() calls");

#define REG_COUNTER(n) \
	sysctl_register_oid(&sysctl__security_mac_count_ ## n ## _c);

#define MAKE_RETSYSCTL(n) \
	static int n ## _ret; \
	SYSCTL_INT(_security_mac_retcontrol, OID_AUTO, n ## _ret, CTLFLAG_RW, \
		&n ## _ret, 0, #n "() return value");

#define REG_RETSYSCTL(n) \
	sysctl_register_oid(&sysctl__security_mac_retcontrol_ ## n ## _ret);

#define INC(n)  (n ## _c)++;
#define RET(n)  return(n ## _ret);

SYSCTL_DECL(_security_mac);

SYSCTL_NODE(_security_mac, OID_AUTO, count, CTLFLAG_RW, 0,
    "Execution counters");
SYSCTL_NODE(_security_mac, OID_AUTO, retcontrol, CTLFLAG_RW, 0,
    "Values to return to the MAC Framework");

static int      count_slot;
SYSCTL_INT(_security_mac_count, OID_AUTO, count, CTLFLAG_RD,
    &count_slot, 0, "Slot allocated by framework");

#include "count_decls.h"

static void
mac_count_destroy(struct mac_policy_conf *conf)
{
}

static void
mac_count_init(struct mac_policy_conf *conf)
{
}

static void
mac_count_init_bsd(struct mac_policy_conf *conf)
{

	sysctl_register_oid(&sysctl__security_mac_count);
	sysctl_register_oid(&sysctl__security_mac_retcontrol);

#include "count_reg.h"
	
}

#include "count_funcs.h"

#include "count_policy_ops.h"

static const char *labelnamespaces[COUNT_NAMESPACE_COUNT] = 
	{ COUNT_LABEL_NAMESPACE };

struct mac_policy_conf count_policy_conf = {
	.mpc_name		= COUNT_LABEL_NAMESPACE,/* policy name */
	.mpc_fullname		= POLICY_DESC,		/* full name */
	.mpc_labelnames		= labelnamespaces,	/* label namespaces */
	.mpc_labelname_count	= COUNT_NAMESPACE_COUNT,/* namespace count */
	.mpc_ops		= &mac_count_ops,	/* policy operations */
	.mpc_loadtime_flags	= 0,			/* loadtime flags*/
	.mpc_field_off		= &count_slot,		/* security field */
	.mpc_runtime_flags	= 0			/* runtime flags */
};
 
static kern_return_t 
kmod_start(kmod_info_t *ki, void *xd) 
{
    
    return mac_policy_register(&count_policy_conf);
}

static kern_return_t 
kmod_stop(kmod_info_t *ki, void *data) 
{
    
    return mac_policy_unregister(&count_policy_conf);
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(security.count, POLICY_VER , _start, _stop);
kmod_start_func_t *_realmain = kmod_start;
kmod_stop_func_t *_antimain = kmod_stop;
int _kext_apple_cc = __APPLE_CC__;
