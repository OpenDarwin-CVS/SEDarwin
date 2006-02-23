
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

#include <sys/types.h>  
#include <sys/vnode.h>  
#include <sys/queue.h>  
#include <sys/mac_policy.h>
#include <security/mac_internal.h>
#include <bsd/bsm/audit.h>
#include <bsd/bsm/audit_kernel.h>
#include <bsd/sys/malloc.h>
#include <vm/vm_kern.h>
#include <kern/kalloc.h>

#ifdef AUDIT

int
mac_check_system_audit(struct ucred *cred, void *record, int length)
{
	int error;

	MAC_CHECK(check_system_audit, cred, record, length);

	return (error);
}

int
mac_check_system_auditon(struct ucred *cred, int cmd)
{
	int error;

	MAC_CHECK(check_system_auditon, cred, cmd);

	return (error);
}

int
mac_check_system_auditctl(struct ucred *cred, struct vnode *vp)
{
	int error;
	struct label *vl = vp ? vp->v_label : NULL;

	MAC_CHECK(check_system_auditctl, cred, vp, vl);

	return (error);
}

int
mac_check_proc_getauid(struct ucred *cred)
{
	int error;

	MAC_CHECK(check_proc_getauid, cred);

	return (error);
}

int
mac_check_proc_setauid(struct ucred *cred, uid_t auid)
{
	int error;

	MAC_CHECK(check_proc_setauid, cred, auid);

	return (error);
}

int 
mac_check_proc_getaudit(struct ucred *cred) 
{
	int error;

	MAC_CHECK(check_proc_getaudit, cred);

	return (error);
}

int
mac_check_proc_setaudit(struct ucred *cred, struct auditinfo *ai)
{
	int error;

	MAC_CHECK(check_proc_setaudit, cred, ai);

	return (error);
}

#if 0
/*
 * This is the framework entry point for MAC policies to use to add
 * arbitrary data to the current audit record.
 * (Currently not supported, as no existing audit viewers would 
 * display this format)
 * 
 * XXX: it currently truncates data that are too long.  If we enable this
 * entry point in the future, it should return EINVAL instead.
 */
int
mac_audit_data(int len, u_char *data, struct mac_policy_conf *caller)
{
	char *sanitized;
	int error, allocd;

	if (len <= 0)
		return (EINVAL);

	allocd = (len > MAC_AUDIT_DATA_LIMIT ? MAC_AUDIT_DATA_LIMIT : len);

	sanitized = kalloc(allocd);
	if (sanitized == NULL)
		return (ENOMEM);

	bcopy(data, sanitized, allocd);
	audit_mac_data(MAC_AUDIT_DATA_TYPE, allocd, sanitized);

	return (0);
}
#endif

/*
 * This is the entry point a MAC policy will call to add NULL-
 * terminated ASCII text to the current audit record.
 */
int
mac_audit_text(char *text, struct mac_policy_conf *caller)
{
	char *sanitized;
	int i, error, allocd, plen, len;

	len = strlen(text);
	plen = 2 + strlen(caller->mpc_name);
	if (plen + len >= MAC_AUDIT_DATA_LIMIT)
		return (EINVAL);

	/*
	 * Make sure the text is only composed of only ASCII printable
	 * characters.
	 */
	for (i=0; i < len; i++)
		if (text[i] < (char) 32 || text[i] > (char) 126)
			return (EINVAL);

	allocd = len + plen + 1;
 	sanitized = kalloc(allocd);
	if (sanitized == NULL)
		return (ENOMEM);

	strcpy(sanitized, caller->mpc_name);
	strcat(sanitized, ": ");
	strcat(sanitized, text);

	audit_mac_data(MAC_AUDIT_TEXT_TYPE, allocd, sanitized);

	return (0);
}

int
mac_audit_preselect(struct ucred *cred, unsigned short syscode, void *args)
{
	struct mac_policy_conf *mpc;
	int ret, error, entrycount;

	ret = MAC_AUDIT_DEFAULT;
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {
		if (mpc->mpc_ops->mpo_audit_preselect != NULL) {
			error = mpc->mpc_ops->mpo_audit_preselect(cred, syscode,
				args);
			ret = (ret > error ? ret : error);
		}
	}
	if ((entrycount = mac_policy_list_conditional_busy()) != 0) {
		LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {
			if (mpc->mpc_ops->mpo_audit_preselect != NULL) {
				error = mpc->mpc_ops->mpo_audit_preselect(cred, syscode,
					args);
				ret = (ret > error ? ret : error);
			}
		}
		mac_policy_list_unbusy();
	}

	return (ret);
}

int
mac_audit_postselect(struct ucred *cred, unsigned short syscode,
    void *args, int error, int retval, int mac_forced)
{
	struct mac_policy_conf *mpc;
	int ret, mac_error, entrycount;

	/*
	 * If the audit was forced by a MAC policy by mac_audit_preselect(),
	 * echo that.
	 */
	if (mac_forced)
		return (MAC_AUDIT_YES);

	ret = MAC_AUDIT_DEFAULT;
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {
		if (mpc->mpc_ops->mpo_audit_postselect != NULL) {
			mac_error = mpc->mpc_ops->mpo_audit_postselect(cred, syscode,
				args, error, retval);
			ret = (ret > mac_error ? ret : mac_error);
		}
	}
	if ((entrycount = mac_policy_list_conditional_busy()) != 0) {
		LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {
			if (mpc->mpc_ops->mpo_audit_postselect != NULL) {
				mac_error = mpc->mpc_ops->mpo_audit_postselect(cred, syscode,
					args, error, retval);
				ret = (ret > mac_error ? ret : mac_error);
			}
		}
		mac_policy_list_unbusy();
	}

	return (ret);
}

#else

/*
 * Function stubs for when AUDIT isn't defined.
 */

int
mac_check_system_audit(struct ucred *cred, void *record, int length)
{

	return (0);
}

int
mac_check_system_auditon(struct ucred *cred, int cmd)
{

	return (0);
}

int
mac_check_system_auditctl(struct ucred *cred, struct vnode *vp)
{

	return (0);
}

int
mac_check_proc_getauid(struct ucred *cred)
{

	return (0);
}

int
mac_check_proc_setauid(struct ucred *cred, uid_t auid)
{

	return (0);
}

int
mac_check_proc_getaudit(struct ucred *cred)
{

	return (0);
}

int
mac_check_proc_setaudit(struct ucred *cred, struct auditinfo *ai)
{

	return (0);
}

int
mac_audit_preselect(struct ucred *cred, unsigned short syscode,
    void *args)
{

	return (MAC_AUDIT_DEFAULT);
}

int
mac_audit_postselect(struct ucred *cred, unsigned short syscode,
    void *args, int error, int retval, int mac_forced)
{

	return (MAC_AUDIT_DEFAULT);
}

int
mac_audit(int len, u_char *data)
{

	return (0);
}
#endif  /*  AUDIT */
