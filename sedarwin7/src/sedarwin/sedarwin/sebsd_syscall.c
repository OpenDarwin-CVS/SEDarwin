/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * Copyright (c) 2005, 2006 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by NAI Labs, the
 * Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS").
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>

#include <sedarwin/linux-compat.h>
#include <sedarwin/sebsd.h>
#include <sedarwin/sebsd_syscalls.h>
#include <sedarwin/avc/avc.h>
#include <sedarwin/ss/services.h>

#define MAX_UC 510

struct lp_args {
	void	*data;
	size_t	 len;
};

static int
sys_load_policy(struct proc *td, void *data, size_t len)
{
	void *kdata;
	int rc;
	
	rc = proc_has_security(td, SECURITY__LOAD_POLICY);
	if (rc)
		return (rc);

	kdata = malloc(len, M_SEBSD, M_WAITOK);
	rc = copyin(data, kdata, len);
	if (rc)
		return (rc);

	rc = security_load_policy(kdata, len);
	free(kdata, M_SEBSD);

	return (rc);
}

static int
sys_load_migscs(struct proc *td, void *data, size_t len)
{
	void *kdata;
	int rc;
	
	rc = cred_has_security(td->p_ucred, SECURITY__LOAD_POLICY);
	if (rc)
		return (rc);

	kdata = malloc(len, M_SEBSD, M_WAITOK);
	rc = copyin(data, kdata, len);
	if (rc)
		return (rc);

	rc = sebsd_load_migscs(kdata, len);
	free(kdata, M_SEBSD);

	return (rc);
}

/*
 * Lists the SIDs currently available for transition to by a given
 * "context\0username\0"
 *
 * or, lists the SIDs that a given context can relabel files to. (username is ignored)
 */
static int
sys_get_sids(int function, char *context, char *username, char *out, int *outlen)
{
	u_int32_t n, nsids, scontext_len;
	u32 *sids, sid;
	char * scontext;
	int error;
	int olen = 1;
	int ubufsz;

	if (copyin(outlen, &ubufsz, sizeof(int))) {
		error = EFAULT;
		goto out;
	}

	/*
	 * XXX We need POLICY_RDLOCK here, but it's not exported!
	 */
	error = security_context_to_sid(context, strlen (context), &sid);
	if (error)
		goto out;
	switch (function) {
	case SEBSDCALL_GETUSERSIDS:
		error = security_get_user_sids(sid, username, &sids, &nsids);
		break;

	case SEBSDCALL_GETFILESIDS:
		error = security_get_file_sids(sid, SECCLASS_FILE, &sids,
		    &nsids);
		break;

	default:
		error = ENOSYS;
		break;
	}
	if (error)
		goto out;
	for (n = 0; n < nsids; n++) {
		error = security_sid_to_context(sids[n], &scontext,
		    &scontext_len);
		if (error)
			goto out2;
		if (out && olen + scontext_len <= ubufsz) {
			error = copyout(scontext, out, scontext_len);
			out += scontext_len;
		} else if (out)
			error = ENOMEM;
		olen += scontext_len;
		security_free_context(scontext);
		if (error)
			goto out2;
	}
	error = copyout(&olen, outlen, sizeof(int));
out2:
	sebsd_free(sids);
out:
	return (error);
}

static int
sys_change_sid(char *domains, char *sources, char *sclasss, char *out,
    int *outlen)
{
	u32       domain, source;
	struct class_datum *cld;
	char *  outc;
	int error;
	int ubufsz, outclen;

	if (copyin(outlen, &ubufsz, sizeof(int)))
		return (EFAULT);

	/*
	 * XXX We need POLICY_RDLOCK here, but it's not exported!
	 */
	error = security_context_to_sid(sources, strlen (sources), &source);
	if (error)
		return (error);

	error = security_context_to_sid(domains, strlen (domains), &domain);
	if (error)
		return (error);

	cld = hashtab_search(policydb.p_classes.table, sclasss);
	if (cld == NULL)
		return (EINVAL);

	error = security_change_sid(domain, source, cld->value, &source);
	if (error)
		return (error);
	error = security_sid_to_context(source, &outc, &outclen);
	if (error)
		return (error);
	if (out) {
		if (outclen > ubufsz) {
			error = ENOMEM;
			goto out;
		}
		error = copyout(outc, out, outclen);
		if (error)
			goto out;
	}
	error = copyout(&outclen, outlen, sizeof(int));

out:
	security_free_context (outc);
	return (error);
}

struct getsid_args {
	char *ctx;
	char *usr;
	char *out;
	int  *outlen;
};

struct changesid_args {
	char *domain;
	char *source;
	char *sclass;
	char *out;
	int  *outlen;
};

static int
sebsd_get_bools(struct proc *td, struct sebsd_get_bools *gb)
{
	char *out = NULL;
	int error;

	if (gb->out)
		out = malloc(gb->len, M_SEBSD, M_WAITOK);
	error = security_get_bool_string(&gb->len, out);
	if (out && error == 0)
		error = copyout(out, gb->out, gb->len);
	if (out)
		free(out, M_SEBSD);
	return (error);
}

int
sebsd_syscall(struct proc *td, int call, void *args, int *retv)
{
	struct lp_args p;
	int error = EINVAL;

	switch(call) {
	case SEBSDCALL_LOAD_POLICY:
		if (copyin(args, &p, sizeof(struct lp_args)))
			return (EFAULT);
		error = sys_load_policy(td, p.data, p.len);
		break;

	case SEBSDCALL_LOAD_MIGSCS:
		if (copyin(args, &p, sizeof(struct lp_args)))
			return (EFAULT);
		error = sys_load_migscs(td, p.data, p.len);
		break;

	case SEBSDCALL_GETUSERSIDS:
	case SEBSDCALL_GETFILESIDS:
	{
		struct getsid_args uap;
		size_t dummy;
		char *ctx, *usr;

		error = copyin(args, &uap, sizeof(struct getsid_args));
		if (error)
			return (error);
		ctx = sebsd_malloc(MAX_UC, M_WAITOK);
		error = copyinstr(uap.ctx, ctx, MAX_UC, &dummy);
		if (error) {
			sebsd_free(ctx);
			return (error);
		}
		usr = sebsd_malloc(MAX_UC, M_WAITOK);
		error = copyinstr(uap.usr, usr, MAX_UC, &dummy);
		if (error) {
			sebsd_free(ctx);
			sebsd_free(usr);
			return (error);
		}
		ctx[MAX_UC-1] = 0;
		usr[MAX_UC-1] = 0;
		error = sys_get_sids(call, ctx, usr, uap.out, uap.outlen);
		sebsd_free(ctx);
		sebsd_free(usr);
		break;
	}

	case SEBSDCALL_CHANGE_SID:
	{
		struct changesid_args uap;
		size_t dummy;
		char *doms, *srcs, *scs;

		error = copyin(args, &uap, sizeof(struct changesid_args));
		if (error)
			return (error);
		doms = sebsd_malloc(MAX_UC, M_WAITOK);
		error = copyinstr(uap.domain, doms, MAX_UC, &dummy);
		if (error) {
			sebsd_free(doms);
			return (error);
		}
		srcs = sebsd_malloc(MAX_UC, M_WAITOK);
		error = copyinstr(uap.source, srcs, MAX_UC, &dummy);
		if (error) {
			sebsd_free(doms);
			sebsd_free(srcs);
			return (error);
		}
		scs = sebsd_malloc(MAX_UC, M_WAITOK);
		error = copyinstr(uap.sclass, scs, MAX_UC, &dummy);
		if (error) {
			sebsd_free(doms);
			sebsd_free(srcs);
			sebsd_free(scs);
			return (error);
		}
		error = sys_change_sid(doms, srcs, scs, uap.out, uap.outlen);
		sebsd_free(doms);
		sebsd_free(srcs);
		sebsd_free(scs);
		return (error);
	}

	case SEBSDCALL_GET_BOOLS:
	{
		struct sebsd_get_bools gb;

		if (copyin(args, &gb, sizeof(struct sebsd_get_bools)))
			return (EFAULT);
		error = sebsd_get_bools(td, &gb);
		if (copyout(&gb, args, sizeof(struct sebsd_get_bools)))
			return (EFAULT);
		break;
	}

	case SEBSDCALL_GET_BOOL:
	{
		size_t dummy;
		char str[128];
		int active, pending;

		error = copyinstr(args, str, sizeof(str), &dummy);
		if (error)
			return (error);
		security_get_bool(str, &active, &pending);
		*retv = active | (pending << 1);
		return (0);
	}

	case SEBSDCALL_SET_BOOL:
	{
		char *str;

		error = cred_has_security(td->p_ucred, SECURITY__SETBOOL);
		if (error)
			return (error);

		if (copyin(args, &p, sizeof(struct lp_args)))
			return (EFAULT);
		str = malloc(p.len, M_SEBSD, M_WAITOK);
		if (!str)
			return (ENOMEM);
		if (copyin(p.data, str, p.len)) {
			free(str, M_SEBSD);
			return (EFAULT);
		}

		str[p.len-1] = 0;
		error = security_set_bool(str+1, str[0]-'0');
		free(str, M_SEBSD);
		break;
	}

	case SEBSDCALL_COMMIT_BOOLS:
		error = cred_has_security(td->p_ucred, SECURITY__SETBOOL);
		if (error)
			return (error);
		return (security_commit_pending_bools());

	default:
		error = EINVAL;
		break;
	}

	return (error);
}
