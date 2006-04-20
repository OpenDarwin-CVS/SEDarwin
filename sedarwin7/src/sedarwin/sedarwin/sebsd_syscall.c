/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * Copyright (c) 2005-2006 SPARTA, Inc.
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

#include <sedarwin/sebsd.h>
#include <sedarwin/sebsd_syscalls.h>
#include <sedarwin/avc/avc.h>
#include <sedarwin/ss/services.h>

#define MAX_UC 510

static int
sys_load_policy(struct proc *td, void *data, size_t len)
{
	void *kdata;
	int rc;
	
	rc = proc_has_security(td, SECURITY__LOAD_POLICY);
	if (rc)
		return (rc);

	kdata = sebsd_malloc(len, M_SEBSD, M_WAITOK);
	rc = copyin(data, kdata, len);
	if (rc)
		return (rc);

	rc = security_load_policy(kdata, len);
	sebsd_free(kdata, M_SEBSD);

	return (rc);
}

static int
sys_load_migscs(struct proc *td, void *data, size_t len)
{
	void *kdata;
	int rc;
	
	rc = proc_has_security(td, SECURITY__LOAD_POLICY);
	if (rc)
		return (rc);

	kdata = sebsd_malloc(len, M_SEBSD, M_WAITOK);
	rc = copyin(data, kdata, len);
	if (rc)
		return (rc);

	rc = sebsd_load_migscs(kdata, len);
	sebsd_free(kdata, M_SEBSD);

	return (rc);
}

static int
sebsd_get_bools(struct proc *td, struct sebsd_get_bools *gb)
{
	char *out = NULL;
	int error;

	if (gb->out)
		out = sebsd_malloc(gb->len, M_SEBSD, M_WAITOK);
	error = security_get_bool_string(&gb->len, out);
	if (out && error == 0)
		error = copyout(out, gb->out, gb->len);
	if (out)
		sebsd_free(out, M_SEBSD);
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

		error = proc_has_security(td, SECURITY__SETBOOL);
		if (error)
			return (error);

		if (copyin(args, &p, sizeof(struct lp_args)))
			return (EFAULT);
		str = sebsd_malloc(p.len, M_SEBSD, M_WAITOK);
		if (!str)
			return (ENOMEM);
		if (copyin(p.data, str, p.len)) {
			sebsd_free(str, M_SEBSD);
			return (EFAULT);
		}

		str[p.len-1] = 0;
		error = security_set_bool(str+1, str[0]-'0');
		sebsd_free(str, M_SEBSD);
		break;
	}

	case SEBSDCALL_COMMIT_BOOLS:
		error = proc_has_security(td, SECURITY__SETBOOL);
		if (error)
			return (error);
		return (security_commit_pending_bools());

	default:
		error = EINVAL;
		break;
	}

	return (error);
}
