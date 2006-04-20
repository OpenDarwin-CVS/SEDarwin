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
#include <sys/sysctl.h>
#include <sys/malloc.h>

#include <sedarwin/linux-compat.h>
#include <sedarwin/sebsd.h>
#include <sedarwin/ss/global.h>
#include <sedarwin/ss/services.h>
#include <sedarwin/ss/security.h>
#include <sedarwin/ss/sidtab.h>

#include <sedarwin/sebsd_syscalls.h>
#include <sedarwin/avc/avc.h>

extern unsigned int policydb_loaded_version;

#if 0
/*
 * Sysctl handler for security.mac.sebsd.sids
 * Lists the SIDs currently active in the security server
 */
static int
sysctl_list_sids(SYSCTL_HANDLER_ARGS)
{
	const int linesize = 128;	/* conservative */
	int i, count, error, len;
	u_int32_t scontext_len;
	struct sidtab_node *cur;
	char *buffer;
	char *scontext;

	count = sidtab.nel;
	MALLOC(buffer, char *, linesize, M_TEMP, M_WAITOK);
	len = snprintf(buffer, linesize, "\n    SID   Context\n");
	error = SYSCTL_OUT(req, buffer, len);
	if (error)
		goto out;
	/*
	 * XXX What's keeping the SID table from changing?  POLICY_RDLOCK
	 * would not be able to do it as of now, so what we really need is
	 * SIDTAB_LOCK.
	 */
	for (i = 0; i < SIDTAB_SIZE; i++) {
		cur = sidtab.htable[i];
		while (cur != NULL && count > 0) {
			error = security_sid_to_context(cur->sid, &scontext,
			    &scontext_len);
			len = snprintf(buffer, linesize, "%7d   %s\n",
			    cur->sid, scontext);
			security_free_context(scontext);
			error = SYSCTL_OUT(req, buffer, len);
			if (error)
				goto out;
			cur = cur->next;
			count--;
		}
	}
	error = SYSCTL_OUT(req, "", 1);
out:
	FREE(buffer, M_TEMP);
	return (error);
}
#endif

/*
 * Sysctl handler for security.mac.sebsd.auditing.  Get or set whether the
 * avc will audit failures.
 */
static int
sysctl_sebsd_auditing SYSCTL_HANDLER_ARGS
{
	int error, auditing;

	/* TBD: XXX Always allow the users to find out? */
	auditing = selinux_auditing;
	error = SYSCTL_OUT(req, &auditing, sizeof(auditing));
	if (error)
		return (error);

	if (req->newptr != NULL) {
		error = SYSCTL_IN(req, &auditing, sizeof(auditing));
		if (error)
			return (error);

		/*
		 * Treat ability to set audit status as equivilent to
		 * changing enforcement status.
		 */
		error = proc_has_system(current_proc(), SECURITY__SETENFORCE);
		if (error)
			return (error);

		selinux_auditing = auditing;
	}

	return (0);
}

/*
 * Sysctl handler for security.mac.sebsd.enforcing.  Get and/or set whether
 * the avc is in enforcement mode.
 */
static int
sysctl_sebsd_enforcing SYSCTL_HANDLER_ARGS
{
	int error, enforcing;

	/* TBD: XXX Always allow the users to find out? */
	enforcing = selinux_enforcing;
	error = SYSCTL_OUT(req, &enforcing, sizeof(enforcing));
	if (error)
		return (error);

	if (req->newptr != NULL) {
		error = SYSCTL_IN(req, &enforcing, sizeof(enforcing));
		if (error)
			return (error);

		error = proc_has_system(current_proc(), SECURITY__SETENFORCE);
		if (error)
			return error;

		selinux_enforcing = enforcing;
	}

	return (0);
}

#if 0
/*
 * Sysctl handler for security.mac.sebsd.user_sids.  Lists the SIDs currently
 * available for transition to by a given "context\0username\0".
 */
static int
sysctl_user_sids(SYSCTL_HANDLER_ARGS)
{
	u_int32_t n, nsids, scontext_len;
	u32 *sids, sid;
	char *scontext;
	char *context, *username;
	int error, len;

	if (req->newlen == 0)
		return (EINVAL);
	if (req->newlen > 512)	/* arbitrary */
		return (ENAMETOOLONG);
	context = sebsd_malloc(req->newlen, M_SEBSD, M_WAITOK);
	error = SYSCTL_IN(req, context, req->newlen);
	if (error)
		goto out;
	if (context[req->newlen - 1] != '\0') {
		error = EINVAL;
		goto out;
	}
	len = strlen(context);
	if (len + 1 >= req->newlen) {
		error = EINVAL;
		goto out;
	}
	username = context + len + 1;
	/*
	 * XXX We need POLICY_RDLOCK here, but it's not exported!
	 */
	error = security_context_to_sid(context, len + 1, &sid);
	if (error)
		goto out;
	error = security_get_user_sids(sid, username, &sids, &nsids);
	if (error)
		goto out;
	for (n = 0; n < nsids; n++) {
		error = security_sid_to_context(sids[n], &scontext,
		    &scontext_len);
		if (error)
			goto out2;
		error = SYSCTL_OUT(req, scontext, scontext_len);
		security_free_context(scontext);
		if (error)
			goto out2;
	}
	error = SYSCTL_OUT(req, "", 1);
out2:
	sebsd_free(sids, M_SEBSD);
out:
	sebsd_free(context, M_SEBSD);
	return (error);
}

/*
 * Sysctl handler for security.mac.sebsd.change_sid
 * Report the SID to relabel to given input "scontext\0tcontext\0",tclass
 */
static int
sysctl_change_sid(SYSCTL_HANDLER_ARGS)
{
	u_int32_t newcontext_len;
	u32 sid, tsid, newsid;
	u16 tclass;
	char *scontext, *tcontext, *newcontext;
	int error;

	if (req->newlen < 4 + sizeof(tclass))
		return (EINVAL);
	if (req->newlen > 512)	/* arbitrary */
		return (ENAMETOOLONG);
	scontext = sebsd_malloc(req->newlen, M_SEBSD, M_WAITOK);
	error = SYSCTL_IN(req, scontext, req->newlen);
	if (error)
		goto out;
	if (scontext[req->newlen - (1 + sizeof(tclass))] != '\0') {
		error = EINVAL;
		goto out;
	}
	tcontext = &scontext[strlen(scontext) + 1];
	if (tcontext >= &scontext[req->newlen - (1 + sizeof(tclass))]) {
		error = EINVAL;
		goto out;
	}
	bcopy(&tcontext[strlen(tcontext) + 1], &tclass, sizeof(tclass));
	/*
	 * XXX We need POLICY_RDLOCK here, but it's not exported!
	 */
	error = security_context_to_sid(scontext, strlen(scontext) + 1, &sid);
	if (error)
		goto out;
	error = security_context_to_sid(tcontext, strlen(tcontext) + 1, &tsid);
	if (error)
		goto out;
	error = security_change_sid(sid, tsid, tclass, &newsid);
	if (error)
		goto out;
	error = security_sid_to_context(newsid, &newcontext, &newcontext_len);
	if (error)
		goto out;
	error = SYSCTL_OUT(req, newcontext, newcontext_len);
	security_free_context(newcontext);
out:
	sebsd_free(scontext, M_SEBSD);
	return (error);
}

/*
 * Sysctl handler for security.mac.sebsd.compute_av.  Compute access vectors
 * given input "scontext\0tcontext\0", tclass, av.
 */
static int
sysctl_compute_av(SYSCTL_HANDLER_ARGS)
{
	u32 sid, tsid;
	u16 tclass;
	u32 av;
	struct av_decision avd;
	char *scontext, *tcontext;
	int error;

	if (req->newlen < 4 + sizeof(tclass) + sizeof(av))
		return (EINVAL);
	if (req->newlen > 512)	/* arbitrary */
		return (ENAMETOOLONG);
	scontext = sebsd_malloc(req->newlen, M_SEBSD, M_WAITOK);
	error = SYSCTL_IN(req, scontext, req->newlen);
	if (error)
		goto out;
	if (scontext[req->newlen - (1 + sizeof(tclass) + sizeof(av))] !=
	    '\0') {
		error = EINVAL;
		goto out;
	}
	tcontext = &scontext[strlen(scontext) + 1];
	if (tcontext >= &scontext[req->newlen - (1 + sizeof(tclass) +
	    sizeof(av))]) {
		error = EINVAL;
		goto out;
	}
	bcopy(&tcontext[strlen(tcontext) + 1], &tclass, sizeof(tclass));
	bcopy(&tcontext[strlen(tcontext) + 1 + sizeof(tclass)], &av,
	    sizeof(av));
	/*
	 * XXX We need POLICY_RDLOCK here, but it's not exported!
	 */
	error = security_context_to_sid(scontext, strlen(scontext) + 1, &sid);
	if (error)
		goto out;
	error = security_context_to_sid(tcontext, strlen(tcontext) + 1, &tsid);
	if (error)
		goto out;
	error = security_compute_av(sid, tsid, tclass, av, &avd);
	if (error)
		goto out;

	error = SYSCTL_OUT(req, &avd, sizeof(avd));
out:
	sebsd_free(scontext, M_SEBSD);
	return (error);
}
#endif

SYSCTL_DECL(_security_mac);
SYSCTL_NODE(_security_mac, OID_AUTO, sebsd, CTLFLAG_RW, 0,
    "Security Enhanced BSD policy controls");

SYSCTL_INT(_security_mac_sebsd, OID_AUTO, verbose, CTLFLAG_RW,
    &sebsd_verbose, 0, " SEBSD Verbose Debug Stuff");
#if 0
SYSCTL_PROC(_security_mac_sebsd, OID_AUTO, sids, CTLTYPE_STRING|CTLFLAG_RD,
    NULL, 0, sysctl_list_sids, "A", "SEBSD SIDs");
SYSCTL_PROC(_security_mac_sebsd, OID_AUTO, user_sids, CTLTYPE_STRING |
    CTLFLAG_RW | CTLFLAG_ANYBODY, NULL, 0, sysctl_user_sids, "A",
    "SEBSD transitionable user SIDs");
SYSCTL_PROC(_security_mac_sebsd, OID_AUTO, change_sid, CTLTYPE_STRING |
    CTLFLAG_RW | CTLFLAG_ANYBODY, NULL, 0, sysctl_change_sid, "A",
    "SEBSD (tty) SID relabel to perform along with transition");
SYSCTL_PROC(_security_mac_sebsd, OID_AUTO, compute_av, CTLTYPE_STRING |
    CTLFLAG_RW | CTLFLAG_ANYBODY, NULL, 0, sysctl_compute_av, "A",
    "SEBSD access vector decision query");
#endif
SYSCTL_PROC(_security_mac_sebsd, OID_AUTO, auditing, CTLTYPE_INT |
    CTLFLAG_RW, NULL, 0, sysctl_sebsd_auditing, "I", "SEBSD avc auditing");
SYSCTL_PROC(_security_mac_sebsd, OID_AUTO, enforcing, CTLTYPE_INT |
    CTLFLAG_RW, NULL, 0, sysctl_sebsd_enforcing, "I",
    "SEBSD avc enforcement");
SYSCTL_UINT(_security_mac_sebsd, OID_AUTO, policyvers, CTLFLAG_RD,
    &policydb_loaded_version, 0, " SEBSD loaded policy version");

void
sebsd_register_sysctls()
{
	sysctl_register_oid(&sysctl__security_mac_sebsd);
	sysctl_register_oid(&sysctl__security_mac_sebsd_verbose);
	sysctl_register_oid(&sysctl__security_mac_sebsd_auditing);
	sysctl_register_oid(&sysctl__security_mac_sebsd_enforcing);
	sysctl_register_oid(&sysctl__security_mac_sebsd_policyvers);
}
