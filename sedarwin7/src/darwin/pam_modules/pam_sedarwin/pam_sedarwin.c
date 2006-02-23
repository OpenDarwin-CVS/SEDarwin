/*-
 * Copyright (c) 2005 SPARTA, Inc.
 * All rights reserved.
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
#ifdef __FreeBSD__
__FBSDID("$FreeBSD$");
#endif

#define _BSD_SOURCE
#include <sys/types.h>
#include <sys/mac.h> 
#include <selinux/get_context_list.h>
#include <sedarwin/sebsd.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#if defined(__FreeBSD__)
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>
#elif defined(__APPLE__)
#include <pam_appl.h>
#include <pam_modules.h>
#include <pam_mod_misc.h>
#endif

static char *textlabel;

static int
choose_context(pam_handle_t *pamh, int ncontexts, char *contexts[], int *which)
{
	size_t size;
	char *cp, *prompt, *resp;
	int i, retval;

#define PROMPT_HEAD	"Available security contexts:\n"
#define PROMPT_TAIL	"Enter context: "

	/* Build a prompt and ask PAM for a user response. */
	size = sizeof(PROMPT_HEAD) + sizeof(PROMPT_TAIL) - 1;
	for (i = 0; i < ncontexts; i++)
		size += strlen((char *)contexts[i]) + 2;
	if ((prompt = malloc(size)) == NULL)
		return (PAM_SYSTEM_ERR);
	strlcpy(prompt, PROMPT_HEAD, size);
	for (i = 0; i < ncontexts; i++) {
		strlcat(prompt, "\t", size);
		strlcat(prompt, (char *)contexts[i], size);
		strlcat(prompt, "\n", size);
	}
	strlcat(prompt, PROMPT_TAIL, size);
	retval = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, prompt, &resp);
	free(prompt);
	if (retval != PAM_SUCCESS) {
		syslog(LOG_ERR, "%s(): pam_prompt returns %d", __func__,
		    retval);
		return (retval);
	}

	/* Strip leading and trailing whitespace from response. */
	while (isspace((unsigned char)*resp))
		resp++;
	for (cp = resp; *cp != '\0' && !isspace((unsigned char)*cp); cp++)
		continue;
	*cp = '\0';

	/* Validate response. */
	for (i = 0; i < ncontexts; i++) {
		if (strcmp(resp, (char *)contexts[i]) == 0)
			break;
	}
	if (i == ncontexts)
		return (PAM_SESSION_ERR);	/* invalid input */

	*which = i;
	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags __unused, int argc __unused,
    const char **argv __unused)
{
	security_context_t *contexts;
	const char *user;
	int ncontexts, retval, which;

	/* XXX - use SELINUX_DEFAULTUSER if not enabled? */
	if (!sebsd_enabled()) {
		syslog(LOG_ERR, "%s(): SEDarwin not enabled", __func__);
		return (PAM_SUCCESS);
	}

	if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "%s(): unable to get user %s",
		    __func__, user);
		return (retval);
	}

	/*
	 * Get an ordered list of possible contexts for the user.
	 * If there is more than one we will prompt the user.
	 */
	ncontexts = get_ordered_context_list(user, NULL, &contexts);
	if (ncontexts <= 0) {
		syslog(LOG_ERR, "%s(): unable to get contexts for user %s",
		    __func__, user);
		return (PAM_SYSTEM_ERR);
	}
	if (ncontexts == 1) {
		which = 0;	/* no choice... */
	} else {
		retval = choose_context(pamh, ncontexts, contexts, &which);
		if (retval != PAM_SUCCESS) {
			freeconary(contexts);
			return (retval);
		}
	}

	retval = asprintf(&textlabel, "sebsd/%s", (char *)contexts[which]);
	freeconary(contexts);
	if (retval == -1) {
		syslog(LOG_ERR, "%s(): %m", __func__);
		return (PAM_SYSTEM_ERR);
	}

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char **argv __unused)
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	mac_t label;
	int retval;

	if (!sebsd_enabled()) {
		syslog(LOG_ERR, "%s(): SEDarwin not enabled", __func__);
		return (PAM_SUCCESS);
	}

	/*
	 * If the user didn't specify a label to use in the authentication
	 * function get the default label.
	 */
	if (textlabel == NULL) {
		security_context_t con;
		const char *user;

		if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
			syslog(LOG_ERR, "%s(): unable to get user %s",
			    __func__, user);
			return (retval);
		}

		/*
		 * Get user's default context.  If we had a way to
		 * prompt the user for a specific context we could
		 * look that up (but we don't).
		 */
		if (get_default_context(user, NULL, &con) != 0) {
			syslog(LOG_ERR,
			    "%s(): unable to get context for user %s",
			    __func__, user);
			return (PAM_SYSTEM_ERR);
		}

		retval = asprintf(&textlabel, "sebsd/%s", (char *)con);
		freecon(con);
		if (retval == -1) {
			syslog(LOG_ERR, "%s(): %m", __func__);
			return (PAM_SYSTEM_ERR);
		}
	}

	if (mac_from_text(&label, textlabel) != 0) {
		syslog(LOG_ERR, "%s(): mac_from_text(..., \"%s\"): %m",
		    __func__, textlabel);
		free(textlabel);
		textlabel = NULL;
		return (PAM_SYSTEM_ERR);
	}

	if (mac_set_proc(label) != 0) {
		syslog(LOG_ERR, "%s(): mac_set_proc(..., \"%s\"): %m",
		    __func__, textlabel);
		free(textlabel);
		textlabel = NULL;
		mac_free(label);
		return (PAM_SYSTEM_ERR);
	}
	free(textlabel);
	textlabel = NULL;
	mac_free(label);

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{

	return (PAM_SUCCESS);
}

#ifdef __FreeBSD__
PAM_MODULE_ENTRY("pam_sedarwin");
#endif
