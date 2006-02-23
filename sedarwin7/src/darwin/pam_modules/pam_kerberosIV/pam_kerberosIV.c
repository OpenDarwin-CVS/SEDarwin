/*-
 * Copyright 1998 Juniper Networks, Inc.
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
 *
 *	$FreeBSD: src/lib/libpam/modules/pam_kerberosIV/pam_kerberosIV.c,v 1.7 2001/08/10 19:07:45 markm Exp $
 */

#include <sys/param.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pam_mod_misc.h"

#define PASSWORD_PROMPT	"Password:"

extern int klogin(struct passwd *, char *, char *, char *);

/* Globals used by klogin.c */
int	notickets = 1;
int	noticketsdontcomplain = 1;
char	*krbtkfile_env;

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct options options;
	int retval;
	const char *user;
	char *principal;
	char *instance;
	const char *password;
	char localhost[MAXHOSTNAMELEN + 1];
	struct passwd *pwd;

	pam_std_option(&options, NULL, argc, argv);

	PAM_LOG("Options processed");

	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS)
		PAM_RETURN(retval);

	PAM_LOG("Got user: %s", user);

	retval = pam_get_pass(pamh, &password, PASSWORD_PROMPT, &options);
	if (retval != PAM_SUCCESS)
		PAM_RETURN(retval);

	PAM_LOG("Got password");

	if (gethostname(localhost, sizeof localhost - 1) == -1)
		PAM_RETURN(PAM_SYSTEM_ERR);

	PAM_LOG("Got localhost: %s", localhost);

	principal = strdup(user);
	if (principal == NULL)
		PAM_RETURN(PAM_BUF_ERR);

	instance = strchr(principal, '.');
	if (instance != NULL)
		*instance++ = '\0';
	else
		instance = "";

	PAM_LOG("Got principal.instance: %s.%s", principal, instance);

	retval = PAM_AUTH_ERR;
	pwd = getpwnam(user);
	if (pwd != NULL) {
		if (klogin(pwd, instance, localhost, (char *)password) == 0) {
			if (!(flags & PAM_SILENT) && notickets && !noticketsdontcomplain)
				pam_prompt(pamh, PAM_ERROR_MSG,
				    "Warning: no Kerberos tickets issued",
				    NULL);
			/*
			 * XXX - I think the ticket file isn't supposed to
			 * be created until pam_sm_setcred() is called.
			 */
			if (krbtkfile_env != NULL)
				setenv("KRBTKFILE", krbtkfile_env, 1);
			retval = PAM_SUCCESS;
		}

		PAM_LOG("Done klogin()");

	}
	/*
	 * The PAM infrastructure will obliterate the cleartext
	 * password before returning to the application.
	 */
	free(principal);

	if (retval != PAM_SUCCESS)
		PAM_VERBOSE_ERROR("Kerberos IV refuses you");

	PAM_RETURN(retval);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct options options;

	pam_std_option(&options, NULL, argc, argv);

	PAM_LOG("Options processed");

	PAM_RETURN(PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_kerberosIV");
