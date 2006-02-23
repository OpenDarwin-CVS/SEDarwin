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
 *	$FreeBSD: src/lib/libpam/modules/pam_unix/pam_unix.c,v 1.4.2.2 2001/06/11 15:28:51 markm Exp $
 */

#include <sys/types.h>
#include <sys/time.h>
#ifndef __APPLE__
#include <login_cap.h>
#endif
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#include <pam/pam_modules.h>

#include <pam/pam_mod_misc.h>

#define PASSWORD_PROMPT	"Password:"

/*
 * authentication management
 */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
    const char **argv)
{
	int retval;
	const char *user;
	const char *password;
	struct passwd *pwd;
	char *encrypted;
	int options;
	int i;

	options = 0;
	for (i = 0;  i < argc;  i++)
		pam_std_option(&options, argv[i]);
	options |= PAM_OPT_TRY_FIRST_PASS;
	if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return retval;
	if ((retval = pam_get_pass(pamh, &password, PASSWORD_PROMPT,
	    options)) != PAM_SUCCESS)
		return retval;
	if ((pwd = getpwnam(user)) != NULL) {
		if( (password[0] == '\0') && (pwd->pw_passwd[0] == '\0') )
			retval = PAM_SUCCESS;
		else {
			encrypted = crypt(password, pwd->pw_passwd);
			if (password[0] == '\0' && pwd->pw_passwd[0] != '\0')
				encrypted = ":";

			retval = strcmp(encrypted, pwd->pw_passwd) == 0 ?
				PAM_SUCCESS : PAM_AUTH_ERR;
		}
	} else {
		/*
		 * User unknown.  Encrypt anyway so that it takes the
		 * same amount of time.
		 */
		crypt(password, "xx");
		retval = PAM_AUTH_ERR;
	}
	/*
	 * The PAM infrastructure will obliterate the cleartext
	 * password before returning to the application.
	 */
	return retval;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/* 
 * account management
 *
 * check pw_change and pw_expire fields
 */
PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
	const char *user;
	struct passwd *pw;
	struct timeval tp;
	time_t warntime;
#ifndef __APPLE__
	login_cap_t *lc = NULL;
#endif
	char buf[128];
	int retval;

	retval = pam_get_item(pamh, PAM_USER, (const void **)&user);
	if (retval != PAM_SUCCESS || user == NULL)
		/* some implementations return PAM_SUCCESS here */
		return PAM_USER_UNKNOWN;

	if ((pw = getpwnam(user)) == NULL)
		return PAM_USER_UNKNOWN;

	retval = PAM_SUCCESS;
#ifndef __APPLE__
	lc = login_getpwclass(pw);
#endif

	if (pw->pw_change || pw->pw_expire)
		gettimeofday(&tp, NULL);

#define DEFAULT_WARN  (2L * 7L * 86400L)  /* Two weeks */

#ifndef __APPLE__
	warntime = login_getcaptime(lc, "warnpassword", DEFAULT_WARN,
	    DEFAULT_WARN);
#else
	warntime = DEFAULT_WARN;
#endif

	if (pw->pw_change) {
		if (tp.tv_sec >= pw->pw_change)
			/* some implementations return PAM_AUTHTOK_EXPIRED */
			retval = PAM_NEW_AUTHTOK_REQD;
		else if (pw->pw_change - tp.tv_sec < warntime) {
			snprintf(buf, sizeof(buf),
			    "Warning: your password expires on %s",
			    ctime(&pw->pw_change));
			pam_prompt(pamh, PAM_ERROR_MSG, buf, NULL);
		}
	}

#ifndef __APPLE__
	warntime = login_getcaptime(lc, "warnexpire", DEFAULT_WARN,
	    DEFAULT_WARN);
#else
	warntime = DEFAULT_WARN;
#endif

	if (pw->pw_expire) {
		if (tp.tv_sec >= pw->pw_expire)
			retval = PAM_ACCT_EXPIRED;
		else if (pw->pw_expire - tp.tv_sec < warntime) {
			snprintf(buf, sizeof(buf),
			    "Warning: your account expires on %s",
			    ctime(&pw->pw_expire));
			pam_prompt(pamh, PAM_ERROR_MSG, buf, NULL);
		}
	}

#ifndef __APPLE__
	login_close(lc);
#endif
	return retval;
}

#ifdef PAM_STATIC
PAM_MODULE_ENTRY("pam_unix");
#endif
