/*-
 * Copyright (c) 2001 Mark R V Murray
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
 * $FreeBSD: src/lib/libpam/modules/pam_securetty/pam_securetty.c,v 1.3 2001/08/10 19:18:52 markm Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <ttyent.h>
#include <string.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <pam_mod_misc.h>

#define TTY_PREFIX	"/dev/"

PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	struct options options;
	struct ttyent *ttyfileinfo;
	struct passwd *pwd;
	int retval;
	const char *user, *ttyname;

	pam_std_option(&options, NULL, argc, argv);

	PAM_LOG("Options processed");

	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS)
		PAM_RETURN(retval);

	PAM_LOG("Got user: %s", user);

	retval = pam_get_item(pamh, PAM_TTY, (const void **)&ttyname);
	if (retval != PAM_SUCCESS)
		PAM_RETURN(retval);

	PAM_LOG("Got TTY: %s", ttyname);

	/* Ignore any "/dev/" on the PAM_TTY item */
	if (strncmp(TTY_PREFIX, ttyname, sizeof(TTY_PREFIX) - 1) == 0)
		ttyname += sizeof(TTY_PREFIX) - 1;

	/* If the user is not root, secure ttys do not apply */
	pwd = getpwnam(user);
	if (pwd == NULL)
		PAM_RETURN(PAM_IGNORE);
	else if (pwd->pw_uid != 0)
		PAM_RETURN(PAM_SUCCESS);

	PAM_LOG("User is not root");

	ttyfileinfo = getttynam(ttyname);
	if (ttyfileinfo == NULL)
		PAM_RETURN(PAM_SERVICE_ERR);

	PAM_LOG("Got ttyfileinfo");

	if (ttyfileinfo->ty_status & TTY_SECURE)
		PAM_RETURN(PAM_SUCCESS);
	else {
		PAM_VERBOSE_ERROR("Not on secure TTY");
		PAM_RETURN(PAM_PERM_DENIED);
	}
}

PAM_EXTERN
int 
pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	struct options options;

	pam_std_option(&options, NULL, argc, argv);

	PAM_LOG("Options processed");

	PAM_RETURN(PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_securetty");
