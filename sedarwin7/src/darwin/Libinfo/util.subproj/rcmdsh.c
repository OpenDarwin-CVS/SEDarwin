/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*	$OpenBSD: rcmdsh.c,v 1.4 1997/07/23 16:59:37 millert Exp $	*/ 

/*
 * This is an rcmd() replacement originally by 
 * Chris Siebenmann <cks@utcc.utoronto.ca>.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char *rcsid = "$OpenBSD: rcmdsh.c,v 1.4 1997/07/23 16:59:37 millert Exp $";
#endif /* LIBC_SCCS and not lint */

#include      <sys/types.h>
#include      <sys/socket.h>
#include      <sys/wait.h>
#include      <signal.h>
#include      <errno.h>
#include      <netdb.h>
#include      <stdio.h>
#include      <string.h>
#include      <pwd.h>
#include      <paths.h>
#include      <unistd.h>
/*
 * This is a replacement rcmd() function that uses the rsh(1)
 * program in place of a direct rcmd(3) function call so as to
 * avoid having to be root.  Note that rport is ignored.
 */
/* ARGSUSED */
int
rcmdsh(ahost, rport, locuser, remuser, cmd, rshprog)
	char **ahost;
	int rport;
	const char *locuser, *remuser, *cmd;
	char *rshprog;
{
	struct hostent *hp;
	int cpid, sp[2];
	char *p;
	struct passwd *pw;

	/* What rsh/shell to use. */
	if (rshprog == NULL)
		rshprog = _PATH_RSH;

	/* locuser must exist on this host. */
	if ((pw = getpwnam(locuser)) == NULL) {
		(void) fprintf(stderr, "rcmdsh: unknown user: %s\n", locuser);
		return(-1);
	}

	/* Validate remote hostname. */
	if (strcmp(*ahost, "localhost") != 0) {
		if ((hp = gethostbyname(*ahost)) == NULL) {
			herror(*ahost);
			return(-1);
		}
		*ahost = hp->h_name;
	}

	/* Get a socketpair we'll use for stdin and stdout. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
		perror("rcmdsh: socketpair");
		return(-1);
	}

	cpid = fork();
	if (cpid < 0) {
		perror("rcmdsh: fork failed");
		return(-1);
	} else if (cpid == 0) {
		/*
		 * Child.  We use sp[1] to be stdin/stdout, and close sp[0].
		 */
		(void) close(sp[0]);
		if (dup2(sp[1], 0) < 0 || dup2(0, 1) < 0) {
			perror("rcmdsh: dup2 failed");
			_exit(255);
		}
		/* Fork again to lose parent. */
		cpid = fork();
		if (cpid < 0) {
			perror("rcmdsh: fork to lose parent failed");
			_exit(255);
		}
		if (cpid > 0)
			_exit(0);

		/* In grandchild here.  Become local user for rshprog. */
		if (setuid(pw->pw_uid)) {
			(void) fprintf(stderr, "rcmdsh: setuid(%u): %s\n",
				       pw->pw_uid, strerror(errno));
			_exit(255);
		}

		/*
		 * If remote host is "localhost" and local and remote user
		 * are the same, avoid running remote shell for efficiency.
		 */
		if (!strcmp(*ahost, "localhost") && !strcmp(locuser, remuser)) {
			if (pw->pw_shell[0] == '\0')
				rshprog = _PATH_BSHELL;
			else
				rshprog = pw->pw_shell;
			p = strrchr(rshprog, '/');
			execlp(rshprog, p ? p+1 : rshprog, "-c", cmd,
			       (char *) NULL);
		} else {
			p = strrchr(rshprog, '/');
			execlp(rshprog, p ? p+1 : rshprog, *ahost, "-l",
			       remuser, cmd, (char *) NULL);
		}
		(void) fprintf(stderr, "rcmdsh: execlp %s failed: %s\n",
			       rshprog, strerror(errno));
		_exit(255);
	} else {
		/* Parent. close sp[1], return sp[0]. */
		(void) close(sp[1]);
		/* Reap child. */
		(void) wait(NULL);
	}
	return(sp[0]);
}
