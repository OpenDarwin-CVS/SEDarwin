/*-
 * Copyright (c) 2002 Networks Associates Technologies, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by NAI Labs, the
 * Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
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
#include <sys/sysctl.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <selinux/selinux.h>

struct getsid_args
{
  char *ctx;
  char *usr;
  char *out;
  int  *outlen;
};

/*
 * Get a malloc()ed array of malloc()ed strings which indicate the
 * allowed SEBSD transitions to be made by a given user in a given
 * context.
 */
static int
security_get_some_contexts(int what, const char *fromcontext, const char *username,
    char ***retcontexts, size_t *ncontexts)
{
	char *contexts, *s, **contextarray;
	size_t contexts_len, n;
	int error;
	struct getsid_args uap;

bigger:
	uap.outlen = &contexts_len;
	uap.ctx = fromcontext;
	uap.usr = username;
	uap.out = NULL;
	if (mac_syscall ("sebsd", what, &uap))
	  {
	    return (-1);
	  }
	contexts = malloc(contexts_len);
	if (contexts == NULL) {
		return (-1);
	}
	uap.out = contexts;
	error = mac_syscall ("sebsd", what, &uap);
	/*
	 * We could possibly race and not have a large enough space
	 * for the current set of contexts.
	 */
	if (error == -1 && errno == ENOMEM) {
		free(contexts);
		goto bigger;
	}
	if (error == -1) {
		free(contexts);
		return (-1);
	}
	n = 0; 
	for (s = contexts; s < &contexts[contexts_len - 1]; s += strlen(s) + 1)
		n++;
	if (!n) {
		free(contexts);
		*ncontexts = 0;
		*retcontexts = NULL;
		return (0);
	}
	contextarray = calloc(1+n, sizeof(char *));
	if (contextarray == NULL) {
		free(contexts);
		return (-1);
	}
	n = 0;
	for (s = contexts; s < &contexts[contexts_len - 1];
	    s += strlen(s) + 1) {
		contextarray[n] = strdup(s);
		/* upon failure here, just free everything */
		if (contextarray[n] == NULL) {
			while (n > 0) {
				free(contextarray[--n]);
			}
			return (-1);
		}
		n++;
	}
	*ncontexts = n;
	*retcontexts = contextarray;
	return (0);
}

int
security_get_user_contexts(const char *fromcontext, const char *username,
    char ***retcontexts, size_t *ncontexts)
{
  return security_get_some_contexts (6, fromcontext, username, retcontexts, ncontexts);
}

int
security_get_file_contexts(const char *fromcontext, char ***retcontexts, size_t *ncontexts)
{
  return security_get_some_contexts (5, fromcontext, "unused", retcontexts, ncontexts);
}

int security_compute_user(security_context_t scon,
			  const char *user,
			  security_context_t **con)
{
	size_t ncon;
	int rc = security_get_user_contexts(scon,user,con,&ncon);
	if (rc || ncon == 0) {
		free(*con);
		return -1;
	}
	con[ncon] = 0;
	return rc;
}
