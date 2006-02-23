/*-
 * Copyright (c) 2004 Networks Associates Technology, Inc.
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

#include <sys/audit.h>
#include <sys/fcntl.h>

int main (int argc, const char *argv[])
{
	int suid = (getuid() != geteuid());
	if (argc != 2) {
		printf ("usage: audit_test <audit file>\n");
		return 1;
	}
	int fd = open (argv[1], O_RDWR | O_CREAT, 0600);
	if (fd < 0) {
		perror (argv[1]);
		return 1;
	}
	close(fd);
	if (auditctl (argv[1])) {
		perror ("auditctl");
		return 1;
	}

	auditinfo_t ai;
	memset (&ai, 0, sizeof (auditinfo_t));
	ai.ai_auid = getuid();
	ai.ai_asid = getpid();
	ai.ai_mask.am_failure = AU_PROCESS | AU_FCREATE | AU_FACCESS |
		AU_FMODIFY | AU_FREAD | AU_FWRITE | AU_FCREATE | AU_FDELETE;
	if (setaudit (&ai)) {
		perror ("setaudit");
		return 1;
	}
	if (suid)
		setuid (getuid());
	execl ("/bin/bash", "-bash", NULL);
	perror ("bash");
	return 1;
}
