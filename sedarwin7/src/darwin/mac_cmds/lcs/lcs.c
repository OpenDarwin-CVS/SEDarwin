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

/*
 * $FreeBSD$
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <err.h>
#include <sysexits.h>
#include <paths.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mac.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#ifdef __APPLE__
#include <sys/lctx.h>
#endif

static int	pflag = 0;	/* Show processes */
static int	zflag = 0;	/* Show MAC labels */

static void	show_lcid (pid_t);
static void	show_lctx (void);
static char *	lctx_label (pid_t);
static void	show_lctx_procs (pid_t);
static void	usage(void);

#if defined(__FreeBSD__)
#define	PS_ARGS		kp[i].ki_pid, kp[i].ki_ppid, kp[i].ki_uid, \
			kp[i].ki_comm
#elif defined(__APPLE__)
#define	PS_ARGS		kp[i].kp_proc.p_pid, kp[i].kp_eproc.e_ppid, \
			kp[i].kp_eproc.e_ucred.cr_uid, kp[i].kp_proc.p_comm
#else
#error "Unsupported platform"
#endif

int
main (int argc, char *argv[])
{
	int lcid = 0;
	int ch;

	while ((ch = getopt(argc, argv, "l:LphZ")) != -1) {
		switch (ch) {
		case 'l':
			lcid = atoi(optarg);
			break;
		case 'L':
			lcid = getlcid(LCID_PROC_SELF);
			break;
		case 'p':
			pflag = 1;
			break;
		case 'Z':
			zflag = 1;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (lcid)
		show_lcid(lcid);
	else
		show_lctx();

	return (0);
}

static void
show_lcid (pid_t lcid)
{
	struct kinfo_lctx kl;
	int mib[4];
	size_t len;
	int error;
	char *label;

	mib[0] = CTL_KERN;
	mib[1] = KERN_LCTX;
	mib[2] = KERN_LCTX_LCID;
	mib[3] = lcid;

	len = sizeof(struct kinfo_lctx);
	error = sysctl(mib, 4, &kl, &len, NULL, 0);
	if (error)
		err(1, "sysctl()");
	if (zflag) {
		printf("  LCID MEMCNT LABEL\n");
		label = lctx_label(kl.id);
		printf("%6d %6d %-s\n", kl.id, kl.mc, label);
		free(label);
	} else {
		printf("  LCID MEMCNT\n");
		printf("%6d %6d\n", kl.id, kl.mc);
	}
	if (pflag)
		show_lctx_procs(kl.id);

	return;
}

static void
show_lctx (void)
{
	int mib[3];
	struct kinfo_lctx *kl;
	size_t len;
	int error, cnt, i;
	char *label;

	mib[0] = CTL_KERN;
	mib[1] = KERN_LCTX;
	mib[2] = KERN_LCTX_ALL;

	error = sysctl(mib, 3, NULL, &len, NULL, 0);
	if (error == -1)
		err(1, "sysctl()");

	kl = (struct kinfo_lctx *)malloc(len);
	error = sysctl(mib, 3, kl, &len, NULL, 0);
	if (error == -1)
		err(1, "sysctl()");
	cnt = len / sizeof(struct kinfo_lctx);

	if (zflag)
		printf("  LCID MEMCNT LABEL\n");
	else
		printf("  LCID MEMCNT\n");
	for (i = 0; i < cnt; i++) {
		if (zflag) {
			label = lctx_label(kl[i].id);
			printf("%6d %6d %-s\n", kl[i].id, kl[i].mc, label);
			free(label);
		} else {
			printf("%6d %6d\n", kl[i].id, kl[i].mc);
		}
		if (pflag)
			show_lctx_procs(kl[i].id);
	}
	printf("%d context%c\n", cnt, cnt != 1 ? 's' : ' ');
	free(kl);

	return;
}

static char *
lctx_label (pid_t lcid)
{
	mac_t lctxlabel;
	char *string;
	int error;

	string = NULL;
	error = mac_prepare_process_label(&lctxlabel);
	if (error == -1) {
		warn("mac_prepare_process_label");
		return (NULL);
	}

	error = mac_get_lcid(lcid, lctxlabel);
	if (error) {
		warn("mac_get_lcid");
		return (NULL);
	}

	error = mac_to_text(lctxlabel, &string);
	if (error == -1) {
		mac_free(lctxlabel);
		return (NULL);
	}

	mac_free(lctxlabel);
	return (string);
}

static void
show_lctx_procs (pid_t lcid)
{
	int mib[4];
	struct kinfo_proc *kp;
	size_t len;
	int cnt, i, error;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_LCID;
	mib[3] = lcid;

	error = sysctl(mib, 4, NULL, &len, NULL, 0);
	if (error == -1)
		err(1, "sysctl()");

	kp = (struct kinfo_proc *)malloc(len);
	if (kp == NULL)
		err(1, "malloc(%d)", len);
	error = sysctl(mib, 4, kp, &len, NULL, 0);
	if (error == -1)
		err(1, "sysctl()");

	cnt = len / sizeof(struct kinfo_proc);

	printf("\t\t  PID  PPID   UID COMMAND\n");
	for (i = 0; i < cnt; i++) {
		printf("\t\t%5u %5u %5u %-s\n", PS_ARGS);
	}
	free(kp);

	return;
}

static void
usage (void)
{
	fprintf(stderr, "usage: %s [-l lcid | -L] [-phZ]\n", getprogname());
	exit (EX_USAGE);
}
