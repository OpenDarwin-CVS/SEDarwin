/*	$NetBSD: ls.c,v 1.31 1998/08/19 01:44:19 thorpej Exp $	*/

/*
 * Copyright (c) 1989, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Michael Fischbein.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef lint
__COPYRIGHT("@(#) Copyright (c) 1989, 1993, 1994\n\
	The Regents of the University of California.  All rights reserved.\n");
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)ls.c	8.7 (Berkeley) 8/5/94";
#else
__RCSID("$NetBSD: ls.c,v 1.31 1998/08/19 01:44:19 thorpej Exp $");
#endif
#endif /* not lint */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/mac.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "ls.h"
#include "extern.h"

int	main __P((int, char *[]));

static void	 display __P((FTSENT *, FTSENT *));
static int	 mastercmp __P((const FTSENT **, const FTSENT **));
static void	 traverse __P((int, char **, int));

static void (*printfcn) __P((DISPLAY *));
static int (*sortfcn) __P((const FTSENT *, const FTSENT *));

#define	BY_NAME 0
#define	BY_SIZE 1
#define	BY_TIME	2

long blocksize;			/* block size units */
int termwidth = 80;		/* default terminal width */
int sortkey = BY_NAME;

/* flags */
int f_accesstime;		/* use time of last access */
int f_column;			/* columnated format */
int f_columnacross;		/* columnated format, sorted across */
int f_flags;			/* show flags associated with a file */
int f_inode;			/* print inode */
int f_listdir;			/* list actual directory, not contents */
int f_listdot;			/* list files beginning with . */
int f_longform;			/* long listing format */
int f_nonprint;			/* show unprintables as ? */
int f_nosort;			/* don't sort output */
int f_numericonly;		/* don't convert uid/gid to name */
int f_recursive;		/* ls subdirectories also */
int f_reversesort;		/* reverse whatever sort is used */
int f_sectime;			/* print the real time for all files */
int f_singlecol;		/* use single column output */
int f_size;			/* list size in short listing */
int f_statustime;		/* use time of last mode change */
int f_type;			/* add type character for non-regular files */
int f_whiteout;			/* show whiteout entries */
int f_label = 0;	       	/* show labels */

int
main(argc, argv)
	int argc;
	char *argv[];
{
	static char dot[] = ".", *dotav[] = { dot, NULL };
	struct winsize win;
	int ch, fts_options, notused;
	int kflag = 0;
	const char *p;

	/* Terminal defaults to -Cq, non-terminal defaults to -1. */
	if (isatty(STDOUT_FILENO)) {
		if ((p = getenv("COLUMNS")) != NULL)
			termwidth = atoi(p);
		else if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &win) == 0 &&
		    win.ws_col > 0)
			termwidth = win.ws_col;
		f_column = f_nonprint = 1;
	} else
		f_singlecol = 1;

	/* Root is -A automatically. */
	if (!getuid())
		f_listdot = 1;

	fts_options = FTS_PHYSICAL;
	while ((ch = getopt(argc, argv, "1ACFLRSTWacdfgiklZnoqrstuxv")) != -1) {
		switch (ch) {
		/*
		 * The -1, -C, -l and -x options all override each other so
		 * shell aliasing works correctly.
		 */
		case '1':
			f_singlecol = 1;
			f_column = f_columnacross = f_longform = 0;
			break;
		case 'C':
			f_column = 1;
			f_columnacross = f_longform = f_singlecol = 0;
			break;
		case 'l':
			f_longform = 1;
			f_column = f_columnacross = f_singlecol = 0;
			break;
		case 'x':
			f_columnacross = 1;
			f_column = f_longform = f_singlecol = 0;
			break;
		/* The -c and -u options override each other. */
		case 'c':
			f_statustime = 1;
			f_accesstime = 0;
			break;
		case 'u':
			f_accesstime = 1;
			f_statustime = 0;
			break;
		case 'F':
			f_type = 1;
			break;
		case 'L':
			fts_options &= ~FTS_PHYSICAL;
			fts_options |= FTS_LOGICAL;
			break;
		case 'R':
			f_recursive = 1;
			break;
		case 'a':
			fts_options |= FTS_SEEDOT;
			/* FALLTHROUGH */
		case 'A':
			f_listdot = 1;
			break;
		/* The -d option turns off the -R option. */
		case 'd':
			f_listdir = 1;
			f_recursive = 0;
			break;
		case 'f':
			f_nosort = 1;
			break;
		case 'g':		/* Compatibility with 4.3BSD. */
			break;
		case 'i':
			f_inode = 1;
			break;
		case 'k':
			blocksize = 1024;
			kflag = 1;
			break;
		case 'n':
			f_numericonly = 1;
			break;
		case 'o':
			f_flags = 1;
			break;
		case 'q':
			f_nonprint = 1;
			break;
		case 'r':
			f_reversesort = 1;
			break;
		case 'S':
			sortkey = BY_SIZE;
			break;
		case 's':
			f_size = 1;
			break;
		case 'T':
			f_sectime = 1;
			break;
		case 't':
			sortkey = BY_TIME;
			break;
		case 'W':
			f_whiteout = 1;
			break;
		case 'v':
			f_nonprint = 0;
			break;
		case 'Z':
			f_label = 1;
			break;
		default:
		case '?':
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/*
	 * If not -F, -i, -l, -S, -s or -t options, don't require stat
	 * information.
	 */
	if (!f_inode && !f_longform && !f_size && !f_type &&
	    sortkey == BY_NAME && !f_label)
		fts_options |= FTS_NOSTAT;

	/*
	 * If not -F, -d or -l options, follow any symbolic links listed on
	 * the command line.
	 */
	if (!f_longform && !f_listdir && !f_type)
		fts_options |= FTS_COMFOLLOW;

	/*
	 * If -W, show whiteout entries
	 */
#ifdef FTS_WHITEOUT
	if (f_whiteout)
		fts_options |= FTS_WHITEOUT;
#endif

	/* If -l or -s, figure out block size. */
	if (f_longform || f_size) {
		if (!kflag)
			(void)getbsize(&notused, &blocksize);
		blocksize /= 512;
	}

	/* Select a sort function. */
	if (f_reversesort) {
		switch (sortkey) {
		case BY_NAME:
			sortfcn = revnamecmp;
			break;
		case BY_SIZE:
			sortfcn = revsizecmp;
			break;
		case BY_TIME:
			if (f_accesstime)
				sortfcn = revacccmp;
			else if (f_statustime)
				sortfcn = revstatcmp;
			else /* Use modification time. */
				sortfcn = revmodcmp;
			break;
		}
	} else {
		switch (sortkey) {
		case BY_NAME:
			sortfcn = namecmp;
			break;
		case BY_SIZE:
			sortfcn = sizecmp;
			break;
		case BY_TIME:
			if (f_accesstime)
				sortfcn = acccmp;
			else if (f_statustime)
				sortfcn = statcmp;
			else /* Use modification time. */
				sortfcn = modcmp;
			break;
		}
	}

	/* Select a print function. */
	if (f_singlecol || (f_label && !f_longform))
		printfcn = printscol;
	else if (f_columnacross)
		printfcn = printacol;
	else if (f_longform)
		printfcn = printlong;
	else
		printfcn = printcol;

	if (argc)
		traverse(argc, argv, fts_options);
	else
		traverse(1, dotav, fts_options);
	exit(0);
	/* NOTREACHED */
}

static int output;			/* If anything output. */

/*
 * Traverse() walks the logical directory structure specified by the argv list
 * in the order specified by the mastercmp() comparison function.  During the
 * traversal it passes linked lists of structures to display() which represent
 * a superset (may be exact set) of the files to be displayed.
 */
static void
traverse(argc, argv, options)
	int argc, options;
	char *argv[];
{
	FTS *ftsp;
	FTSENT *p, *chp;
	int ch_options;
	char pbuf[MAXPATHLEN + 1], *path;

	if ((ftsp =
	    fts_open(argv, options, f_nosort ? NULL : mastercmp)) == NULL)
		err(1, "%s", "");

	display(NULL, fts_children(ftsp, 0));
	if (f_listdir)
		return;

	/*
	 * If not recursing down this tree and don't need stat info, just get
	 * the names.
	 */
	ch_options = !f_recursive && !f_label && 
	    options & FTS_NOSTAT ? FTS_NAMEONLY : 0;

	while ((p = fts_read(ftsp)) != NULL)
		switch (p->fts_info) {
		case FTS_DC:
			warnx("%s: directory causes a cycle", p->fts_name);
			break;
		case FTS_DNR:
		case FTS_ERR:
			warnx("%s: %s", p->fts_name, strerror(p->fts_errno));
			break;
		case FTS_D:
			if (p->fts_level != FTS_ROOTLEVEL &&
			    p->fts_name[0] == '.' && !f_listdot)
				break;

			/*
			 * If already output something, put out a newline as
			 * a separator.  If multiple arguments, precede each
			 * directory with its name.
			 */
			if (f_nonprint) {
				prcopy(p->fts_path, pbuf, p->fts_pathlen+1);
				path = pbuf;
			} else
				path = p->fts_path;

			if (output)
				(void)printf("\n%s:\n", path);
			else if (argc > 1) {
				(void)printf("%s:\n", path);
				output = 1;
			}

			chp = fts_children(ftsp, ch_options);
			display(p, chp);

			if (!f_recursive && chp != NULL)
				(void)fts_set(ftsp, p, FTS_SKIP);
			break;
		}
	if (errno)
		err(1, "fts_read");
}

/*
 * Display() takes a linked list of FTSENT structures and passes the list
 * along with any other necessary information to the print function.  P
 * points to the parent directory of the display list.
 */
static void
display(p, list)
	FTSENT *p, *list;
{
	struct stat *sp;
	DISPLAY d;
	FTSENT *cur;
	NAMES *np;
	u_int64_t btotal, maxblock, maxsize;
	int maxinode, maxnlink, maxmajor, maxminor;
	int bcfile, entries, flen, glen, ulen, maxflags, maxgroup, maxlen;
	int maxuser, maxlabelstr, needstats, labelstrlen;
	const char *user, *group;
	char ubuf[21]="", gbuf[21]="", buf[21];	/* 64 bits == 20 digits, +1 for NUL */
	char nuser[12], ngroup[12];
	char *flags = NULL;
	char *labelstr = NULL;

#ifdef __GNUC__
	/* This outrageous construct just to shut up a GCC warning. */
	(void) &maxsize;
#endif

	/*
	 * If list is NULL there are two possibilities: that the parent
	 * directory p has no children, or that fts_children() returned an
	 * error.  We ignore the error case since it will be replicated
	 * on the next call to fts_read() on the post-order visit to the
	 * directory p, and will be signalled in traverse().
	 */
	if (list == NULL)
		return;

	needstats = f_inode || f_longform || f_size || f_label;
	flen = 0;
	maxinode = maxnlink = 0;
	bcfile = 0;
	maxuser = maxgroup = maxflags = maxlen = 0;
	btotal = maxblock = maxsize = 0;
	maxmajor = maxminor = maxlabelstr = 0;
	for (cur = list, entries = 0; cur; cur = cur->fts_link) {
		if (cur->fts_info == FTS_ERR || cur->fts_info == FTS_NS) {
			warnx("%s: %s",
			    cur->fts_name, strerror(cur->fts_errno));
			cur->fts_number = NO_PRINT;
			continue;
		}

		/*
		 * P is NULL if list is the argv list, to which different rules
		 * apply.
		 */
		if (p == NULL) {
			/* Directories will be displayed later. */
			if (cur->fts_info == FTS_D && !f_listdir) {
				cur->fts_number = NO_PRINT;
				continue;
			}
		} else {
			/* Only display dot file if -a/-A set. */
			if (cur->fts_name[0] == '.' && !f_listdot) {
				cur->fts_number = NO_PRINT;
				continue;
			}
		}
		if (cur->fts_namelen > maxlen)
			maxlen = cur->fts_namelen;
		if (needstats) {
			sp = cur->fts_statp;
			if (sp->st_blocks > maxblock)
				maxblock = sp->st_blocks;
			if (sp->st_ino > maxinode)
				maxinode = sp->st_ino;
			if (sp->st_nlink > maxnlink)
				maxnlink = sp->st_nlink;
			if (sp->st_size > maxsize)
				maxsize = sp->st_size;
			if (S_ISCHR(sp->st_mode) || S_ISBLK(sp->st_mode)) {
				bcfile = 1;
				if (major(sp->st_rdev) > maxmajor)
					maxmajor = major(sp->st_rdev);
				if (minor(sp->st_rdev) > maxminor)
					maxminor = minor(sp->st_rdev);
			}

			btotal += sp->st_blocks;
			if (f_longform || f_label) {
				if (f_numericonly) {
					(void)snprintf(nuser, sizeof(nuser),
					    "%u", sp->st_uid);
					(void)snprintf(ngroup, sizeof(ngroup),
					    "%u", sp->st_gid);
					user = nuser;
					group = ngroup;
				} else {
					if ((user = user_from_uid(sp->st_uid, 0)) == NULL) {
						(void)snprintf(ubuf, sizeof(ubuf), "%d", (int)sp->st_uid);
						user = ubuf;
					}
					if ((group = group_from_gid(sp->st_gid, 0)) == NULL) {
						(void)snprintf(gbuf, sizeof(gbuf), "%d", (int)sp->st_gid);
						group = gbuf;
					}
				}
				if ((ulen = strlen(user)) > maxuser)
					maxuser = ulen;
				if ((glen = strlen(group)) > maxgroup)
					maxgroup = glen;
				if (f_flags) {
					flags =
					    flags_to_string(sp->st_flags, "-");
					if ((flen = strlen(flags)) > maxflags)
						maxflags = flen;
				} else
					flen = 0;

				if (f_label)
				  {
					char name[PATH_MAX + 1];
					mac_t label;
					int error;

					error = mac_prepare_file_label(&label);
					if (error == -1) {
						warn("MAC label for %s/%s",
						    cur->fts_parent->fts_path,
						    cur->fts_name);
						goto label_out;
					}

					if (cur->fts_level == FTS_ROOTLEVEL)
						snprintf(name, sizeof(name),
						    "%s", cur->fts_name);
					else
						snprintf(name, sizeof(name),
						    "%s/%s", cur->fts_parent->fts_accpath, cur->fts_name);

					/*if (options & FTS_LOGICAL)
						error = mac_get_file(name,
						    label);
						    else*/
						error = mac_get_link(name,
						    label);
					if (error == -1) {
						warn("MAC label for %s/%s",
						    cur->fts_parent->fts_path,
						    cur->fts_name);
						mac_free(label);
						goto label_out;
					}

					error = mac_to_text(label,
					    &labelstr);
					if (error == -1) {
						warn("MAC label for %s/%s",
						    cur->fts_parent->fts_path,
						    cur->fts_name);
						mac_free(label);
						goto label_out;
					}
					mac_free(label);
label_out:
					if (labelstr == NULL)
						labelstr = strdup("-");
					labelstrlen = strlen(labelstr);
					if (labelstrlen > maxlabelstr)
						maxlabelstr = labelstrlen;
				} else
					labelstrlen = 0;

				if ((np = malloc(sizeof(NAMES) + labelstrlen +
				    ulen + glen + flen + 4)) == NULL)
					err(1, "malloc");

				np->user = &np->data[0];
				(void)strcpy(np->user, user);
				np->group = &np->data[ulen + 1];
				(void)strcpy(np->group, group);

				if (S_ISCHR(sp->st_mode) ||
				    S_ISBLK(sp->st_mode))
					bcfile = 1;

				if (f_flags) {
					np->flags = &np->data[ulen + glen + 2];
					(void)strcpy(np->flags, flags);
				}
				if (f_label) {
					np->label = &np->data[ulen + glen + 2
					    + (f_flags ? flen + 1 : 0)];
					(void)strcpy(np->label, labelstr);
					free(labelstr);
				}

				cur->fts_pointer = np;
			}
		}
		++entries;
	}

	if (!entries)
		return;

	d.list = list;
	d.entries = entries;
	d.maxlen = maxlen;
	d.s_label = maxlabelstr;
	if (needstats) {
		d.btotal = btotal;
		(void)snprintf(buf, sizeof(buf), "%qu", (long long)maxblock);
		d.s_block = strlen(buf);
		d.s_flags = maxflags;
		d.s_group = maxgroup;
		(void)snprintf(buf, sizeof(buf), "%u", maxinode);
		d.s_inode = strlen(buf);
		(void)snprintf(buf, sizeof(buf), "%u", maxnlink);
		d.s_nlink = strlen(buf);
		(void)snprintf(buf, sizeof(buf), "%qu", (long long)maxsize);
		d.s_size = strlen(buf);
		d.s_user = maxuser;
		if (bcfile) {
			(void)snprintf(buf, sizeof(buf), "%u", maxmajor);
			d.s_major = strlen(buf);
			(void)snprintf(buf, sizeof(buf), "%u", maxminor);
			d.s_minor = strlen(buf);
			if (d.s_major + d.s_minor + 2 > d.s_size)
				d.s_size = d.s_major + d.s_minor + 2;
			else if (d.s_size - d.s_minor - 2 > d.s_major)
				d.s_major = d.s_size - d.s_minor - 2;
		} else {
			d.s_major = 0;
			d.s_minor = 0;
		}
	}

	printfcn(&d);
	output = 1;

	if (f_longform || f_label)
		for (cur = list; cur; cur = cur->fts_link)
			free(cur->fts_pointer);
}

/*
 * Ordering for mastercmp:
 * If ordering the argv (fts_level = FTS_ROOTLEVEL) return non-directories
 * as larger than directories.  Within either group, use the sort function.
 * All other levels use the sort function.  Error entries remain unsorted.
 */
static int
mastercmp(a, b)
	const FTSENT **a, **b;
{
	int a_info, b_info;

	a_info = (*a)->fts_info;
	if (a_info == FTS_ERR)
		return (0);
	b_info = (*b)->fts_info;
	if (b_info == FTS_ERR)
		return (0);

	if (a_info == FTS_NS || b_info == FTS_NS) {
		if (b_info != FTS_NS)
			return (1);
		else if (a_info != FTS_NS)
			return (-1);
		else
			return (namecmp(*a, *b));
	}

	if (a_info != b_info && !f_listdir &&
	    (*a)->fts_level == FTS_ROOTLEVEL) {
		if (a_info == FTS_D)
			return (1);
		else if (b_info == FTS_D)
			return (-1);
	}
	return (sortfcn(*a, *b));
}
