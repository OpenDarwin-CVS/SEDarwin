/* 
 * Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved
 *
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * The NEXTSTEP Software License Agreement specifies the terms
 * and conditions for redistribution.
 *
 *	@(#)cap_mkdb.c	8.2 (Berkeley) 4/27/95
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <db.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void	 db_build __P((char **));
void	 dounlink __P((void));
void	 usage __P((void));

DB *capdbp;
int verbose;
char *capdb, *capname, buf[8 * 1024];

HASHINFO openinfo = {
	4096,		/* bsize */
	16,		/* ffactor */
	256,		/* nelem */
	2048 * 1024,	/* cachesize */
	NULL,		/* hash() */
	0		/* lorder */
};

/*
 * Mkcapdb creates a capability hash database for quick retrieval of capability
 * records.  The database contains 2 types of entries: records and references
 * marked by the first byte in the data.  A record entry contains the actual
 * capability record whereas a reference contains the name (key) under which
 * the correct record is stored.
 */
int
main(argc, argv)
	int argc;
	char *argv[];
{
	int c;

	capname = NULL;
	while ((c = getopt(argc, argv, "f:v")) != EOF) {
		switch(c) {
		case 'f':
			capname = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (*argv == NULL)
		usage();

	/*
	 * The database file is the first argument if no name is specified.
	 * Make arrangements to unlink it if exit badly.
	 */
	(void)snprintf(buf, sizeof(buf), "%s.db", capname ? capname : *argv);
	if ((capname = strdup(buf)) == NULL)
		err(1, "");
	if ((capdbp = dbopen(capname, O_CREAT | O_TRUNC | O_RDWR,
	    DEFFILEMODE, DB_HASH, &openinfo)) == NULL)
		err(1, "%s", buf);

	if (atexit(dounlink))
		err(1, "atexit");

	db_build(argv);

	if (capdbp->close(capdbp) < 0)
		err(1, "%s", capname);
	capname = NULL;
	exit(0);
}

void
dounlink()
{
	if (capname != NULL)
		(void)unlink(capname);
}

/*
 * Any changes to these definitions should be made also in the getcap(3)
 * library routines.
 */
#define RECOK	(char)0
#define TCERR	(char)1
#define SHADOW	(char)2

/*
 * Db_build() builds the name and capabilty databases according to the
 * details above.
 */
void
db_build(ifiles)
	char **ifiles;
{
	DBT key, data;
	recno_t reccnt;
	size_t len, bplen;
	int st;
	char *bp, *p, *t;

	data.data = NULL;
	key.data = NULL;
	for (reccnt = 0, bplen = 0; (st = cgetnext(&bp, ifiles)) > 0;) {

		/*
		 * Allocate enough memory to store record, terminating
		 * NULL and one extra byte.
		 */
		len = strlen(bp);
		if (bplen <= len + 2) {
			bplen += MAX(256, len + 2);
			if ((data.data = realloc(data.data, bplen)) == NULL)
				err(1, "");
		}

		/* Find the end of the name field. */
		if ((p = strchr(bp, ':')) == NULL) {
			warnx("no name field: %.*s", MIN(len, 20), bp);
			continue;
		}

		/* First byte of stored record indicates status. */
		switch(st) {
		case 1:
			((char *)(data.data))[0] = RECOK;
			break;
		case 2:
			((char *)(data.data))[0] = TCERR;
			warnx("Record not tc expanded: %.*s", p - bp, bp);
			break;
		}

		/* Create the stored record. */
		memmove(&((u_char *)(data.data))[1], bp, len + 1);
		data.size = len + 2;

		/* Store the record under the name field. */
		key.data = bp;
		key.size = p - bp;

		switch(capdbp->put(capdbp, &key, &data, R_NOOVERWRITE)) {
		case -1:
			err(1, "put");
			/* NOTREACHED */
		case 1:
			warnx("ignored duplicate: %.*s",
			    key.size, (char *)key.data);
			continue;
		}
		++reccnt;

		/* If only one name, ignore the rest. */
		if ((p = strchr(bp, '|')) == NULL)
			continue;

		/* The rest of the names reference the entire name. */
		((char *)(data.data))[0] = SHADOW;
		memmove(&((u_char *)(data.data))[1], key.data, key.size);
		data.size = key.size + 1;

		/* Store references for other names. */
		for (p = t = bp;; ++p) {
			if (p > t && (*p == ':' || *p == '|')) {
				key.size = p - t;
				key.data = t;
				switch(capdbp->put(capdbp,
				    &key, &data, R_NOOVERWRITE)) {
				case -1:
					err(1, "put");
					/* NOTREACHED */
				case 1:
					warnx("ignored duplicate: %.*s",
					    key.size, (char *)key.data);
				}
				t = p + 1;
			}
			if (*p == ':')
				break;
		}
	}

	switch(st) {
	case -1:
		err(1, "file argument");
		/* NOTREACHED */
	case -2:
		errx(1, "potential reference loop detected");
		/* NOTREACHED */
	}

	if (verbose)
		(void)printf("cap_mkdb: %d capability records\n", reccnt);
}

void
usage()
{
	(void)fprintf(stderr,
	    "usage: cap_mkdb [-v] [-f outfile] file1 [file2 ...]\n");
	exit(1);
}
