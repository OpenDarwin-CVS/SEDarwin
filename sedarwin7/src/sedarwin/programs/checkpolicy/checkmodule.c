/*
 * Authors: Joshua Brindle <jbrindle@tresys.com>
 *	    Karl MacMillan <kmacmillan@tresys.com>
 *          Jason Tang     <jtang@tresys.com>
 *
 *
 * Copyright (C) 2004-5 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/flask.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>

#include "queue.h"
#include "checkpolicy.h"

extern char *optarg;
extern int optind;

static sidtab_t sidtab;

extern policydb_t *policydbp;
extern queue_t id_queue;
extern unsigned int policydb_errors;
extern unsigned long policydb_lineno;
extern char source_file[];
extern int mlspol;

extern FILE *yyin;
extern void init_parser(int);
extern int yyparse(void);
extern void yyrestart(FILE *);

static char *txtfile = "policy.conf";
static char *binfile = "policy";

unsigned int policy_type = POLICY_BASE;
unsigned int policyvers = MOD_POLICYDB_VERSION_MAX;

static int read_binary_policy(policydb_t *p, char *file, char *progname)
{
        int fd;
	struct stat sb;
        void *map;
	struct policy_file f, *fp;
        
        fd = open(file, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "Can't open '%s':  %s\n",
                        file, strerror(errno));
                return -1;
        }
        if (fstat(fd, &sb) < 0) {
                fprintf(stderr, "Can't stat '%s':  %s\n",
                        file, strerror(errno));
                return -1;
        }
        map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (map == MAP_FAILED) {
                fprintf(stderr, "Can't map '%s':  %s\n",
                        file, strerror(errno));
                return -1;
        }
        f.type = PF_USE_MEMORY;
        f.data = map;
        f.len = sb.st_size;
        fp = &f;

	if (policydb_init(p)) {
		fprintf(stderr, "%s:  policydb_init:  Out of memory!\n", progname);
		return -1;
	}	
        if (policydb_read(p, fp, 1)) {
                fprintf(stderr, "%s:  error(s) encountered while parsing configuration\n", progname);
                return -1;
        }
        
        /* Check Policy Consistency */
        if (p->mls) {
                if (!mlspol) {
                        fprintf(stderr,"%s:  MLS policy, but non-MLS"
                                " is specified\n", progname);
                        return -1;
                }
        } else {
                if (mlspol) {
                        fprintf(stderr,"%s:  non-MLS policy, but MLS"
                                " is specified\n", progname);
                        return -1;
                }
        }
        return 0;
}

static int read_source_policy(policydb_t *p, char *file, char *progname)
{
        yyin = fopen(file, "r");
        if (!yyin) {
                fprintf(stderr, "%s:  unable to open %s\n", progname, 
                        file);
                return -1;
        }
        
        if (policydb_init(p) ||
            ((id_queue = queue_create()) == NULL)) {
                fprintf(stderr, "%s: out of memory!\n", progname);
                return -1;
        }

	p->policy_type = policy_type;
	p->mls = mlspol;

        init_parser(1);
        if (yyparse() || policydb_errors) {
                fprintf(stderr, "%s:  error(s) encountered while parsing configuration\n", progname);
                return -1;
        }
        rewind(yyin);
        init_parser(2);
        source_file[0] = '\0';
        yyrestart(yyin);
        if (yyparse() || policydb_errors) {
                fprintf(stderr, "%s:  error(s) encountered while parsing configuration\n", progname);
                return -1;
        }
        queue_destroy(id_queue);

        if (hierarchy_check_constraints(NULL, p)) {
                return -1;
        }
        
        if (policydb_errors) 
                return -1;

        fclose(yyin);
        return 0;
}

static int write_binary_policy(policydb_t *p, char *file, char *progname)
{
	FILE *outfp = NULL;
	struct policy_file pf;
        int ret;
        
        printf("%s:  writing binary representation (version %d) to %s\n",
               progname, policyvers, file);
        
        outfp = fopen(file, "w");
        if (!outfp) {
                perror(file);
                exit(1);
        }
        
	p->policy_type = policy_type;
	p->policyvers = policyvers;
        
        pf.type = PF_USE_STDIO;
        pf.fp = outfp;
        ret = policydb_write(p, &pf);
        if (ret) {
                fprintf(stderr, "%s:  error writing %s\n",
                        progname, file);
                return -1;
        }
        fclose(outfp);
        return 0;
}

static void usage(char *progname)
{
	printf("usage:  %s [-V] [-b] [-m] [-M] [-o FILE] [INPUT]\n",
		progname);
        printf("Build base and policy modules.\n");
        printf("Options:\n");
        printf("  INPUT      build module from INPUT (else read from \"%s\")\n", txtfile);
        printf("  -V         show policy versions created by this program\n");
        printf("  -b         treat input as a binary policy file\n");
        printf("  -m         build a policy module instead of a base module\n");
        printf("  -M         enable MLS policy\n");
        printf("  -o FILE    write module to FILE (else just check syntax)\n");
	exit(1);
}

int main(int argc, char **argv)
{
	char *file = txtfile, *outfile = NULL;
	unsigned int binary = 0;
	int ch;
	int show_version = 0;
        policydb_t modpolicydb;

	while ((ch = getopt(argc, argv, "ho:dbVmM")) != EOF) {
		switch (ch) {
                case 'h':
                        usage (argv [0]);
                        break;
		case 'o':
			outfile = optarg;
			break;
		case 'b':
			binary = 1;
			file = binfile;
			break;
		case 'V':
			show_version = 1;
			break;
		case 'm':
			policy_type = POLICY_MOD;
                        policyvers = MOD_POLICYDB_VERSION_MAX;
			break;
                case 'M':
			mlspol = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (show_version) {
                printf("Module versions %d-%d\n",
                       MOD_POLICYDB_VERSION_MIN, MOD_POLICYDB_VERSION_MAX);
		exit(0);
	}

	if (optind != argc) {
		file = argv[optind++];
		if (optind != argc)
			usage(argv[0]);
	}
	printf("%s:  loading policy configuration from %s\n", argv[0],
	       file);

        /* Set policydb and sidtab used by libsepol service functions
           to my structures, so that I can directly populate and
           manipulate them. */
        sepol_set_policydb(&modpolicydb);
        sepol_set_sidtab(&sidtab);

        policydbp = &modpolicydb;
	if (binary) {
                if (read_binary_policy(policydbp, file, argv[0]) == -1) {
                        exit(1);
                }
	} else {
                if (read_source_policy(policydbp, file, argv[0]) == -1) {
                        exit(1);
                }
        }

	if (policydbp->policy_type == POLICY_BASE) {
		/* Verify that we can successfully expand the base module. */
		policydb_t kernpolicydb;

		if (policydb_init(&kernpolicydb)) {
			fprintf(stderr, "%s:  policydb_init failed\n", argv[0]);
			exit(1);
		}
		if (link_modules(NULL, policydbp, NULL, 0, 0)) {
			fprintf(stderr, "%s:  link modules failed\n", argv[0]);
			exit(1);
		}
		if (expand_module(NULL, policydbp, &kernpolicydb, 0, 1)) {
			fprintf(stderr, "%s:  expand module failed\n", argv[0]);
			exit(1);
		}
		policydb_destroy(&kernpolicydb);
	}

	if (policydb_load_isids(policydbp, &sidtab))
		exit(1);

	printf("%s:  policy configuration loaded\n", argv[0]);

	if (outfile &&
            write_binary_policy(policydbp, outfile, argv[0]) == -1) {
                exit(1);
        }
	return 0;
}

/* FLASK */

