
/*
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil> 
 */

/* Updated: Karl MacMillan <kmacmillan@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Updated: James Morris <jmorris@intercode.com.au>
 *
 *	Added IPv6 support.
 *
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* FLASK */

/* 
 * checkpolicy
 *
 * Load and check a policy configuration.
 *
 * A policy configuration is created in a text format,
 * and then compiled into a binary format for use by
 * the security server.  By default, checkpolicy reads
 * the text format.   If '-b' is specified, then checkpolicy
 * reads the binary format instead.
 * 
 * If '-o output_file' is specified, then checkpolicy 
 * writes the binary format version of the configuration
 * to the specified output file.  
 * 
 * If '-d' is specified, then checkpolicy permits the user 
 * to interactively test the security server functions with 
 * the loaded policy configuration.
 *
 * If '-c' is specified, then the supplied parameter is used to
 * determine which policy version to use for generating binary
 * policy.  This is for compatibility with older kernels. If any
 * booleans or conditional rules are thrown away a warning is printed.
 */

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>

#include <sepol/policydb.h>
#include <sepol/services.h>
#include <sepol/conditional.h>
#include <sepol/flask.h>

#include "queue.h"
#include "checkpolicy.h"

extern char *optarg;
extern int optind;

static policydb_t policydb;
static sidtab_t sidtab;

extern policydb_t *policydbp;
extern queue_t id_queue;
extern unsigned int policydb_errors;
extern unsigned long policydb_lineno;
extern unsigned long source_lineno;
extern char source_file[];
extern unsigned int pass;

extern FILE *yyin;
extern int yyparse(void);
extern void yyrestart(FILE *);

char *txtfile = "policy.conf";
char *binfile = "policy";

unsigned int policyvers = POLICYDB_VERSION_MAX;

void usage(char *progname)
{
	printf("usage:  %s [-b] [-d] [-c policyvers (%d-%d)] [-o output_file] [input_file]\n",
		progname, POLICYDB_VERSION_MIN, POLICYDB_VERSION_MAX);
	exit(1);
}

static int print_sid(security_id_t sid,
		     context_struct_t * context __attribute__ ((unused)), void *data __attribute__ ((unused)))
{
	security_context_t scontext;
	size_t scontext_len;
	int rc;

	rc = sepol_sid_to_context(sid, &scontext, &scontext_len);
	if (rc)
		printf("sid %d -> error %d\n", sid, rc);
	else {
		printf("sid %d -> scontext %s\n", sid, scontext);
		free(scontext);
	}
	return 0;
}

struct val_to_name {
	unsigned int val;
	char *name;
};

static int find_perm(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	struct val_to_name *v = p;
	perm_datum_t *perdatum;

	perdatum = (perm_datum_t *) datum;

	if (v->val == perdatum->value) {
		v->name = key;
		return 1;
	}

	return 0;
}

static int type_attr_remove(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	type_datum_t *typdatum;

	typdatum = (type_datum_t *) datum;
	if (typdatum->isattr)
		return 1;
	return 0;
}

#ifdef EQUIVTYPES
static int insert_type_rule(avtab_key_t *k, avtab_datum_t *d, 
			    struct avtab_node *type_rules)
{
	struct avtab_node *p, *c, *n;

	for (p = type_rules, c = type_rules->next; c; p = c, c = c->next) {
		/* 
		 * Find the insertion point, keeping the list
		 * ordered by source type, then target type, then
		 * target class.
		 */
		if (k->source_type < c->key.source_type)
			break;
		if (k->source_type == c->key.source_type && 
		    k->target_type < c->key.target_type)
			break;
		if (k->source_type == c->key.source_type && 
		    k->target_type == c->key.target_type &&
		    k->target_class < c->key.target_class)
			break;
	}

	/* Insert the rule */
	n = malloc(sizeof(struct avtab_node));
	if (!n) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

	n->key = *k;
	n->datum = *d;
	n->next = p->next;
	p->next = n;
	return 0;
}

static int create_type_rules(avtab_key_t *k, avtab_datum_t *d, void *args)
{
	struct avtab_node *type_rules = args;

	if (d->specified & AVTAB_ALLOWED) {
		/* 
		 * Insert the rule into the lists for both 
		 * the source type and the target type.
		 */
		if (insert_type_rule(k, d, &type_rules[k->source_type-1])) return -1;
		if (insert_type_rule(k, d, &type_rules[k->target_type-1])) return -1;
	}

	return 0;
}

static void free_type_rules(struct avtab_node *l)
{
	struct avtab_node *tmp;

	while (l) {
		tmp = l;
		l = l->next;
		free(tmp);
	}
}

static int identify_equiv_types(void) 
{
        struct avtab_node *type_rules, *l1, *l2;
	int i, j;

	/*
	 * Create a list of access vector rules for each type
	 * from the access vector table.
	 */
	type_rules = malloc(sizeof(struct avtab_node)*policydb.p_types.nprim);
	if (!type_rules) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	memset(type_rules, 0, sizeof(struct avtab_node)*policydb.p_types.nprim);
	if (avtab_map(&policydb.te_avtab, create_type_rules, type_rules))
		exit(1);
	

	/*
	 * Compare the type lists and identify equivalent types.
	 */
	for (i = 0; i < policydb.p_types.nprim - 1; i++) {
		if (!type_rules[i].next)
			continue;
		for (j = i + 1; j < policydb.p_types.nprim; j++) {
			for (l1 = type_rules[i].next, l2 = type_rules[j].next; l1 && l2;
			     l1 = l1->next, l2 = l2->next) {
				if (l2->key.source_type == (j+1)) {
					if (l1->key.source_type != (i+1))
						break;
				} else {
					if (l1->key.source_type != l2->key.source_type)
						break;
				}
				if (l2->key.target_type == (j+1)) {
					if (l1->key.target_type != (i+1))
						break;
				} else {
					if (l1->key.target_type != l2->key.target_type)
						break;
				}
				if (l1->key.target_class != l2->key.target_class || 
				    l1->datum.allowed != l2->datum.allowed)
					break;
			}
			if (l1 || l2) 
				continue;
			free_type_rules(type_rules[j].next);
			type_rules[j].next = NULL;
			printf("Types %s and %s are equivalent.\n",
			       policydb.p_type_val_to_name[i],
			       policydb.p_type_val_to_name[j]);
		}
		free_type_rules(type_rules[i].next);		
		type_rules[i].next = NULL;
	}

	free(type_rules);	
	return 0;
}
#endif 

static void cond_check_type_rules_list(cond_av_list_t *list)
{
	cond_av_list_t *cur = list;

	while (cur) {
		if (cur->node->datum.specified & AVTAB_TYPE) {
			if (avtab_search(&policydbp->te_avtab, &cur->node->key, AVTAB_TYPE)) {
				fprintf(stderr, "conditional type rule for (%s, %s : %s) conflicts with entry in base policy; "
					"conditional rule discarded.\n", policydbp->p_type_val_to_name[cur->node->key.source_type-1],
					policydbp->p_type_val_to_name[cur->node->key.target_type-1],
					policydbp->p_class_val_to_name[cur->node->key.target_class-1]);
				cur->node->parse_context = (void*)0;
			} else {
				cur->node->parse_context = (void*)1;
			}
		} else {
			cur->node->parse_context = (void*)1;
		}
		cur = cur->next;
	}
}

/* check for duplicate type rules - this has to be done after all of
 * the parsing is finished because the conditional and base type rules
 * are collected in the same pass */
static void cond_check_type_rules(void)
{
	cond_list_t *node;

	for (node = policydbp->cond_list; node != NULL; node = node->next) {
		cond_check_type_rules_list(node->true_list);
		cond_check_type_rules_list(node->false_list);
	}
}

extern char *av_to_string(uint32_t tclass, access_vector_t av);

void check_assertion_helper(unsigned int stype, unsigned int ttype, ebitmap_t *tclasses, 
			    access_vector_t *avp, unsigned long line) 
{
	avtab_key_t avkey;
	avtab_datum_t *avdatump;
	unsigned int k;
	

	for (k = ebitmap_startbit(tclasses); k < ebitmap_length(tclasses); k++) {
		if (!ebitmap_get_bit(tclasses, k)) 
			continue;
		avkey.source_type = stype + 1;
		avkey.target_type = ttype + 1;
		avkey.target_class = k + 1;
		avdatump = avtab_search(&policydb.te_avtab, &avkey, AVTAB_AV);
		if (!avdatump) 
			continue;

		if ((avdatump->specified & AVTAB_ALLOWED) &&
		    (avtab_allowed(avdatump) & avp[k])) {
			fprintf(stderr, "assertion on line %ld violated by allow %s %s:%s {%s };\n", line, policydb.p_type_val_to_name[stype], policydb.p_type_val_to_name[ttype], policydb.p_class_val_to_name[k], 
				av_to_string(k+1,
					     avtab_allowed(avdatump) & avp[k]));
			policydb_errors++;
		}
	}
}

void check_assertions(void) 
{
	te_assert_t *a, *tmp;
	unsigned int i, j;

	a = te_assertions;
	while (a) {
		for (i = ebitmap_startbit(&a->stypes); i < ebitmap_length(&a->stypes); i++) {
			if (!ebitmap_get_bit(&a->stypes, i))
				continue;
			if (a->self) {
				check_assertion_helper(i, i, &a->tclasses, a->avp, a->line);
			}
			for (j = ebitmap_startbit(&a->ttypes); j < ebitmap_length(&a->ttypes); j++) {
				if (!ebitmap_get_bit(&a->ttypes, j)) 
					continue;
				check_assertion_helper(i, j, &a->tclasses, a->avp, a->line);
			}
		}
		tmp = a;
		a = a->next;
		ebitmap_destroy(&tmp->stypes);
		ebitmap_destroy(&tmp->ttypes);
		ebitmap_destroy(&tmp->tclasses);
		free(tmp->avp);
		free(tmp);
	}
}

int display_bools()
{
	int i;

	for (i = 0; i < policydbp->p_bools.nprim; i++) {
		printf("%s : %d\n", policydbp->p_bool_val_to_name[i],
			policydbp->bool_val_to_struct[i]->state);
	}
	return 0;
}

void display_expr(cond_expr_t *exp)
{

	cond_expr_t *cur;
	for (cur = exp; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			printf("%s ", policydbp->p_bool_val_to_name[cur->bool - 1]);
			break;
		case COND_NOT:
			printf("! ");
			break;
		case COND_OR:
			printf("|| ");
			break;
		case COND_AND:
			printf("&& ");
			break;
		case COND_XOR:
			printf("^ ");
			break;
		case COND_EQ:
			printf("== ");
			break;
		case COND_NEQ:
			printf("!= ");
			break;
		default:
			printf("error!");
			break;
		}
	}
}

int display_cond_expressions()
{
	cond_node_t *cur;

	for (cur = policydbp->cond_list; cur != NULL; cur = cur->next) {
		printf("expression: ");
		display_expr(cur->expr);
		printf("current state: %d\n", cur->cur_state);
	}
	return 0;
}

int change_bool(char *name, int state)
{
	cond_bool_datum_t *bool;

	bool = hashtab_search(policydbp->p_bools.table, name);
	if (bool == NULL) {
		printf("Could not find bool %s\n", name);
		return -1;
	}
	bool->state = state;
	evaluate_conds(policydbp);
	return 0;
}

int main(int argc, char **argv)
{
	security_class_t tclass;
	security_id_t ssid, tsid, *sids;
	security_context_t scontext;
	struct av_decision avd;
	class_datum_t *cladatum;
	char ans[80 + 1], *file = txtfile, *outfile = NULL, *path, *fstype;
	size_t scontext_len, pathlen;
	unsigned int i;
	unsigned int protocol, port;
	unsigned int binary = 0, debug = 0;
	struct val_to_name v;
	int ret, ch, fd;
	unsigned int nel;
	struct stat sb;
	void *map;
	FILE *outfp = NULL;
	char *name;
	int state;
	int show_version = 0;
	struct policy_file pf;


	while ((ch = getopt(argc, argv, "o:dbVc:")) != EOF) {
		switch (ch) {
		case 'o':
			outfile = optarg;
			break;
		case 'b':
			binary = 1;
			file = binfile;
			break;
		case 'd':
			debug = 1;
			break;
		case 'V':
			show_version = 1;
			break;
		case 'c': {
			long int n = strtol(optarg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid policyvers specified: %s\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			if (n < POLICYDB_VERSION_MIN || n > POLICYDB_VERSION_MAX) {
				fprintf(stderr, "policyvers value %ld not in range %d-%d\n",
					n, POLICYDB_VERSION_MIN, POLICYDB_VERSION_MAX);
				usage(argv[0]);
				exit(1);
			}
			if (policyvers != n)
				policyvers = n;
			break;
		}
		default:
			usage(argv[0]);
		}
	}

	if (show_version) {
#ifdef CONFIG_SECURITY_SELINUX_MLS	
		printf("%d-mls (compatibility range %d-%d)\n", policyvers, POLICYDB_VERSION_MAX, POLICYDB_VERSION_MIN);
#else
		printf("%d (compatibility range %d-%d)\n", policyvers, POLICYDB_VERSION_MAX, POLICYDB_VERSION_MIN);
#endif
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
	sepol_set_policydb(&policydb);
	sepol_set_sidtab(&sidtab);

	if (binary) {
		fd = open(file, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Can't open '%s':  %s\n",
				file, strerror(errno));
			exit(1);
		}
		if (fstat(fd, &sb) < 0) {
			fprintf(stderr, "Can't stat '%s':  %s\n",
				file, strerror(errno));
			exit(1);
		}
		map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (map == MAP_FAILED) {
			fprintf(stderr, "Can't map '%s':  %s\n",
				file, strerror(errno));
			exit(1);
		}
		pf.type = PF_USE_MEMORY;
		pf.data = map;
		pf.len = sb.st_size;
		ret = policydb_read(&policydb, &pf, 1);
		if (ret) {
			fprintf(stderr, "%s:  error(s) encountered while parsing configuration\n", argv[0]);
			exit(1);
		}
		policydbp = &policydb;
	} else {
		yyin = fopen(file, "r");
		if (!yyin) {
			fprintf(stderr, "%s:  unable to open %s\n", argv[0], 
				file);
			exit(1);
		}

		if (policydb_init(&policydb))
			exit(1);

		id_queue = queue_create();
		if (!id_queue) {
			fprintf(stderr, "%s:  out of memory\n", argv[0]);
			exit(1);
		}
		policydbp = &policydb;
		policydb_errors = 0;
		pass = 1;
		if (yyparse() || policydb_errors) {
			fprintf(stderr, "%s:  error(s) encountered while parsing configuration\n", argv[0]);
			exit(1);
		}
		rewind(yyin);
		policydb_lineno = 1;
		source_file[0] = '\0';
		source_lineno = 1;
		yyrestart(yyin);
		pass = 2;
		if (yyparse() || policydb_errors) {
			fprintf(stderr, "%s:  error(s) encountered while parsing configuration\n", argv[0]);
			exit(1);
		}
		queue_destroy(id_queue);

		cond_check_type_rules();
		cond_optimize_lists(policydb.cond_list);

		check_assertions();
		if (policydb_errors) 
			exit(1);

		if (policyvers >= POLICYDB_VERSION_NLCLASS &&
		    policydb.p_classes.nprim < SECCLASS_NETLINK_DNRT_SOCKET) {
			fprintf(stderr, "%s:  policy lacks new netlink classes, unable to generate policy version %d\n", argv[0], policyvers);
			exit(1);
		}
	    
		/* remove type attributes */
		hashtab_map_remove_on_error(policydb.p_types.table, 
					    type_attr_remove, 0, 0);
		fclose(yyin);
	}

	if (policydb_load_isids(&policydb, &sidtab))
		exit(1);

	printf("%s:  policy configuration loaded\n", argv[0]);

	if (outfile) {
		printf("%s:  writing binary representation (version %d) to %s\n",
		       argv[0], policyvers, outfile);
		outfp = fopen(outfile, "w");
		if (!outfp) {
			perror(outfile);
			exit(1);
		}

		sepol_set_policyvers(policyvers);

		pf.type = PF_USE_STDIO;
		pf.fp = outfp;
		ret = policydb_write(&policydb, &pf);
		if (ret) {
			fprintf(stderr, "%s:  error writing %s\n",
				argv[0], outfile);
			exit(1);
		}
		fclose(outfp);
	}
	if (!debug)
		exit(0);

      menu:
	printf("\nSelect an option:\n");
	printf("0)  Call compute_access_vector\n");
	printf("1)  Call sid_to_context\n");
	printf("2)  Call context_to_sid\n");
	printf("3)  Call transition_sid\n");
	printf("4)  Call member_sid\n");
	printf("5)  Call change_sid\n");
	printf("6)  Call list_sids\n");
	printf("7)  Call load_policy\n");
	printf("8)  Call fs_sid\n");
	printf("9)  Call port_sid\n");
	printf("a)  Call netif_sid\n");
	printf("b)  Call node_sid\n");
	printf("c)  Call fs_use\n");
	printf("d)  Call genfs_sid\n");
	printf("e)  Call get_user_sids\n");
	printf("f)  display conditional bools\n");
	printf("g)  display conditional expressions\n");
	printf("h)  change a boolean value\n");
#ifdef EQUIVTYPES
	printf("z)  Show equivalent types\n");
#endif
	printf("m)  Show menu again\n");
	printf("q)  Exit\n");
	while (1) {
		printf("\nChoose:  ");
		fgets(ans, sizeof(ans), stdin);
		switch (ans[0]) {
		case '0':
			printf("source sid?  ");
			fgets(ans, sizeof(ans), stdin);
			ssid = atoi(ans);

			printf("target sid?  ");
			fgets(ans, sizeof(ans), stdin);
			tsid = atoi(ans);

			printf("target class?  ");
			fgets(ans, sizeof(ans), stdin);
			if (isdigit(ans[0])) {
				tclass = atoi(ans);
				if (!tclass || tclass > policydb.p_classes.nprim) {
					printf("\nNo such class.\n");
					break;
				}
				cladatum = policydb.class_val_to_struct[tclass - 1];
			} else {
				ans[strlen(ans) - 1] = 0;
				cladatum = (class_datum_t *) hashtab_search(policydb.p_classes.table,
								    ans);
				if (!cladatum) {
					printf("\nNo such class\n");
					break;
				}
				tclass = cladatum->value;
			}

			if (!cladatum->comdatum && !cladatum->permissions.nprim) {
				printf("\nNo access vector definition for that class\n");
				break;
			}
			ret = sepol_compute_av(ssid, tsid, tclass, 0,
						  &avd);
			switch (ret) {
			case 0:
				printf("\nallowed {");
				for (i = 1; i <= sizeof(avd.allowed) * 8; i++) {
					if (avd.allowed & (1 << (i - 1))) {
						v.val = i;
						ret = hashtab_map(cladatum->permissions.table,
								   find_perm, &v);
						if (!ret && cladatum->comdatum) {
							ret = hashtab_map(cladatum->comdatum->permissions.table,
									 find_perm, &v);
						}
						if (ret)
							printf(" %s", v.name);
					}
				}
				printf(" }\n");
				break;
			case -EINVAL:
				printf("\ninvalid sid\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '1':
			printf("sid?  ");
			fgets(ans, sizeof(ans), stdin);
			ssid = atoi(ans);
			ret = sepol_sid_to_context(ssid,
					       &scontext, &scontext_len);
			switch (ret) {
			case 0:
				printf("\nscontext %s\n", scontext);
				free(scontext);
				break;
			case -EINVAL:
				printf("\ninvalid sid\n");
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '2':
			printf("scontext?  ");
			fgets(ans, sizeof(ans), stdin);
			scontext_len = strlen(ans);
			ans[scontext_len - 1] = 0;
			ret = sepol_context_to_sid(ans, scontext_len,
						      &ssid);
			switch (ret) {
			case 0:
				printf("\nsid %d\n", ssid);
				break;
			case -EINVAL:
				printf("\ninvalid context\n");
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '3':
		case '4':
		case '5':
			ch = ans[0];

			printf("source sid?  ");
			fgets(ans, sizeof(ans), stdin);
			ssid = atoi(ans);
			printf("target sid?  ");
			fgets(ans, sizeof(ans), stdin);
			tsid = atoi(ans);

			printf("object class?  ");
			fgets(ans, sizeof(ans), stdin);
			if (isdigit(ans[0])) {
				tclass = atoi(ans);
				if (!tclass || tclass > policydb.p_classes.nprim) {
					printf("\nNo such class.\n");
					break;
				}
			} else {
				ans[strlen(ans) - 1] = 0;
				cladatum = (class_datum_t *) hashtab_search(policydb.p_classes.table,
								    ans);
				if (!cladatum) {
					printf("\nNo such class\n");
					break;
				}
				tclass = cladatum->value;
			}

			if (ch == '3')
				ret = sepol_transition_sid(ssid, tsid, tclass, &ssid);
			else if (ch == '4')
				ret = sepol_member_sid(ssid, tsid, tclass, &ssid);
			else 
				ret = sepol_change_sid(ssid, tsid, tclass, &ssid);
			switch (ret) {
			case 0:
				printf("\nsid %d\n", ssid);
				break;
			case -EINVAL:
				printf("\ninvalid sid\n");
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '6':
			sepol_sidtab_map(&sidtab, print_sid, 0);
			break;
		case '7':
			printf("pathname?  ");
			fgets(ans, sizeof(ans), stdin);
			pathlen = strlen(ans);
			ans[pathlen - 1] = 0;
			printf("%s:  loading policy configuration from %s\n", argv[0], ans);
			fd = open(ans, O_RDONLY);
			if (fd < 0) {
				fprintf(stderr, "Can't open '%s':  %s\n",
					ans, strerror(errno));
				break;
			}
			if (fstat(fd, &sb) < 0) {
				fprintf(stderr, "Can't stat '%s':  %s\n",
					ans, strerror(errno));
				break;
			}
			map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
			if (map == MAP_FAILED) {
				fprintf(stderr, "Can't map '%s':  %s\n",
					ans, strerror(errno));
				break;
			}
			ret = sepol_load_policy(map,sb.st_size);
			switch (ret) {
			case 0:
				printf("\nsuccess\n");
				break;
			case -EINVAL:
				printf("\ninvalid policy\n");
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			default:
				printf("return code 0x%x\n", ret);
			}
			break;
		case '8':
			printf("fs kdevname?  ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			sepol_fs_sid(ans, &ssid, &tsid);
			printf("fs_sid %d default_file_sid %d\n",
			       ssid, tsid);
			break;
		case '9':
			printf("protocol?  ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			if (!strcmp(ans, "tcp") || !strcmp(ans, "TCP"))
				protocol = IPPROTO_TCP;
			else if (!strcmp(ans, "udp") || !strcmp(ans, "UDP"))
				protocol = IPPROTO_UDP;
			else {
				printf("unknown protocol\n");
				break;
			}
			printf("port? ");
			fgets(ans, sizeof(ans), stdin);
			port = atoi(ans);
			sepol_port_sid(0, 0, protocol, port, &ssid);
			printf("sid %d\n", ssid);
			break;
		case 'a':
			printf("netif name?  ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			sepol_netif_sid(ans, &ssid, &tsid);
			printf("if_sid %d default_msg_sid %d\n",
			       ssid, tsid);
			break;
		case 'b': {
			char *p;
			int family, len;
			struct in_addr addr4;
			struct in6_addr addr6;
			
			printf("protocol family? ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			if (!strcasecmp(ans, "ipv4"))
				family = AF_INET;
			else if (!strcasecmp(ans, "ipv6"))
				family = AF_INET6;
			else {
				printf("unknown protocol family\n");
				break;
			}
			
			printf("node address?  ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			
			if (family == AF_INET) {
				p = (char *)&addr4;
				len = sizeof(addr4);
			} else {
				p = (char *)&addr6;
				len = sizeof(addr6);
			}
			
			if (inet_pton(family, ans, p) < 1) {
				printf("error parsing address\n");
				break;
			}

			sepol_node_sid(family, p, len, &ssid);
			printf("sid %d\n", ssid);
			break;
		}	
		case 'c':
			printf("fstype?  ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			sepol_fs_use(ans, &ret, &ssid);
			switch (ret) {
			case SECURITY_FS_USE_XATTR:
				printf("use xattr\n");
				break;
			case SECURITY_FS_USE_TRANS:
				printf("use transition SIDs\n");
				break;
			case SECURITY_FS_USE_TASK:
				printf("use task SIDs\n");
				break;
			case SECURITY_FS_USE_GENFS:
				printf("use genfs\n");
				break;
			case SECURITY_FS_USE_NONE:
				printf("no labeling support\n");
				break;
			}
			printf("sid %d\n", ssid);
			break;
		case 'd':
			printf("fstype?  ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			fstype = strdup(ans);
			printf("path?  ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			path = strdup(ans);
			printf("object class?  ");
			fgets(ans, sizeof(ans), stdin);
			if (isdigit(ans[0])) {
				tclass = atoi(ans);
				if (!tclass || tclass > policydb.p_classes.nprim) {
					printf("\nNo such class.\n");
					break;
				}
			} else {
				ans[strlen(ans) - 1] = 0;
				cladatum = (class_datum_t *) hashtab_search(policydb.p_classes.table,
								    ans);
				if (!cladatum) {
					printf("\nNo such class\n");
					break;
				}
				tclass = cladatum->value;
			}
			sepol_genfs_sid(fstype, path, tclass, &ssid);
			printf("sid %d\n", ssid);
			free(fstype);
			free(path);
			break;
		case 'e':
			printf("from SID?  ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			ssid = atoi(ans);

			printf("username?  ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;

			ret = sepol_get_user_sids(ssid, ans, &sids, &nel);
			switch (ret) {
			case 0:
			        if (!nel)
				        printf("\nnone\n");
				for (i = 0; i < nel; i++)
					print_sid(sids[i],NULL,NULL);
				free(sids);
				break;
			case -ENOMEM:
				printf("\nout of memory\n");
				break;
			case -EINVAL:
				printf("\ninvalid argument\n");
				break;
			default:
				printf("\nerror\n");
				break;
			}
			break;
		case 'f':
			display_bools();
			break;
		case 'g':
			display_cond_expressions();
			break;
		case 'h':
			printf("name? ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;
			
			name = malloc((strlen(ans) + 1) * sizeof(char));
			if (name == NULL) {
				fprintf(stderr, "couldn't malloc string.\n");
				break;
			}
			strcpy(name, ans);


			printf("state? ");
			fgets(ans, sizeof(ans), stdin);
			ans[strlen(ans) - 1] = 0;

			if (atoi(ans))
				state = 1;
			else
				state = 0;

			change_bool(name, state);
			free(name);
			break;
#ifdef EQUIVTYPES
		case 'z':
			identify_equiv_types();
			break;
#endif
		case 'm':
			goto menu;
		case 'q':
			exit(0);
			break;
		default:
			printf("\nUnknown option %s.\n", ans);
		}
	}

	return 0;
}

/* FLASK */

