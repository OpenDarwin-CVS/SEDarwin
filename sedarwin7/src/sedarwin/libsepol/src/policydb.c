
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/* Updated: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* FLASK */

/*
 * Implementation of the policy database.
 */

#include <stdlib.h>

#include <sepol/policydb.h>
#include <sepol/mls.h>
#include <sepol/conditional.h>

#include "private.h"

/* These need to be updated if SYM_NUM or OCON_NUM changes */
static struct policydb_compat_info policydb_compat[] = {
	{
		.version	= POLICYDB_VERSION_BASE,
		.sym_num	= SYM_NUM - 1,
		.ocon_num	= OCON_NUM - 1,
	},
	{
		.version	= POLICYDB_VERSION_BOOL,
		.sym_num	= SYM_NUM,
		.ocon_num	= OCON_NUM - 1,
	},
	{
		.version	= POLICYDB_VERSION_IPV6,
		.sym_num	= SYM_NUM,
		.ocon_num	= OCON_NUM,
	},
	{
		.version	= POLICYDB_VERSION_NLCLASS,
		.sym_num	= SYM_NUM,
		.ocon_num	= OCON_NUM,
	},
};

#if 0
static char *symtab_name[SYM_NUM] = {
	"common prefixes",
	"classes",
	"roles",
	"types",
	"users",
	"bools"
	mls_symtab_names
	cond_symtab_names
};
#endif

static unsigned int symtab_sizes[SYM_NUM] = {
	2,
	32,
	16,
	512,
	128,
	mls_symtab_sizes
	16
};

struct policydb_compat_info *policydb_lookup_compat(int version)
{
	int i;
	struct policydb_compat_info *info = NULL;
	
	for (i = 0; i < sizeof(policydb_compat)/sizeof(*info); i++) {
		if (policydb_compat[i].version == version) {
			info = &policydb_compat[i];
			break;
		}
	}
	return info;
}

/* 
 * Initialize the role table.
 */
static int roles_init(policydb_t *p)
{
	char *key = 0;
	int rc;
	role_datum_t *role;

	role = malloc(sizeof(role_datum_t));
	if (!role) {
		rc = -ENOMEM;
		goto out;
	}	
	memset(role, 0, sizeof(role_datum_t));
	role->value = ++p->p_roles.nprim;
	if (role->value != OBJECT_R_VAL) {
		rc = -EINVAL;
		goto out_free_role;
	}
	key = malloc(strlen(OBJECT_R)+1);
	if (!key) {
		rc = -ENOMEM;
		goto out_free_role;
	}
	strcpy(key, OBJECT_R);
	rc = hashtab_insert(p->p_roles.table, key, role);
	if (rc)
		goto out_free_key;
out:	
	return rc;

out_free_key:
	free(key);
out_free_role:
	free(role);
	goto out;
}


/*
 * Initialize a policy database structure.
 */
int policydb_init(policydb_t * p)
{
	int i, rc;

	memset(p, 0, sizeof(policydb_t));

	for (i = 0; i < SYM_NUM; i++) {
		p->sym_val_to_name[i] = NULL;
		rc = symtab_init(&p->symtab[i], symtab_sizes[i]);
		if (rc)
			goto out_free_symtab;
	}

	rc = avtab_init(&p->te_avtab);
	if (rc)
		goto out_free_symtab;

	rc = roles_init(p);
	if (rc)
		goto out_free_avtab;

	rc = cond_policydb_init(p);
	if (rc)
		goto out_free_avtab;
out:
	return rc;

out_free_avtab:
	avtab_destroy(&p->te_avtab);
	
out_free_symtab:
	for (i = 0; i < SYM_NUM; i++)
		hashtab_destroy(p->symtab[i].table);
	goto out;
}


/*
 * The following *_index functions are used to
 * define the val_to_name and val_to_struct arrays
 * in a policy database structure.  The val_to_name
 * arrays are used when converting security context
 * structures into string representations.  The
 * val_to_struct arrays are used when the attributes
 * of a class, role, or user are needed.
 */

static int common_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	common_datum_t *comdatum;


	comdatum = (common_datum_t *) datum;
	p = (policydb_t *) datap;
	if (!comdatum->value || comdatum->value > p->p_commons.nprim)
		return -EINVAL;
	p->p_common_val_to_name[comdatum->value - 1] = (char *) key;

	return 0;
}


static int class_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	class_datum_t *cladatum;


	cladatum = (class_datum_t *) datum;
	p = (policydb_t *) datap;
	if (!cladatum->value || cladatum->value > p->p_classes.nprim)
		return -EINVAL;
	p->p_class_val_to_name[cladatum->value - 1] = (char *) key;
	p->class_val_to_struct[cladatum->value - 1] = cladatum;

	return 0;
}


static int role_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	role_datum_t *role;


	role = (role_datum_t *) datum;
	p = (policydb_t *) datap;
	if (!role->value || role->value > p->p_roles.nprim)
		return -EINVAL;
	p->p_role_val_to_name[role->value - 1] = (char *) key;
	p->role_val_to_struct[role->value - 1] = role;

	return 0;
}


static int type_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	type_datum_t *typdatum;


	typdatum = (type_datum_t *) datum;
	p = (policydb_t *) datap;

	if (typdatum->primary) {
		if (!typdatum->value || typdatum->value > p->p_types.nprim)
			return -EINVAL;
		p->p_type_val_to_name[typdatum->value - 1] = (char *) key;
	}

	return 0;
}

static int user_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	user_datum_t *usrdatum;


	usrdatum = (user_datum_t *) datum;
	p = (policydb_t *) datap;

	if (!usrdatum->value || usrdatum->value > p->p_users.nprim)
		return -EINVAL;

	p->p_user_val_to_name[usrdatum->value - 1] = (char *) key;
	p->user_val_to_struct[usrdatum->value - 1] = usrdatum;

	return 0;
}

static int (*index_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum, void *datap) =
{
	common_index,
	class_index,
	role_index,
	type_index,
	user_index,
	mls_index_f
	cond_index_bool
};


/*
 * Define the common val_to_name array and the class
 * val_to_name and val_to_struct arrays in a policy
 * database structure.  
 */
int policydb_index_classes(policydb_t * p)
{
	p->p_common_val_to_name = (char **)
	    malloc(p->p_commons.nprim * sizeof(char *));
	if (!p->p_common_val_to_name)
		return -1;

	if (hashtab_map(p->p_commons.table, common_index, p))
		return -1;

	p->class_val_to_struct = (class_datum_t **)
	    malloc(p->p_classes.nprim * sizeof(class_datum_t *));
	if (!p->class_val_to_struct)
		return -1;

	p->p_class_val_to_name = (char **)
	    malloc(p->p_classes.nprim * sizeof(char *));
	if (!p->p_class_val_to_name)
		return -1;

	if (hashtab_map(p->p_classes.table, class_index, p))
		return -1;

	return 0;
}

int policydb_index_bools(policydb_t * p)
{

	if (cond_init_bool_indexes(p) == -1)
		return -1;
	p->p_bool_val_to_name = (char **)
		malloc(p->p_bools.nprim * sizeof(char *));
	if (!p->p_bool_val_to_name)
		return -1;
	if (hashtab_map(
		    p->p_bools.table, 
		    cond_index_bool, 
		    p))
		return -1;
	return 0;
}

/*
 * Define the other val_to_name and val_to_struct arrays
 * in a policy database structure.  
 */
int policydb_index_others(policydb_t * p, unsigned verbose)
{
	int i;


	if (verbose) {
		printf("security:  %d users, %d roles, %d types, %d bools",
		       p->p_users.nprim, p->p_roles.nprim, p->p_types.nprim, p->p_bools.nprim);
		mls_policydb_index_others(p);
		printf("\n");

		printf("security:  %d classes, %d rules\n",
		       p->p_classes.nprim, p->te_avtab.nel);
	}

#if 0
	avtab_hash_eval(&p->te_avtab, "rules");
	for (i = 0; i < SYM_NUM; i++) 
		hashtab_hash_eval(p->symtab[i].table, symtab_name[i]);
#endif

	p->role_val_to_struct = (role_datum_t **)
	    malloc(p->p_roles.nprim * sizeof(role_datum_t *));
	if (!p->role_val_to_struct)
		return -1;

	p->user_val_to_struct = (user_datum_t **)
	    malloc(p->p_users.nprim * sizeof(user_datum_t *));
	if (!p->user_val_to_struct)
		return -1;

	cond_init_bool_indexes(p);

	for (i = SYM_ROLES; i < SYM_NUM; i++) {
		if (p->sym_val_to_name[i])
			free(p->sym_val_to_name[i]);
		p->sym_val_to_name[i] = (char **)
		    malloc(p->symtab[i].nprim * sizeof(char *));
		if (!p->sym_val_to_name[i])
			return -1;
		if (hashtab_map(p->symtab[i].table, index_f[i], p))
			return -1;
	}

	return 0;
}


/*
 * The following *_destroy functions are used to
 * free any memory allocated for each kind of
 * symbol data in the policy database.
 */

static int perm_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	if (key)
		free(key);
	free(datum);
	return 0;
}


static int common_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	common_datum_t *comdatum;

	if (key)
		free(key);
	comdatum = (common_datum_t *) datum;
	hashtab_map(comdatum->permissions.table, perm_destroy, 0);
	hashtab_destroy(comdatum->permissions.table);
	free(datum);
	return 0;
}


static int class_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	class_datum_t *cladatum;
	constraint_node_t *constraint, *ctemp;
	constraint_expr_t *e, *etmp;

	if (key)
		free(key);
	cladatum = (class_datum_t *) datum;
	hashtab_map(cladatum->permissions.table, perm_destroy, 0);
	hashtab_destroy(cladatum->permissions.table);
	constraint = cladatum->constraints;
	while (constraint) {
		e = constraint->expr;
		while (e) {
			ebitmap_destroy(&e->names);
			etmp = e;
			e = e->next;
			free(etmp);
		}
		ctemp = constraint;
		constraint = constraint->next;
		free(ctemp);
	}
	if (cladatum->comkey)
		free(cladatum->comkey);
	free(datum);
	return 0;
}

static int role_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	role_datum_t *role;

	if (key)
		free(key);
	role = (role_datum_t *) datum;
	ebitmap_destroy(&role->dominates);
	ebitmap_destroy(&role->types);
	free(datum);
	return 0;
}

static int type_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	if (key)
		free(key);
	free(datum);
	return 0;
}

static int user_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	user_datum_t *usrdatum;

	if (key)
		free(key);
	usrdatum = (user_datum_t *) datum;
	ebitmap_destroy(&usrdatum->roles);
	mls_user_destroy(usrdatum);
	free(datum);
	return 0;
}


static int (*destroy_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum, void *datap) =
{
	common_destroy,
	class_destroy,
	role_destroy,
	type_destroy,
	user_destroy,
	mls_destroy_f
	cond_destroy_bool
};


/*
 * Free any memory allocated by a policy database structure.
 */
void policydb_destroy(policydb_t * p)
{
	ocontext_t *c, *ctmp;
	genfs_t *g, *gtmp;
	int i;

	for (i = 0; i < SYM_NUM; i++) {
		hashtab_map(p->symtab[i].table, destroy_f[i], 0);
		hashtab_destroy(p->symtab[i].table);
	}

	for (i = 0; i < SYM_NUM; i++) {
		if (p->sym_val_to_name[i])
			free(p->sym_val_to_name[i]);
	}

	if (p->class_val_to_struct)
		free(p->class_val_to_struct);
	if (p->role_val_to_struct)
		free(p->role_val_to_struct);
	if (p->user_val_to_struct)
		free(p->user_val_to_struct);

	avtab_destroy(&p->te_avtab);

	for (i = 0; i < OCON_NUM; i++) {
		c = p->ocontexts[i];
		while (c) {
			ctmp = c;
			c = c->next;
			context_destroy(&ctmp->context[0]);
			context_destroy(&ctmp->context[1]);
			if (i == OCON_ISID || i == OCON_FS || i == OCON_NETIF || i == OCON_FSUSE)
				free(ctmp->u.name);
			free(ctmp);
		}
	}

	g = p->genfs;
	while (g) {
		free(g->fstype);
		c = g->head;
		while (c) {
			ctmp = c;
			c = c->next;
			context_destroy(&ctmp->context[0]);
			free(ctmp->u.name);
			free(ctmp);
		}
		gtmp = g;
		g = g->next;
		free(gtmp);
	}
	cond_policydb_destroy(p);
	return;
}

/*
 * Load the initial SIDs specified in a policy database
 * structure into a SID table.
 */
int policydb_load_isids(policydb_t *p, sidtab_t *s) 
{
	ocontext_t *head, *c;

	if (sepol_sidtab_init(s)) {
		printf("security:  out of memory on SID table init\n");
		return -1;
	}

	head = p->ocontexts[OCON_ISID];
	for (c = head; c; c = c->next) {
		if (!c->context[0].user) {
			printf("security:  SID %s was never defined.\n", 
			       c->u.name);
			return -1;
		}
		if (sepol_sidtab_insert(s, c->sid[0], &c->context[0])) {
			printf("security:  unable to load initial SID %s.\n", 
			       c->u.name);
			return -1;
		}
	}

	return 0;
}

/*
 * Return 1 if the fields in the security context 
 * structure `c' are valid.  Return 0 otherwise.
 */
int policydb_context_isvalid(policydb_t *p, context_struct_t *c)
{
	role_datum_t *role;
	user_datum_t *usrdatum;


	if (!c->role || c->role > p->p_roles.nprim)
		return 0;

	if (!c->user || c->user > p->p_users.nprim)
		return 0;

	if (!c->type || c->type > p->p_types.nprim)
		return 0;

	if (c->role != OBJECT_R_VAL) {
		/*
		 * Role must be authorized for the type.
		 */
		role = p->role_val_to_struct[c->role - 1];
		if (!ebitmap_get_bit(&role->types,
				     c->type - 1))
			/* role may not be associated with type */
			return 0;
		
		/*
		 * User must be authorized for the role.
		 */
		usrdatum = p->user_val_to_struct[c->user - 1];
		if (!usrdatum)
			return 0;

		if (!ebitmap_get_bit(&usrdatum->roles,
				     c->role - 1))
			/* user may not be associated with role */
			return 0;
	}

	if (!mls_context_isvalid(p, c))
		return 0;

	return 1;
}


/*
 * Read and validate a security context structure
 * from a policydb binary representation file.
 */
static int context_read_and_validate(context_struct_t * c,
				     policydb_t * p,
				     struct policy_file * fp)
{
	uint32_t *buf;

	buf = next_entry(fp, sizeof(uint32_t)*3);
	if (!buf) {
		printf("security: context truncated\n");
		return -1;
	}
	c->user = le32_to_cpu(buf[0]);
	c->role = le32_to_cpu(buf[1]);
	c->type = le32_to_cpu(buf[2]);
	if (mls_read_range(c, fp)) {
		printf("security: error reading MLS range of context\n");
		return -1;
	}

	if (!policydb_context_isvalid(p, c)) {
		printf("security:  invalid security context\n");
		context_destroy(c);
		return -1;
	}
	return 0;
}


/*
 * The following *_read functions are used to
 * read the symbol data from a policy database
 * binary representation file.
 */

static int perm_read(policydb_t * p __attribute__ ((unused)), hashtab_t h, struct policy_file * fp)
{
	char *key = 0;
	perm_datum_t *perdatum;
	uint32_t *buf;
	size_t len;

	perdatum = malloc(sizeof(perm_datum_t));
	if (!perdatum)
		return -1;
	memset(perdatum, 0, sizeof(perm_datum_t));

	buf = next_entry(fp, sizeof(uint32_t)*2);
	if (!buf)
		goto bad;

	len = le32_to_cpu(buf[0]);
	perdatum->value = le32_to_cpu(buf[1]);
	if (mls_read_perm(perdatum, fp))
		goto bad;

	buf = next_entry(fp, len);
	if (!buf)
		goto bad;
	key = malloc(len + 1);
	if (!key)
		goto bad;
	memcpy(key, buf, len);
	key[len] = 0;

	if (hashtab_insert(h, key, perdatum))
		goto bad;

	return 0;

      bad:
	perm_destroy(key, perdatum, NULL);
	return -1;
}


static int common_read(policydb_t * p, hashtab_t h, struct policy_file * fp)
{
	char *key = 0;
	common_datum_t *comdatum;
	uint32_t *buf;
	size_t len, nel;
	unsigned int i;

	comdatum = malloc(sizeof(common_datum_t));
	if (!comdatum)
		return -1;
	memset(comdatum, 0, sizeof(common_datum_t));

	buf = next_entry(fp, sizeof(uint32_t)*4);
	if (!buf)
		goto bad;

	len = le32_to_cpu(buf[0]);
	comdatum->value = le32_to_cpu(buf[1]);

	if (symtab_init(&comdatum->permissions, PERM_SYMTAB_SIZE))
		goto bad;
	comdatum->permissions.nprim = le32_to_cpu(buf[2]);
	nel = le32_to_cpu(buf[3]);

	buf = next_entry(fp, len);
	if (!buf)
		goto bad;
	key = malloc(len + 1);
	if (!key)
		goto bad;
	memcpy(key, buf, len);
	key[len] = 0;

	for (i = 0; i < nel; i++) {
		if (perm_read(p, comdatum->permissions.table, fp))
			goto bad;
	}

	if (hashtab_insert(h, key, comdatum))
		goto bad;

	return 0;

      bad:
	common_destroy(key, comdatum, NULL);
	return -1;
}


static int class_read(policydb_t * p, hashtab_t h, struct policy_file * fp)
{
	char *key = 0;
	class_datum_t *cladatum;
	constraint_node_t *c, *lc;
	constraint_expr_t *e, *le;
	uint32_t *buf;
	size_t len, len2, ncons, nexpr, nel;
	unsigned int i, j;
	int depth;

	cladatum = (class_datum_t *) malloc(sizeof(class_datum_t));
	if (!cladatum)
		return -1;
	memset(cladatum, 0, sizeof(class_datum_t));

	buf = next_entry(fp, sizeof(uint32_t)*6);
	if (!buf)
		goto bad;

	len = le32_to_cpu(buf[0]);
	len2 = le32_to_cpu(buf[1]);
	cladatum->value = le32_to_cpu(buf[2]);

	if (symtab_init(&cladatum->permissions, PERM_SYMTAB_SIZE))
		goto bad;
	cladatum->permissions.nprim = le32_to_cpu(buf[3]);
	nel = le32_to_cpu(buf[4]);

	ncons = le32_to_cpu(buf[5]);
	
	buf = next_entry(fp, len);
	if (!buf)
		goto bad;
	key = malloc(len + 1);
	if (!key)
		goto bad;
	memcpy(key, buf, len);
	key[len] = 0;

	if (len2) {
		cladatum->comkey = malloc(len2 + 1);
		if (!cladatum->comkey)
			goto bad;
		buf = next_entry(fp, len2);
		if (!buf)
			goto bad;
		memcpy(cladatum->comkey, buf, len2);
		cladatum->comkey[len2] = 0;

		cladatum->comdatum = hashtab_search(p->p_commons.table,
						    cladatum->comkey);
		if (!cladatum->comdatum) {
			printf("security:  unknown common %s\n", cladatum->comkey);
			goto bad;
		}
	}
	for (i = 0; i < nel; i++) {
		if (perm_read(p, cladatum->permissions.table, fp))
			goto bad;
	}

	lc = NULL;
	for (i = 0; i < ncons; i++) {
		c = malloc(sizeof(constraint_node_t));
		if (!c)
			goto bad;
		memset(c, 0, sizeof(constraint_node_t));
		buf = next_entry(fp, sizeof(uint32_t)*2);
		if (!buf)
			goto bad;
		c->permissions = le32_to_cpu(buf[0]);
		nexpr = le32_to_cpu(buf[1]);
		le = NULL;
		depth = -1;
		for (j = 0; j < nexpr; j++) {
			e = malloc(sizeof(constraint_expr_t));
			if (!e)
				goto bad;
			memset(e, 0, sizeof(constraint_expr_t));
			buf = next_entry(fp, sizeof(uint32_t)*3);
			if (!buf) {
				free(e);
				goto bad;
			}
			e->expr_type = le32_to_cpu(buf[0]);
			e->attr = le32_to_cpu(buf[1]);
			e->op = le32_to_cpu(buf[2]);

			switch (e->expr_type) {
			case CEXPR_NOT:
				if (depth < 0) {
					free(e);
					goto bad;
				}
				break;
			case CEXPR_AND:
			case CEXPR_OR:
				if (depth < 1) {
					free(e);
					goto bad;
				}
				depth--;
				break;
			case CEXPR_ATTR:
				if (depth == (CEXPR_MAXDEPTH-1)) {
					free(e);
					goto bad;
				}
				depth++;
				break;
			case CEXPR_NAMES:
				if (depth == (CEXPR_MAXDEPTH-1)) {
					free(e);
					goto bad;
				}
				depth++;
				if (ebitmap_read(&e->names, fp)) {
					free(e);
					goto bad;
				}
				break;
			default:
				free(e);
				goto bad;
				break;
			}
			if (le) {
				le->next = e;
			} else {
				c->expr = e;
			}
			le = e;
		}
		if (depth != 0)
			goto bad;
		if (lc) {
			lc->next = c;
		} else {
			cladatum->constraints = c;
		}
		lc = c;
	}

	if (mls_read_class(cladatum, fp))
		goto bad;

	if (hashtab_insert(h, key, cladatum))
		goto bad;

	return 0;

      bad:
	class_destroy(key, cladatum, NULL);
	return -1;
}


static int role_read(policydb_t * p __attribute__ ((unused)), hashtab_t h, struct policy_file * fp)
{
	char *key = 0;
	role_datum_t *role;
	uint32_t *buf;
	size_t len;

	role = malloc(sizeof(role_datum_t));
	if (!role)
		return -1;
	memset(role, 0, sizeof(role_datum_t));

	buf = next_entry(fp, sizeof(uint32_t)*2);
	if (!buf)
		goto bad;

	len = le32_to_cpu(buf[0]);
	role->value = le32_to_cpu(buf[1]);

	buf = next_entry(fp, len);
	if (!buf)
		goto bad;
	key = malloc(len + 1);
	if (!key)
		goto bad;
	memcpy(key, buf, len);
	key[len] = 0;

	if (ebitmap_read(&role->dominates, fp))
		goto bad;

	if (ebitmap_read(&role->types, fp))
		goto bad;

	if (strcmp(key, OBJECT_R) == 0) {
		if (role->value != OBJECT_R_VAL) {
			printf("Role %s has wrong value %d\n",
			       OBJECT_R, role->value);
			role_destroy(key, role, NULL);
			return -1;
		}
		role_destroy(key, role, NULL);
		return 0;
	}

	if (hashtab_insert(h, key, role))
		goto bad;

	return 0;

      bad:
	role_destroy(key, role, NULL);
	return -1;
}


static int type_read(policydb_t * p __attribute__ ((unused)), hashtab_t h, struct policy_file * fp)
{
	char *key = 0;
	type_datum_t *typdatum;
	uint32_t *buf;
	size_t len;

	typdatum = malloc(sizeof(type_datum_t));
	if (!typdatum)
		return -1;
	memset(typdatum, 0, sizeof(type_datum_t));

	buf = next_entry(fp, sizeof(uint32_t)*3);
	if (!buf)
		goto bad;

	len = le32_to_cpu(buf[0]);
	typdatum->value = le32_to_cpu(buf[1]);
	typdatum->primary = le32_to_cpu(buf[2]);

	buf = next_entry(fp, len);
	if (!buf)
		goto bad;
	key = malloc(len + 1);
	if (!key)
		goto bad;
	memcpy(key, buf, len);
	key[len] = 0;

	if (hashtab_insert(h, key, typdatum))
		goto bad;

	return 0;

      bad:
	type_destroy(key, typdatum, NULL);
	return -1;
}

static int user_read(policydb_t * p __attribute__ ((unused)), hashtab_t h, struct policy_file * fp)
{
	char *key = 0;
	user_datum_t *usrdatum;
	uint32_t *buf;
	size_t len;


	usrdatum = malloc(sizeof(user_datum_t));
	if (!usrdatum)
		return -1;
	memset(usrdatum, 0, sizeof(user_datum_t));

	buf = next_entry(fp, sizeof(uint32_t)*2);
	if (!buf)
		goto bad;

	len = le32_to_cpu(buf[0]);
	usrdatum->value = le32_to_cpu(buf[1]);

	buf = next_entry(fp, len);
	if (!buf)
		goto bad;
	key = malloc(len + 1);
	if (!key)
		goto bad;
	memcpy(key, buf, len);
	key[len] = 0;

	if (ebitmap_read(&usrdatum->roles, fp))
		goto bad;

	if (mls_read_user(usrdatum, fp))
		goto bad;

	if (hashtab_insert(h, key, usrdatum))
		goto bad;

	return 0;

      bad:
	user_destroy(key, usrdatum, NULL);
	return -1;
}


static int (*read_f[SYM_NUM]) (policydb_t * p, hashtab_t h, struct policy_file * fp) =
{
	common_read,
	class_read,
	role_read,
	type_read,
	user_read,
	mls_read_f
	cond_read_bool
};

#define mls_config(x) \
       ((x) & POLICYDB_CONFIG_MLS) ? "mls" : "no_mls"

/*
 * Read the configuration data from a policy database binary
 * representation file into a policy database structure.
 */
int policydb_read(policydb_t * p, struct policy_file * fp, unsigned verbose)
{
	struct role_allow *ra, *lra;
	struct role_trans *tr, *ltr;
	ocontext_t *l, *c, *newc;
	genfs_t *genfs_p, *genfs, *newgenfs;
	unsigned int i, j, r_policyvers;
	uint32_t *buf, config;
	size_t len, len2, nprim, nel, nel2;
	char *policydb_str;
	struct policydb_compat_info *info;

	config = 0;
	mls_set_config(config);

	if (policydb_init(p)) 
		return -1;

	/* Read the magic number and string length. */
	buf = next_entry(fp, sizeof(uint32_t)* 2);
	if (!buf)
		goto bad;
	for (i = 0; i < 2; i++)
		buf[i] = le32_to_cpu(buf[i]);

	if (buf[0] != POLICYDB_MAGIC) {
		printf("security:  policydb magic number 0x%x does not match expected magic number 0x%x\n", buf[0], POLICYDB_MAGIC);
		goto bad;
	}

	len = buf[1];
	if (len != strlen(POLICYDB_STRING)) {
		printf("security:  policydb string length %zu does not match expected length %zu\n", len, strlen(POLICYDB_STRING));
		goto bad;
	}
	buf = next_entry(fp, len);
	if (!buf) {
		printf("security:  truncated policydb string identifier\n");
		goto bad;
	}
	policydb_str = malloc(len + 1);
	if (!policydb_str) {
		printf("security:  unable to allocate memory for policydb string of length %zu\n", len);
		goto bad;
	}
	memcpy(policydb_str, buf, len);
	policydb_str[len] = 0;
	if (strcmp(policydb_str, POLICYDB_STRING)) {
		printf("security:  policydb string %s does not match my string %s\n", policydb_str, POLICYDB_STRING);
		free(policydb_str);
		goto bad;
	}
	/* Done with policydb_str. */
	free(policydb_str);
	policydb_str = NULL;

	/* Read the version, config, and table sizes. */
	buf = next_entry(fp, sizeof(uint32_t)*4);
	if (!buf)
		goto bad;
	for (i = 0; i < 4; i++)
		buf[i] = le32_to_cpu(buf[i]);

	p->policyvers = r_policyvers = buf[0];
	if (r_policyvers < POLICYDB_VERSION_MIN || r_policyvers > POLICYDB_VERSION_MAX) {
		printf("security:  policydb version %d does not match "
		       "my version range %d-%d\n", buf[0], POLICYDB_VERSION_MIN, POLICYDB_VERSION_MAX);
		goto bad;
	}

	if (buf[1] != config) {
		printf("security:  policydb configuration (%s) does not match my configuration (%s)\n",
		       mls_config(buf[1]),
		       mls_config(config));
		goto bad;
	}

	info = policydb_lookup_compat(r_policyvers);
	if (!info) {
		printf("security:  unable to find policy compat info for version %d\n", r_policyvers);
		goto bad;
	}

	if (buf[2] != info->sym_num || buf[3] != info->ocon_num) {
		printf("security:  policydb table sizes (%d,%d) do not match mine (%d,%d)\n",
		       buf[2], buf[3], info->sym_num, info->ocon_num);
		goto bad;
	}

	if (mls_read_nlevels(p, fp)) 
		goto bad;

	for (i = 0; i < info->sym_num; i++) {
		buf = next_entry(fp, sizeof(uint32_t)*2);
		if (!buf)
			goto bad;
		nprim = le32_to_cpu(buf[0]);
		nel = le32_to_cpu(buf[1]);
		for (j = 0; j < nel; j++) {
			if (read_f[i] (p, p->symtab[i].table, fp))
				goto bad;
		}

		p->symtab[i].nprim = nprim;
	}

	if (avtab_read(&p->te_avtab, fp, config))
		goto bad;
	if (r_policyvers >= POLICYDB_VERSION_BOOL)
		if (cond_read_list(p, fp))
			goto bad;

	buf = next_entry(fp, sizeof(uint32_t));
	if (!buf)
		goto bad;
	nel = le32_to_cpu(buf[0]);
	ltr = NULL;
	for (i = 0; i < nel; i++) {
		tr = malloc(sizeof(struct role_trans));
		if (!tr) {
			goto bad;
		}
		memset(tr, 0, sizeof(struct role_trans));
		if (ltr) {
			ltr->next = tr;
		} else {
			p->role_tr = tr;
		}
		buf = next_entry(fp, sizeof(uint32_t)*3);
		if (!buf)
			goto bad;
		tr->role = le32_to_cpu(buf[0]);
		tr->type = le32_to_cpu(buf[1]);
		tr->new_role = le32_to_cpu(buf[2]);
		ltr = tr;
	}

	buf = next_entry(fp, sizeof(uint32_t));
	if (!buf)
		goto bad;
	nel = le32_to_cpu(buf[0]);
	lra = NULL;
	for (i = 0; i < nel; i++) {
		ra = malloc(sizeof(struct role_allow));
		if (!ra) {
			goto bad;
		}
		memset(ra, 0, sizeof(struct role_allow));
		if (lra) {
			lra->next = ra;
		} else {
			p->role_allow = ra;
		}
		buf = next_entry(fp, sizeof(uint32_t)*2);
		if (!buf)
			goto bad;
		ra->role = le32_to_cpu(buf[0]);
		ra->new_role = le32_to_cpu(buf[1]);
		lra = ra;
	}

	if (policydb_index_classes(p))
		goto bad;

	if (policydb_index_others(p, verbose))
		goto bad;

	for (i = 0; i < info->ocon_num; i++) {
		buf = next_entry(fp, sizeof(uint32_t));
		if (!buf)
			goto bad;
		nel = le32_to_cpu(buf[0]);
		l = NULL;
		for (j = 0; j < nel; j++) {
			c = malloc(sizeof(ocontext_t));
			if (!c) {
				goto bad;
			}
			memset(c, 0, sizeof(ocontext_t));
			if (l) {
				l->next = c;
			} else {
				p->ocontexts[i] = c;
			}
			l = c;
			switch (i) {
			case OCON_ISID:
				buf = next_entry(fp, sizeof(uint32_t));
				if (!buf)
					goto bad;
				c->sid[0] = le32_to_cpu(buf[0]);
				if (context_read_and_validate(&c->context[0], p, fp))
					goto bad;
				break;
			case OCON_FS:
			case OCON_NETIF:
				buf = next_entry(fp, sizeof(uint32_t));
				if (!buf)
					goto bad;
				len = le32_to_cpu(buf[0]);
				buf = next_entry(fp, len);
				if (!buf)
					goto bad;
				c->u.name = malloc(len + 1);
				if (!c->u.name) {
					goto bad;
				}
				memcpy(c->u.name, buf, len);
				c->u.name[len] = 0;
				if (context_read_and_validate(&c->context[0], p, fp))
					goto bad;
				if (context_read_and_validate(&c->context[1], p, fp))
					goto bad;
				break;
			case OCON_PORT:
				buf = next_entry(fp, sizeof(uint32_t)*3);
				if (!buf)
					goto bad;
				c->u.port.protocol = le32_to_cpu(buf[0]);
				c->u.port.low_port = le32_to_cpu(buf[1]);
				c->u.port.high_port = le32_to_cpu(buf[2]);
				if (context_read_and_validate(&c->context[0], p, fp))
					goto bad;
				break;
			case OCON_NODE:
				buf = next_entry(fp, sizeof(uint32_t)* 2);
				if (!buf)
					goto bad;
				c->u.node.addr = le32_to_cpu(buf[0]);
				c->u.node.mask = le32_to_cpu(buf[1]);
				if (context_read_and_validate(&c->context[0], p, fp))
					goto bad;
				break;
			case OCON_FSUSE:
				buf = next_entry(fp, sizeof(uint32_t)*2);
				if (!buf)
					goto bad;
				c->v.behavior = le32_to_cpu(buf[0]);
				len = le32_to_cpu(buf[1]);
				buf = next_entry(fp, len);
				if (!buf)
					goto bad;
				c->u.name = malloc(len + 1);
				if (!c->u.name) {
					goto bad;
				}
				memcpy(c->u.name, buf, len);
				c->u.name[len] = 0;
				if (context_read_and_validate(&c->context[0], p, fp))
					goto bad;
				break;
			case OCON_NODE6: {
				int k;
				
				buf = next_entry(fp, sizeof(uint32_t) * 8);
				if (!buf)
					goto bad;
				for (k = 0; k < 4; k++)
					c->u.node6.addr[k] = le32_to_cpu(buf[k]);
				for (k = 0; k < 4; k++)
					c->u.node6.mask[k] = le32_to_cpu(buf[k+4]);
				if (context_read_and_validate(&c->context[0], p, fp))
					goto bad;
				break;
			}
			}
		}
	}

	buf = next_entry(fp, sizeof(uint32_t));
	if (!buf)
		goto bad;
	nel = le32_to_cpu(buf[0]);
	genfs_p = NULL;
	for (i = 0; i < nel; i++) {
		newgenfs = malloc(sizeof(genfs_t));
		if (!newgenfs) {
			goto bad;
		}
		memset(newgenfs, 0, sizeof(genfs_t));
		buf = next_entry(fp, sizeof(uint32_t));
		if (!buf)
			goto bad;
		len = le32_to_cpu(buf[0]);
		buf = next_entry(fp, len);
		if (!buf)
			goto bad;
		newgenfs->fstype = malloc(len + 1);
		if (!newgenfs->fstype) {
			goto bad;
		}
		memcpy(newgenfs->fstype, buf, len);
		newgenfs->fstype[len] = 0;
		for (genfs_p = NULL, genfs = p->genfs; genfs; 
		     genfs_p = genfs, genfs = genfs->next) {
			if (strcmp(newgenfs->fstype, genfs->fstype) == 0) {
				printf("security:  dup genfs fstype %s\n", newgenfs->fstype);
				goto bad;
			}
			if (strcmp(newgenfs->fstype, genfs->fstype) < 0)
				break;
		}
		newgenfs->next = genfs;
		if (genfs_p)
			genfs_p->next = newgenfs;
		else
			p->genfs = newgenfs;
		buf = next_entry(fp, sizeof(uint32_t));
		if (!buf)
			goto bad;
		nel2 = le32_to_cpu(buf[0]);
		for (j = 0; j < nel2; j++) {
			newc = malloc(sizeof(ocontext_t));
			if (!newc) {
				goto bad;
			}
			memset(newc, 0, sizeof(ocontext_t));
			buf = next_entry(fp, sizeof(uint32_t));
			if (!buf)
				goto bad;
			len = le32_to_cpu(buf[0]);
			buf = next_entry(fp, len);
			if (!buf)
				goto bad;
			newc->u.name = malloc(len + 1);
			if (!newc->u.name) {
				goto bad;
			}
			memcpy(newc->u.name, buf, len);
			newc->u.name[len] = 0;
			buf = next_entry(fp, sizeof(uint32_t));
			if (!buf)
				goto bad;
			newc->v.sclass = le32_to_cpu(buf[0]);
			if (context_read_and_validate(&newc->context[0], p, fp))
				goto bad;
			for (l = NULL, c = newgenfs->head; c; 
			     l = c, c = c->next) {
				if (!strcmp(newc->u.name, c->u.name) &&
				    (!c->v.sclass || !newc->v.sclass || newc->v.sclass == c->v.sclass)) {
					printf("security:  dup genfs entry (%s,%s)\n", newgenfs->fstype, c->u.name);
					goto bad;
				}
				len = strlen(newc->u.name);
				len2 = strlen(c->u.name);
				if (len > len2)
					break;
			}
			newc->next = c;
			if (l)
				l->next = newc;
			else
				newgenfs->head = newc;
		}
	}

	if (mls_read_trusted(p, fp))
		goto bad;

	return 0;
bad:
	policydb_destroy(p);
	return -1;
}



