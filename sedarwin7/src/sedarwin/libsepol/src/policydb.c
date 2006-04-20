
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */


/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Updated: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 * 	Added conditional policy language extensions
 * 
 * Updated: Red Hat, Inc.  James Morris <jmorris@redhat.com>
 *      Fine-grained netlink support
 *      IPv6 support
 *      Code cleanup
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003 - 2005 Tresys Technology, LLC
 * Copyright (C) 2003 - 2004 Red Hat, Inc.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* FLASK */

/*
 * Implementation of the policy database.
 */

#include <assert.h>
#include <stdlib.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/avrule_block.h>

#include "private.h"
#include "debug.h"
#include "mls.h"

/* These need to be updated if SYM_NUM or OCON_NUM changes */
static struct policydb_compat_info policydb_compat[] = {
	{
		.type		= POLICY_KERN,
		.version	= POLICYDB_VERSION_BASE,
		.sym_num	= SYM_NUM - 3,
		.ocon_num	= OCON_FSUSE + 1,
	},
	{
		.type		= POLICY_KERN,
		.version	= POLICYDB_VERSION_BOOL,
		.sym_num	= SYM_NUM - 2,
		.ocon_num	= OCON_FSUSE + 1,
	},
	{
		.type		= POLICY_KERN,
		.version	= POLICYDB_VERSION_IPV6,
		.sym_num	= SYM_NUM - 2,
		.ocon_num	= OCON_NODE6 + 1,
	},
	{
		.type		= POLICY_KERN,
		.version	= POLICYDB_VERSION_NLCLASS,
		.sym_num	= SYM_NUM - 2,
		.ocon_num	= OCON_NODE6 + 1,
	},
	{
		.type		= POLICY_KERN,
		.version	= POLICYDB_VERSION_MLS,
		.sym_num	= SYM_NUM,
		.ocon_num	= OCON_NODE6 + 1,
	},
	{
		.type		= POLICY_KERN,
		.version	= POLICYDB_VERSION_AVTAB,
		.sym_num	= SYM_NUM,
		.ocon_num	= OCON_NODE6 + 1,
	},
	{
		.type		= POLICY_BASE,
		.version 	= MOD_POLICYDB_VERSION_BASE,
		.sym_num	= SYM_NUM,
		.ocon_num	= OCON_NODE6 + 1,
        },
	{
		.type		= POLICY_BASE,
		.version 	= MOD_POLICYDB_VERSION_MLS,
		.sym_num	= SYM_NUM,
		.ocon_num	= OCON_NODE6 + 1,
        },
	{
		.type		= POLICY_MOD,
		.version	= MOD_POLICYDB_VERSION_BASE,
		.sym_num	= SYM_NUM,
		.ocon_num	= 0,
        },
	{
		.type		= POLICY_MOD,
		.version	= MOD_POLICYDB_VERSION_MLS,
		.sym_num	= SYM_NUM,
		.ocon_num	= 0,
        }
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
	16,
	16,
	16,
};

struct policydb_compat_info *policydb_lookup_compat(unsigned int version, 
						    unsigned int type)
{
	unsigned int i;
	struct policydb_compat_info *info = NULL;
	
	for (i = 0; i < sizeof(policydb_compat)/sizeof(*info); i++) {
		if (policydb_compat[i].version == version &&
		    policydb_compat[i].type == type) {
			info = &policydb_compat[i];
			break;
		}
	}
	return info;
}

void type_set_init(type_set_t *x)
{       
        memset(x, 0, sizeof(type_set_t));
        ebitmap_init(&x->types);
        ebitmap_init(&x->negset); 
}       
        
void type_set_destroy(type_set_t *x)
{
        if (x != NULL) {
                ebitmap_destroy(&x->types);
                ebitmap_destroy(&x->negset);
        }
}           

void role_set_init(role_set_t *x)
{       
        memset(x, 0, sizeof(role_set_t));
        ebitmap_init(&x->roles);
}

void role_set_destroy(role_set_t *x)
{       
        ebitmap_destroy(&x->roles);
}

void role_datum_init(role_datum_t *x)
{
        memset(x, 0, sizeof(role_datum_t));
        ebitmap_init(&x->dominates);
        type_set_init(&x->types);
	ebitmap_init(&x->cache);
}

void role_datum_destroy(role_datum_t *x)
{
        if (x != NULL) {
                ebitmap_destroy(&x->dominates);
                type_set_destroy(&x->types);
		ebitmap_destroy(&x->cache);
        }
}

void type_datum_init(type_datum_t *x)
{
        memset(x, 0, sizeof(*x));
        ebitmap_init(&x->types);
}

void type_datum_destroy(type_datum_t *x)
{
        if (x != NULL) {
                ebitmap_destroy(&x->types);
        }
}

void user_datum_init(user_datum_t *x)
{
        memset(x, 0, sizeof(user_datum_t));
        role_set_init(&x->roles);
	ebitmap_init(&x->cache);
}

void user_datum_destroy(user_datum_t *x)
{
	if (x != NULL) {
                role_set_destroy(&x->roles);
		ebitmap_destroy(&x->range.level[0].cat);
		ebitmap_destroy(&x->range.level[1].cat);
		ebitmap_destroy(&x->dfltlevel.cat);
		ebitmap_destroy(&x->cache);
        }
}

void class_perm_node_init(class_perm_node_t *x)
{
        memset(x, 0, sizeof(class_perm_node_t));
}

void avrule_init(avrule_t *x)
{
        memset(x, 0, sizeof(avrule_t));
        type_set_init(&x->stypes);
        type_set_init(&x->ttypes);
}

void avrule_destroy(avrule_t *x)
{
        class_perm_node_t *cur, *next;

        if (x == NULL) {
                return;
        }
        type_set_destroy(&x->stypes);
        type_set_destroy(&x->ttypes);

        next = x->perms;
        while (next) {
                cur = next;
                next = cur->next;
                free(cur);
        }
}

void role_trans_rule_init(role_trans_rule_t *x)
{
        memset(x,0,sizeof(*x));
        role_set_init(&x->roles);
        type_set_init(&x->types);
}

void role_trans_rule_destroy(role_trans_rule_t *x)
{
        if (x != NULL) {
                role_set_destroy(&x->roles);
                type_set_destroy(&x->types);
        }
}

void role_trans_rule_list_destroy(role_trans_rule_t *x)
{
        while (x != NULL) {
                role_trans_rule_t *next = x->next;
                role_trans_rule_destroy(x);
                free(x);
                x = next;
        }
}

void role_allow_rule_init(role_allow_rule_t *x)
{
        memset(x,0,sizeof(role_allow_rule_t));
        role_set_init(&x->roles);
        role_set_init(&x->new_roles);
}

void role_allow_rule_destroy(role_allow_rule_t *x)
{
        role_set_destroy(&x->roles);
        role_set_destroy(&x->new_roles);
}

void role_allow_rule_list_destroy(role_allow_rule_t *x)
{
        while (x != NULL) {
                role_allow_rule_t *next = x->next;
                role_allow_rule_destroy(x);
                free(x);
                x = next;
        }
}

void avrule_list_destroy(avrule_t *x)
{
        avrule_t *next, *cur;

        if (!x)
                return;

        next = x;
        while (next) {
                cur = next;
                next = next->next;
                avrule_destroy(cur);
		free(cur);
        }
}

/* 
 * Initialize the role table by implicitly adding role 'object_r'.  If
 * the policy is a module, set object_r's scope to be SCOPE_REQ,
 * otherwise set it to SCOPE_DECL.
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
	key = malloc(strlen(OBJECT_R)+1);
	if (!key) {
		rc = -ENOMEM;
		goto out_free_role;
	}
	strcpy(key, OBJECT_R);
        rc = symtab_insert(p, SYM_ROLES, key, role,
                           (p->policy_type == POLICY_MOD ? SCOPE_REQ : SCOPE_DECL),
                           1, &role->value);
	if (rc)
		goto out_free_key;
	if (role->value != OBJECT_R_VAL) {
		rc = -EINVAL;
		goto out_free_role;
	}
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

	/* initialize the module stuff */
	for (i = 0; i < SYM_NUM; i++) {
		if (symtab_init(&p->scope[i], symtab_sizes[i])) {
				goto out_free_symtab;
		}
	}
        if ((p->global = avrule_block_create()) == NULL ||
            (p->global->branch_list = avrule_decl_create(1)) == NULL) {
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
	for (i = 0; i < SYM_NUM; i++) {
		hashtab_destroy(p->symtab[i].table);
                hashtab_destroy(p->scope[i].table);
        }
        avrule_block_list_destroy(p->global);
	goto out;
}

int policydb_role_cache(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *arg)
{
	policydb_t *p;
	role_datum_t *role;

	role = (role_datum_t *)datum;
	p = (policydb_t *)arg;

	ebitmap_destroy(&role->cache);
	if (type_set_expand(&role->types, &role->cache, p, 1)) {
		return -1;
	}

	return 0;
}

int policydb_user_cache(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *arg)
{
	policydb_t *p;
	user_datum_t *user;

	user = (user_datum_t *)datum;
	p = (policydb_t *)arg;

	ebitmap_destroy(&user->cache);
	if (role_set_expand(&user->roles, &user->cache, p)) {
		return -1;
	}

	return 0;
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
		p->type_val_to_struct[typdatum->value - 1] = typdatum;
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

static int sens_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	level_datum_t *levdatum;

	levdatum = (level_datum_t *)datum;
	p = (policydb_t *) datap;

	if (!levdatum->isalias) {
		if (!levdatum->level->sens ||
		    levdatum->level->sens > p->p_levels.nprim)
			return -EINVAL;
		p->p_sens_val_to_name[levdatum->level->sens - 1] = (char *)key;
	}

	return 0;
}

static int cat_index(hashtab_key_t key, hashtab_datum_t datum, void *datap)
{
	policydb_t *p;
	cat_datum_t *catdatum;

	catdatum = (cat_datum_t *)datum;
	p = (policydb_t *) datap;

	if (!catdatum->isalias) {
		if (!catdatum->value || catdatum->value > p->p_cats.nprim)
			return -EINVAL;
		p->p_cat_val_to_name[catdatum->value - 1] = (char *)key;
	}

	return 0;
}

static int (*index_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum, void *datap) =
{
	common_index,
	class_index,
	role_index,
	type_index,
	user_index,
	cond_index_bool,
	sens_index,
	cat_index,
};


/*
 * Define the common val_to_name array and the class
 * val_to_name and val_to_struct arrays in a policy
 * database structure.  
 */
int policydb_index_classes(policydb_t * p)
{
	free(p->p_common_val_to_name);
	p->p_common_val_to_name = (char **)
	    malloc(p->p_commons.nprim * sizeof(char *));
	if (!p->p_common_val_to_name)
		return -1;

	if (hashtab_map(p->p_commons.table, common_index, p))
		return -1;

	free(p->class_val_to_struct);
	p->class_val_to_struct = (class_datum_t **)
	    malloc(p->p_classes.nprim * sizeof(class_datum_t *));
	if (!p->class_val_to_struct)
		return -1;

	free(p->p_class_val_to_name);
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
int policydb_index_others(sepol_handle_t *handle, 
			  policydb_t * p, unsigned verbose)
{
	int i;


	if (verbose) {
		INFO(handle, "security:  %d users, %d roles, %d types, %d bools",
		     p->p_users.nprim, p->p_roles.nprim, p->p_types.nprim,
		     p->p_bools.nprim);

		if (p->mls)
			INFO(handle, "security: %d sens, %d cats", 
			     p->p_levels.nprim,
			     p->p_cats.nprim);

		INFO(handle, "security:  %d classes, %d rules, %d cond rules",
		     p->p_classes.nprim, p->te_avtab.nel, p->te_cond_avtab.nel);
	}

#if 0
	avtab_hash_eval(&p->te_avtab, "rules");
	for (i = 0; i < SYM_NUM; i++) 
		hashtab_hash_eval(p->symtab[i].table, symtab_name[i]);
#endif

        free(p->role_val_to_struct);
	p->role_val_to_struct = (role_datum_t **)
	    malloc(p->p_roles.nprim * sizeof(role_datum_t *));
	if (!p->role_val_to_struct)
		return -1;
        
        free(p->user_val_to_struct);
	p->user_val_to_struct = (user_datum_t **)
	    malloc(p->p_users.nprim * sizeof(user_datum_t *));
	if (!p->user_val_to_struct)
		return -1;
        
        free(p->type_val_to_struct);
        p->type_val_to_struct = (type_datum_t **)
            malloc(p->p_types.nprim * sizeof(type_datum_t *));
        if (!p->type_val_to_struct)
                return -1;
	memset(p->type_val_to_struct, 0, 
	       p->p_types.nprim*sizeof(type_datum_t *));

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

	/* This pre-expands the roles and users for context validity checking */
	if (hashtab_map(p->p_roles.table, policydb_role_cache, p))
		return -1;

	if (hashtab_map(p->p_users.table, policydb_user_cache, p))
		return -1;

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
        if (cladatum == NULL) {
                return 0;
        }
	hashtab_map(cladatum->permissions.table, perm_destroy, 0);
	hashtab_destroy(cladatum->permissions.table);
	constraint = cladatum->constraints;
	while (constraint) {
		e = constraint->expr;
		while (e) {
			etmp = e;
			e = e->next;
                        constraint_expr_destroy(etmp);
		}
		ctemp = constraint;
		constraint = constraint->next;
		free(ctemp);
	}

	constraint = cladatum->validatetrans;
	while (constraint) {
		e = constraint->expr;
		while (e) {
			etmp = e;
			e = e->next;
                        constraint_expr_destroy(etmp);
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
	free(key);
	role_datum_destroy((role_datum_t*)datum);
	free(datum);
	return 0;
}

static int type_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	free(key);
	type_datum_destroy((type_datum_t*) datum);
	free(datum);
	return 0;
}

static int user_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	free(key);
	user_datum_destroy((user_datum_t*) datum);
	free(datum);
	return 0;
}

static int sens_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	level_datum_t *levdatum;

	if (key)
		free(key);
	levdatum = (level_datum_t *)datum;
	ebitmap_destroy(&levdatum->level->cat);
	free(levdatum->level);
	free(datum);
	return 0;
}

static int cat_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	if (key)
		free(key);
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
	cond_destroy_bool,
	sens_destroy,
	cat_destroy,
};


/*
 * Free any memory allocated by a policy database structure.
 */
void policydb_destroy(policydb_t * p)
{
	ocontext_t *c, *ctmp;
	genfs_t *g, *gtmp;
	unsigned int i;
	role_allow_t *ra, *lra = NULL;
	role_trans_t *tr, *ltr = NULL;
	range_trans_t *rt, *lrt = NULL;

        if (!p)
                return;

        symtabs_destroy(p->symtab);

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
	if (p->type_val_to_struct)
		free(p->type_val_to_struct);

	for (i = 0; i < SYM_NUM; i++) {
		hashtab_map(p->scope[i].table, scope_destroy, 0);
		hashtab_destroy(p->scope[i].table);
        }
        avrule_block_list_destroy(p->global);
        free(p->name);
        free(p->version);

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

	for (tr = p->role_tr; tr; tr = tr->next) {
		if (ltr) free(ltr);
		ltr = tr;
	}
	if (ltr) free(ltr);

	for (ra = p->role_allow; ra; ra = ra -> next) {
		if (lra) free(lra);
		lra = ra;
	}
	if (lra) free(lra);

	for (rt = p->range_tr; rt; rt = rt -> next) {
		if (lrt) { 
			ebitmap_destroy(&lrt->range.level[0].cat);
			ebitmap_destroy(&lrt->range.level[1].cat);
			free(lrt);
		}
		lrt = rt;
	}
	if (lrt) {
		ebitmap_destroy(&lrt->range.level[0].cat);
		ebitmap_destroy(&lrt->range.level[1].cat);
		free(lrt);
	}

	if (p->type_attr_map) {
		for (i = 0; i < p->p_types.nprim; i++) {
			ebitmap_destroy(&p->type_attr_map[i]);
		}
		free(p->type_attr_map);
	}

	if (p->attr_type_map) {
		for (i = 0; i < p->p_types.nprim; i++) {
			ebitmap_destroy(&p->attr_type_map[i]);
		}
		free(p->attr_type_map);
	}

	return;
}

void symtabs_destroy(symtab_t *symtab) {
        int i;
      	for (i = 0; i < SYM_NUM; i++) {
		hashtab_map(symtab[i].table, destroy_f[i], 0);
		hashtab_destroy(symtab[i].table);
	}
}

int scope_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
        scope_datum_t *cur = (scope_datum_t *) datum;
        free(key);
        if (cur != NULL) {
                free (cur->decl_ids);
        }
	free(cur);
        return 0;
}

hashtab_destroy_func_t get_symtab_destroy_func(int sym_num) {
        if (sym_num < 0 || sym_num >= SYM_NUM) {
                return NULL;
        }
        return (hashtab_destroy_func_t) destroy_f[sym_num];
}

/*
 * Load the initial SIDs specified in a policy database
 * structure into a SID table.
 */
int policydb_load_isids(policydb_t *p, sidtab_t *s) 
{
	ocontext_t *head, *c;

	if (sepol_sidtab_init(s)) {
		ERR(NULL, "out of memory on SID table init");
		return -1;
	}

	head = p->ocontexts[OCON_ISID];
	for (c = head; c; c = c->next) {
		if (!c->context[0].user) {
			ERR(NULL, "SID %s was never defined", c->u.name);
			return -1;
		}
		if (sepol_sidtab_insert(s, c->sid[0], &c->context[0])) {
			ERR(NULL, "unable to load initial SID %s", c->u.name);
			return -1;
		}
	}

	return 0;
}

/***********************************************************************/
/* everything below is for policy reads */


/* The following are read functions for module structures */

static int role_set_read(role_set_t *r, struct policy_file *fp)
{                       
        uint32_t *buf;
        if (ebitmap_read(&r->roles, fp))
                return -1;
        buf = next_entry(fp, sizeof(uint32_t));
        if (!buf)
                return -1;
        r->flags = le32_to_cpu(buf[0]);

        return 0;
}

static int type_set_read(type_set_t *t, struct policy_file *fp)
{
        uint32_t *buf;

        if (ebitmap_read(&t->types, fp))
                return -1;
        if (ebitmap_read(&t->negset, fp))
                return -1;

        buf = next_entry(fp, sizeof(uint32_t));
        if (!buf)
                return -1;
        t->flags = le32_to_cpu(buf[0]);

        return 0;
}

/*
 * Read a MLS range structure from a policydb binary 
 * representation file.
 */
static int mls_read_range_helper(mls_range_t *r, struct policy_file *fp)
{
	uint32_t *buf;
	int items, rc = -EINVAL;

	buf = next_entry(fp, sizeof(uint32_t));
	if (!buf)
		goto out;

	items = le32_to_cpu(buf[0]);
	buf = next_entry(fp, sizeof(uint32_t)*items);
	if (!buf) {
		ERR(fp->handle, "truncated range");
		goto out;
	}
	r->level[0].sens = le32_to_cpu(buf[0]);
	if (items > 1)
		r->level[1].sens = le32_to_cpu(buf[1]);
	else
		r->level[1].sens = r->level[0].sens;

	rc = ebitmap_read(&r->level[0].cat, fp);
	if (rc) {
		ERR(fp->handle, "error reading low categories");
		goto out;
	}
	if (items > 1) {
		rc = ebitmap_read(&r->level[1].cat, fp);
		if (rc) {
			ERR(fp->handle, "error reading high categories");
			goto bad_high;
		}
	} else {
		rc = ebitmap_cpy(&r->level[1].cat, &r->level[0].cat);
		if (rc) {
			ERR(fp->handle, "out of memory");
			goto bad_high;
		}
	}

	rc = 0;
out:	
	return rc;
bad_high:
	ebitmap_destroy(&r->level[0].cat);
	goto out;
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
		ERR(fp->handle, "context truncated");
		return -1;
	}
	c->user = le32_to_cpu(buf[0]);
	c->role = le32_to_cpu(buf[1]);
	c->type = le32_to_cpu(buf[2]);
	if ((p->policy_type == POLICY_KERN && p->policyvers >= POLICYDB_VERSION_MLS) ||
	    (p->policy_type == POLICY_BASE && p->policyvers >= MOD_POLICYDB_VERSION_MLS)) {
		if (mls_read_range_helper(&c->range, fp)) {
			ERR(fp->handle, "error reading MLS range "
				"of context");
			return -1;
		}
	}

	if (!policydb_context_isvalid(p, c)) {
		ERR(fp->handle, "invalid security context");
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

static int read_cons_helper(policydb_t *p, constraint_node_t **nodep, 
			    unsigned int ncons,
                            int allowxtarget, struct policy_file *fp)
{
	constraint_node_t *c, *lc;
	constraint_expr_t *e, *le;
	uint32_t *buf;
	size_t nexpr;
	unsigned int i, j;
	int depth;

	lc = NULL;
	for (i = 0; i < ncons; i++) {
		c = malloc(sizeof(constraint_node_t));
		if (!c)
			return -1;
		memset(c, 0, sizeof(constraint_node_t));
		buf = next_entry(fp, (sizeof(uint32_t) * 2));
		if (!buf)
			return -1;
		c->permissions = le32_to_cpu(buf[0]);
		nexpr = le32_to_cpu(buf[1]);
		le = NULL;
		depth = -1;
		for (j = 0; j < nexpr; j++) {
			e = malloc(sizeof(constraint_expr_t));
			if (!e)
				return -1;
                        if (constraint_expr_init(e) == -1) {
                                free(e);
                                return -1;
                        }
			buf = next_entry(fp, (sizeof(uint32_t) * 3));
			if (!buf) {
                                constraint_expr_destroy(e);
				return -1;
			}
			e->expr_type = le32_to_cpu(buf[0]);
			e->attr = le32_to_cpu(buf[1]);
			e->op = le32_to_cpu(buf[2]);

			switch (e->expr_type) {
			case CEXPR_NOT:
				if (depth < 0) {
					constraint_expr_destroy(e);
					return -1;
				}
				break;
			case CEXPR_AND:
			case CEXPR_OR:
				if (depth < 1) {
					constraint_expr_destroy(e);
					return -1;
				}
				depth--;
				break;
			case CEXPR_ATTR:
				if (depth == (CEXPR_MAXDEPTH-1)) {
					constraint_expr_destroy(e);
					return -1;
				}
				depth++;
				break;
			case CEXPR_NAMES:
				if (!allowxtarget && (e->attr & CEXPR_XTARGET)) {
					constraint_expr_destroy(e);
					return -1;
				}
				if (depth == (CEXPR_MAXDEPTH-1)) {
					constraint_expr_destroy(e);
					return -1;
				}
				depth++;
				if (ebitmap_read(&e->names, fp)) {
					constraint_expr_destroy(e);
					return -1;
				}
                                if (p->policy_type != POLICY_KERN &&
                                    type_set_read(e->type_names, fp)) {
					constraint_expr_destroy(e);
                                        return -1;
                                }
				break;
			default:
                                constraint_expr_destroy(e);
				return -1;
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
			return -1;
		if (lc) {
			lc->next = c;
		} else {
			*nodep = c;
		}
		lc = c;
	}

	return 0;
}

static int class_read(policydb_t * p, hashtab_t h, struct policy_file * fp)
{
	char *key = 0;
	class_datum_t *cladatum;
	uint32_t *buf;
	size_t len, len2, ncons, nel;
	unsigned int i;

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
			ERR(fp->handle, "unknown common %s",
				cladatum->comkey);
			goto bad;
		}
	}
	for (i = 0; i < nel; i++) {
		if (perm_read(p, cladatum->permissions.table, fp))
			goto bad;
	}

	if (read_cons_helper(p, &cladatum->constraints, ncons, 0, fp))
		goto bad;

	if ((p->policy_type == POLICY_KERN && p->policyvers >= POLICYDB_VERSION_VALIDATETRANS) ||
	    (p->policy_type == POLICY_BASE && p->policyvers >= MOD_POLICYDB_VERSION_VALIDATETRANS)) {
		/* grab the validatetrans rules */
		buf = next_entry(fp, sizeof(uint32_t));
		if (!buf)
			goto bad;
		ncons = le32_to_cpu(buf[0]);
		if (read_cons_helper(p, &cladatum->validatetrans, ncons, 1, fp))
			goto bad;
	}

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

        if (p->policy_type == POLICY_KERN) {
                if (ebitmap_read(&role->types.types, fp))
                        goto bad;
        }
        else {
                if (type_set_read(&role->types, fp))
                        goto bad;
        }

	if (strcmp(key, OBJECT_R) == 0) {
		if (role->value != OBJECT_R_VAL) {
			ERR(fp->handle, "role %s has wrong value %d",
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

        if (p->policy_type == POLICY_KERN) {
                buf = next_entry(fp, sizeof(uint32_t)*3);
        }
        else {
                buf = next_entry(fp, sizeof(uint32_t)*4);
        }
	if (!buf)
		goto bad;

	len = le32_to_cpu(buf[0]);
	typdatum->value = le32_to_cpu(buf[1]);
	typdatum->primary = le32_to_cpu(buf[2]);
        if (p->policy_type != POLICY_KERN) {
                typdatum->isattr = le32_to_cpu(buf[3]);
                if (ebitmap_read(&typdatum->types, fp))
                        goto bad;
        }

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

int role_trans_read(role_trans_t **t, struct policy_file *fp)
{                       
        unsigned int i;
        uint32_t *buf, nel;
        role_trans_t *tr, *ltr;
                                
        buf = next_entry(fp, sizeof(uint32_t));
        if (!buf)
                return -1;
        nel = le32_to_cpu(buf[0]);
        ltr = NULL;
        for (i = 0; i < nel; i++) {
                tr = malloc(sizeof(struct role_trans));
                if (!tr) {
                        return -1;
                }       
                memset(tr, 0, sizeof(struct role_trans));
                if (ltr) {
                        ltr->next = tr;
                } else {
                        *t = tr;
                }       
                buf = next_entry(fp, sizeof(uint32_t)*3);
                if (!buf)
                        return -1;
                tr->role = le32_to_cpu(buf[0]);
                tr->type = le32_to_cpu(buf[1]);
                tr->new_role = le32_to_cpu(buf[2]);
                ltr = tr;
        }
        return 0;
}

int role_allow_read(role_allow_t **r, struct policy_file *fp)
{
        unsigned int i;
        uint32_t *buf, nel;
        role_allow_t *ra, *lra;

        buf = next_entry(fp, sizeof(uint32_t));
        if (!buf)
                return -1;
        nel = le32_to_cpu(buf[0]);
        lra = NULL;
        for (i = 0; i < nel; i++) {
                ra = malloc(sizeof(struct role_allow));
                if (!ra) {
                        return -1;
                }
                memset(ra, 0, sizeof(struct role_allow));
                if (lra) {
                        lra->next = ra;
                } else {
                        *r = ra;
                }
                buf = next_entry(fp, sizeof(uint32_t)*2);
                if (!buf)
                        return -1;
                ra->role = le32_to_cpu(buf[0]);
                ra->new_role = le32_to_cpu(buf[1]);
                lra = ra;
        }
        return 0;
}

static int ocontext_read (struct policydb_compat_info *info,
                          policydb_t * p, struct policy_file * fp) {
        unsigned int i, j;
        size_t nel, len;
        ocontext_t *l, *c;
        uint32_t *buf;
        for (i = 0; i < info->ocon_num; i++) {
                buf = next_entry(fp, sizeof(uint32_t));
                if (!buf)
                        return -1;
                nel = le32_to_cpu(buf[0]);
                l = NULL;
                for (j = 0; j < nel; j++) {
                        c = malloc(sizeof(ocontext_t));
                        if (!c) {
                                return -1;
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
                                        return -1;
                                c->sid[0] = le32_to_cpu(buf[0]);
                                if (context_read_and_validate(&c->context[0], p, fp))
                                        return -1;
                                break;
                        case OCON_FS:
                        case OCON_NETIF:
                                buf = next_entry(fp, sizeof(uint32_t));
                                if (!buf)
                                        return -1;
                                len = le32_to_cpu(buf[0]);
                                buf = next_entry(fp, len);
                                if (!buf)
                                        return -1;
                                c->u.name = malloc(len + 1);
                                if (!c->u.name) {
                                        return -1;
                                }
                                memcpy(c->u.name, buf, len);
                                c->u.name[len] = 0;
                                if (context_read_and_validate(&c->context[0], p, fp))
                                        return -1;
                                if (context_read_and_validate(&c->context[1], p, fp))
                                        return -1;
                                break;
                        case OCON_PORT:
				buf = next_entry(fp, sizeof(uint32_t)*3);
                                if (!buf)
                                        return -1;
                                c->u.port.protocol = le32_to_cpu(buf[0]);
                                c->u.port.low_port = le32_to_cpu(buf[1]);
                                c->u.port.high_port = le32_to_cpu(buf[2]);
                                if (context_read_and_validate(&c->context[0], p, fp))
                                        return -1;
                                break;
                        case OCON_NODE:
                                buf = next_entry(fp, sizeof(uint32_t)* 2);
                                if (!buf)
                                        return -1;
                                c->u.node.addr = le32_to_cpu(buf[0]);
                                c->u.node.mask = le32_to_cpu(buf[1]);
                                if (context_read_and_validate(&c->context[0], p, fp))
                                        return -1;
                                break;
                        case OCON_FSUSE:
                                buf = next_entry(fp, sizeof(uint32_t)*2);
                                if (!buf)
                                        return -1;
                                c->v.behavior = le32_to_cpu(buf[0]);
                                len = le32_to_cpu(buf[1]);
                                buf = next_entry(fp, len);
                                if (!buf)
                                        return -1; 
                                c->u.name = malloc(len + 1);
                                if (!c->u.name) {
                                        return -1; 
                                }               
                                memcpy(c->u.name, buf, len);
                                c->u.name[len] = 0;
                                if (context_read_and_validate(&c->context[0], p, fp))
                                        return -1;
                                break;  
                        case OCON_NODE6: {
                                int k;
                                
                                buf = next_entry(fp, sizeof(uint32_t) * 8);
                                if (!buf) 
                                        return -1;
                                for (k = 0; k < 4; k++)
                                        c->u.node6.addr[k] = le32_to_cpu(buf[k]);
                                for (k = 0; k < 4; k++)
                                        c->u.node6.mask[k] = le32_to_cpu(buf[k+4]);
                                if (context_read_and_validate(&c->context[0], p, fp))
                                        return -1;
                                break;  
                        }
                        default: {
                                assert(0);  /* should never get here */
                        }
                        }
                }               
        }
        return 0;               
}

static int genfs_read (policydb_t *p, struct policy_file *fp) {
        uint32_t *buf;
        size_t nel, nel2, len, len2;
        genfs_t *genfs_p, *newgenfs, *genfs;
        unsigned int i, j;
        ocontext_t *l, *c, *newc;

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
				ERR(fp->handle, "dup genfs fstype %s", 
					newgenfs->fstype);
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
                                    (!c->v.sclass || !newc->v.sclass || 
				     newc->v.sclass == c->v.sclass)) {
					ERR(fp->handle, "dup genfs entry "
						"(%s,%s)", newgenfs->fstype, 
							c->u.name);
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

        return 0;

bad:
	return -1;
}

/*
 * Read a MLS level structure from a policydb binary 
 * representation file.
 */
static int mls_read_level(mls_level_t *lp, struct policy_file *fp)
{
	uint32_t *buf;

	memset(lp, 0, sizeof(mls_level_t));

	buf = next_entry(fp, sizeof(uint32_t));
	if (!buf) {
		ERR(fp->handle, "truncated level");
		goto bad;
	}
	lp->sens = le32_to_cpu(buf[0]);

	if (ebitmap_read(&lp->cat, fp)) {
		ERR(fp->handle, "error reading level categories");
		goto bad;
	}
	return 0;

bad:
	return -EINVAL;
}

static int user_read(policydb_t * p, hashtab_t h, struct policy_file * fp)
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

	if (p->policy_type == POLICY_KERN) {
		if (ebitmap_read(&usrdatum->roles.roles, fp))
			goto bad;
	} else {
		if (role_set_read(&usrdatum->roles, fp))
			goto bad;
	}

	if ((p->policy_type == POLICY_KERN && p->policyvers >= POLICYDB_VERSION_MLS) ||
	    (p->policy_type == POLICY_BASE && p->policyvers >= MOD_POLICYDB_VERSION_MLS)) {
		if (mls_read_range_helper(&usrdatum->range, fp))
			goto bad;
		if (mls_read_level(&usrdatum->dfltlevel, fp))
			goto bad;
	}

	if (hashtab_insert(h, key, usrdatum))
		goto bad;

	return 0;

bad:
	user_destroy(key, usrdatum, NULL);
	return -1;
}

static int sens_read(policydb_t * p __attribute__ ((unused)), hashtab_t h, struct policy_file * fp)
{
	char *key = 0;
	level_datum_t *levdatum;
	uint32_t *buf, len;

	levdatum = malloc(sizeof(level_datum_t));
	if (!levdatum)
		return -1;
	memset(levdatum, 0, sizeof(level_datum_t));

	buf = next_entry(fp, (sizeof(uint32_t) * 2));
	if (!buf)
		goto bad;

	len = le32_to_cpu(buf[0]);
	levdatum->isalias = le32_to_cpu(buf[1]);

	buf = next_entry(fp, len);
	if (!buf)
		goto bad;
	key = malloc(len + 1);
	if (!key)
		goto bad;
	memcpy(key, buf, len);
	key[len] = 0;

	levdatum->level = malloc(sizeof(mls_level_t));
	if (!levdatum->level || mls_read_level(levdatum->level, fp))
		goto bad;

	if (hashtab_insert(h, key, levdatum))
		goto bad;

	return 0;

bad:
	sens_destroy(key, levdatum, NULL);
	return -1;
}

static int cat_read(policydb_t * p __attribute__ ((unused)), hashtab_t h, struct policy_file * fp)
{
	char *key = 0;
	cat_datum_t *catdatum;
	uint32_t *buf, len;

	catdatum = malloc(sizeof(cat_datum_t));
	if (!catdatum)
		return -1;
	memset(catdatum, 0, sizeof(cat_datum_t));

	buf = next_entry(fp, (sizeof(uint32_t) * 3));
	if (!buf)
		goto bad;

	len = le32_to_cpu(buf[0]);
	catdatum->value = le32_to_cpu(buf[1]);
	catdatum->isalias = le32_to_cpu(buf[2]);

	buf = next_entry(fp, len);
	if (!buf)
		goto bad;
	key = malloc(len + 1);
	if (!key)
		goto bad;
	memcpy(key, buf, len);
	key[len] = 0;

	if (hashtab_insert(h, key, catdatum))
		goto bad;

	return 0;

bad:
	cat_destroy(key, catdatum, NULL);
	return -1;
}

static int (*read_f[SYM_NUM]) (policydb_t * p, hashtab_t h, struct policy_file * fp) =
{
	common_read,
	class_read,
	role_read,
	type_read,
	user_read,
	cond_read_bool,
	sens_read,
	cat_read,
};

/************** module reading functions below **************/

static avrule_t *avrule_read(policydb_t *p __attribute__ ((unused)), struct policy_file *fp)
{                       
        unsigned int i;                  
        uint32_t *buf, len;
        class_perm_node_t *cur, *tail = NULL;
        avrule_t *avrule;

        avrule = (avrule_t*)malloc(sizeof(avrule_t));
        if (!avrule)
                return NULL;

        avrule_init(avrule);

        buf = next_entry(fp, sizeof(uint32_t) * 2);
        if (!buf)
                goto bad;
        
        (avrule)->specified = le32_to_cpu(buf[0]);
        (avrule)->flags = le32_to_cpu(buf[1]);
                                
        if (type_set_read(&avrule->stypes, fp))
                goto bad;
                
        if (type_set_read(&avrule->ttypes, fp))
                goto bad;
                                
        buf = next_entry(fp, sizeof(uint32_t));
        if (!buf)
                goto bad;
        len = le32_to_cpu(buf[0]); 
                        
                        
        for (i = 0; i < len; i++) { 
                cur = (class_perm_node_t*)malloc(sizeof(class_perm_node_t));
                if (!cur)
                        goto bad;
                class_perm_node_init(cur);

                buf = next_entry(fp, sizeof(uint32_t) * 2);
                if (!buf) {
                        free(cur);
                        goto bad;
       }

                cur->class = le32_to_cpu(buf[0]);
                cur->data = le32_to_cpu(buf[1]);

                if (!tail) {
			avrule->perms = cur;
                } else {
                        tail->next = cur;
                }
                tail = cur;
        }

        return avrule;
bad:
        if (avrule) {
                avrule_destroy(avrule);
		free(avrule);
	}
        return NULL;
}

static int range_read(policydb_t *p, struct policy_file *fp)
{
        uint32_t *buf, nel;
        range_trans_t *rt, *lrt;
        unsigned int i;
        
        buf = next_entry(fp, sizeof(uint32_t));
        if (!buf)
                return -1;
        nel = le32_to_cpu(buf[0]);
        lrt = NULL;
        for (i = 0; i < nel; i++) {
                rt = malloc(sizeof(range_trans_t));
                if (!rt)
                        return -1;
                memset(rt, 0, sizeof(range_trans_t));
                if (lrt)
                        lrt->next = rt;
                else
                        p->range_tr = rt;
                buf = next_entry(fp, (sizeof(uint32_t) * 2));
                if (!buf)
                        return -1;
                rt->dom = le32_to_cpu(buf[0]);
                rt->type = le32_to_cpu(buf[1]);
                if (mls_read_range_helper(&rt->range, fp))
                        return -1;
                lrt = rt;
        }
        return 0;
}

int avrule_read_list(policydb_t *p, avrule_t **avrules,
                     struct policy_file *fp)
{
        unsigned int i;
        avrule_t *cur, *tail;
        uint32_t *buf, len;

        *avrules = tail = NULL;

        buf = next_entry(fp, sizeof(uint32_t));
        if (!buf) {
                return -1;
        }
        len = le32_to_cpu(buf[0]);

        for (i = 0; i < len; i++) {
                cur = avrule_read(p, fp);
                if (!cur) {
                        return -1;
                }

                if (!tail) {
                        *avrules = cur;
                } else {
                        tail->next = cur;
                }
                tail = cur;
        }

        return 0;
}

static int role_trans_rule_read(role_trans_rule_t **r, struct policy_file *fp)
{
        uint32_t *buf, nel;
        unsigned int i;
        role_trans_rule_t *tr, *ltr;

        buf = next_entry(fp, sizeof(uint32_t));
        if (!buf)
                return -1;
        nel = le32_to_cpu(buf[0]);
        ltr = NULL;
        for (i = 0; i < nel; i++) {
                tr = malloc(sizeof(role_trans_rule_t));
                if (!tr) {
                        return -1;
                }
                role_trans_rule_init(tr);

                if (ltr) {
                        ltr->next = tr;
                } else {
                        *r = tr;
                }

                if (role_set_read(&tr->roles, fp))
                        return -1;

                if (type_set_read(&tr->types, fp))
                        return -1;

                buf = next_entry(fp, sizeof(uint32_t));
		if (!buf)
			return -1;
                tr->new_role = le32_to_cpu(buf[0]);
                ltr = tr;
        }

        return 0;
}

static int role_allow_rule_read(role_allow_rule_t **r, struct policy_file *fp)
{
        unsigned int i;
        uint32_t *buf, nel;
        role_allow_rule_t *ra, *lra;

        buf = next_entry(fp, sizeof(uint32_t));
        if (!buf)
                return -1;
        nel = le32_to_cpu(buf[0]);
        lra = NULL;
        for (i = 0; i < nel; i++) {
                ra = malloc(sizeof(role_allow_rule_t));
                if (!ra) {
                        return -1;
                }
                role_allow_rule_init(ra);

                if (lra) {
                        lra->next = ra;
                } else {
                        *r = ra;
                }

                if (role_set_read(&ra->roles, fp))
                        return -1;

                if (role_set_read(&ra->new_roles, fp))
                        return -1;

                lra = ra;
        }
        return 0;
}

static int scope_index_read(scope_index_t *scope_index, 
			    unsigned int num_scope_syms,
                            struct policy_file *fp)
{
        unsigned int i;
        uint32_t *buf;
        for (i = 0; i < num_scope_syms; i++) {
                if (ebitmap_read(scope_index->scope + i, fp) == -1) {
                        return -1;
                }
        }
        if ((buf = next_entry(fp, sizeof(uint32_t))) == NULL) {
                return -1;
        }
        scope_index->class_perms_len = le32_to_cpu(buf[0]);
        if (scope_index->class_perms_len == 0) {
                scope_index->class_perms_map = NULL;
                return 0;
        }
        if ((scope_index->class_perms_map =
             calloc(scope_index->class_perms_len, sizeof(*scope_index->class_perms_map))) == NULL) {
                return -1;
        }
        for (i = 0; i < scope_index->class_perms_len; i++) {
                if (ebitmap_read(scope_index->class_perms_map + i, fp) == -1) {
                        return -1;
                }
        }
        return 0;
}

static int avrule_decl_read(policydb_t *p, avrule_decl_t *decl,
                            unsigned int num_scope_syms, struct policy_file *fp) {
        uint32_t *buf, nprim, nel;
        unsigned int i, j;
        if ((buf = next_entry(fp, sizeof(uint32_t) * 2)) == NULL) {
                return -1;
        }
        decl->decl_id = le32_to_cpu(buf[0]);
        decl->enabled = le32_to_cpu(buf[1]);        
        if (cond_read_list(p, &decl->cond_list, fp) == -1 ||
            avrule_read_list(p, &decl->avrules, fp) == -1 ||
            role_trans_rule_read(&decl->role_tr_rules, fp) == -1 ||
            role_allow_rule_read(&decl->role_allow_rules, fp) == -1) {
                return -1;
        }
        if (scope_index_read(&decl->required, num_scope_syms, fp) == -1 ||
            scope_index_read(&decl->declared, num_scope_syms, fp) == -1) {
                return -1;
        }
        
        for (i = 0; i < num_scope_syms; i++) {
		if ((buf = next_entry(fp, sizeof(uint32_t)*2)) == NULL) {
                        return -1;
                }
		nprim = le32_to_cpu(buf[0]);
		nel = le32_to_cpu(buf[1]);
		for (j = 0; j < nel; j++) {
			if (read_f[i] (p, decl->symtab[i].table, fp)) {
                                return -1;
                        }
		}
		decl->symtab[i].nprim = nprim;
        }
        return 0;
}

static int avrule_block_read(policydb_t *p,
                             avrule_block_t **block, unsigned int num_scope_syms,
                             struct policy_file *fp)
{
        avrule_block_t *last_block = NULL, *curblock;
        uint32_t *buf, num_blocks;

        if ((buf = next_entry(fp, sizeof(uint32_t))) == NULL) {
                return -1;
        }
        num_blocks = le32_to_cpu(buf[0]);

        while (num_blocks > 0) {
                avrule_decl_t *last_decl = NULL, *curdecl;
                uint32_t num_decls;
                if ((curblock = calloc(1, sizeof (*curblock))) == NULL) {
                        return -1;
                }
                
                if ((buf = next_entry(fp, sizeof(uint32_t))) == NULL) {
                        return -1;
                }
                num_decls = le32_to_cpu(buf[0]);
                while (num_decls > 0) {
                        if ((curdecl = avrule_decl_create(0)) == NULL) {
                                return -1;
                        }
                        if (avrule_decl_read(p, curdecl, num_scope_syms, fp) == -1) {
                                return -1;
                        }
                        if (curdecl->enabled) {
                                if (curblock->enabled != NULL) {
                                        /* probably a corrupt file */
                                        return -1;
                                }
                                curblock->enabled = curdecl;
                        }
                        /* one must be careful to reconstruct the
                         * decl chain in its correct order */
                        if (curblock->branch_list == NULL) {
                                curblock->branch_list = curdecl;
                        }
                        else {
                                last_decl->next = curdecl;
                        }
                        last_decl = curdecl;
                        num_decls--;
                }
               
                /* one must be careful to reconstruct the block chain
                 * in its correct order */
                if (*block == NULL) {
                        *block = curblock;
                }
                else {
                        last_block->next = curblock;
                }
                last_block = curblock;
                
                num_blocks--;
        }
        
        return 0;
}


static int scope_read(policydb_t * p, int symnum, struct policy_file * fp)
{
	scope_datum_t *scope = NULL;
	uint32_t *buf;
        char *key = NULL;
        size_t key_len;
        unsigned int i;
        hashtab_t h = p->scope[symnum].table;

        if ((buf = next_entry(fp, sizeof(uint32_t))) == NULL) {
                goto cleanup;
        }
        key_len = le32_to_cpu(buf[0]);
        if ((buf = next_entry(fp, key_len)) == NULL) {
                goto cleanup;
        }
        if ((key = malloc(key_len + 1)) == NULL) {
                goto cleanup;
        }
        memcpy(key, buf, key_len);
        key[key_len] = '\0';
        
        /* ensure that there already exists a symbol with this key */
        if (hashtab_search(p->symtab[symnum].table, key) == NULL) {
                goto cleanup;
        }
                
	if ((scope = calloc(1, sizeof(*scope))) == NULL) {
                goto cleanup;
        }
	if ((buf = next_entry(fp, sizeof(uint32_t)*2)) == NULL) {
                goto cleanup;
        }
	scope->scope = le32_to_cpu(buf[0]);
        scope->decl_ids_len = le32_to_cpu(buf[1]);
        assert(scope->decl_ids_len > 0);
        if ((scope->decl_ids = malloc(scope->decl_ids_len * sizeof(uint32_t))) == NULL) {
                goto cleanup;
        }
        if ((buf = next_entry(fp, sizeof(uint32_t) * scope->decl_ids_len)) == NULL) {
                goto cleanup;
        }
        for (i = 0; i < scope->decl_ids_len; i++) {
                scope->decl_ids[i] = le32_to_cpu(buf[i]);
        }

        if (strcmp(key, "object_r") == 0 && h == p->p_roles_scope.table) {
                /* object_r was already added to this table in roles_init() */
                scope_destroy(key, scope, NULL);
        }
        else {
                if (hashtab_insert(h, key, scope)) {
                        goto cleanup;
                }
        }

	return 0;
        
 cleanup:
	scope_destroy(key, scope, NULL);
	return -1;
}

/*
 * Read the configuration data from a policy database binary
 * representation file into a policy database structure.
 */
int policydb_read(policydb_t * p, struct policy_file * fp, unsigned verbose)
{

	unsigned int i, j, r_policyvers;
	uint32_t *buf, config;
	size_t len, nprim, nel;
	char *policydb_str, *target_str = NULL;
	struct policydb_compat_info *info;
        unsigned int policy_type, bufindex;
	ebitmap_node_t *tnode;

	config = 0;

	/* Read the magic number and string length. */
	buf = next_entry(fp, sizeof(uint32_t)* 2);
	if (!buf)
		return -1;
	for (i = 0; i < 2; i++)
		buf[i] = le32_to_cpu(buf[i]);

        if (buf[0] == POLICYDB_MAGIC) {
                policy_type = POLICY_KERN;
                target_str = POLICYDB_STRING;
        }
        else if (buf[0] == POLICYDB_MOD_MAGIC) {
                policy_type = POLICY_MOD;
                target_str = POLICYDB_MOD_STRING;
        }
        else {
		ERR(fp->handle, "policydb magic number %#08x does not "
			"match expected magic number %#08x or %#08x",
			buf[0], POLICYDB_MAGIC, POLICYDB_MOD_MAGIC);
		return -1;
	}

        len = buf[1];
        if (len != strlen(target_str)) {
		ERR(fp->handle, "policydb string length %zu does not match "
			"expected length %zu", len, strlen(target_str));
                return -1;
        }

	buf = next_entry(fp, len);
	if (!buf) {
		ERR(fp->handle, "truncated policydb string identifier");
		return -1;
	}
	policydb_str = malloc(len + 1);
	if (!policydb_str) {
		ERR(fp->handle, "unable to allocate memory for policydb "
			"string of length %zu", len);
		return -1;
	}
	memcpy(policydb_str, buf, len);
	policydb_str[len] = 0;
	if (strcmp(policydb_str, target_str)) {
		ERR(fp->handle, "policydb string %s does not match "
			"my string %s", policydb_str, target_str);
		free(policydb_str);
		return -1;
	}
	/* Done with policydb_str. */
	free(policydb_str);
	policydb_str = NULL;

	/* Read the version, config, and table sizes (and policy type if it's a module). */
        if (policy_type == POLICY_KERN)
                nel = 4;
        else
                nel = 5;

	buf = next_entry(fp, sizeof(uint32_t)*nel);
	if (!buf)
		return -1;
	for (i = 0; i < nel; i++)
		buf[i] = le32_to_cpu(buf[i]);

	bufindex = 0;

	if (policy_type == POLICY_MOD) {
		/* We know it's a module but not whether it's a base
		   module or regular binary policy module.  buf[0]
		   tells us which. */
		policy_type = buf[bufindex];
                if (policy_type != POLICY_MOD && policy_type != POLICY_BASE) {
			ERR(fp->handle, "unknown module type: %#08x",
				policy_type);
                        return -1;
                }
		bufindex++;
	}

	r_policyvers = buf[bufindex];
        if (policy_type == POLICY_KERN) {
                if (r_policyvers < POLICYDB_VERSION_MIN ||
                    r_policyvers > POLICYDB_VERSION_MAX) {
			ERR(fp->handle, "policydb version %d does not match "
				"my version range %d-%d", buf[bufindex], 
				POLICYDB_VERSION_MIN, POLICYDB_VERSION_MAX);
                        return -1;
                }
        }
        else if (policy_type == POLICY_BASE || policy_type == POLICY_MOD) {
                if (r_policyvers < MOD_POLICYDB_VERSION_MIN ||
                    r_policyvers > MOD_POLICYDB_VERSION_MAX) {
			ERR(fp->handle, "policydb module version %d does "
				"not match my version range %d-%d",
				buf[bufindex], MOD_POLICYDB_VERSION_MIN,
				MOD_POLICYDB_VERSION_MAX);
                        return -1;
                }
        }
        else {
                assert(0);
        }
	bufindex++;

	/* Set the policy type and version from the read values. */
	p->policy_type = policy_type;
        p->policyvers = r_policyvers;

	if (buf[bufindex] & POLICYDB_CONFIG_MLS) {
                p->mls = 1;
        } else {
		p->mls = 0;
	}
 
        bufindex++;

	info = policydb_lookup_compat(r_policyvers, policy_type);
	if (!info) {
		ERR(fp->handle, "unable to find policy compat info "
			"for version %d", r_policyvers);
		goto bad;
	}

	if (buf[bufindex] != info->sym_num || buf[bufindex + 1] != info->ocon_num) {
		ERR(fp->handle, "policydb table sizes (%d,%d) do not "
			"match mine (%d,%d)", buf[bufindex], buf[bufindex + 1],
			info->sym_num, info->ocon_num);
		goto bad;
	}

        if (p->policy_type == POLICY_MOD) {
                /* Get the module name and version */
                if ((buf = next_entry(fp, sizeof(uint32_t))) == NULL) {
                        goto bad;
                }
                len = le32_to_cpu(buf[0]);
                if ((buf = next_entry(fp, len)) == NULL) {
                        goto bad;
                }
                if ((p->name = malloc(len + 1)) == NULL) {
                        goto bad;
                }
                memcpy(p->name, buf, len);
                p->name[len] = '\0';
                if ((buf = next_entry(fp, sizeof(uint32_t))) == NULL) {
                        goto bad;
                }
                len = le32_to_cpu(buf[0]);
                if ((buf = next_entry(fp, len)) == NULL) {
                        goto bad;
                }
                if ((p->version = malloc(len + 1)) == NULL) {
                        goto bad;
                }
                memcpy(p->version, buf, len);
                p->version[len] = '\0';
        }
        
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
        
	if (policy_type == POLICY_KERN) {
		if (avtab_read(&p->te_avtab, fp, r_policyvers))
			goto bad;
		if (r_policyvers >= POLICYDB_VERSION_BOOL)
			if (cond_read_list(p, &p->cond_list, fp))
				goto bad;
                if (role_trans_read(&p->role_tr, fp))
                        goto bad;
                if (role_allow_read(&p->role_allow, fp))
                        goto bad;
        }
        else {
                /* first read the AV rule blocks, then the scope tables */
                avrule_block_destroy(p->global);
                p->global = NULL;
                if (avrule_block_read(p, &p->global, info->sym_num, fp) == -1) {
                        goto bad;
                }
                for (i = 0; i < info->sym_num; i++) {
                        if ((buf = next_entry(fp, sizeof(uint32_t))) == NULL) {
                                goto bad;
                        }
                        nel = le32_to_cpu(buf[0]);
                        for (j = 0; j < nel; j++) {
                                if (scope_read(p, i, fp))
                                        goto bad;
                        }
                }

        }


	if (policydb_index_classes(p))
		goto bad;

	if (policydb_index_others(fp->handle, p, verbose))
		goto bad;

	if (ocontext_read (info, p, fp) == -1) {
                goto bad;
        }

        if (genfs_read (p, fp) == -1) {
                goto bad;
        }

	if ((p->policy_type == POLICY_KERN && p->policyvers >= POLICYDB_VERSION_MLS) ||
	    (p->policy_type == POLICY_BASE && p->policyvers >= MOD_POLICYDB_VERSION_MLS)) {
                if (range_read(p, fp)) {
			goto bad;
                }
	}

	if (policy_type == POLICY_KERN) {
		p->type_attr_map = malloc(p->p_types.nprim*sizeof(ebitmap_t));
		p->attr_type_map = malloc(p->p_types.nprim*sizeof(ebitmap_t));
		if (!p->type_attr_map || !p->attr_type_map)
			goto bad;
		for (i = 0; i < p->p_types.nprim; i++) {
			ebitmap_init(&p->type_attr_map[i]);
			ebitmap_init(&p->attr_type_map[i]);
		}
		for (i = 0; i < p->p_types.nprim; i++) {
			if (r_policyvers >= POLICYDB_VERSION_AVTAB) {
				if (ebitmap_read(&p->type_attr_map[i], fp))
					goto bad;
				ebitmap_for_each_bit(&p->type_attr_map[i], tnode, j) {
					if (!ebitmap_node_get_bit(tnode, j) || i == j) 
						continue;
					if (ebitmap_set_bit(&p->attr_type_map[j], i, 1))
						goto bad;
				}
			}
			/* add the type itself as the degenerate case */
			if (ebitmap_set_bit(&p->type_attr_map[i], i, 1))
				goto bad;
		}
	}

	return 0;
bad:
	return -1;
}

int policydb_reindex_users(policydb_t * p)
{
	unsigned int i = SYM_USERS;

	if (p->user_val_to_struct)
		free(p->user_val_to_struct);
	if (p->sym_val_to_name[i])
		free(p->sym_val_to_name[i]);

	p->user_val_to_struct = (user_datum_t **)
	    malloc(p->p_users.nprim * sizeof(user_datum_t *));
	if (!p->user_val_to_struct)
		return -1;

	p->sym_val_to_name[i] = (char **)
		malloc(p->symtab[i].nprim * sizeof(char *));
	if (!p->sym_val_to_name[i])
		return -1;

	if (hashtab_map(p->symtab[i].table, index_f[i], p))
		return -1;

	/* Expand user roles for context validity checking */
	if (hashtab_map(p->p_users.table, policydb_user_cache, p))
		return -1;

	return 0;
}
