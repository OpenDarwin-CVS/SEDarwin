
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

#include <sepol/ebitmap.h>
#include <sepol/avtab.h>
#include <sepol/mls.h>
#include <sepol/policydb.h>
#include <sepol/conditional.h>

#include "private.h"

static unsigned int policyvers = POLICYDB_VERSION_MAX;

int sepol_set_policyvers(unsigned int version)
{
	if (version < POLICYDB_VERSION_MIN ||
	    version > POLICYDB_VERSION_MAX)
		return -EINVAL;
	policyvers = version;
	return 0;
}

static inline size_t put_entry(const void *ptr, size_t size, size_t n, struct policy_file *fp)
{
	size_t bytes = size * n;

	switch (fp->type) {
	case PF_USE_STDIO:
		return fwrite(ptr, size, n, fp->fp);
	case PF_USE_MEMORY:
		if (bytes > fp->len) {
			errno = ENOSPC;
			return 0;
		}

		memcpy(fp->data, ptr, bytes);
		fp->data += bytes;
		fp->len -= bytes;
		return n;
	default:
		return 0;
	}
	return 0;
}

int ebitmap_write(ebitmap_t * e, struct policy_file * fp)
{
	ebitmap_node_t *n;
	uint32_t buf[32], bit, count;
	uint64_t map;
	size_t items;

	buf[0] = cpu_to_le32(MAPSIZE);
	buf[1] = cpu_to_le32(e->highbit);

	count = 0;
	for (n = e->node; n; n = n->next)
		count++;
	buf[2] = cpu_to_le32(count);

	items = put_entry(buf, sizeof(uint32_t), 3, fp);
	if (items != 3)
		return -1;

	for (n = e->node; n; n = n->next) {
		bit = cpu_to_le32(n->startbit);
		items = put_entry(&bit, sizeof(uint32_t), 1, fp);
		if (items != 1)
			return -1;
		map = cpu_to_le64(n->map);
		items = put_entry(&map, sizeof(uint64_t), 1, fp);
		if (items != 1)
			return -1;

	}

	return 0;
}

int avtab_write_item(avtab_ptr_t cur, struct policy_file *fp)
{
	uint32_t buf[32];
	size_t items, items2;

	items = 1;	/* item 0 is used for the item count */
	buf[items++] = cpu_to_le32(cur->key.source_type);
	buf[items++] = cpu_to_le32(cur->key.target_type);
	buf[items++] = cpu_to_le32(cur->key.target_class);
	buf[items++] = cpu_to_le32(cur->datum.specified);
	if (!(cur->datum.specified & (AVTAB_AV | AVTAB_TYPE))) {
		printf("security: avtab: null entry\n");
		return -1;
	}
	if ((cur->datum.specified & AVTAB_AV) &&
	    (cur->datum.specified & AVTAB_TYPE)) {
		printf("security: avtab: entry has both access vectors and types\n");
		return -1;
	}
	if (cur->datum.specified & AVTAB_AV) {
		if (cur->datum.specified & AVTAB_ALLOWED)
			buf[items++] = cpu_to_le32(avtab_allowed(&cur->datum));
		if (cur->datum.specified & AVTAB_AUDITDENY)
			buf[items++] = cpu_to_le32(avtab_auditdeny(&cur->datum));
		if (cur->datum.specified & AVTAB_AUDITALLOW)
			buf[items++] = cpu_to_le32(avtab_auditallow(&cur->datum));
	} else {
		if (cur->datum.specified & AVTAB_TRANSITION)
			buf[items++] = cpu_to_le32(avtab_transition(&cur->datum));
		if (cur->datum.specified & AVTAB_CHANGE)
			buf[items++] = cpu_to_le32(avtab_change(&cur->datum));
		if (cur->datum.specified & AVTAB_MEMBER)
			buf[items++] = cpu_to_le32(avtab_member(&cur->datum));
	}
	buf[0] = cpu_to_le32(items - 1);
	
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;
	return 0;
}

int avtab_write(avtab_t * a, struct policy_file * fp)
{
	int i;
	avtab_ptr_t cur;
	uint32_t nel;
	size_t items;

	nel = cpu_to_le32(a->nel);
	items = put_entry(&nel, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;

	for (i = 0; i < AVTAB_SIZE; i++) {
		for (cur = a->htable[i]; cur; cur = cur->next) {
			if (avtab_write_item(cur, fp))
			    return -1;
		}	
	}

	return 0;
}

#ifdef CONFIG_SECURITY_SELINUX_MLS
/*
 * Write a MLS level structure to a policydb binary 
 * representation file.
 */
int mls_write_level(mls_level_t * l,
		    struct policy_file * fp)
{
	uint32_t sens;
	size_t items;

	sens = cpu_to_le32(l->sens);
	items = put_entry(&sens, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;

	if (ebitmap_write(&l->cat, fp))
		return -1;

	return 0;
}


/*
 * Write a MLS range structure to a policydb binary 
 * representation file.
 */
static int mls_write_range_helper(mls_range_t * r,
				  struct policy_file * fp)
{
	uint32_t buf[3];
	size_t items, items2;
	int rel;

	rel = mls_level_relation(r->level[1], r->level[0]);

	items = 1;		/* item 0 is used for the item count */
	buf[items++] = cpu_to_le32(r->level[0].sens);
	if (rel != MLS_RELATION_EQ)
		buf[items++] = cpu_to_le32(r->level[1].sens);
	buf[0] = cpu_to_le32(items - 1);

	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items2 != items)
		return -1;

	if (ebitmap_write(&r->level[0].cat, fp))
		return -1;
	if (rel != MLS_RELATION_EQ)
		if (ebitmap_write(&r->level[1].cat, fp))
			return -1;

	return 0;
}

int mls_write_range(context_struct_t * c,
		    struct policy_file * fp)
{
	return mls_write_range_helper(&c->range, fp);
}


/*
 * Write a MLS perms structure to a policydb binary 
 * representation file.
 */
int mls_write_class(class_datum_t * cladatum,
		    struct policy_file * fp)
{
	mls_perms_t *p = &cladatum->mlsperms;
	uint32_t buf[32];
	size_t items, items2;

	items = 0;
	buf[items++] = cpu_to_le32(p->read);
	buf[items++] = cpu_to_le32(p->readby);
	buf[items++] = cpu_to_le32(p->write);
	buf[items++] = cpu_to_le32(p->writeby);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items2 != items)
		return -1;

	return 0;
}

#define mls_write_perm(buf, items, perdatum) \
	buf[items++] = cpu_to_le32(perdatum->base_perms);

int mls_write_user(user_datum_t *usrdatum, struct policy_file *fp)
{
	mls_range_list_t *r;
	uint32_t nel;
	uint32_t buf[32];
	int items;

	nel = 0;
	for (r = usrdatum->ranges; r; r = r->next)
		nel++;
	buf[0] = cpu_to_le32(nel);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;
	for (r = usrdatum->ranges; r; r = r->next) {
		if (mls_write_range_helper(&r->range, fp))
			return -1;
	}
	return 0;
}

int mls_write_nlevels(policydb_t *p, struct policy_file *fp)
{
	uint32_t buf[32];
	size_t items;

	buf[0] = cpu_to_le32(p->nlevels);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;
	return 0;
}

int mls_write_trusted(policydb_t *p, struct policy_file *fp)
{
	if (ebitmap_write(&p->trustedreaders, fp))
		return -1;
	if (ebitmap_write(&p->trustedwriters, fp))
		return -1;
	if (ebitmap_write(&p->trustedobjects, fp))
		return -1;
	return 0;
}

int sens_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	level_datum_t *levdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_file *fp = p;

	levdatum = (level_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(levdatum->isalias);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	if (mls_write_level(levdatum->level, fp))
		return -1;

	return 0;
}

int cat_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	cat_datum_t *catdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_file *fp = p;


	catdatum = (cat_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(catdatum->value);
	buf[items++] = cpu_to_le32(catdatum->isalias);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	return 0;
}
#else
#define mls_write_range(c, fp) 0
#define mls_write_class(c, fp) 0
#define mls_write_perm(buf, items, perdatum) 
#define mls_write_user(u, fp) 0
#define mls_write_nlevels(p, fp) 0
#define mls_write_trusted(p, fp) 0
#endif


int cond_write_bool(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	cond_bool_datum_t *booldatum;
	uint32_t buf[3], len;
	int items, items2;
	struct policy_file *fp = p;

	booldatum = (cond_bool_datum_t*)datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(booldatum->value);
	buf[items++] = cpu_to_le32(booldatum->state);
	buf[items++] = cpu_to_le32(len);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;
	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;
	return 0;
}

/*
 * cond_write_cond_av_list doesn't write out the av_list nodes.
 * Instead it writes out the key/value pairs from the avtab. This
 * is necessary because there is no way to uniquely identifying rules
 * in the avtab so it is not possible to associate individual rules
 * in the avtab with a conditional without saving them as part of
 * the conditional. This means that the avtab with the conditional
 * rules will not be saved but will be rebuilt on policy load.
 */
int cond_write_av_list(cond_av_list_t *list, struct policy_file *fp)
{
	uint32_t buf[4];
	cond_av_list_t *cur_list;
	uint32_t len, items;

	len = 0;
	for (cur_list = list; cur_list != NULL; cur_list = cur_list->next) {
		if (cur_list->node->parse_context)
			len++;
	}
	
	buf[0] = cpu_to_le32(len);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;
	if (items == 0)
		return 0;

	for (cur_list = list; cur_list != NULL; cur_list = cur_list->next) {
		if (cur_list->node->parse_context)
			if (avtab_write_item(cur_list->node, fp))
				return -1;
	}
	return 0;
}

int cond_write_node(cond_node_t *node, struct policy_file *fp)
{
	cond_expr_t *cur_expr;
	uint32_t buf[2];
	uint32_t items, items2, len;

	buf[0] = cpu_to_le32(node->cur_state);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;

	/* expr */
	len = 0;
	for (cur_expr = node->expr; cur_expr != NULL; cur_expr = cur_expr->next)
		len++;

	buf[0] = cpu_to_le32(len);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;

	for (cur_expr = node->expr; cur_expr != NULL; cur_expr = cur_expr->next) {
		items = 0;
		buf[items++] = cpu_to_le32(cur_expr->expr_type);
		buf[items++] = cpu_to_le32(cur_expr->bool);
		items2 = put_entry(buf, sizeof(uint32_t), items, fp);
		if (items2 != items)
			return -1;
	}

	if (cond_write_av_list(node->true_list, fp) != 0)
		return -1;
	if (cond_write_av_list(node->false_list, fp) != 0)
		return -1;
	
	return 0;
}

int cond_write_list(cond_list_t *list, void *p)
{
	struct policy_file *fp = p;
	cond_node_t *cur;
	uint32_t len, items;
	uint32_t buf[1];

	len = 0;
	for (cur = list; cur != NULL; cur = cur->next)
		len++;
	buf[0] = cpu_to_le32(len);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;

	for (cur = list; cur != NULL; cur = cur->next) {
		if (cond_write_node(cur, p) != 0)
			return -1;
	}
	return 0;
}

/*
 * Write a security context structure
 * to a policydb binary representation file.
 */
static int context_write(context_struct_t * c, struct policy_file * fp)
{
	uint32_t buf[32];
	size_t items, items2;

	items = 0;
	buf[items++] = cpu_to_le32(c->user);
	buf[items++] = cpu_to_le32(c->role);
	buf[items++] = cpu_to_le32(c->type);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items2 != items)
		return -1;
	if (mls_write_range(c, fp))
		return -1;

	return 0;
}


/*
 * The following *_write functions are used to
 * write the symbol data to a policy database
 * binary representation file.
 */

static int perm_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	perm_datum_t *perdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_file *fp = p;

	perdatum = (perm_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(perdatum->value);
	mls_write_perm(buf, items, perdatum);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	return 0;
}


static int common_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	common_datum_t *comdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_file *fp = p;

	comdatum = (common_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(comdatum->value);
	buf[items++] = cpu_to_le32(comdatum->permissions.nprim);
	buf[items++] = cpu_to_le32(comdatum->permissions.table->nel);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	if (hashtab_map(comdatum->permissions.table, perm_write, fp))
		return -1;

	return 0;
}


static int class_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	class_datum_t *cladatum;
	constraint_node_t *c;
	constraint_expr_t *e;
	uint32_t buf[32], ncons, nexpr;
	size_t items, items2, len, len2;
	struct policy_file *fp = p;

	cladatum = (class_datum_t *) datum;

	len = strlen(key);
	if (cladatum->comkey)
		len2 = strlen(cladatum->comkey);
	else
		len2 = 0;

	ncons = 0;
	for (c = cladatum->constraints; c; c = c->next) {
		ncons++;
	}

	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(len2);
	buf[items++] = cpu_to_le32(cladatum->value);
	buf[items++] = cpu_to_le32(cladatum->permissions.nprim);
	if (cladatum->permissions.table) 
		buf[items++] = cpu_to_le32(cladatum->permissions.table->nel);
	else
		buf[items++] = 0;
	buf[items++] = cpu_to_le32(ncons);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	if (cladatum->comkey) {
		items = put_entry(cladatum->comkey, 1, len2, fp);
		if (items != len2)
			return -1;
	}
	if (hashtab_map(cladatum->permissions.table, perm_write, fp))
		return -1;

	for (c = cladatum->constraints; c; c = c->next) {
		nexpr = 0;
		for (e = c->expr; e; e = e->next) {
			nexpr++;
		}
		buf[0] = cpu_to_le32(c->permissions);
		buf[1] = cpu_to_le32(nexpr);
		items = put_entry(buf, sizeof(uint32_t), 2, fp);
		if (items != 2)
			return -1;
		for (e = c->expr; e; e = e->next) {
			items = 0;
			buf[items++] = cpu_to_le32(e->expr_type);
			buf[items++] = cpu_to_le32(e->attr);
			buf[items++] = cpu_to_le32(e->op);
			items2 = put_entry(buf, sizeof(uint32_t), items, fp);
			if (items != items2)
				return -1;

			switch (e->expr_type) {
			case CEXPR_NAMES:
				if (ebitmap_write(&e->names, fp))
					return -1;
				break;
			default:
				break;
			}
		}
	}

	if (mls_write_class(cladatum, fp))
		return -1;

	return 0;
}

static int role_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	role_datum_t *role;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_file *fp = p;

	role = (role_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(role->value);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	if (ebitmap_write(&role->dominates, fp))
		return -1;

	if (ebitmap_write(&role->types, fp))
		return -1;

	return 0;
}

static int type_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	type_datum_t *typdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_file *fp = p;

	typdatum = (type_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(typdatum->value);
	buf[items++] = cpu_to_le32(typdatum->primary);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	return 0;
}

static int user_write(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	user_datum_t *usrdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_file *fp = p;


	usrdatum = (user_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(usrdatum->value);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	if (ebitmap_write(&usrdatum->roles, fp))
		return -1;

	return mls_write_user(usrdatum, fp);
}


static int (*write_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum, void *datap) =
{
	common_write,
	class_write,
	role_write,
	type_write,
	user_write,
	mls_write_f
	cond_write_bool
};


/*
 * Write the configuration data in a policy database
 * structure to a policy database binary representation
 * file.
 */
int policydb_write(policydb_t * p, struct policy_file * fp)
{
	struct role_allow *ra;
	struct role_trans *tr;
	ocontext_t *c;
	genfs_t *genfs;
	int i, j, num_syms;
	uint32_t buf[32], config;
	size_t items, items2, len, nel;
	struct policydb_compat_info *info;
	char *policydb_str = POLICYDB_STRING;

	config = 0;
	mls_set_config(config);

	/* Write the magic number and string identifiers. */
	items = 0;
	buf[items++] = cpu_to_le32(POLICYDB_MAGIC);
	len = strlen(POLICYDB_STRING);
	buf[items++] = cpu_to_le32(len);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;
	items = put_entry(policydb_str, 1, len, fp);
	if (items != len)
		return -1;

	/* Write the version, config, and table sizes. */
	items = 0;
	info = policydb_lookup_compat(policyvers);
	if (!info) {
		fprintf(stderr, "policydb_lookup_compat() failed for %d\n", policyvers);
		return -1;
	}

	buf[items++] = cpu_to_le32(policyvers);
	buf[items++] = cpu_to_le32(config);
	buf[items++] = cpu_to_le32(info->sym_num);
	buf[items++] = cpu_to_le32(info->ocon_num);
	
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	if (mls_write_nlevels(p, fp))
		return -1;

	num_syms = info->sym_num;
	for (i = 0; i < num_syms; i++) {
		buf[0] = cpu_to_le32(p->symtab[i].nprim);
		buf[1] = cpu_to_le32(p->symtab[i].table->nel);
		items = put_entry(buf, sizeof(uint32_t), 2, fp);
		if (items != 2)
			return -1;
		if (hashtab_map(p->symtab[i].table, write_f[i], fp))
			return -1;
	}

	if (avtab_write(&p->te_avtab, fp))
		return -1;

	if (policyvers < POLICYDB_VERSION_BOOL) {
		if (p->p_bools.nprim)
			fprintf(stderr, "warning: discarding booleans and conditional rules\n");

	} else {
		if (cond_write_list(p->cond_list, fp))
			return -1;
	}

	nel = 0;
	for (tr = p->role_tr; tr; tr = tr->next) 
		nel++;
	buf[0] = cpu_to_le32(nel);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;
	for (tr = p->role_tr; tr; tr = tr->next) {
		buf[0] = cpu_to_le32(tr->role);
		buf[1] = cpu_to_le32(tr->type);
		buf[2] = cpu_to_le32(tr->new_role);
		items = put_entry(buf, sizeof(uint32_t), 3, fp);
		if (items != 3)
			return -1;		
	}

	nel = 0;
	for (ra = p->role_allow; ra; ra = ra->next) 
		nel++;
	buf[0] = cpu_to_le32(nel);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;
	for (ra = p->role_allow; ra; ra = ra->next) {
		buf[0] = cpu_to_le32(ra->role);
		buf[1] = cpu_to_le32(ra->new_role);
		items = put_entry(buf, sizeof(uint32_t), 2, fp);
		if (items != 2)
			return -1;		
	}

	for (i = 0; i < info->ocon_num; i++) {
		nel = 0;
		for (c = p->ocontexts[i]; c; c = c->next)
			nel++;
		buf[0] = cpu_to_le32(nel);
		items = put_entry(buf, sizeof(uint32_t), 1, fp);
		if (items != 1)
			return -1;
		for (c = p->ocontexts[i]; c; c = c->next) {
			switch (i) {
			case OCON_ISID:
				buf[0] = cpu_to_le32(c->sid[0]);
				items = put_entry(buf, sizeof(uint32_t), 1, fp);
				if (items != 1)
					return -1;
				if (context_write(&c->context[0], fp))
					return -1;
				break;
			case OCON_FS:
			case OCON_NETIF:
				len = strlen(c->u.name);
				buf[0] = cpu_to_le32(len);
				items = put_entry(buf, sizeof(uint32_t), 1, fp);
				if (items != 1)
					return -1;
				items = put_entry(c->u.name, 1, len, fp);
				if (items != len)
					return -1;
				if (context_write(&c->context[0], fp))
					return -1;
				if (context_write(&c->context[1], fp))
					return -1;
				break;
			case OCON_PORT:
				buf[0] = c->u.port.protocol;
				buf[1] = c->u.port.low_port;
				buf[2] = c->u.port.high_port;
				for (j = 0; j < 3; j++) {
					buf[j] = cpu_to_le32(buf[j]);
				}
				items = put_entry(buf, sizeof(uint32_t), 3, fp);
				if (items != 3)
					return -1;
				if (context_write(&c->context[0], fp))
					return -1;
				break;
			case OCON_NODE:
				buf[0] = cpu_to_le32(c->u.node.addr);
				buf[1] = cpu_to_le32(c->u.node.mask);
				items = put_entry(buf, sizeof(uint32_t), 2, fp);
				if (items != 2)
					return -1;
				if (context_write(&c->context[0], fp))
					return -1;
				break;
			case OCON_FSUSE:
				buf[0] = cpu_to_le32(c->v.behavior);
				len = strlen(c->u.name);
				buf[1] = cpu_to_le32(len);
				items = put_entry(buf, sizeof(uint32_t), 2, fp);
				if (items != 2)
					return -1;
				items = put_entry(c->u.name, 1, len, fp);
				if (items != len)
					return -1;
				if (context_write(&c->context[0], fp))
					return -1;
				break;
			case OCON_NODE6:
				for (j = 0; j < 4; j++)
					buf[j] = cpu_to_le32(c->u.node6.addr[j]);
				for (j = 0; j < 4; j++)
					buf[j+4] = cpu_to_le32(c->u.node6.mask[j]);
				items = put_entry(buf, sizeof(uint32_t), 8, fp);
				if (items != 8)
					return -1;
				if (context_write(&c->context[0], fp))
					return -1;
				break;	
			}
		}
	}

	nel = 0;
	for (genfs = p->genfs; genfs; genfs = genfs->next) 
		nel++;
	buf[0] = cpu_to_le32(nel);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;	
	for (genfs = p->genfs; genfs; genfs = genfs->next) {
		len = strlen(genfs->fstype);
		buf[0] = cpu_to_le32(len);
		items = put_entry(buf, sizeof(uint32_t), 1, fp);
		if (items != 1)
			return -1;
		items = put_entry(genfs->fstype, 1, len, fp);
		if (items != len)
			return -1;
		nel = 0;
		for (c = genfs->head; c; c = c->next)
			nel++;
		buf[0] = cpu_to_le32(nel);
		items = put_entry(buf, sizeof(uint32_t), 1, fp);
		if (items != 1)
			return -1;
		for (c = genfs->head; c; c = c->next) {
			len = strlen(c->u.name);
			buf[0] = cpu_to_le32(len);
			items = put_entry(buf, sizeof(uint32_t), 1, fp);
			if (items != 1)
				return -1;
			items = put_entry(c->u.name, 1, len, fp);
			if (items != len)
				return -1;
			buf[0] = cpu_to_le32(c->v.sclass);
			items = put_entry(buf, sizeof(uint32_t), 1, fp);
			if (items != 1)
				return -1;
			if (context_write(&c->context[0], fp))
				return -1;
		}
	}

	if (mls_write_trusted(p, fp))
		return -1;

	return 0;
}

