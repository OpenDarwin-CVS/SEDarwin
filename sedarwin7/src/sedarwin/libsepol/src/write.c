
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
 * Updated: Joshua Brindle <jbrindle@tresys.com> and Jason Tang <jtang@tresys.org>
 *
 *	Module writing support
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003-2005 Tresys Technology, LLC
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
#include <assert.h>
#include <stdlib.h>

#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/expand.h>

#include "debug.h"
#include "private.h"
#include "mls.h"

struct policy_data
{
	struct policy_file *fp;
	struct policydb *p;
};

static int avrule_write_list(avrule_t *avrules, struct policy_file *fp);

static int ebitmap_write(ebitmap_t * e, struct policy_file * fp)
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

/* Ordering of datums in the original avtab format in the policy file. */
static uint16_t spec_order[] = {
	AVTAB_ALLOWED,
	AVTAB_AUDITDENY,
	AVTAB_AUDITALLOW,
	AVTAB_TRANSITION,
	AVTAB_CHANGE,
	AVTAB_MEMBER
};

static int avtab_write_item(policydb_t *p,
			    avtab_ptr_t cur, struct policy_file *fp, 
	                    unsigned merge, unsigned commit,
			    uint32_t *nel)
{
	avtab_ptr_t node;
	uint16_t buf16[4];
	uint32_t buf32[10], lookup, val;
	size_t items, items2;
	unsigned set;
	unsigned int oldvers = (p->policy_type == POLICY_KERN && p->policyvers < POLICYDB_VERSION_AVTAB);
	unsigned int i;

	if (oldvers) {
		/* Generate the old avtab format.
		   Requires merging similar entries if uncond avtab. */
		if (merge) {
			if (cur->merged)
				return 0; /* already merged by prior merge */
		}

		items = 1;	/* item 0 is used for the item count */
		val = cur->key.source_type;
		buf32[items++] = cpu_to_le32(val);
		val = cur->key.target_type;
		buf32[items++] = cpu_to_le32(val);
		val = cur->key.target_class;
		buf32[items++] = cpu_to_le32(val);

		val = cur->key.specified & ~AVTAB_ENABLED;
		if (cur->key.specified & AVTAB_ENABLED)
			val |= AVTAB_ENABLED_OLD;
		set = 1;

		if (merge) {
			/* Merge specifier values for all similar (av or type)
			   entries that have the same key. */
			if (val & AVTAB_AV) 
				lookup = AVTAB_AV;
			else if (val & AVTAB_TYPE)
				lookup = AVTAB_TYPE;
			else
				return -1;
			for (node = avtab_search_node_next(cur, lookup); 
			     node; node = avtab_search_node_next(node, lookup)) {
				val |= (node->key.specified & ~AVTAB_ENABLED);
				set++;
				if (node->key.specified & AVTAB_ENABLED)
					val |= AVTAB_ENABLED_OLD;
			}
		}

		if (!(val & (AVTAB_AV | AVTAB_TYPE))) {
			ERR(fp->handle, "null entry");
			return -1;
		}
		if ((val & AVTAB_AV) && (val & AVTAB_TYPE)) {
			ERR(fp->handle, "entry has both access " 
			      "vectors and types");
			return -1;
		}

		buf32[items++] = cpu_to_le32(val);

		if (merge) {
			/* Include datums for all similar (av or type)
			   entries that have the same key. */
			for (i = 0; 
			     i < (sizeof(spec_order)/sizeof(spec_order[0]));
			     i++) {
				if (val & spec_order[i]) {
					if (cur->key.specified & spec_order[i])
						node = cur;
					else {
						node = avtab_search_node_next(cur, spec_order[i]);
						if (nel)
							(*nel)--; /* one less node */
					}

					if (!node) {
						ERR(fp->handle, "missing node");
						return -1;
					}
					buf32[items++] = cpu_to_le32(node->datum.data);
					set--;
					node->merged = 1;
				}
			}
		} else {
			buf32[items++] = cpu_to_le32(cur->datum.data);
			cur->merged = 1;
			set--;
		}

		if (set) {
			ERR(fp->handle, "data count wrong");
			return -1;
		}

		buf32[0] = cpu_to_le32(items - 1);

		if (commit) {
			/* Commit this item to the policy file. */
			items2 = put_entry(buf32, sizeof(uint32_t), items, fp);
			if (items != items2)
				return -1;
		}

		return 0;
	}

	/* Generate the new avtab format. */
	buf16[0] = cpu_to_le16(cur->key.source_type);
	buf16[1] = cpu_to_le16(cur->key.target_type);
	buf16[2] = cpu_to_le16(cur->key.target_class);
	buf16[3] = cpu_to_le16(cur->key.specified);
	items = put_entry(buf16, sizeof(uint16_t), 4, fp);
	if (items != 4)
		return -1;
	buf32[0] = cpu_to_le32(cur->datum.data);
	items = put_entry(buf32, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;
 	return 0;
}

static inline void avtab_reset_merged(avtab_t *a)
{
	int i;
	avtab_ptr_t cur;
	for (i = 0; i < AVTAB_SIZE; i++) {
		for (cur = a->htable[i]; cur; cur = cur->next)
			cur->merged = 0;
	}
}

static int avtab_write(struct policydb *p, 
		       avtab_t * a, struct policy_file * fp)
{
	int i, rc;
	avtab_t expa;
	avtab_ptr_t cur;
	uint32_t nel;
	size_t items;
	unsigned int oldvers = (p->policy_type == POLICY_KERN && p->policyvers < POLICYDB_VERSION_AVTAB);


	if (oldvers) {
		/* Old avtab format.
		   First, we need to expand attributes.  Then, we need to
		   merge similar entries, so we need to track merged nodes 
		   and compute the final nel. */
		if (avtab_init(&expa))
			return -1;
		if (expand_avtab(p, a, &expa)) {
			rc = -1;
			goto out;
		}
		a = &expa;
		avtab_reset_merged(a);
		nel = a->nel;
	} else {
		/* New avtab format.  nel is good to go. */
		nel = cpu_to_le32(a->nel);
		items = put_entry(&nel, sizeof(uint32_t), 1, fp);
		if (items != 1)
			return -1;
	}

	for (i = 0; i < AVTAB_SIZE; i++) {
		for (cur = a->htable[i]; cur; cur = cur->next) {
			/* If old format, compute final nel.
			   If new format, write out the items. */
			if (avtab_write_item(p, cur, fp, 1, !oldvers, &nel)) {
				rc = -1;
				goto out;
			}
		}	
	}

	if (oldvers) {
		/* Old avtab format.
		   Write the computed nel value, then write the items. */
		nel = cpu_to_le32(nel);
		items = put_entry(&nel, sizeof(uint32_t), 1, fp);
		if (items != 1) {
			rc = -1;
			goto out;
		}
		avtab_reset_merged(a);
		for (i = 0; i < AVTAB_SIZE; i++) {
			for (cur = a->htable[i]; cur; cur = cur->next) {
				if (avtab_write_item(p, cur, fp, 1, 1, NULL)) {
					rc = -1;
					goto out;
				}
			}	
		}
	}

	rc = 0;
out:
	if (oldvers)
		avtab_destroy(&expa);
	return rc;
}

/*
 * Write a MLS level structure to a policydb binary 
 * representation file.
 */
static int mls_write_level(mls_level_t * l,
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
	int eq;

	eq = mls_level_eq(&r->level[1], &r->level[0]);

	items = 1;		/* item 0 is used for the item count */
	buf[items++] = cpu_to_le32(r->level[0].sens);
	if (!eq)
		buf[items++] = cpu_to_le32(r->level[1].sens);
	buf[0] = cpu_to_le32(items - 1);

	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items2 != items)
		return -1;

	if (ebitmap_write(&r->level[0].cat, fp))
		return -1;
	if (!eq)
		if (ebitmap_write(&r->level[1].cat, fp))
			return -1;

	return 0;
}

static int sens_write(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	level_datum_t *levdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;

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

static int cat_write(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	cat_datum_t *catdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;

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

static int role_trans_write(role_trans_t *r, struct policy_file *fp) 
{
	role_trans_t *tr;
	uint32_t buf[3];
	size_t nel, items;

	nel = 0;
	for (tr = r; tr; tr = tr->next) 
		nel++;
	buf[0] = cpu_to_le32(nel);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;
	for (tr = r; tr; tr = tr->next) {
		buf[0] = cpu_to_le32(tr->role);
		buf[1] = cpu_to_le32(tr->type);
		buf[2] = cpu_to_le32(tr->new_role);
		items = put_entry(buf, sizeof(uint32_t), 3, fp);
		if (items != 3)
			return -1;		
	}

	return 0;
}

static int role_allow_write(role_allow_t *r, struct policy_file *fp)
{
	role_allow_t *ra;
	uint32_t buf[2];
	size_t nel, items;

	nel = 0;
	for (ra = r; ra; ra = ra->next) 
		nel++;
	buf[0] = cpu_to_le32(nel);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;
	for (ra = r; ra; ra = ra->next) {
		buf[0] = cpu_to_le32(ra->role);
		buf[1] = cpu_to_le32(ra->new_role);
		items = put_entry(buf, sizeof(uint32_t), 2, fp);
		if (items != 2)
			return -1;		
	}
	return 0;
}

static int role_set_write(role_set_t *x, struct policy_file *fp)
{
	size_t items;
	uint32_t buf[1];

	if (ebitmap_write(&x->roles, fp))
		return -1;

	buf[0] = cpu_to_le32(x->flags);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;

	return 0;
}

static int type_set_write(type_set_t *x, struct policy_file *fp)
{
	size_t items;
	uint32_t buf[1];

	if (ebitmap_write(&x->types, fp))
		return -1;
	if (ebitmap_write(&x->negset, fp))
		return -1;
        
	buf[0] = cpu_to_le32(x->flags);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		return -1;

	return 0;
}

static int cond_write_bool(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	cond_bool_datum_t *booldatum;
	uint32_t buf[3], len;
	unsigned int items, items2;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;

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
static int cond_write_av_list(policydb_t *p,
			      cond_av_list_t *list, struct policy_file *fp)
{
	uint32_t buf[4];
	cond_av_list_t *cur_list, *new_list = NULL;
	avtab_t expa;
	uint32_t len, items;
	unsigned int oldvers = (p->policy_type == POLICY_KERN && p->policyvers < POLICYDB_VERSION_AVTAB);
	int rc = -1;

	if (oldvers) {
		if (avtab_init(&expa))
			return -1;
		if (expand_cond_av_list(p, list, &new_list, &expa))
			goto out;
		list = new_list;
	}

	len = 0;
	for (cur_list = list; cur_list != NULL; cur_list = cur_list->next) {
		if (cur_list->node->parse_context)
			len++;
	}
	
	buf[0] = cpu_to_le32(len);
	items = put_entry(buf, sizeof(uint32_t), 1, fp);
	if (items != 1)
		goto out;

	if (len == 0) {
		rc = 0;
		goto out;
	}

	for (cur_list = list; cur_list != NULL; cur_list = cur_list->next) {
		if (cur_list->node->parse_context)
			if (avtab_write_item(p, cur_list->node, fp, 0, 1, NULL))
				goto out;
	}

	rc = 0;
out:
	if (oldvers) {
		cond_av_list_destroy(new_list);
		avtab_destroy(&expa);
	}

	return rc;
}

static int cond_write_node(policydb_t *p, 
			   cond_node_t *node, struct policy_file *fp)
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

        if (p->policy_type == POLICY_KERN) {
		if (cond_write_av_list(p, node->true_list, fp) != 0)
			return -1;
		if (cond_write_av_list(p, node->false_list, fp) != 0)
			return -1;
	} else {
		if (avrule_write_list(node->avtrue_list, fp))
			return -1;
		if (avrule_write_list(node->avfalse_list, fp))
			return -1;
	}
	
	return 0;
}

static int cond_write_list(policydb_t *p, cond_list_t *list, struct policy_file *fp)
{
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
		if (cond_write_node(p, cur, fp) != 0)
			return -1;
	}
	return 0;
}

/*
 * Write a security context structure
 * to a policydb binary representation file.
 */
static int context_write(struct policydb *p, context_struct_t * c, struct policy_file * fp)
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
	if ((p->policyvers >= POLICYDB_VERSION_MLS && p->policy_type == POLICY_KERN) ||
	    (p->policyvers >= MOD_POLICYDB_VERSION_MLS && p->policy_type == POLICY_BASE))
		if (mls_write_range_helper(&c->range, fp))
			return -1;

	return 0;
}


/*
 * The following *_write functions are used to
 * write the symbol data to a policy database
 * binary representation file.
 */

static int perm_write(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	perm_datum_t *perdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;

	perdatum = (perm_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(perdatum->value);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	return 0;
}


static int common_write(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	common_datum_t *comdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;

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

	if (hashtab_map(comdatum->permissions.table, perm_write, pd))
		return -1;

	return 0;
}

static int write_cons_helper(policydb_t *p,
	                     constraint_node_t *node, int allowxtarget,
                             struct policy_file *fp)
{
	constraint_node_t *c;
	constraint_expr_t *e;
	uint32_t buf[3], nexpr;
	int items;

	for (c = node; c; c = c->next) {
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
			buf[0] = cpu_to_le32(e->expr_type);
			buf[1] = cpu_to_le32(e->attr);
			buf[2] = cpu_to_le32(e->op);
			items = put_entry(buf, sizeof(uint32_t), 3, fp);
			if (items != 3)
				return -1;

			switch (e->expr_type) {
			case CEXPR_NAMES:
				if (!allowxtarget && (e->attr & CEXPR_XTARGET))
					return -1;
				if (ebitmap_write(&e->names, fp)) {
                                        return -1;
                                }
                                if (p->policy_type != POLICY_KERN &&
                                    type_set_write(e->type_names, fp)) {
					return -1;
                                }
				break;
			default:
				break;
			}
		}
	}

	return 0;
}

static int class_write(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	class_datum_t *cladatum;
	constraint_node_t *c;
	uint32_t buf[32], ncons;
	size_t items, items2, len, len2;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;
	struct policydb *p = pd->p;

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
	if (hashtab_map(cladatum->permissions.table, perm_write, pd))
		return -1;

	if (write_cons_helper(p, cladatum->constraints, 0, fp))
		return -1;

	if ((p->policy_type == POLICY_KERN && p->policyvers >= POLICYDB_VERSION_VALIDATETRANS) ||
	    (p->policy_type == POLICY_BASE && p->policyvers >= MOD_POLICYDB_VERSION_VALIDATETRANS)) {
		/* write out the validatetrans rule */
		ncons = 0;
		for (c = cladatum->validatetrans; c; c = c->next) {
			ncons++;
		}
		buf[0] = cpu_to_le32(ncons);
		items = put_entry(buf, sizeof(uint32_t), 1, fp);
		if (items != 1)
			return -1;
		if (write_cons_helper(p, cladatum->validatetrans, 1, fp))
			return -1;
	}

	return 0;
}

static int role_write(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	role_datum_t *role;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;
	struct policydb *p = pd->p;

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
	if (p->policy_type == POLICY_KERN) {
		if (ebitmap_write(&role->types.types, fp))
			return -1;
	} else {
		if (type_set_write(&role->types, fp))
			return -1;
	}

	return 0;
}

static int type_write(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	type_datum_t *typdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;
	struct policydb *p = pd->p;

	typdatum = (type_datum_t *) datum;

	len = strlen(key);
	items = 0;
	buf[items++] = cpu_to_le32(len);
	buf[items++] = cpu_to_le32(typdatum->value);
	buf[items++] = cpu_to_le32(typdatum->primary);
	if (p->policy_type != POLICY_KERN) {
		buf[items++] = cpu_to_le32(typdatum->isattr);
	}
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;
		
	if (p->policy_type != POLICY_KERN) {
		if (ebitmap_write(&typdatum->types, fp))
			return -1;
	}

	items = put_entry(key, 1, len, fp);
	if (items != len)
		return -1;

	return 0;
}

static int user_write(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
	user_datum_t *usrdatum;
	uint32_t buf[32];
	size_t items, items2, len;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;
	struct policydb *p = pd->p;

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

	if (p->policy_type == POLICY_KERN) {
		if (ebitmap_write(&usrdatum->roles.roles, fp))
			return -1;
	} else {
		if (role_set_write(&usrdatum->roles, fp))
			return -1;
	}
	/* Users are allowed in non-mls modules, so the empty field will be present
	   in modules with users >= MOD_POLICYDB_VERSION_MLS */
	if ((p->policyvers >= POLICYDB_VERSION_MLS && p->policy_type == POLICY_KERN) ||
	    (p->policyvers >= MOD_POLICYDB_VERSION_MLS && p->policy_type == POLICY_MOD) ||
	    (p->policyvers >= MOD_POLICYDB_VERSION_MLS && p->policy_type == POLICY_BASE)) {
		if (mls_write_range_helper(&usrdatum->range, fp))
			return -1;
		if (mls_write_level(&usrdatum->dfltlevel, fp))
			return -1;
	}

	return 0;
}


static int (*write_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum, void *datap) =
{
	common_write,
	class_write,
	role_write,
	type_write,
	user_write,
	cond_write_bool,
	sens_write,
	cat_write,
};

static int ocontext_write (struct policydb_compat_info *info, policydb_t * p,
                           struct policy_file * fp) {
        unsigned int i, j;
        size_t nel, items, len;
	uint32_t buf[32];
        ocontext_t *c;
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
				if (context_write(p, &c->context[0], fp))
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
				if (context_write(p, &c->context[0], fp))
					return -1;
				if (context_write(p, &c->context[1], fp))
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
				if (context_write(p, &c->context[0], fp))
					return -1;
				break;
			case OCON_NODE:
				buf[0] = cpu_to_le32(c->u.node.addr);
				buf[1] = cpu_to_le32(c->u.node.mask);
				items = put_entry(buf, sizeof(uint32_t), 2, fp);
				if (items != 2)
					return -1;
				if (context_write(p, &c->context[0], fp))
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
				if (context_write(p, &c->context[0], fp))
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
				if (context_write(p, &c->context[0], fp))
					return -1;
				break;	
			}
		}
	}    
        return 0;
}

static int genfs_write (policydb_t *p, struct policy_file *fp) {
        genfs_t *genfs;
        ocontext_t *c;
        size_t nel = 0, items, len;
        uint32_t buf[32];

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
			if (context_write(p, &c->context[0], fp))
				return -1;
		}
	}
        return 0;
}

static int range_write(policydb_t *p, struct policy_file *fp)
{
        size_t nel, items;
        struct range_trans *rt;
        uint32_t buf[32];
        nel = 0;
        for (rt = p->range_tr; rt; rt = rt->next)
                nel++;
        buf[0] = cpu_to_le32(nel);
        items = put_entry(buf, sizeof(uint32_t), 1, fp);
        if (items != 1)
                return -1;
        for (rt = p->range_tr; rt; rt = rt->next) {
                buf[0] = cpu_to_le32(rt->dom);
                buf[1] = cpu_to_le32(rt->type);
                items = put_entry(buf, sizeof(uint32_t), 2, fp);
                if (items != 2)
                        return -1;
                if (mls_write_range_helper(&rt->range, fp))
                        return -1;
        }
        return 0;
}

/************** module writing functions below **************/

static int avrule_write(avrule_t *avrule, struct policy_file *fp)
{
	size_t items, items2;
	uint32_t buf[32], len;
	class_perm_node_t *cur;

	items = 0;
	buf[items++] = cpu_to_le32(avrule->specified);
	buf[items++] = cpu_to_le32(avrule->flags);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items2 != items)
		return -1;

	if (type_set_write(&avrule->stypes, fp))
		return -1;

	if (type_set_write(&avrule->ttypes, fp))
		return -1;

	cur = avrule->perms;
	len = 0;
	while (cur) {
		len++;
		cur = cur->next;
	}
	items = 0;
	buf[items++] = cpu_to_le32(len);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items2 != items)
		return -1;
	cur = avrule->perms;
	while (cur) {
		items = 0;
		buf[items++] = cpu_to_le32(cur->class);
		buf[items++] = cpu_to_le32(cur->data);
		items2 = put_entry(buf, sizeof(uint32_t), items, fp);
		if (items2 != items)
			return -1;
		
		cur = cur->next;
	}

	return 0;
}

static int avrule_write_list(avrule_t *avrules, struct policy_file *fp)
{
	uint32_t buf[32], len;
	avrule_t *avrule;

	avrule = avrules;
	len = 0;
	while (avrule) {
		len++;
		avrule = avrule->next;
	}

	buf[0] = cpu_to_le32(len);
	if (put_entry(buf, sizeof(uint32_t), 1, fp) != 1)
		return -1;

	avrule = avrules;
	while (avrule) {
		avrule_write(avrule, fp);
		avrule = avrule->next;
	}

	return 0;
}

static int role_trans_rule_write(role_trans_rule_t *t, struct policy_file *fp)
{
	int nel = 0;
	size_t items;
	uint32_t buf[1];
	role_trans_rule_t *tr;

        for (tr = t; tr; tr = tr->next)
                nel++;
        buf[0] = cpu_to_le32(nel);
        items = put_entry(buf, sizeof(uint32_t), 1, fp);
        if (items != 1)
                return -1;
        for (tr =t; tr; tr = tr->next) {
		if (role_set_write(&tr->roles, fp))
			return -1;
		if (type_set_write(&tr->types, fp))
			return -1;
                buf[0] = cpu_to_le32(tr->new_role);
                items = put_entry(buf, sizeof(uint32_t), 1, fp);
                if (items != 1)
                        return -1;
        }
	return 0;
}

static int role_allow_rule_write(role_allow_rule_t *r, struct policy_file * fp)
{
	int nel = 0;
	size_t items;
	uint32_t buf[1];
	role_allow_rule_t *ra;

        for (ra = r ; ra; ra = ra->next)
                nel++;
        buf[0] = cpu_to_le32(nel);
        items = put_entry(buf, sizeof(uint32_t), 1, fp);
        if (items != 1)
                return -1;
        for (ra = r; ra; ra = ra->next) {
		if (role_set_write(&ra->roles, fp))
			return -1;
		if (role_set_write(&ra->new_roles, fp))
			return -1;
        }
	return 0;
}

static int scope_index_write(scope_index_t *scope_index, unsigned int num_scope_syms,
                             struct policy_file *fp)
{
        unsigned int i;
        uint32_t buf[1];
        for (i = 0; i < num_scope_syms; i++) {
                if (ebitmap_write(scope_index->scope + i, fp) == -1) {
                        return -1;
                }
        }
        buf[0] = cpu_to_le32(scope_index->class_perms_len);
        if (put_entry(buf, sizeof(uint32_t), 1, fp) != 1) {
                return -1;
        }
        for (i = 0; i < scope_index->class_perms_len; i++) {
                if (ebitmap_write(scope_index->class_perms_map + i, fp) == -1) {
                        return -1;
                }
        }
        return 0;
}

static int avrule_decl_write(avrule_decl_t *decl, int num_scope_syms,
			     policydb_t *p,
                             struct policy_file *fp) {
	struct policy_data pd;
        uint32_t buf[2];
        int i;
        buf[0] = cpu_to_le32(decl->decl_id);
        buf[1] = cpu_to_le32(decl->enabled);
        if (put_entry(buf, sizeof(uint32_t), 2, fp) != 2) {
                return -1;
        }
        if (cond_write_list(p, decl->cond_list, fp) == -1 ||
            avrule_write_list(decl->avrules, fp) == -1 ||
            role_trans_rule_write(decl->role_tr_rules, fp) == -1 ||
            role_allow_rule_write(decl->role_allow_rules, fp) == -1) {
                return -1;
        }
        if (scope_index_write(&decl->required, num_scope_syms, fp) == -1 ||
            scope_index_write(&decl->declared, num_scope_syms, fp) == -1) {
                return -1;
        }
	pd.fp = fp;
	pd.p = p;
        for (i = 0; i < num_scope_syms; i++) {
		buf[0] = cpu_to_le32(decl->symtab[i].nprim);
		buf[1] = cpu_to_le32(decl->symtab[i].table->nel);
                if (put_entry(buf, sizeof(uint32_t), 2, fp) != 2) {
                        return -1;
                }
		if (hashtab_map(decl->symtab[i].table, write_f[i], &pd)) {
			return -1;
                }
        }
        return 0;
}

static int avrule_block_write(avrule_block_t *block, int num_scope_syms,
			      policydb_t *p,
                              struct policy_file *fp) {
        /* first write a count of the total number of blocks */
        uint32_t buf[1], num_blocks = 0;
        avrule_block_t *cur;
        for (cur = block; cur != NULL; cur = cur->next) {
                num_blocks++;
        }
        buf[0] = cpu_to_le32(num_blocks);
        if (put_entry(buf, sizeof(uint32_t), 1, fp) != 1) {
                return -1;
        }

        /* now write each block */
        for (cur = block; cur != NULL; cur = cur->next) {
                uint32_t num_decls = 0;
                avrule_decl_t *decl;
                /* write a count of number of branches */
                for (decl = cur->branch_list; decl != NULL; decl = decl->next) {
                        num_decls++;
                }
                buf[0] = cpu_to_le32(num_decls);
                if (put_entry(buf, sizeof(uint32_t), 1, fp) != 1) {
                        return -1;
                }
                for (decl = cur->branch_list; decl != NULL; decl = decl->next) {
                        if (avrule_decl_write(decl, num_scope_syms, p, fp) == -1) {
                                return -1;
                        }
                }
        }
        return 0;
}

static int scope_write(hashtab_key_t key, hashtab_datum_t datum, void *ptr)
{
        scope_datum_t *scope = (scope_datum_t *) datum;
	struct policy_data *pd = ptr;
	struct policy_file *fp = pd->fp;
        uint32_t static_buf[32], *dyn_buf = NULL, *buf;
        size_t key_len = strlen(key);
        unsigned int items = 2 + scope->decl_ids_len, i;

        if (items >= sizeof(buf)) {
                /* too many things required, so dynamically create a
                 * buffer.  this would have been easier with C99's
                 * dynamic arrays... */
                if ((dyn_buf = malloc(items * sizeof(*dyn_buf))) == NULL) {
                        return -1;
                }
                buf = dyn_buf;
        }
        else {
                buf = static_buf;
        }
        buf[0] = cpu_to_le32(key_len);
        if (put_entry(buf, sizeof(*buf), 1, fp) != 1 ||
            put_entry(key, 1, key_len, fp) != key_len) {
                return -1;
        }
        buf[0] = cpu_to_le32(scope->scope);
        buf[1] = cpu_to_le32(scope->decl_ids_len);
        for (i = 0; i < scope->decl_ids_len; i++) {
                buf[2 + i] = cpu_to_le32(scope->decl_ids[i]);
        }
        if (put_entry(buf, sizeof(*buf), items, fp) != items) {
                free(dyn_buf);
                return -1;
        }
        free(dyn_buf);
        return 0;
}

/*
 * Write the configuration data in a policy database
 * structure to a policy database binary representation
 * file.
 */
int policydb_write(policydb_t * p, struct policy_file * fp)
{
	unsigned int i, num_syms;
	uint32_t buf[32], config;
	size_t items, items2, len;
	struct policydb_compat_info *info;
	struct policy_data pd;
	char *policydb_str;

	pd.fp = fp;
	pd.p = p;

	config = 0;
	if (p->mls)
		config |= POLICYDB_CONFIG_MLS;

	/* Write the magic number and string identifiers. */
	items = 0;
        if (p->policy_type == POLICY_KERN) {
		buf[items++] = cpu_to_le32(POLICYDB_MAGIC);
		len = strlen(POLICYDB_STRING);
		policydb_str = POLICYDB_STRING;
	} else {
		buf[items++] = cpu_to_le32(POLICYDB_MOD_MAGIC);
		len = strlen(POLICYDB_MOD_STRING);
		policydb_str = POLICYDB_MOD_STRING;
	}
	buf[items++] = cpu_to_le32(len);
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;
	items = put_entry(policydb_str, 1, len, fp);
	if (items != len)
		return -1;

	/* Write the version, config, and table sizes. */
	items = 0;
	info = policydb_lookup_compat(p->policyvers, p->policy_type);
	if (!info) {
		ERR(fp->handle, "compatibility lookup failed for policy "
			"version %d", p->policyvers);
		return -1;
	}

        if (p->policy_type != POLICY_KERN) {
		buf[items++] = cpu_to_le32(p->policy_type);
	}
	buf[items++] = cpu_to_le32(p->policyvers);
	buf[items++] = cpu_to_le32(config);
	buf[items++] = cpu_to_le32(info->sym_num);
	buf[items++] = cpu_to_le32(info->ocon_num);
	
	items2 = put_entry(buf, sizeof(uint32_t), items, fp);
	if (items != items2)
		return -1;
        
        if (p->policy_type == POLICY_MOD) {
                /* Write module name and version */
                len = strlen(p->name);
                buf[0] = cpu_to_le32(len);
                items = put_entry(buf, sizeof(uint32_t), 1, fp);
                if (items != 1)
                        return -1;
                items = put_entry(p->name, 1, len, fp);
                if (items != len)
                        return -1;
                len = strlen(p->version);
                buf[0] = cpu_to_le32(len);
                items = put_entry(buf, sizeof(uint32_t), 1, fp);
                if (items != 1)
                        return -1;
                items = put_entry(p->version, 1, len, fp);
                if (items != len)
                        return -1;
        } 
	num_syms = info->sym_num;
	for (i = 0; i < num_syms; i++) {
		buf[0] = cpu_to_le32(p->symtab[i].nprim);
		buf[1] = cpu_to_le32(p->symtab[i].table->nel);
		items = put_entry(buf, sizeof(uint32_t), 2, fp);
		if (items != 2)
			return -1;
		if (hashtab_map(p->symtab[i].table, write_f[i], &pd))
			return -1;
	}

	if (p->policy_type == POLICY_KERN) {
		if (avtab_write(p, &p->te_avtab, fp))
			return -1;
                if (p->policyvers < POLICYDB_VERSION_BOOL) {
                        if (p->p_bools.nprim)
				WARN(fp->handle, "Discarding "
					"booleans and conditional rules");
                }
                else {
                        if (cond_write_list(p, p->cond_list, fp))
                                return -1;
                }
                if (role_trans_write(p->role_tr, fp))
                        return -1;
                if (role_allow_write(p->role_allow, fp))
                        return -1;
        }
        else {
                if (avrule_block_write(p->global, num_syms, p, fp) == -1) {
                        return -1;
                }
                
                for (i = 0; i < num_syms; i++) {
                        buf[0] = cpu_to_le32(p->scope[i].table->nel);
                        if (put_entry(buf, sizeof(uint32_t), 1, fp) != 1) {
                                return -1;
                        }
                        if (hashtab_map(p->scope[i].table, scope_write, &pd))
                                return -1;
                }
        }

        if (ocontext_write(info, p, fp) == -1 ||
            genfs_write(p, fp) == -1) {
                return -1;
        }

	if ((p->policyvers >= POLICYDB_VERSION_MLS && p->policy_type == POLICY_KERN) ||
	    (p->policyvers >= MOD_POLICYDB_VERSION_MLS && p->policy_type == POLICY_BASE)) {
                if (range_write(p, fp)) {
                        return -1;
                }
        }

	if (p->policy_type == POLICY_KERN && p->policyvers >= POLICYDB_VERSION_AVTAB) {
		for (i = 0; i < p->p_types.nprim; i++) {
			if (ebitmap_write(&p->type_attr_map[i], fp) == -1)
				return -1;
		}
	}

	return 0;
}
