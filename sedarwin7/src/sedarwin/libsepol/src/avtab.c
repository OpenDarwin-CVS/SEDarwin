
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/* Updated: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Updated: Red Hat, Inc.  James Morris <jmorris@redhat.com>
 *
 *      Code cleanup
 *
 * Copyright (C) 2003 Tresys Technology, LLC
 * Copyright (C) 2003 Red Hat, Inc.
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
 * Implementation of the access vector table type.
 */

#include <stdlib.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/policydb.h>

#include "debug.h"
#include "private.h"

#define AVTAB_HASH(keyp) \
((keyp->target_class + \
 (keyp->target_type << 2) + \
 (keyp->source_type << 9)) & \
 AVTAB_HASH_MASK)

static avtab_ptr_t 
   avtab_insert_node(avtab_t *h, int hvalue, avtab_ptr_t prev, avtab_key_t *key, avtab_datum_t *datum)
{
	avtab_ptr_t newnode;
	newnode = (avtab_ptr_t) malloc(sizeof(struct avtab_node));
	if (newnode == NULL)
		return NULL;
	memset(newnode, 0, sizeof(struct avtab_node));
	newnode->key = *key;
	newnode->datum = *datum;
	if (prev) {
		newnode->next = prev->next;
		prev->next = newnode;
	} else {
		newnode->next = h->htable[hvalue];
		h->htable[hvalue] = newnode;
	}

	h->nel++;
	return newnode;
}



int avtab_insert(avtab_t * h, avtab_key_t * key, avtab_datum_t * datum)
{
	int hvalue;
	avtab_ptr_t prev, cur, newnode;
	uint16_t specified = key->specified & ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);

	if (!h)
		return -ENOMEM;

	hvalue = AVTAB_HASH(key);
	for (prev = NULL, cur = h->htable[hvalue];
	     cur;
	     prev = cur, cur = cur->next) {
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->key.specified))
			return -EEXIST;
		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type && 
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}

	newnode = avtab_insert_node(h, hvalue, prev, key, datum);
	if(!newnode)
		return -ENOMEM;

	return 0;
}

/* Unlike avtab_insert(), this function allow multiple insertions of the same 
 * key/specified mask into the table, as needed by the conditional avtab.  
 * It also returns a pointer to the node inserted.
 */
avtab_ptr_t
  avtab_insert_nonunique(avtab_t * h, avtab_key_t * key, avtab_datum_t * datum)
{
	int hvalue;
	avtab_ptr_t prev, cur, newnode;
	uint16_t specified = key->specified & ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);

	if (!h)
		return NULL;
	hvalue = AVTAB_HASH(key);
	for (prev = NULL, cur = h->htable[hvalue];
	     cur;
	     prev = cur, cur = cur->next) {
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->key.specified))
			break;
		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type && 
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}
	newnode = avtab_insert_node(h, hvalue, prev, key, datum);
	
	return newnode;
}

avtab_datum_t *
 avtab_search(avtab_t * h, avtab_key_t * key)
{
	int hvalue;
	avtab_ptr_t cur;
	uint16_t specified = key->specified & ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);


	if (!h)
		return NULL;

	hvalue = AVTAB_HASH(key);
	for (cur = h->htable[hvalue]; cur; cur = cur->next) {
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->key.specified))
			return &cur->datum;

		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type && 
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}

	return NULL;
}

/* This search function returns a node pointer, and can be used in
 * conjunction with avtab_search_next_node()
 */
avtab_ptr_t 
 avtab_search_node(avtab_t * h, avtab_key_t * key)
{
	int hvalue;
	avtab_ptr_t cur;
	uint16_t specified = key->specified & ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);

	if (!h)
		return NULL;

	hvalue = AVTAB_HASH(key);
	for (cur = h->htable[hvalue]; cur; cur = cur->next) {
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->key.specified))
			return cur;

		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type && 
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}
	return NULL;
}

avtab_ptr_t
  avtab_search_node_next(avtab_ptr_t node, int specified)
{
	avtab_ptr_t cur;

	if (!node)
		return NULL;
		
	specified &= ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);
	for (cur = node->next; cur; cur = cur->next) {
		if (node->key.source_type == cur->key.source_type && 
		    node->key.target_type == cur->key.target_type &&
		    node->key.target_class == cur->key.target_class &&
		    (specified & cur->key.specified))
			return cur;

		if (node->key.source_type < cur->key.source_type)
			break;
		if (node->key.source_type == cur->key.source_type && 
		    node->key.target_type < cur->key.target_type)
			break;
		if (node->key.source_type == cur->key.source_type && 
		    node->key.target_type == cur->key.target_type &&
		    node->key.target_class < cur->key.target_class)
			break;
	}
	return NULL;
}

void avtab_destroy(avtab_t * h)
{
	int i;
	avtab_ptr_t cur, temp;


	if (!h || !h->htable)
		return;

	for (i = 0; i < AVTAB_SIZE; i++) {
		cur = h->htable[i];
		while (cur != NULL) {
			temp = cur;
			cur = cur->next;
			free(temp);
		}
		h->htable[i] = NULL;
	}
	free(h->htable);
	h->htable = NULL;
}


int avtab_map(avtab_t * h,
	      int (*apply) (avtab_key_t * k,
			    avtab_datum_t * d,
			    void *args),
	      void *args)
{
	int i, ret;
	avtab_ptr_t cur;


	if (!h)
		return 0;

	for (i = 0; i < AVTAB_SIZE; i++) {
		cur = h->htable[i];
		while (cur != NULL) {
			ret = apply(&cur->key, &cur->datum, args);
			if (ret)
				return ret;
			cur = cur->next;
		}
	}
	return 0;
}


int avtab_init(avtab_t * h)
{
	int i;

	h->htable = malloc(sizeof(avtab_ptr_t)*AVTAB_SIZE);
	if (!h->htable)
		return -1;
	for (i = 0; i < AVTAB_SIZE; i++)
		h->htable[i] = (avtab_ptr_t) NULL;
	h->nel = 0;
	return 0;
}


void avtab_hash_eval(avtab_t * h, char *tag)
{
	int i, chain_len, slots_used, max_chain_len;
	avtab_ptr_t cur;


	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < AVTAB_SIZE; i++) {
		cur = h->htable[i];
		if (cur) {
			slots_used++;
			chain_len = 0;
			while (cur) {
				chain_len++;
				cur = cur->next;
			}

			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
	}

	printf("%s:  %d entries and %d/%d buckets used, longest chain length %d\n",
	       tag, h->nel, slots_used, AVTAB_SIZE, max_chain_len);
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

int avtab_read_item(struct policy_file *fp, uint32_t vers, avtab_t *a, 
	            int (*insertf)(avtab_t *a, avtab_key_t *k, 
				   avtab_datum_t *d, void *p),
		    void *p)
{
  	uint16_t *buf16, enabled;
	uint32_t *buf32, items, items2, val;
	avtab_key_t key;
	avtab_datum_t datum;
	unsigned set;
	unsigned int i;
	int rc;

	memset(&key, 0, sizeof(avtab_key_t));
	memset(&datum, 0, sizeof(avtab_datum_t));

	if (vers < POLICYDB_VERSION_AVTAB) {
		buf32 = next_entry(fp, sizeof(uint32_t));
		if (!buf32) {
			ERR(fp->handle, "truncated entry");
			return -1;
		}
		items2 = le32_to_cpu(buf32[0]);

		if (items2 < 5 || items2 > 8) {
			ERR(fp->handle, "invalid item count");
			return -1;
		}

		buf32 = next_entry(fp, sizeof(uint32_t)*items2);
		if (!buf32) {
			ERR(fp->handle, "truncated entry");
			return -1;
		}

		items = 0;
		val = le32_to_cpu(buf32[items++]);
		key.source_type = (uint16_t)val;
		if (key.source_type != val) {
			ERR(fp->handle, "truncated source type");
			return -1;
		}
		val = le32_to_cpu(buf32[items++]);
		key.target_type = (uint16_t)val;
		if (key.target_type != val) {
			ERR(fp->handle, "truncated target type");
			return -1;
		}
		val = le32_to_cpu(buf32[items++]);
		key.target_class = (uint16_t)val;
		if (key.target_class != val) {
			ERR(fp->handle, "truncated target class");
			return -1;
		}

		val = le32_to_cpu(buf32[items++]);
		enabled = (val & AVTAB_ENABLED_OLD) ? AVTAB_ENABLED : 0;

		if (!(val & (AVTAB_AV | AVTAB_TYPE))) {
			ERR(fp->handle, "null entry");
			return -1;
		}
		if ((val & AVTAB_AV) &&
		    (val & AVTAB_TYPE)) {
			ERR(fp->handle, "entry has both access "
				"vectors and types");
			return -1;
		}

		for (i = 0; i < sizeof(spec_order)/sizeof(uint16_t); i++) {
			if (val & spec_order[i]) {
				key.specified = spec_order[i] | enabled;
				datum.data = le32_to_cpu(buf32[items++]);
				rc = insertf(a, &key, &datum, p);
				if (rc) return rc;
			}
		}

		if (items != items2) {
			ERR(fp->handle, "entry only had %d items, "
				"expected %d", items2, items);
			return -1;
		}
		return 0;
	}
	
	buf16 = next_entry(fp, sizeof(uint16_t)*4);
	if (!buf16) {
		ERR(fp->handle, "truncated entry");
		return -1;
	}
	items = 0;
	key.source_type = le16_to_cpu(buf16[items++]);
	key.target_type = le16_to_cpu(buf16[items++]);
	key.target_class = le16_to_cpu(buf16[items++]);
	key.specified = le16_to_cpu(buf16[items++]);

	set = 0;
	for (i = 0; i < sizeof(spec_order)/sizeof(uint16_t); i++) {
			if (key.specified & spec_order[i])
				set++;
	}
	if (!set || set > 1) {
		ERR(fp->handle, "more than one specifier");
		return -1;
	}
		
	buf32 = next_entry(fp, sizeof(uint32_t));
	if (!buf32) {
		ERR(fp->handle, "truncated entry");
		return -1;
	}
	datum.data = le32_to_cpu(*buf32);
	return insertf(a, &key, &datum, p);
}

static int avtab_insertf(avtab_t *a, avtab_key_t *k, avtab_datum_t *d, void *p __attribute__ ((unused)))
{
	return avtab_insert(a, k, d);
}

int avtab_read(avtab_t * a, struct policy_file * fp, uint32_t vers)
{
	unsigned int i;
	int rc;
	uint32_t *buf;
	uint32_t nel;


	buf = next_entry(fp, sizeof(uint32_t));
	if (!buf) {
		ERR(fp->handle, "truncated table");
		goto bad;
	}
	nel = le32_to_cpu(buf[0]);
	if (!nel) {
		ERR(fp->handle, "table is empty");
		goto bad;
	}
	for (i = 0; i < nel; i++) {
		rc = avtab_read_item(fp, vers, a, avtab_insertf, NULL);
		if (rc) {
			if (rc == -ENOMEM)
				ERR(fp->handle, "out of memory");
			if (rc == -EEXIST)
				ERR(fp->handle, "duplicate entry");
			ERR(fp->handle, "failed on entry %d of %u", i, nel);
			goto bad;
		}
	}

	return 0;

      bad:
	avtab_destroy(a);
	return -1;
}


