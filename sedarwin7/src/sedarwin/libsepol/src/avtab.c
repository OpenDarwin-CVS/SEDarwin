
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/* Updated: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Copyright (C) 2003 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */
 
/* FLASK */

/* 
 * Implementation of the access vector table type.
 */

#include <stdlib.h>
#include <sepol/avtab.h>
#include <sepol/policydb.h>

#include "private.h"

#define AVTAB_HASH(keyp) \
((keyp->target_class + \
 (keyp->target_type << 2) + \
 (keyp->source_type << 9)) & \
 AVTAB_HASH_MASK)

static avtab_ptr_t 
   avtab_insert_node(avtab_t *h, int hvalue, avtab_ptr_t prev, avtab_ptr_t cur, avtab_key_t *key, avtab_datum_t *datum)
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

	if (!h)
		return -ENOMEM;

	hvalue = AVTAB_HASH(key);
	for (prev = NULL, cur = h->htable[hvalue];
	     cur;
	     prev = cur, cur = cur->next) {
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (datum->specified & cur->datum.specified))
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

	newnode = avtab_insert_node(h, hvalue, prev, cur, key, datum);
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

	if (!h)
		return NULL;
	hvalue = AVTAB_HASH(key);
	for (prev = NULL, cur = h->htable[hvalue];
	     cur;
	     prev = cur, cur = cur->next) {
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (datum->specified & cur->datum.specified))
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
	newnode = avtab_insert_node(h, hvalue, prev, cur, key, datum);
	
	return newnode;
}

/* Unlike avtab_insert(), this function stores a caller-provided parse_context pointer, AND
 * allow multiple insertions of the same key/specified mask into the table, AND returns
 * a pointer to the new node added, all as needed by the conditional avtab.  
 */
avtab_ptr_t
 avtab_insert_with_parse_context(avtab_t *h, avtab_key_t *key, avtab_datum_t *datum, void *parse_context)
{
	avtab_ptr_t newnode;

	if (!h)
		return NULL;

	newnode = avtab_insert_nonunique(h, key, datum);
	if(!newnode)
		return NULL;
		
	newnode->parse_context = parse_context;
		
	return newnode;			
}

avtab_datum_t *
 avtab_search(avtab_t * h, avtab_key_t * key, int specified)
{
	int hvalue;
	avtab_ptr_t cur;


	if (!h)
		return NULL;

	hvalue = AVTAB_HASH(key);
	for (cur = h->htable[hvalue]; cur; cur = cur->next) {
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->datum.specified))
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
 avtab_search_node(avtab_t * h, avtab_key_t * key, int specified)
{
	int hvalue;
	avtab_ptr_t cur;

	if (!h)
		return NULL;

	hvalue = AVTAB_HASH(key);
	for (cur = h->htable[hvalue]; cur; cur = cur->next) {
		if (key->source_type == cur->key.source_type && 
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->datum.specified))
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
		
	for (cur = node->next; cur; cur = cur->next) {
		if (node->key.source_type == cur->key.source_type && 
		    node->key.target_type == cur->key.target_type &&
		    node->key.target_class == cur->key.target_class &&
		    (specified & cur->datum.specified))
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

int avtab_read_item(void *fp, avtab_datum_t *avdatum, avtab_key_t *avkey)
{
	uint32_t *buf;
	uint32_t items, items2;

	memset(avkey, 0, sizeof(avtab_key_t));
	memset(avdatum, 0, sizeof(avtab_datum_t));
	
	buf = next_entry(fp, sizeof(uint32_t));
	if (!buf) {
		printf("security: avtab: truncated entry\n");
		return -1;
	}
	items2 = le32_to_cpu(buf[0]);
	buf = next_entry(fp, sizeof(uint32_t)*items2);
	if (!buf) {
		printf("security: avtab: truncated entry\n");
		return -1;
	}
	items = 0;
	avkey->source_type = le32_to_cpu(buf[items++]);
	avkey->target_type = le32_to_cpu(buf[items++]);
	avkey->target_class = le32_to_cpu(buf[items++]);
	avdatum->specified = le32_to_cpu(buf[items++]);
	if (!(avdatum->specified & (AVTAB_AV | AVTAB_TYPE))) {
		printf("security: avtab: null entry\n");
		return -1;
	}
	if ((avdatum->specified & AVTAB_AV) &&
	    (avdatum->specified & AVTAB_TYPE)) {
		printf("security: avtab: entry has both access vectors and types\n");
		return -1;
	}
	if (avdatum->specified & AVTAB_AV) {
		if (avdatum->specified & AVTAB_ALLOWED)
			avtab_allowed(avdatum) = le32_to_cpu(buf[items++]);
		if (avdatum->specified & AVTAB_AUDITDENY) 
			avtab_auditdeny(avdatum) = le32_to_cpu(buf[items++]);
		if (avdatum->specified & AVTAB_AUDITALLOW) 
			avtab_auditallow(avdatum) = le32_to_cpu(buf[items++]);
	} else {		
		if (avdatum->specified & AVTAB_TRANSITION)
			avtab_transition(avdatum) = le32_to_cpu(buf[items++]);
		if (avdatum->specified & AVTAB_CHANGE)
			avtab_change(avdatum) = le32_to_cpu(buf[items++]);
		if (avdatum->specified & AVTAB_MEMBER)
			avtab_member(avdatum) = le32_to_cpu(buf[items++]);
	}	
	if (items != items2) {
		printf("security: avtab: entry only had %d items, expected %d\n", items2, items);
		return -1;
	}	
	return 0;
}

int avtab_read(avtab_t * a, void * fp, uint32_t config __attribute__ ((unused)))
{
	unsigned int i;
	int rc;
	avtab_key_t avkey;
	avtab_datum_t avdatum;
	uint32_t *buf;
	uint32_t nel;


	buf = next_entry(fp, sizeof(uint32_t));
	if (!buf) {
		printf("security: avtab: truncated table\n");
		goto bad;
	}
	nel = le32_to_cpu(buf[0]);
	if (!nel) {
		printf("security: avtab: table is empty\n");
		goto bad;
	}
	for (i = 0; i < nel; i++) {
		if (avtab_read_item(fp, &avdatum, &avkey))
			goto bad;
		rc = avtab_insert(a, &avkey, &avdatum);
		if (rc) {
			if (rc == -ENOMEM)
				printf("security: avtab: out of memory\n");
			if (rc == -EEXIST)
				printf("security: avtab: duplicate entry\n");
			goto bad;
		}
	}

	return 0;

      bad:
	avtab_destroy(a);
	return -1;
}


