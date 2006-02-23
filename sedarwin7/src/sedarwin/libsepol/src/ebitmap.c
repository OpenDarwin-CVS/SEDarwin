
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/* FLASK */

/* 
 * Implementation of the extensible bitmap type.
 */

#include <stdlib.h>

#include <sepol/ebitmap.h>
#include <sepol/policydb.h>

#include "private.h"

int ebitmap_or(ebitmap_t * dst, ebitmap_t * e1, ebitmap_t * e2)
{
	ebitmap_node_t *n1, *n2, *new, *prev;


	ebitmap_init(dst);

	n1 = e1->node;
	n2 = e2->node;
	prev = 0;
	while (n1 || n2) {
		new = (ebitmap_node_t *) malloc(sizeof(ebitmap_node_t));
		if (!new) {
			ebitmap_destroy(dst);
			return -ENOMEM;
		}
		memset(new, 0, sizeof(ebitmap_node_t));
		if (n1 && n2 && n1->startbit == n2->startbit) {
			new->startbit = n1->startbit;
			new->map = n1->map | n2->map;
			n1 = n1->next;
			n2 = n2->next;
		} else if (!n2 || (n1 && n1->startbit < n2->startbit)) {
			new->startbit = n1->startbit;
			new->map = n1->map;
			n1 = n1->next;
		} else {
			new->startbit = n2->startbit;
			new->map = n2->map;
			n2 = n2->next;
		}

		new->next = 0;
		if (prev)
			prev->next = new;
		else
			dst->node = new;
		prev = new;
	}

	dst->highbit = (e1->highbit > e2->highbit) ? e1->highbit : e2->highbit;
	return 0;
}


int ebitmap_cmp(ebitmap_t * e1, ebitmap_t * e2)
{
	ebitmap_node_t *n1, *n2;


	if (e1->highbit != e2->highbit)
		return 0;

	n1 = e1->node;
	n2 = e2->node;
	while (n1 && n2 &&
	       (n1->startbit == n2->startbit) &&
	       (n1->map == n2->map)) {
		n1 = n1->next;
		n2 = n2->next;
	}

	if (n1 || n2)
		return 0;

	return 1;
}


int ebitmap_cpy(ebitmap_t * dst, ebitmap_t * src)
{
	ebitmap_node_t *n, *new, *prev;


	ebitmap_init(dst);
	n = src->node;
	prev = 0;
	while (n) {
		new = (ebitmap_node_t *) malloc(sizeof(ebitmap_node_t));
		if (!new) {
			ebitmap_destroy(dst);
			return -ENOMEM;
		}
		memset(new, 0, sizeof(ebitmap_node_t));
		new->startbit = n->startbit;
		new->map = n->map;
		new->next = 0;
		if (prev)
			prev->next = new;
		else
			dst->node = new;
		prev = new;
		n = n->next;
	}

	dst->highbit = src->highbit;
	return 0;
}


int ebitmap_contains(ebitmap_t * e1, ebitmap_t * e2)
{
	ebitmap_node_t *n1, *n2;


	if (e1->highbit < e2->highbit)
		return 0;

	n1 = e1->node;
	n2 = e2->node;
	while (n1 && n2 && (n1->startbit <= n2->startbit)) {
		if (n1->startbit < n2->startbit) {
			n1 = n1->next;
			continue;
		}
		if ((n1->map & n2->map) != n2->map)
			return 0;

		n1 = n1->next;
		n2 = n2->next;
	}

	if (n2)
		return 0;

	return 1;
}


int ebitmap_get_bit(ebitmap_t * e, unsigned int bit)
{
	ebitmap_node_t *n;


	if (e->highbit < bit)
		return 0;

	n = e->node;
	while (n && (n->startbit <= bit)) {
		if ((n->startbit + MAPSIZE) > bit) {
			if (n->map & (MAPBIT << (bit - n->startbit)))
				return 1;
			else
				return 0;
		}
		n = n->next;
	}

	return 0;
}


int ebitmap_set_bit(ebitmap_t * e, unsigned int bit, int value)
{
	ebitmap_node_t *n, *prev, *new;


	prev = 0;
	n = e->node;
	while (n && n->startbit <= bit) {
		if ((n->startbit + MAPSIZE) > bit) {
			if (value) {
				n->map |= (MAPBIT << (bit - n->startbit));
			} else {
				n->map &= ~(MAPBIT << (bit - n->startbit));
				if (!n->map) {
					/* drop this node from the bitmap */

					if (!n->next) {
						/*
						 * this was the highest map
						 * within the bitmap
						 */
						if (prev)
							e->highbit = prev->startbit + MAPSIZE;
						else
							e->highbit = 0;
					}
					if (prev)
						prev->next = n->next;
					else
						e->node = n->next;

					free(n);
				}
			}
			return 0;
		}
		prev = n;
		n = n->next;
	}

	if (!value)
		return 0;

	new = (ebitmap_node_t *) malloc(sizeof(ebitmap_node_t));
	if (!new)
		return -ENOMEM;
	memset(new, 0, sizeof(ebitmap_node_t));

	new->startbit = bit & ~(MAPSIZE - 1);
	new->map = (MAPBIT << (bit - new->startbit));

	if (!n)
		/* this node will be the highest map within the bitmap */
		e->highbit = new->startbit + MAPSIZE;

	if (prev) {
		new->next = prev->next;
		prev->next = new;
	} else {
		new->next = e->node;
		e->node = new;
	}

	return 0;
}


void ebitmap_destroy(ebitmap_t * e)
{
	ebitmap_node_t *n, *temp;


	if (!e)
		return;

	n = e->node;
	while (n) {
		temp = n;
		n = n->next;
		free(temp);
	}

	e->highbit = 0;
	e->node = 0;
	return;
}


int ebitmap_read(ebitmap_t * e, void * fp)
{
	int rc = -EINVAL;
	ebitmap_node_t *n, *l;
	uint32_t *buf, mapsize, count, i;
	uint64_t map;


	ebitmap_init(e);

	buf = next_entry(fp, sizeof(uint32_t)*3);
	if (!buf)
		goto out;

	mapsize = le32_to_cpu(buf[0]);
	e->highbit = le32_to_cpu(buf[1]);
	count = le32_to_cpu(buf[2]);

	if (mapsize != MAPSIZE) {
		printf("security: ebitmap: map size %d does not match my size %zu (high bit was %d)\n", mapsize, MAPSIZE, e->highbit);
		goto out;
	}
	if (!e->highbit) {
		e->node = NULL;
		goto ok;
	}
	if (e->highbit & (MAPSIZE - 1)) {
		printf("security: ebitmap: high bit (%d) is not a multiple of the map size (%zu)\n", e->highbit, MAPSIZE);
		goto bad;
	}
	l = NULL;
	for (i = 0; i < count; i++) {
		buf = next_entry(fp, sizeof(uint32_t));
		if (!buf) {
			printf("security: ebitmap: truncated map\n");
			goto bad;
		}
		n = (ebitmap_node_t *) malloc(sizeof(ebitmap_node_t));
		if (!n) {
			printf("security: ebitmap: out of memory\n");
			rc = -ENOMEM;
			goto bad;
		}
		memset(n, 0, sizeof(ebitmap_node_t));

		n->startbit = le32_to_cpu(buf[0]);

		if (n->startbit & (MAPSIZE - 1)) {
			printf("security: ebitmap start bit (%d) is not a multiple of the map size (%zu)\n", n->startbit, MAPSIZE);
			goto bad_free;
		}
		if (n->startbit > (e->highbit - MAPSIZE)) {
			printf("security: ebitmap start bit (%d) is beyond the end of the bitmap (%zu)\n", n->startbit, (e->highbit - MAPSIZE));
			goto bad_free;
		}
		buf = next_entry(fp, sizeof(uint64_t));
		if (!buf) {
			printf("security: ebitmap: truncated map\n");
			goto bad_free;
		}
		memcpy(&map, buf, sizeof(uint64_t));
		n->map = le64_to_cpu(map);

		if (!n->map) {
			printf("security: ebitmap: null map in ebitmap (startbit %d)\n", n->startbit);
			goto bad_free;
		}
		if (l) {
			if (n->startbit <= l->startbit) {
				printf("security: ebitmap: start bit %d comes after start bit %d\n", n->startbit, l->startbit);
				goto bad_free;
			}
			l->next = n;
		} else
			e->node = n;

		l = n;
	}

ok:
	rc = 0;
out:
	return rc;
bad_free:
	free(n);
bad:
	ebitmap_destroy(e);
	goto out;
}

/* FLASK */

