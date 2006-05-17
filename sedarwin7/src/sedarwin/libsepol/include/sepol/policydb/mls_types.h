
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */
/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
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
 * Type definitions for the multi-level security (MLS) policy.
 */

#ifndef _SEPOL_POLICYDB_MLS_TYPES_H_
#define _SEPOL_POLICYDB_MLS_TYPES_H_

#include <stdint.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/flask_types.h>

typedef struct mls_level {
	uint32_t sens; 	   /* sensitivity */
	ebitmap_t cat;	   /* category set */
} mls_level_t;

typedef struct mls_range {
	mls_level_t level[2]; /* low == level[0], high == level[1] */
} mls_range_t;

static inline int mls_level_cpy(
	struct mls_level* dst,
	struct mls_level* src) {

	dst->sens = src->sens;
	if (ebitmap_cpy(&dst->cat, &src->cat) < 0)
		return -1;
	return 0;
}

static inline void mls_level_init(
	struct mls_level* level) {

	memset(level, 0, sizeof(mls_level_t));
}

static inline void mls_level_destroy(
	struct mls_level* level) {

	if (level == NULL)
		return;

	ebitmap_destroy(&level->cat);
	mls_level_init(level);
}

static inline int mls_level_eq(struct mls_level *l1, struct mls_level *l2)
{
	return ((l1->sens == l2->sens) &&
	        ebitmap_cmp(&l1->cat, &l2->cat));
}

static inline int mls_level_dom(struct mls_level *l1, struct mls_level *l2)
{
	return ((l1->sens >= l2->sens) &&
	        ebitmap_contains(&l1->cat, &l2->cat));
}

#define mls_level_incomp(l1, l2) \
(!mls_level_dom((l1), (l2)) && !mls_level_dom((l2), (l1)))

#define mls_level_between(l1, l2, l3) \
(mls_level_dom((l1), (l2)) && mls_level_dom((l3), (l1)))

#define mls_range_contains(r1, r2) \
(mls_level_dom(&(r2).level[0], &(r1).level[0]) && \
 mls_level_dom(&(r1).level[1], &(r2).level[1]))

static inline int mls_range_cpy(
	mls_range_t * dst,
	mls_range_t * src)  {

	if (mls_level_cpy(&dst->level[0], &src->level[0]) < 0)
		goto err;

	if (mls_level_cpy(&dst->level[1], &src->level[1]) < 0)
		goto err_destroy;

	return 0;

	err_destroy:
	mls_level_destroy(&dst->level[0]);

	err:
	return -1;
}

#endif
