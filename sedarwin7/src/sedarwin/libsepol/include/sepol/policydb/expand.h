/* Authors: Jason Tang <jtang@tresys.com>
 *	    Joshua Brindle <jbrindle@tresys.com>
 *          Karl MacMillan <kmacmillan@tresys.com>
 *
 * A set of utility functions that aid policy decision when dealing
 * with hierarchal items.
 *
 * Copyright (C) 2005 Tresys Technology, LLC
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

#ifndef _SEPOL_POLICYDB_EXPAND_H
#define _SEPOL_POLICYDB_EXPAND_H

#include <stddef.h>
#include <sepol/handle.h>
#include <sepol/policydb/conditional.h>

extern int expand_module(sepol_handle_t *handle,
			 policydb_t *base, policydb_t *out,
			 int verbose, int check);
extern int expand_convert_type_set(policydb_t *p, uint32_t *typemap, type_set_t *set, ebitmap_t *types, unsigned char alwaysexpand);
extern int type_set_expand(type_set_t *set, ebitmap_t *t, policydb_t *p, unsigned char alwaysexpand);
extern int role_set_expand(role_set_t *x, ebitmap_t *r, policydb_t *p);
extern int expand_rule(sepol_handle_t *handle, 
		       policydb_t *source_pol,
		       avrule_t *source_rule, avtab_t *dest_avtab,
		       cond_av_list_t **cond, cond_av_list_t **other,
		       int enabled);

extern int expand_avtab(policydb_t *p, avtab_t *a, avtab_t *expa);

extern int expand_cond_av_list(policydb_t *p, cond_av_list_t *l,
			       cond_av_list_t **newl, avtab_t *expa);

#endif
