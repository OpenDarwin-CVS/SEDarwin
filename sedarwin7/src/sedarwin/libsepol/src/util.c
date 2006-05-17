/* Authors: Joshua Brindle <jbrindle@tresys.com>
 * 	    Jason Tang <jtang@tresys.com>
 *
 * A set of utility functions that aid policy decision when dealing
 * with hierarchal namespaces.
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <sepol/policydb/flask_types.h>
#include <sepol/policydb/policydb.h>

struct val_to_name {
	unsigned int val;
	char *name;
};

/* Add an unsigned integer to a dynamically reallocated array.  *cnt
 * is a reference pointer to the number of values already within array
 * *a; it will be incremented upon successfully appending i.  If *a is
 * NULL then this function will create a new array (*cnt is reset to
 * 0).  Return 0 on success, -1 on out of memory. */
static int add_i_to_a(uint32_t i, uint32_t *cnt, uint32_t **a)
{
        if(cnt == NULL || a == NULL)
                return -1;

        /* FIX ME: This is not very elegant! We use an array that we
         * grow as new uint32_t are added to an array.  But rather
         * than be smart about it, for now we realloc() the array each
         * time a new uint32_t is added! */
        if(*a != NULL)
                *a = (uint32_t *) realloc(*a, (*cnt + 1) * sizeof(uint32_t));
        else /* empty list */ {
                *cnt = 0;
                *a = (uint32_t *) malloc(sizeof(uint32_t));
        }
        if(*a == NULL) {
                return -1;
        }
        (*a)[*cnt] = i;
        (*cnt)++;
        return 0;
}

int type_set_or(type_set_t *dst, type_set_t *a, type_set_t *b)
{
        type_set_init(dst);

        if (ebitmap_or(&dst->types, &a->types, &b->types)) {
                return -1;
        }
        if (ebitmap_or(&dst->negset, &a->negset, &b->negset)) {
                return -1;
        }

        dst->flags |= a->flags;
        dst->flags |= b->flags;

        return 0;
}

int type_set_cpy(type_set_t *dst, type_set_t *src)
{
        type_set_init(dst);

        dst->flags = src->flags;
        if (ebitmap_cpy(&dst->types, &src->types))
                return -1;
        if (ebitmap_cpy(&dst->negset, &src->negset))
                return -1;

        return 0;
}

int type_set_or_eq(type_set_t *dst, type_set_t *other)
{
        int ret;
        type_set_t tmp;

        if (type_set_or(&tmp, dst, other))
                return -1;
        type_set_destroy(dst);
        ret = type_set_cpy(dst, &tmp);
        type_set_destroy(&tmp);

        return ret;
}

int role_set_get_role(role_set_t *x, uint32_t role)
{
        if (x->flags & ROLE_STAR)
                return 1;

        if (ebitmap_get_bit(&x->roles, role - 1)) {
                if (x->flags & ROLE_COMP)
                        return 0;
                else
                        return 1;
        } else {
                if (x->flags & ROLE_COMP)
                        return 1;
                else
                        return 0;
        }
}

/* Declare a symbol for a certain avrule_block context.  Insert it
 * into a symbol table for a policy.  This function will handle
 * inserting the appropriate scope information in addition to
 * inserting the symbol into the hash table.
 *
 * arguments:
 *   policydb_t *pol       module policy to modify
 *   uint32_t sym          the symbole table for insertion (SYM_*)
 *   hashtab_key_t key     the key for the symbol - not cloned
 *   hashtab_datum_t data  the data for the symbol - not cloned
 *   scope                 scope of this symbol, either SCOPE_REQ or SCOPE_DECL
 *   avrule_decl_id        identifier for this symbol's encapsulating declaration
 *   value (out)           assigned value to the symbol (if value is not NULL)
 *
 * returns:
 *   0                     success
 *   1                     success, but symbol already existed as a requirement
 *                         (datum was not inserted and needs to be free()d)
 *   -1                    general error
 *   -2                    scope conflicted
 *   -ENOMEM               memory error
 *   error codes from hashtab_insert
 */
int symtab_insert(policydb_t *pol, uint32_t sym,
                  hashtab_key_t key, hashtab_datum_t datum,
                  uint32_t scope, uint32_t avrule_decl_id,
                  uint32_t *value)
{
	int rc, retval = 0;
	unsigned int i;
        scope_datum_t *scope_datum;
        
        /* check if the symbol is already there.  multiple
         * declarations of non-roles/non-users are illegal, but
         * multiple requires are allowed. */
        
        /* FIX ME - the failures after the hashtab_insert will leave
         * the policy in a inconsistent state. */
        rc = hashtab_insert(pol->symtab[sym].table, key, datum);
        if (rc == 0) {
                /* if no value is passed in the symbol is not primary
                 * (i.e. aliases) */
                if (value)
                        *value = ++pol->symtab[sym].nprim;
        }
        else if (rc == HASHTAB_PRESENT && scope == SCOPE_REQ) {
                retval = 1;   /* symbol not added -- need to free() later */
        }
        else if (rc == HASHTAB_PRESENT && scope == SCOPE_DECL) {
                if (sym == SYM_ROLES || sym == SYM_USERS) {
                        /* allow multiple declarations for these two */
                        retval = 1;
                }
                else {
                        /* duplicate declarations not allowed for all else */
                        return -2;
                }
        }
        else {
                return rc;
        }

        /* get existing scope information; if there is not one then
         * create it */
        scope_datum = (scope_datum_t *) hashtab_search(pol->scope[sym].table, key);
        if (scope_datum == NULL) {
		hashtab_key_t key2 = strdup((char*)key);
		if (!key2)
			return -ENOMEM;
                if ((scope_datum = malloc(sizeof(*scope_datum))) == NULL) {
			free(key2);
                        return -ENOMEM;
                }
                scope_datum->scope = scope;
                scope_datum->decl_ids = NULL;
                scope_datum->decl_ids_len = 0;
                if ((rc = hashtab_insert(pol->scope[sym].table, key2, scope_datum)) != 0) {	
			free(key2);
			free(scope_datum);
                        return rc;
                }
        }
        else if (scope_datum->scope == SCOPE_DECL) {
                /* disallow multiple declarations for non-roles/users */
                if (sym != SYM_ROLES && sym != SYM_USERS) {
                        return -2;
                }
        }
        else if (scope_datum->scope == SCOPE_REQ && scope == SCOPE_DECL) {
                /* appending to required symbol only allowed for roles/users */
                if (sym != SYM_ROLES && sym != SYM_USERS) {
                        return -2;
                }
                
        }
        else if (scope_datum->scope != scope) {
                /* scope does not match */
                return -2;
        }

        /* search through the pre-existing list to avoid adding duplicates */
        for (i = 0; i < scope_datum->decl_ids_len; i++) {
                if (scope_datum->decl_ids[i] == avrule_decl_id) {
                        /* already there, so don't modify its scope */
                        return retval;
                }
        }

        if (add_i_to_a(avrule_decl_id,
                       &scope_datum->decl_ids_len,
                       &scope_datum->decl_ids) == -1) {
                return -ENOMEM;
        }
        
        return retval;
}

static int perm_name(hashtab_key_t key, hashtab_datum_t datum, void *data)
{       
        struct val_to_name *v = data;
        perm_datum_t *perdatum;
                
        perdatum = (perm_datum_t *) datum;

        if (v->val == perdatum->value) {
                v->name = key;
                return 1;
        }       
        
        return 0;
}       
   
char *sepol_av_to_string(policydb_t *policydbp, uint32_t tclass, sepol_access_vector_t av)
{               
        struct val_to_name v;
        static char avbuf[1024];
        class_datum_t *cladatum;
        char *perm = NULL, *p;
        unsigned int i;
        int rc; 
        int avlen = 0, len;
                
        cladatum = policydbp->class_val_to_struct[tclass-1];
        p = avbuf;
        for (i = 0; i < cladatum->permissions.nprim; i++) {
                if (av & (1 << i)) {
                        v.val = i+1;
                        rc = hashtab_map(cladatum->permissions.table,
                                         perm_name, &v);
                        if (!rc && cladatum->comdatum) {
                                rc = hashtab_map(
                                        cladatum->comdatum->permissions.table,
                                        perm_name, &v);
                        }
                        if (rc)
                                perm = v.name;
                        if (perm) {
				len = snprintf(p, sizeof(avbuf) - avlen, " %s", perm);
				if (len < 0 || (size_t) len >= (sizeof(avbuf) - avlen))
					return NULL;
				p += len;
				avlen += len;
                        }
                }
        }

        return avbuf;
}
