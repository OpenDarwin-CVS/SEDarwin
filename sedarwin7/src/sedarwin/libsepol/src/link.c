/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *	    Joshua Brindle <jbrindle@tresys.com>
 *          Jason Tang <jtang@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
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

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/avrule_block.h>
#include <sepol/policydb/link.h>

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "debug.h"

typedef struct policy_module {
        policydb_t *policy;
        uint32_t num_decls;
        uint32_t *map[SYM_NUM];
        uint32_t *avdecl_map;
        uint32_t **perm_map;
        uint32_t *perm_map_len;
        
        /* a pointer to within the base module's avrule_block chain to
         * where this module's global now resides */
        avrule_block_t *base_global;
} policy_module_t;

typedef struct link_state {
	int verbose;
	policydb_t *base;
        avrule_block_t *last_avrule_block, *last_base_avrule_block;
        uint32_t next_decl_id, current_decl_id;
        avrule_decl_t **decl_id_to_decl;

        /* temporary variables, used during hashtab_map() calls */
	policy_module_t *cur;
        char *cur_mod_name;
        avrule_decl_t *dest_decl;
        class_datum_t *src_class, *dest_class;
        uint32_t symbol_num;

        /* error reporting fields */
	sepol_handle_t *handle;
} link_state_t;

struct missing_requirement {
        uint32_t symbol_type;
        uint32_t symbol_value;
        uint32_t perm_value;
};

static const char *symtab_names[SYM_NUM] = {
        "common", "class", "role", "type/attribute", "user",
        "bool", "level", "category"
};

/* FIX ME: this function is in util.c already! */

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

/* Deallocates all elements within a module, but NOT the policydb_t
 * structure within, as well as the pointer itself. */
static void policy_module_destroy(policy_module_t *mod)
{
        unsigned int i;
        if (mod == NULL) {
                return;
        }
        for (i = 0; i < SYM_NUM; i++) {
                free(mod->map[i]);
        }
        for (i = 0; mod->perm_map != NULL && i < mod->policy->p_classes.nprim; i++) {
                free(mod->perm_map[i]);
        }
        free(mod->perm_map);
        free(mod->perm_map_len);
        free(mod->avdecl_map);
        free(mod);
}

/***** functions that copy identifiers from a module to base *****/

static int permission_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        /* build the mapping for permissions encompassing this class.
         * unlike symbols, the permission map translates between
         * module permission bit to target permission bit.  that bit
         * may have originated from the class -or- it could be from
         * the class's common parent.*/
        char *perm_id = key;
        perm_datum_t *perm, *new_perm;
        link_state_t *state = (link_state_t *)data;

        class_datum_t *src_class = state->src_class;
        class_datum_t *dest_class = state->dest_class;
        policy_module_t *mod = state->cur;
        uint32_t sclassi = src_class->value - 1;

        perm = (perm_datum_t *) datum;
        new_perm = hashtab_search(dest_class->permissions.table, perm_id);
        if (new_perm == NULL && dest_class->comdatum != NULL) {
                new_perm = hashtab_search(dest_class->comdatum->permissions.table, perm_id);
        }
        if (!new_perm) {
                ERR(state->handle, "Module %s depends on permission %s in class %s, not satisfied", state->cur_mod_name, perm_id, mod->policy->p_class_val_to_name[dest_class->value - 1]);
                return -1;
        }

        if (perm->value > mod->perm_map_len[sclassi]) {
                uint32_t *newmap = calloc(perm->value, sizeof(*newmap));
                if (newmap == NULL) {
                        ERR(state->handle, "Out of memory!");
                        return -1;
                }
                memcpy(newmap, mod->perm_map[sclassi], mod->perm_map_len[sclassi] * sizeof(*newmap));
                free(mod->perm_map[sclassi]);
                mod->perm_map[sclassi] = newmap;
                mod->perm_map_len[sclassi] = perm->value;
        }
        mod->perm_map[sclassi][perm->value - 1] = new_perm->value;
        
        return 0;
}

static int class_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        char *id = key;
        class_datum_t *cladatum, *new_class;
	link_state_t *state = (link_state_t *)data;

        cladatum = (class_datum_t *) datum;
        new_class = hashtab_search(state->base->p_classes.table, id);
        if (!new_class) {
                ERR(state->handle, "%s: Modules may not yet declare new classes.", state->cur_mod_name);
                return -1;
        }
        state->cur->map[SYM_CLASSES][cladatum->value - 1] = new_class->value;

        /* copy permissions */
        state->src_class = cladatum;
        state->dest_class = new_class;
        if (hashtab_map(cladatum->permissions.table, permission_copy_callback, state) != 0) {
                return -1;
        }
        
        return 0;
}

static int role_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id = key, *new_id = NULL;
        role_datum_t *role, *base_role, *new_role = NULL;
	link_state_t *state = (link_state_t *)data;

        role = (role_datum_t*)datum;

        base_role = hashtab_search(state->base->p_roles.table, id);
        if (base_role == NULL) {
                if (state->verbose)
                        INFO(state->handle, "copying role %s", id);

                if ((new_id = strdup(id)) == NULL) {
                        goto cleanup;
                }
                
                if ((new_role = (role_datum_t *) malloc(sizeof(*new_role))) == NULL) {
                        goto cleanup;
                }
                role_datum_init(new_role);

                /* new_role's dominates and types field will be copied
                 * during role_fix_callback() */
                new_role->value = state->base->p_roles.nprim + 1;

                ret = hashtab_insert(state->base->p_roles.table,
                                     (hashtab_key_t) new_id, (hashtab_datum_t) new_role);
                if (ret) {
                        goto cleanup;
                }
                state->base->p_roles.nprim++;
                base_role = new_role;
        }

        new_id = NULL;
        if ((new_role = malloc(sizeof(*new_role))) == NULL) {
                goto cleanup;
        }
        role_datum_init(new_role);
        new_role->value = base_role->value;
        if ((new_id = strdup(id)) == NULL) {
                goto cleanup;
        }
        if (hashtab_insert(state->dest_decl->p_roles.table, new_id, new_role)) {
                goto cleanup;
        }
        state->dest_decl->p_roles.nprim++;
        
        state->cur->map[SYM_ROLES][role->value - 1] = new_role->value;
        return 0;
        
 cleanup:
        ERR(state->handle, "Out of memory!");
        role_datum_destroy(new_role);
	free(new_id);
	free(new_role);
        return -1;
}

/* Copy types and attributes from a module into the base module. The
 * attributes are copied, but the types that make up this attribute
 * are delayed type_fix_callback(). */
static int type_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id = key, *new_id = NULL;
        type_datum_t *type, *base_type, *new_type = NULL;
	link_state_t *state = (link_state_t *)data;

        type = (type_datum_t*)datum;
        if (!type->primary) {
                /* aliases are handled later, in alias_copy_callback() */
                return 0;
        }

        base_type = hashtab_search(state->base->p_types.table, id);
        if (base_type != NULL) {
                /* type already exists.  check that it is what this
                 * module expected.  duplicate declarations (e.g., two
                 * modules both declare type foo_t) is checked during
                 * scope_copy_callback(). */
                if (type->isattr && !base_type->isattr) {
                        ERR(state->handle, "%s: Expected %s to be an attribute, but it was already declared as a type.",
                                    state->cur_mod_name, id);
                        return -1;
                }
                else if (!type->isattr && base_type->isattr) {
                        ERR(state->handle, "%s: Expected %s to be a type, but it was already declared as an attribute.",
                                    state->cur_mod_name, id);
                        return -1;
                }
        }
        else {
                if (state->verbose)
                        INFO(state->handle, "copying type %s", id);

                if ((new_id = strdup(id)) == NULL) {
                        goto cleanup;
                }
                
                if ((new_type = (type_datum_t *) calloc(1, sizeof(*new_type))) == NULL) {
                        goto cleanup;
                }
                new_type->primary = type->primary;
                new_type->isattr = type->isattr;
                /* for attributes, the writing of new_type->types is
                   done in type_fix_callback() */

                new_type->value = state->base->p_types.nprim + 1;

                ret = hashtab_insert(state->base->p_types.table,
                                     (hashtab_key_t) new_id, (hashtab_datum_t) new_type);
                if (ret) {
                        goto cleanup;
                }
                state->base->p_types.nprim++;
                base_type = new_type;
        }

        new_id = NULL;
        if ((new_type = calloc(1, sizeof(*new_type))) == NULL) {
                goto cleanup;
        }
        new_type->primary = type->primary;
        new_type->isattr = type->isattr;
        new_type->value = base_type->value;
        if ((new_id = strdup(id)) == NULL) {
                goto cleanup;
        }
        if (hashtab_insert(state->dest_decl->p_types.table, new_id, new_type)) {
                goto cleanup;
        }
        state->dest_decl->p_types.nprim++;
        
        state->cur->map[SYM_TYPES][type->value - 1] = new_type->value;
        return 0;
        
 cleanup:
        ERR(state->handle, "Out of memory!");
        free(new_id);
        free(new_type);
        return -1;
}


static int user_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id = key, *new_id = NULL;
        user_datum_t *user, *base_user, *new_user = NULL;
	link_state_t *state = (link_state_t *)data;

	if (state->base->mls) {
		ERR(state->handle, "Users cannot be declared in MLS modules");
		return -1;
	}

        user = (user_datum_t*)datum;

        base_user = hashtab_search(state->base->p_users.table, id);
        if (base_user == NULL) {
                if (state->verbose)
                        INFO(state->handle, "copying user %s", id);

                if ((new_id = strdup(id)) == NULL) {
                        goto cleanup;
                }
                
                if ((new_user = (user_datum_t *) malloc(sizeof(*new_user))) == NULL) {
                        goto cleanup;
                }
                user_datum_init(new_user);
                /* new_users's roles field will be copied during
                   fix_user_callback().  the MLS fields are currently
                   unimplemented */
                
                new_user->value = state->base->p_users.nprim + 1;

                ret = hashtab_insert(state->base->p_users.table,
                                     (hashtab_key_t) new_id, (hashtab_datum_t) new_user);
                if (ret) {
                        goto cleanup;
                }
                state->base->p_users.nprim++;
                base_user = new_user;
        }

        new_id = NULL;
        if ((new_user = malloc(sizeof(*new_user))) == NULL) {
                goto cleanup;
        }
        user_datum_init(new_user);
        new_user->value = base_user->value;
        if ((new_id = strdup(id)) == NULL) {
                goto cleanup;
        }
        if (hashtab_insert(state->dest_decl->p_users.table, new_id, new_user)) {
                goto cleanup;
        }
        state->dest_decl->p_users.nprim++;
        
        state->cur->map[SYM_USERS][user->value - 1] = new_user->value;
        return 0;
        
 cleanup:
        ERR(state->handle, "Out of memory!");
        user_datum_destroy(new_user);
	free(new_id);
	free(new_user);
        return -1;
}

static int bool_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id = key, *new_id = NULL;
        cond_bool_datum_t *booldatum, *base_bool, *new_bool = NULL;
	link_state_t *state = (link_state_t *)data;

        booldatum = (cond_bool_datum_t*)datum;

        base_bool = hashtab_search(state->base->p_bools.table, id);
        if (base_bool == NULL) {
                if (state->verbose)
                        INFO(state->handle, "copying boolean %s", id);

                if ((new_id = strdup(id)) == NULL) {
                        goto cleanup;
                }
                
                if ((new_bool = (cond_bool_datum_t *) malloc(sizeof(*new_bool))) == NULL) {
                        goto cleanup;
                }
                new_bool->state = booldatum->state;
                new_bool->value = state->base->p_bools.nprim + 1;

                ret = hashtab_insert(state->base->p_bools.table,
                                     (hashtab_key_t) new_id, (hashtab_datum_t) new_bool);
                if (ret) {
                        goto cleanup;
                }
                state->base->p_bools.nprim++;
                base_bool = new_bool;
                
        }

        new_id = NULL;
        if ((new_bool = malloc(sizeof(*new_bool))) == NULL) {
                goto cleanup;
        }
        new_bool->state = base_bool->state;
        new_bool->value = base_bool->value;
        if ((new_id = strdup(id)) == NULL) {
                goto cleanup;
        }
        if (hashtab_insert(state->dest_decl->p_bools.table, new_id, new_bool)) {
                goto cleanup;
        }
        state->dest_decl->p_bools.nprim++;

        state->cur->map[SYM_BOOLS][booldatum->value - 1] = new_bool->value;
        return 0;
        
 cleanup:
        ERR(state->handle, "Out of memory!");
        cond_destroy_bool(new_id, new_bool, NULL);
        return -1;
}

static int (*copy_callback_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum, void *datap) = {
        NULL,
        class_copy_callback,
        role_copy_callback,
        type_copy_callback,
        user_copy_callback,
        bool_copy_callback,
        NULL,
        NULL
};

/* The aliases have to be copied after the types and attributes to be
 * certain that the base symbol table will have the type that the
 * alias refers. Otherwise, we won't be able to find the type value
 * for the alias. We can't depend on the declaration ordering because
 * of the hash table.
 */
static int alias_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        char *id = key, *new_id = NULL, *target_id;
        type_datum_t *type, *base_type, *new_type = NULL, *target_type;
	link_state_t *state = (link_state_t *)data;
        policy_module_t *mod = state->cur;

        type = (type_datum_t*)datum;
        if (type->primary) {
                /* ignore types and attributes -- they were handled in
                 * type_copy_callback() */
                return 0;
        }

        target_id = mod->policy->p_type_val_to_name[type->value - 1];
        target_type = hashtab_search(state->base->p_types.table, target_id);
        if (target_type == NULL) {
                ERR(state->handle, "%s: Could not find type %s for alias %s.",
                            state->cur_mod_name, target_id, id);
                return -1;
        }
        
        base_type = hashtab_search(state->base->p_types.table, id);
        if (base_type == NULL) {
                if (state->verbose)
                        INFO(state->handle, "copying alias %s", id);

                if ((new_type = (type_datum_t *) calloc(1, sizeof(*new_type))) == NULL) {
                        goto cleanup;
                }
                new_type->primary = type->primary;
                new_type->isattr = type->isattr;
                new_type->value = target_type->value;
                if ((new_id = strdup(id)) == NULL) {
                        goto cleanup;
                }
                if (hashtab_insert(state->base->p_types.table, new_id, new_type)) {
                        goto cleanup;
                }
                base_type = new_type;
        }

        new_id = NULL;
        if ((new_type = (type_datum_t *) calloc(1, sizeof(*new_type))) == NULL) {
                goto cleanup;
        }
        new_type->primary = type->primary;
        new_type->isattr = type->isattr;
        new_type->value = base_type->value;
        if ((new_id = strdup(id)) == NULL) {
                goto cleanup;
        }
        if (hashtab_insert(state->dest_decl->p_types.table, new_id, new_type)) {
                goto cleanup;
        }

        state->cur->map[SYM_TYPES][type->value - 1] = new_type->value;
        return 0;

 cleanup:
        ERR(state->handle, "Out of memory!");
        free(new_id);
        free(new_type);
        return -1;
}


/*********** callbacks that fix bitmaps ***********/

static int type_set_convert(type_set_t *types, type_set_t *dst,
                            policy_module_t *mod, link_state_t *state __attribute__ ((unused)))
{
	unsigned int i;
	ebitmap_node_t *tnode;
	ebitmap_for_each_bit(&types->types, tnode, i) {
		if (ebitmap_node_get_bit(tnode, i)) {
                        assert(mod->map[SYM_TYPES][i]);
                        if (ebitmap_set_bit(&dst->types, mod->map[SYM_TYPES][i] - 1, 1)) {
                                goto cleanup;
                        }
                }
        }
	ebitmap_for_each_bit(&types->negset, tnode, i) {
                if (ebitmap_node_get_bit(tnode, i)) {
                        assert(mod->map[SYM_TYPES][i]);
                        if (ebitmap_set_bit(&dst->negset, mod->map[SYM_TYPES][i] - 1, 1)) {
                                goto cleanup;
                        }
                }
        }
        dst->flags = types->flags;
	return 0;

 cleanup:
        return -1;
}

/* OR 2 typemaps together and at the same time map the src types to
 * the correct values in the dst typeset.
 */
static int type_set_or_convert(type_set_t *types, type_set_t *dst,
                               policy_module_t *mod, link_state_t *state)
{
	type_set_t ts_tmp;

	type_set_init(&ts_tmp);
        if (type_set_convert(types, &ts_tmp, mod, state) == -1) {
                goto cleanup;
        }
        if (type_set_or_eq(dst, &ts_tmp)) {
                goto cleanup;
        }
        type_set_destroy(&ts_tmp);
	return 0;

 cleanup:
        ERR(state->handle, "Out of memory!");
        type_set_destroy(&ts_tmp);
        return -1;
}


static int role_set_or_convert(role_set_t *roles, role_set_t *dst,
                               policy_module_t *mod, link_state_t *state)
{
	unsigned int i;
	ebitmap_t tmp;
	ebitmap_node_t *rnode;

	ebitmap_init(&tmp);
	ebitmap_for_each_bit(&roles->roles, rnode, i) {
                if (ebitmap_node_get_bit(rnode, i)) {
                        assert(mod->map[SYM_ROLES][i]);
                        if (ebitmap_set_bit(&tmp, mod->map[SYM_ROLES][i] - 1, 1)) {
                                goto cleanup;
                        }
                }
	}
	if (ebitmap_union(&dst->roles, &tmp)) {
                goto cleanup;
        }
        dst->flags |= roles->flags;
        ebitmap_destroy(&tmp);
	return 0;
 cleanup:
        ERR(state->handle, "Out of memory!");
        ebitmap_destroy(&tmp);
        return -1;
}

static int role_fix_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        unsigned int i;
        char *id = key;
        role_datum_t *role, *dest_role = NULL;
	link_state_t *state = (link_state_t *)data;
        ebitmap_t e_tmp;
        policy_module_t *mod = state->cur;
	ebitmap_node_t *rnode;

        role = (role_datum_t *)datum;
        
        dest_role = hashtab_search(state->dest_decl->p_roles.table, id);
        assert(dest_role != NULL);

        if (state->verbose) {
                INFO(state->handle, "fixing role %s", id);
        }

        ebitmap_init(&e_tmp);
	ebitmap_for_each_bit(&role->dominates, rnode, i) {
                if (ebitmap_node_get_bit(rnode, i)) {
                        assert(mod->map[SYM_ROLES][i]);
                        if (ebitmap_set_bit(&e_tmp, mod->map[SYM_ROLES][i] - 1, 1)) {
                                goto cleanup;
                        }
                }
        }
        if (ebitmap_union(&dest_role->dominates, &e_tmp)) {
                goto cleanup;
        }
        if (type_set_or_convert(&role->types, &dest_role->types, mod, state)) {
                goto cleanup;
        }
        ebitmap_destroy(&e_tmp);
        return 0;

 cleanup:
        ERR(state->handle, "Out of memory!");
        ebitmap_destroy(&e_tmp);
        return -1;
}


static int type_fix_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        unsigned int i;
        char *id = key;
        type_datum_t *type, *new_type = NULL;
	link_state_t *state = (link_state_t *)data;
        ebitmap_t e_tmp;
        policy_module_t *mod = state->cur;
	ebitmap_node_t *tnode;

        type = (type_datum_t *)datum;

        /* only fix attributes */
        if (!type->primary || !type->isattr) {
                return 0;
        }

        new_type = hashtab_search(state->dest_decl->p_types.table, id);
        assert(new_type != NULL && new_type->isattr);

        if (state->verbose) {
                INFO(state->handle, "fixing attribute %s", id);
        }

        ebitmap_init(&e_tmp);
	ebitmap_for_each_bit(&type->types, tnode, i) {
                if (ebitmap_node_get_bit(tnode, i)) {
                        assert(mod->map[SYM_TYPES][i]);
                        if (ebitmap_set_bit(&e_tmp, mod->map[SYM_TYPES][i] - 1, 1)) {
                                goto cleanup;
                        }
                }
        }
        if (ebitmap_union(&new_type->types, &e_tmp)) {
                goto cleanup;
        }
        ebitmap_destroy(&e_tmp);
        return 0;

 cleanup:
        ERR(state->handle, "Out of memory!");
        ebitmap_destroy(&e_tmp);
        return -1;
}


static int user_fix_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        char *id = key;
        user_datum_t *user, *new_user = NULL;
	link_state_t *state = (link_state_t *)data;
        policy_module_t *mod = state->cur;

        user = (user_datum_t *)datum;
        
        new_user = hashtab_search(state->dest_decl->p_users.table, id);
        assert(new_user != NULL);

        if (state->verbose) {
                INFO(state->handle, "fixing user %s", id);
        }

        if (role_set_or_convert(&user->roles, &new_user->roles, mod, state)) {
                goto cleanup;
        }

        return 0;

 cleanup:
        ERR(state->handle, "Out of memory!");
        return -1;
}

static int (*fix_callback_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum, void *datap) = {
        NULL,
        NULL,
        role_fix_callback,
        type_fix_callback,
        user_fix_callback,
        NULL,
        NULL,
        NULL
};

static int role_merge_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        char *id = key;
        role_datum_t *role, *dest_role = NULL;
	link_state_t *state = (link_state_t *)data;

        role = (role_datum_t *)datum;
        
        dest_role = hashtab_search(state->base->p_roles.table, id);
        assert(dest_role != NULL);

        if (ebitmap_union(&dest_role->dominates, &role->dominates) ||
            type_set_or_eq(&dest_role->types, &role->types)) {
                ERR(state->handle, "Out of memory!");
                return -1;
        }
        return 0;
}

static int type_merge_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        char *id = key;
        type_datum_t *type, *new_type = NULL;
	link_state_t *state = (link_state_t *)data;

        type = (type_datum_t *)datum;

        /* only fix attributes */
        if (!type->primary || !type->isattr) {
                return 0;
        }

        new_type = hashtab_search(state->base->p_types.table, id);
        assert(new_type != NULL && new_type->isattr);

        if (ebitmap_union(&new_type->types, &type->types)) {
                ERR(state->handle, "Out of memory!");
                return -1;
        }
        return 0;
}

static int user_merge_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        char *id = key;
        user_datum_t *user, *new_user = NULL;
	link_state_t *state = (link_state_t *)data;

        user = (user_datum_t *)datum;
        
        new_user = hashtab_search(state->base->p_users.table, id);
        assert(new_user != NULL);
        if (ebitmap_union(&new_user->roles.roles, &user->roles.roles)) {
                ERR(state->handle, "Out of memory!");
                return -1;
        }
        new_user->roles.flags |= user->roles.flags;
        return 0;
}

static int (*merge_callback_f[SYM_NUM]) (hashtab_key_t key, hashtab_datum_t datum, void *datap) = {
        NULL,
        NULL,
        role_merge_callback,
        type_merge_callback,
        user_merge_callback,
        NULL,
        NULL,
        NULL
};

/*********** functions that copy AV rules ***********/

static int copy_avrule_list(avrule_t *list, avrule_t **dst,
                            policy_module_t *module, link_state_t *state)
{
        unsigned int i;
        avrule_t *cur, *new_rule = NULL, *tail;
        class_perm_node_t *cur_perm, *new_perm, *tail_perm = NULL;

        tail = *dst;
        while (tail && tail->next) {
                tail = tail->next;
        }

        cur = list;
        while (cur) {
                if ((new_rule = (avrule_t*)malloc(sizeof(avrule_t))) == NULL) {
                        goto cleanup;
                }
                avrule_init(new_rule);

                new_rule->specified = cur->specified;
                new_rule->flags = cur->flags;
                if (type_set_convert(&cur->stypes, &new_rule->stypes, module, state) == -1 ||
                    type_set_convert(&cur->ttypes, &new_rule->ttypes, module, state) == -1) {
                        goto cleanup;
                }

                cur_perm = cur->perms;
                tail_perm = NULL;
                while (cur_perm) {
                        if ((new_perm = (class_perm_node_t*)malloc(sizeof(class_perm_node_t))) == NULL) {
                                goto cleanup;
                        }
                        class_perm_node_init(new_perm);

                        new_perm->class = module->map[SYM_CLASSES][cur_perm->class - 1];
                        assert(new_perm->class);

                        if (new_rule->specified & (AVRULE_AV | AVRULE_NEVERALLOW)) {
                                for (i = 0; i < module->perm_map_len[cur_perm->class - 1]; i++) {
                                        if (!(cur_perm->data & (1U << i)))
                                                continue;
					new_perm->data |=
						(1U << (module->perm_map[cur_perm->class - 1][i] - 1));
                                }
                        } else {
                                new_perm->data = module->map[SYM_TYPES][cur_perm->data - 1];
                        }

                        if (new_rule->perms == NULL) {
                                new_rule->perms = new_perm;
                        }
                        else {
                                tail_perm->next = new_perm;
                        }
                        tail_perm = new_perm;
                        cur_perm = cur_perm->next;
                }
                new_rule->line = cur->line;

                cur = cur->next;

                if (*dst == NULL) {
                        *dst = new_rule;
                }
                else {
                        tail->next = new_rule;
                }
                tail = new_rule;
        }

        return 0;
 cleanup:
        ERR(state->handle, "Out of memory!");
        avrule_destroy(new_rule);
	free(new_rule);
        return -1;
}

static int copy_role_trans_list(role_trans_rule_t *list, role_trans_rule_t **dst,
                                policy_module_t *module, link_state_t *state)
{
	role_trans_rule_t *cur, *new_rule = NULL, *tail;

	cur = list;
        tail = *dst;
        while (tail && tail->next) {
                tail = tail->next;
        }
	while (cur) {
                if ((new_rule = (role_trans_rule_t*)malloc (sizeof(role_trans_rule_t))) == NULL) {
			goto cleanup;
		}
		role_trans_rule_init(new_rule);

		if (role_set_or_convert(&cur->roles, &new_rule->roles, module, state) ||
                    type_set_or_convert(&cur->types, &new_rule->types, module, state)) {
                        goto cleanup;
                }

		new_rule->new_role = module->map[SYM_ROLES][cur->new_role - 1];

		if (*dst == NULL) {
			*dst = new_rule;
                }
		else {
			tail->next = new_rule;
                }
                tail = new_rule;
		cur = cur->next;
	}
	return 0;
 cleanup:
        ERR(state->handle, "Out of memory!");
        role_trans_rule_list_destroy(new_rule);
        return -1;
}

static int copy_role_allow_list(role_allow_rule_t *list, role_allow_rule_t **dst,
                                policy_module_t *module, link_state_t *state)
{
	role_allow_rule_t *cur, *new_rule = NULL, *tail;
	
	cur = list;
        tail = *dst;
        while (tail && tail->next) {
                tail = tail->next;
        }

	while (cur) {
		if ((new_rule = (role_allow_rule_t *)malloc (sizeof(role_allow_rule_t))) == NULL) {
                        goto cleanup;
		}
		role_allow_rule_init(new_rule);

		if (role_set_or_convert(&cur->roles, &new_rule->roles, module, state) ||
                    role_set_or_convert(&cur->new_roles, &new_rule->new_roles, module, state)) {
                        goto cleanup;
                }
                if (*dst == NULL) {
                        *dst = new_rule;
                }
                else {
			tail->next = new_rule;
                }
                tail = new_rule;
		cur = cur->next;
        }
	return 0;
 cleanup:
        ERR(state->handle, "Out of memory!");
        role_allow_rule_list_destroy(new_rule);
        return -1;
}

static int copy_cond_list(cond_node_t *list, cond_node_t **dst,
                          policy_module_t *module, link_state_t *state)
{
        unsigned i;
        cond_node_t *cur, *new_node = NULL, *tail;
        cond_expr_t *cur_expr;
        tail = *dst;
        while (tail && tail->next)
                tail = tail->next;

        cur = list;
        while (cur) {
                new_node = (cond_node_t *)malloc(sizeof(cond_node_t));
                if (!new_node) {
                        goto cleanup;
                }
                memset(new_node, 0, sizeof(cond_node_t));

                new_node->cur_state = cur->cur_state;
                new_node->expr = cond_copy_expr(cur->expr);
                if (!new_node->expr)
                        goto cleanup;
                /* go back through and remap the expression */
                for (cur_expr = new_node->expr; cur_expr != NULL; cur_expr = cur_expr->next) {
			/* expression nodes don't have a bool value of 0 - don't map them */
			if (cur_expr->expr_type != COND_BOOL)
				continue;
                        assert(module->map[SYM_BOOLS][cur_expr->bool - 1] != 0);
                        cur_expr->bool = module->map[SYM_BOOLS][cur_expr->bool - 1];
                }
                new_node->nbools = cur->nbools;
                for (i = 0; i < cur->nbools; i++) {
                        uint32_t remapped_id = module->map[SYM_BOOLS][cur->bool_ids[i] - 1];
                        assert(remapped_id != 0);
                        new_node->bool_ids[i] = remapped_id;
                }
                new_node->expr_pre_comp = cur->expr_pre_comp;

                if (copy_avrule_list(cur->avtrue_list, &new_node->avtrue_list, module, state) ||
                    copy_avrule_list(cur->avfalse_list, &new_node->avfalse_list, module, state)) {
                        goto cleanup;
                }

                if (*dst == NULL) {
                        *dst = new_node;
                }
                else {
                        tail->next = new_node;
                }
                tail = new_node;
                cur = cur->next;
        }
        return 0;
 cleanup:
        ERR(state->handle, "Out of memory!");
        cond_node_destroy(new_node);
        free(new_node);
        return -1;
        
}

/*********** functions that copy avrule_decls from module to base ***********/

static int copy_identifiers(link_state_t *state,
                            symtab_t *src_symtab, avrule_decl_t *dest_decl) {
        int i;
        state->dest_decl = dest_decl;
        for (i = 0; i < SYM_NUM; i++) {
                if (copy_callback_f[i] != NULL &&
                    hashtab_map(src_symtab[i].table, copy_callback_f[i], state)) {
                        return -1;
                }
        }

        if (hashtab_map(src_symtab[SYM_TYPES].table, alias_copy_callback, state)) {
                return -1;
        }

        /* then fix bitmaps associated with those newly copied identifiers */
        for (i = 0; i < SYM_NUM; i++) {
                if (fix_callback_f[i] != NULL &&
                    hashtab_map(src_symtab[i].table, fix_callback_f[i], state)) {
                        return -1;
                }
        }
        return 0;
}

static int copy_module_identifiers(link_state_t *state, policy_module_t *module) {
        avrule_block_t *new_avrule = avrule_block_create();
        avrule_decl_t *new_decl;
        policydb_t *pol = module->policy;

        if (new_avrule == NULL) {
                ERR(state->handle, "Out of memory!");
                goto cleanup;
        }
        new_decl = avrule_decl_create(state->next_decl_id);
        if (new_decl == NULL) {
                ERR(state->handle, "Out of memory!");
                goto cleanup;
        }
        new_avrule->branch_list = new_decl;
        module->base_global = new_avrule;
        state->decl_id_to_decl[state->next_decl_id] = new_decl;
        module->avdecl_map[pol->global->branch_list->decl_id] = new_decl->decl_id;

        /* for now assume that this global scope is enabled.  in
         * verify_module_requirements() this assumption will be
         * checked */
        new_avrule->enabled = new_decl;
        new_decl->enabled = 1;

        if (copy_identifiers(state, pol->symtab, new_decl) == -1) {
                goto cleanup;
        }

        state->last_avrule_block->next = new_avrule;
        state->last_avrule_block = new_avrule;
        state->next_decl_id++;

        return 0;
 cleanup:
        avrule_block_list_destroy(new_avrule);
        return -1;
}

static int copy_scope_index(scope_index_t *src, scope_index_t *dest,
                            policy_module_t *module, link_state_t *state) {
        unsigned int i, j;
        uint32_t largest_mapped_class_value = 0;
	ebitmap_node_t *node;
        /* copy the scoping information for this avrule decl block */
        for (i = 0; i < SYM_NUM; i++) {
                ebitmap_t *srcmap = src->scope + i;
                ebitmap_t *destmap = dest->scope + i;
                if (copy_callback_f[i] == NULL) {
                        continue;
                }
		ebitmap_for_each_bit(srcmap, node, j) {
                        if (ebitmap_node_get_bit(node, j)) {
                                assert(module->map[i][j] != 0);
                                if (ebitmap_set_bit(destmap, module->map[i][j] - 1, 1) != 0) {
                                        
                                        goto cleanup;
                                }
                                if (i == SYM_CLASSES && 
                                    largest_mapped_class_value < module->map[SYM_CLASSES][j]) {
                                    largest_mapped_class_value = module->map[SYM_CLASSES][j];
                                }
                        }
                }
        }
        
        /* next copy the enabled permissions data  */
        if ((dest->class_perms_map = malloc(largest_mapped_class_value *
                                            sizeof(*dest->class_perms_map))) == NULL) {
                goto cleanup;
        }
        for (i = 0; i < largest_mapped_class_value; i++) {
                ebitmap_init(dest->class_perms_map + i);
        }
        dest->class_perms_len = largest_mapped_class_value;
        for (i = 0; i < src->class_perms_len; i++) {
                ebitmap_t *srcmap = src->class_perms_map + i;
                ebitmap_t *destmap = dest->class_perms_map + module->map[SYM_CLASSES][i] - 1;
		ebitmap_for_each_bit(srcmap, node, j) {
                        if (ebitmap_node_get_bit(node, j) &&
                            ebitmap_set_bit(destmap, module->perm_map[i][j] - 1, 1)) {
                                goto cleanup;
                        }
                }
        }
        
        return 0;
        
 cleanup:
        ERR(state->handle, "Out of memory!");
        return -1;
}

static int copy_avrule_decl(link_state_t *state, policy_module_t *module,
                            avrule_decl_t *src_decl, avrule_decl_t *dest_decl) {
        /* first copy all of the RBAC and TE rules */
        if (copy_avrule_list(src_decl->avrules, &dest_decl->avrules, module, state) == -1 ||
            copy_role_trans_list(src_decl->role_tr_rules, &dest_decl->role_tr_rules, module, state) == -1 ||
            copy_role_allow_list(src_decl->role_allow_rules, &dest_decl->role_allow_rules, module, state) == -1 ||
            copy_cond_list(src_decl->cond_list, &dest_decl->cond_list, module, state) == -1) {
                return -1;
        }
        
        /* then copy required and declared scope indices here */
        if (copy_scope_index(&src_decl->required, &dest_decl->required,
                             module, state) == -1 ||
            copy_scope_index(&src_decl->declared, &dest_decl->declared,
                             module, state) == -1) {
                return -1;
        }

        /* finally copy any identifiers local to this declaration */
        if (copy_identifiers(state, src_decl->symtab, dest_decl) == -1) {
                return -1;
        }
        return 0;
}

static int copy_avrule_block(link_state_t *state, policy_module_t *module,
                             avrule_block_t *block) {
        avrule_block_t *new_block = avrule_block_create();
        avrule_decl_t *decl, *last_decl = NULL;
        if (new_block == NULL) {
                ERR(state->handle, "Out of memory!");
                goto cleanup;
        }

        for (decl = block->branch_list; decl != NULL; decl = decl->next) {
                avrule_decl_t *new_decl = avrule_decl_create(state->next_decl_id);
                if (new_decl == NULL) {
                        ERR(state->handle, "Out of memory!");
                        goto cleanup;
                }
                if (last_decl == NULL) {
                        new_block->branch_list = new_decl;
                }
                else {
                        last_decl->next = new_decl;
                }
                last_decl = new_decl;
                state->decl_id_to_decl[state->next_decl_id] = new_decl;
                module->avdecl_map[decl->decl_id] = new_decl->decl_id;

                if (copy_avrule_decl(state, module, decl, new_decl) == -1) {
                        goto cleanup;
                }

                state->next_decl_id++;
        }
        state->last_avrule_block->next = new_block;
        state->last_avrule_block = new_block;
        return 0;

 cleanup:
        avrule_block_list_destroy(new_block);
        return -1;
}

static int scope_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	unsigned int i;
	int ret;
        char *id = key, *new_id = NULL;
        scope_datum_t *scope, *base_scope;
	link_state_t *state = (link_state_t *)data;
        uint32_t symbol_num = state->symbol_num;
        uint32_t *avdecl_map = state->cur->avdecl_map;

        scope = (scope_datum_t*)datum;
        
        /* check if the base already has a scope entry */
        base_scope = hashtab_search(state->base->scope[symbol_num].table, id);
        if (base_scope == NULL) {
                scope_datum_t *new_scope;
                if ((new_id = strdup(id)) == NULL) {
                        goto cleanup;
                }
                
                if ((new_scope = (scope_datum_t *) calloc(1, sizeof(*new_scope))) == NULL) {
                        free(new_id);
                        goto cleanup;
                }
                ret = hashtab_insert(state->base->scope[symbol_num].table,
                                     (hashtab_key_t) new_id, (hashtab_datum_t) new_scope);
                if (ret) {
                        free(new_id);
                        free(new_scope);
                        goto cleanup;
                }
                new_scope->scope = SCOPE_REQ;  /* this is reset further down */
                base_scope = new_scope;
        }
        if (base_scope->scope == SCOPE_REQ && scope->scope == SCOPE_DECL) {
                /* this module declared symbol, so overwrite the old
                 * list with the new decl ids */
                base_scope->scope = SCOPE_DECL;
                free(base_scope->decl_ids);
                base_scope->decl_ids = NULL;
                base_scope->decl_ids_len = 0;
                for (i = 0; i < scope->decl_ids_len; i++) {
                        if (add_i_to_a(avdecl_map[scope->decl_ids[i]],
                                       &base_scope->decl_ids_len,
                                       &base_scope->decl_ids) == -1) {
                                goto cleanup;
                        }
                }
        }
        else if (base_scope->scope == SCOPE_DECL && scope->scope == SCOPE_REQ) {
                /* this module depended on a symbol that now exists,
                 * so don't do anything */
        }
        else if (base_scope->scope == SCOPE_REQ && scope->scope == SCOPE_REQ) {
                /* symbol is still required, so add to the list */
                for (i = 0; i < scope->decl_ids_len; i++) {
                        if (add_i_to_a(avdecl_map[scope->decl_ids[i]],
                                       &base_scope->decl_ids_len,
                                       &base_scope->decl_ids) == -1) {
                                goto cleanup;
                        }
                }
        }
        else {
                /* this module declared a symbol, and it was already
                 * declared.  only roles and users may be multiply
                 * declared; for all others this is an error. */
                if (symbol_num != SYM_ROLES && symbol_num != SYM_USERS) {
                        ERR(state->handle, "%s: Duplicate declaration in module: %s %s",
                                    state->cur_mod_name, symtab_names[state->symbol_num], id);
                        return -1;
                }
                for (i = 0; i < scope->decl_ids_len; i++) {
                        if (add_i_to_a(avdecl_map[scope->decl_ids[i]],
                                       &base_scope->decl_ids_len,
                                       &base_scope->decl_ids) == -1) {
                                goto cleanup;
                        }
                }
        }
        return 0;

 cleanup:
        ERR(state->handle, "Out of memory!");
        return -1;
}

/* Copy a module over to a base, remapping all values within.  After
 * all identifiers and rules are done, copy the scoping information.
 * This is when it checks for duplicate declarations. */
static int copy_module(link_state_t *state, policy_module_t *module) {
        int i;
        avrule_block_t *cur;
        state->cur = module;
        state->cur_mod_name = module->policy->name;

        /* first copy the identifiers used by this module */
        if (copy_module_identifiers(state, module) == -1) {
                return -1;
        }
        /* next copy the avrule blocks for the module's global scope */
        if (copy_avrule_decl(state, module,
                             module->policy->global->branch_list,
                             module->base_global->branch_list) == -1) {
                return -1;
        }
        assert(module->policy->global->branch_list->next == NULL);

        /* next copy all of the optional avrule blocks */
        for (cur = module->policy->global->next; cur != NULL; cur = cur->next) {
                if (copy_avrule_block(state, module, cur) == -1) {
                        return -1;
                }
        }

        /* then copy the scoping tables */
        for (i = 0; i < SYM_NUM; i++) {
                state->symbol_num = i;
                if (hashtab_map(module->policy->scope[i].table, scope_copy_callback, state)) {
                        return -1;
                }
        }

        return 0;
}

/***** functions that check requirements and enable blocks in a module ******/

/* borrowed from checkpolicy.c */

struct find_perm_arg {
	unsigned int valuep;
	hashtab_key_t key;
};

static int find_perm(
	hashtab_key_t key, 
	hashtab_datum_t datum, 
	void *varg) {

	struct find_perm_arg* arg = varg;

	perm_datum_t* perdatum = (perm_datum_t *) datum;
	if (arg->valuep == perdatum->value) {
		arg->key = key;
		return 1;
	}

	return 0;
}

/* Check if the requirements are met for a single declaration.  If all
 * are met return 1.  For the first requirement found to be missing,
 * if 'missing_sym_num' and 'missing_value' are both not NULL then
 * write to them the symbol number and value for the missing
 * declaration.  Then return 0 to indicate a missing declaration.
 * Note that if a declaration had no requirement at all (e.g., an ELSE
 * block) this returns 1. */
static int is_decl_requires_met(link_state_t *state,
                                avrule_decl_t *decl,
                                struct missing_requirement *req) {
        /* (This algorithm is very unoptimized.  It performs many
         * redundant checks.  A very obvious improvement is to cache
         * which symbols have been verified, so that they do not need
         * to be re-checked.) */
        unsigned int i, j;
        ebitmap_t *bitmap;
        char *id, *perm_id;
        policydb_t *pol = state->base;
	ebitmap_node_t *node;
        
        if (decl->enabled) {
                /* this declaration was already checked */
                return 1;
        }
        
        /* check that all symbols have been satisfied */
        for (i = 0; i < SYM_NUM; i++) {
                if (i == SYM_CLASSES) {
                        /* classes will be checked during permissions
                         * checking phase below */
                        continue;
                }
                bitmap = &decl->required.scope[i];
		ebitmap_for_each_bit(bitmap, node, j) {
			if (!ebitmap_node_get_bit(node, j)) {
                                continue;
                        }

                        /* check base's scope table */
                        id = pol->sym_val_to_name[i][j];
                        if (!is_id_enabled(id, state->base, i)) {
                                /* this symbol was not found */
                                if (req != NULL) {
                                        req->symbol_type = i;
                                        req->symbol_value = j + 1;
                                }
                                return 0;
                        }
                }
        }
        /* check that all classes and permissions have been satisfied */
        for (i = 0; i < decl->required.class_perms_len; i++) {

                bitmap = decl->required.class_perms_map + i;
		ebitmap_for_each_bit(bitmap, node, j) {

                        struct find_perm_arg fparg;

                        class_datum_t *cladatum;
                        uint32_t perm_value = j + 1;
                        if (!ebitmap_node_get_bit(node, j)) {
                                continue;
                        }
                        id = pol->p_class_val_to_name[i];
                        cladatum = pol->class_val_to_struct[i];
		
			fparg.valuep = perm_value;
			fparg.key = NULL;
			
                        hashtab_map(cladatum->permissions.table, find_perm, &fparg);
                        if (fparg.key == NULL && cladatum->comdatum != NULL)
                               hashtab_map(cladatum->comdatum->permissions.table, find_perm, &fparg);
                        perm_id = fparg.key;

                        assert(perm_id != NULL);
                        if (!is_perm_enabled(id, perm_id, state->base)) {
                                if (req != NULL) {
                                        req->symbol_type = SYM_CLASSES;
                                        req->symbol_value = i + 1;
                                        req->perm_value = perm_value;
                                }
                                return 0;
                        }
                }
        }
        
        /* all requirements have been met */
        return 1;
}

/* Check each of the avrules blocks within a chain, enabling as many
 * as possible.  If multiple decls within a chain can be enabled, give
 * preference to the earlier one.  The result is an algorithm akin to
 * iterative-deepening search.
 *
 * N.b.: This algorithm is position dependent and is not guaranteed to
 * find the optimal enabled declarations, for resolving dependencies
 * is at least an NP-complete problem.  This solution works /only/
 * because it exploits two limitations of the module language.  First,
 * else branches may not have make any declarations of their own.
 * Second, the grammar does not currently support else-if branches.
 *
 * Proof: The problem is similar to a boolean satisfiability problem,
 * for nothing less than an exhaustive search is guaranteed to derive
 * the optimal enabling arrangement.
 */
static void enable_avrules(link_state_t *state, policydb_t *pol) {
        int more_to_go;
        int max_depth = 1;
        int changed;
        do {
                more_to_go = 0;
                changed = 0;
                avrule_block_t *block;
                for (block = pol->global;
                     block != NULL;
                     block = block->next) {
                        avrule_decl_t *decl = block->branch_list;
                        int depth_count = max_depth;
                        if (block->enabled != NULL) {
                                continue;
                        }
                        while (depth_count-- > 0 && decl != NULL) {
                                if (is_decl_requires_met(state, decl, NULL)) {
                                        decl->enabled = 1;
                                        block->enabled = decl;
                                        changed = 1;
                                        break;
                                }
                                decl = decl->next;
                        }
                        if (decl != NULL) {
                                more_to_go = 1;
                        }
                }
                if (!changed) {
                        /* increase search depth if nothing changed on
                           this pass */
                        max_depth++;
                }
        } while (more_to_go);
}

static int verify_module_requirements(link_state_t *state,
                                      policy_module_t **modules,
                                      int len) {
        int i;
        struct missing_requirement req;
        policydb_t *p = state->base;

        if (state->verbose) {
                INFO(state->handle, "Verifying module global requirements.");
        }
        
        for (i = 0; i < len; i++) {
                avrule_decl_t *module_global = modules[i]->base_global->branch_list;
                char *mod_name = modules[i]->policy->name;
                module_global->enabled = 0;
                if (!is_decl_requires_met(state, module_global, &req)) {
                        if (req.symbol_type == SYM_CLASSES) {
	
                                struct find_perm_arg fparg;

                                class_datum_t *cladatum;
                                cladatum = p->class_val_to_struct[req.symbol_value - 1];

                                fparg.valuep = req.perm_value;
                                fparg.key = NULL;
                                hashtab_map(cladatum->permissions.table, find_perm, &fparg);

                                ERR(state->handle,
                                            "Module %s's global requirements were not met: class %s, permission %s",
                                            mod_name,
                                            p->p_class_val_to_name[req.symbol_value - 1],
                                            fparg.key);
                                return -1;
                        }
                        else {
                                ERR(state->handle,
                                            "Module %s's global requirements were not met: %s %s",
                                            mod_name, 
                                            symtab_names[req.symbol_type],
                                            p->sym_val_to_name[req.symbol_type][req.symbol_value - 1]);
                                return -1;
                        }
                }
                module_global->enabled = 1;
        }
        return 0;
}

/*********** merging and stripping functions ***********/

/* for each enabled block, merge its identifiers and avrules into the base */
static int merge_avrules(link_state_t *state, avrule_block_t *block) {
        avrule_decl_t *dest_decl = block->branch_list;
        cond_node_t *src_cond, *dest_cond;
        avrule_t *last_avrule = dest_decl->avrules, *tmp;
        role_trans_rule_t *last_rt = dest_decl->role_tr_rules;
        role_allow_rule_t *last_ra = dest_decl->role_allow_rules;

        while (last_avrule != NULL && last_avrule->next != NULL) {
                last_avrule = last_avrule->next;
        }
        while (last_rt != NULL && last_rt->next != NULL) {
                last_rt = last_rt->next;
        }
        while (last_ra != NULL && last_ra->next != NULL) {
                last_ra = last_ra->next;
        }
        
        block = block->next; /* start with the first non-base block */
        while (block != NULL) {
                avrule_decl_t *decl = block->enabled;
                unsigned int i, j;

                block = block->next;
                if (decl == NULL) {
                        continue;
                }

                /* merge additive statements */
                for (i = 0; i < SYM_NUM; i++) {
                        if (merge_callback_f[i] != NULL &&
                            hashtab_map(decl->symtab[i].table, merge_callback_f[i], state)) {
                                return -1;
                        }
                }
                
                /* merge cond_list, avrules, role_tr rules, and
                 * role_allow rules */
                src_cond = decl->cond_list;
                while (src_cond != NULL) {
                        dest_cond = get_decl_cond_list(state->base, dest_decl, src_cond);
                        if (dest_cond == NULL) {
                                ERR(state->handle, "Out of memory!");
                                return -1;
                        }
                        if (dest_cond->avtrue_list == NULL) {
                                dest_cond->avtrue_list = src_cond->avtrue_list;
                        }
                        else {
                                tmp = dest_cond->avtrue_list;
                                while (tmp->next != NULL) {
                                        tmp = tmp->next;
                                }
                                tmp->next = src_cond->avtrue_list; 
                        }
                        src_cond->avtrue_list = NULL;
                        if (dest_cond->avfalse_list == NULL) {
                                dest_cond->avfalse_list = src_cond->avfalse_list;
                        }
                        else {
                                tmp = dest_cond->avfalse_list;
                                while (tmp->next != NULL) {
                                        tmp = tmp->next;
                                }
                                tmp->next = src_cond->avfalse_list; 
                        }
                        src_cond->avfalse_list = NULL;
                        src_cond = src_cond->next;
                }
                
                if (decl->avrules != NULL) {
                        if (last_avrule == NULL) {
                                dest_decl->avrules = decl->avrules;
                        }
                        else {
                                last_avrule->next = decl->avrules;
                        }
                        last_avrule = decl->avrules;
                        while (last_avrule->next != NULL) {
                                last_avrule = last_avrule->next;
                        }
                        decl->avrules = NULL;
                }
                if (decl->role_tr_rules != NULL) {
                        if (last_rt == NULL) {
                                dest_decl->role_tr_rules = decl->role_tr_rules;
                        }
                        else {
                                last_rt->next = decl->role_tr_rules;
                        }
                        last_rt = decl->role_tr_rules;
                        while (last_rt->next != NULL) {
                                last_rt = last_rt->next;
                        }
                        decl->role_tr_rules = NULL;
                }
                if (decl->role_allow_rules != NULL) {
                        if (last_ra == NULL) {
                                dest_decl->role_allow_rules = decl->role_allow_rules;
                        }
                        else {
                                last_ra->next = decl->role_allow_rules;
                        }
                        last_ra = decl->role_allow_rules;
                        while (last_ra->next != NULL) {
                                last_ra = last_ra->next;
                        }
                        decl->role_allow_rules = NULL;
                }
                /* checks for conflicting type transitions / role
                 * transitions will occur during expansion */
                
                /* finally merge declarations table */
                for (i = 0; i < SYM_NUM; i++) {
                        ebitmap_t *srcmap = decl->declared.scope + i;
                        ebitmap_t *destmap = dest_decl->declared.scope + i;
			ebitmap_node_t *node;
                        if (copy_callback_f[i] == NULL) {
                                continue;
                        }
			ebitmap_for_each_bit(srcmap, node, j) {
                                if (ebitmap_node_get_bit(node, j) &&
                                    ebitmap_set_bit(destmap, j, 1) != 0) {
                                        ERR(state->handle, "Out of memory!");
                                        return -1;
                                }
                        }
                }
        }
        return 0;
}

static int check_symbol_used(hashtab_key_t k, hashtab_datum_t d, void *args) {
        scope_datum_t *scope = (scope_datum_t *) d;
        link_state_t *state = (link_state_t *) args;
        int sym_num = state->symbol_num, retval;

        /* if the scope is declared and at least one of its decls is
         * enabled then don't remove this symbol */
        if (scope->scope == SCOPE_DECL) {
                unsigned int i;
                for (i = 0; i < scope->decl_ids_len; i++) {
                        avrule_decl_t *decl = state->decl_id_to_decl[scope->decl_ids[i]];
                        if (decl->enabled) {
                                /* overwrite this scope_datum's
                                 * declaration table to only point to
                                 * the root block */
                                free(scope->decl_ids);
                                scope->decl_ids = NULL;
                                if (add_i_to_a(state->dest_decl->decl_id,
                                               &scope->decl_ids_len,
                                               &scope->decl_ids) == -1) {
                                        ERR(state->handle, "Out of memory!");
                                }
                                return 0;
                        }
                }
        }

        /* prune this symbol from the global symbol table */
        retval = hashtab_remove(state->base->symtab[sym_num].table, k,
                                get_symtab_destroy_func(sym_num),
                                state->base);
        assert(retval == 0);
        /* hashtab_map_remove_on_error() will handle removing the
         * scope_datum_t */
        return -1;
}

/* Note that as a side effect of this removal, there will be 'holes'
 * within the scope and symbol tables.  Thus, if there exists a symbol
 * table with an nprim field of 50, there is not necessarily at least
 * 50 items actually within it. */
static int strip_symbols(link_state_t *state) {
        int i;
        state->dest_decl = state->base->global->branch_list;
        for (i = 0; i < SYM_NUM; i++) {
                state->symbol_num = i;
                hashtab_map_remove_on_error(state->base->scope[i].table,
                                            check_symbol_used,
                                            (hashtab_destroy_func_t) scope_destroy,
                                            state);
        }
        return 0;
}


/*********** the main linking functions ***********/

/* Given a module's policy, normalize all conditional expressions
 * within.  Return 0 on success, -1 on error. */
static int cond_normalize(policydb_t *p) {
        avrule_block_t *block;
        for (block = p->global; block != NULL; block = block->next) {
                avrule_decl_t *decl;
                for (decl = block->branch_list; decl != NULL; decl = decl->next) {
                        cond_list_t *cond = decl->cond_list;
                        if (cond != NULL && cond_normalize_expr(p, cond) < 0) {
                                return -1;
                        }
                }
        }
        return 0;
}

/* Allocate space for the various remapping arrays. */
static int prepare_module(link_state_t *state, policy_module_t *module) {
        int i;
        uint32_t items, num_decls = 0;
        avrule_block_t *cur;
        
        /* allocate the maps */
        for (i = 0; i < SYM_NUM; i++) {
                items = module->policy->symtab[i].nprim;
                if ((module->map[i] = (uint32_t*)calloc(items, sizeof(*module->map[i]))) == NULL) {
                        ERR(state->handle, "Out of memory!");
                        return -1;
                }
        }

        /* allocate the permissions remap here */
        items = module->policy->p_classes.nprim;
        if ((module->perm_map_len = calloc(items, sizeof(*module->perm_map_len))) == NULL) {
                ERR(state->handle, "Out of memory!");
                return -1;
        }
        if ((module->perm_map = calloc(items, sizeof(*module->perm_map))) == NULL) {
                ERR(state->handle, "Out of memory!");
                return -1;
        }

        /* allocate a map for avrule_decls */
        for (cur = module->policy->global; cur != NULL; cur = cur->next) {
                avrule_decl_t *decl;
                for (decl = cur->branch_list; decl != NULL; decl = decl->next) {
                        if (decl->decl_id > num_decls) {
                                num_decls = decl->decl_id;
                        }
                }
        }
        num_decls++;
        if ((module->avdecl_map = calloc(num_decls, sizeof(uint32_t))) == NULL) {
                ERR(state->handle, "Out of memory!");
                return -1;
        }
        module->num_decls = num_decls;
        
        /* normalize conditionals within */
        if (cond_normalize(module->policy) < 0) {
                ERR(state->handle, "Error while normalizing conditionals within the module %s.", module->policy->name);
                return -1;
        }
        return 0;
}

static int prepare_base(link_state_t *state, uint32_t num_mod_decls) {
        avrule_block_t *cur = state->base->global;
        assert(cur != NULL);
        state->next_decl_id = 0;

        /* iterate through all of the declarations in the base, to
           determine what the next decl_id should be */
        while (cur != NULL) {
                avrule_decl_t *decl;
                for (decl = cur->branch_list; decl != NULL; decl = decl->next) {
                        if (decl->decl_id > state->next_decl_id) {
                                state->next_decl_id = decl->decl_id;
                        }
                }
                state->last_avrule_block = cur;
                cur = cur->next;
        }
        state->last_base_avrule_block = state->last_avrule_block;
        state->next_decl_id++;

        /* allocate the table mapping from base's decl_id to its
         * avrule_decls and set the initial mappings */
        if ((state->decl_id_to_decl = calloc(state->next_decl_id + num_mod_decls,
                                             sizeof(*(state->decl_id_to_decl)))) == NULL) {
                ERR(state->handle, "Out of memory!");
                return -1;
        }
        cur = state->base->global;
        while (cur != NULL) {
                avrule_decl_t *decl = cur->branch_list;
                while (decl != NULL) {
                        state->decl_id_to_decl[decl->decl_id] = decl;
                        decl = decl->next;
                }
                cur = cur->next;
        }

        /* normalize conditionals within */
        if (cond_normalize(state->base) < 0) {
                ERR(state->handle, "Error while normalizing conditionals within the base module.");
                return -1;
        }
        return 0;
}

/* Link a set of modules into a base module. This process is somewhat
 * similar to an actual compiler: it requires a set of order dependent
 * steps.  The base and every module must have been indexed prior to
 * calling this function.
 * 
 * The general linking algorithm is:
 *
 *   1. Iterate through each module's avrule block.  Copy every avrule
 *      decl within to the base; during the copy remap every 'value'
 *      reference from the module to base.  During this copy enable the
 *      'global' block for each module.  (symbol remap phase)
 *   2. Enable the first avrule_decl in base module's 'global' block.
 *      (By definition any requires in the base module are ignored.)
 *   3. Iterate through each of base's avrule blocks.  If it has not
 *      been decided which decl has been enabled, check the requirements
 *      for the first decl.  If it is met, enable the decl.  (flow
 *      analysis phase)
 *   4. For each avrule block not enabled yet, try the first and second
 *      decl.  Keep increasing the search so that eventually each block's
 *      chain is search, to find the first decl to enable.  (This is a
 *      type of iterative deepening search, for you AI folks out there.)
 *   5. From step 1, it was recorded where within base's avrule_block
 *      chain were each of the global block that was auto-enabled.  Go
 *      through those and actually verify that their requirements have
 *      been met.  This step is deliberately done after all processing to
 *      to enable as many avrule blocks as possible.
 *   6. Now that the linker has enabled the appropriate modules and
 *      optionals, merge their symbol tables into base.  Do the same
 *      with avrule rule declarations.  (static link phase)
 *   7. Then search through the base policy and prune symbols that are
 *      were used only by disabled optionals.  (strip phase)
 *
 * Returns 0 on success, -1 on memory error, or -2 if could not copy a
 * block, or -3 if a module requirement was not met.
 *
 * To enable error reporting, pass a non-NULL allocated error buffer
 * and its size.  This function will fill in the buffer with a
 * detailed error description, ala errno.  Upon success the error
 * buffer will be untouched.
 */
int link_modules(sepol_handle_t *handle,
		 policydb_t *b, policydb_t **mods, int len,
                 int verbose)
{
        int i, retval = -1;
        policy_module_t **modules = NULL;
	link_state_t state;
        uint32_t num_mod_decls = 0;
        uint32_t base_was_enabled;

        memset(&state, 0, sizeof(state));
        state.base = b;
        state.verbose = verbose;
        state.handle = handle;

        if (b->policy_type != POLICY_BASE) {
                ERR(state.handle, "Target of link was not a base policy.");
                return -1;
        }

        /* first allocate some space to hold the maps from module
         * symbol's value to the destination symbol value; then do
         * other preparation work */
        if ((modules = (policy_module_t**)calloc(len, sizeof(*modules))) == NULL) {
                ERR(state.handle, "Out of memory!");
        	return -1;
        }
        for (i = 0; i < len; i++) {
                if (mods[i]->policy_type != POLICY_MOD) {
                        ERR(state.handle, "Tried to link in a policy that was not a module.");
                        goto cleanup;
                }

		if (mods[i]->mls != b->mls) {
			if (b->mls) 
				ERR(state.handle, "Tried to link in a non-MLS module with an MLS base.");
			else	
				ERR(state.handle, "Tried to link in an MLS module with a non-MLS base.");
			goto cleanup;
		}

        	if ((modules[i] = (policy_module_t*)calloc(1, sizeof(policy_module_t))) == NULL) {
                        ERR(state.handle, "Out of memory!");
                        goto cleanup;
		}
        	modules[i]->policy = mods[i];
                if (prepare_module(&state, modules[i]) == -1) {
                        goto cleanup;
                }
                num_mod_decls += modules[i]->num_decls;
        }
        if (prepare_base(&state, num_mod_decls) == -1) {
                goto cleanup;
        }

        /* copy and remap the module's data over to base */
        for (i = 0; i < len; i++) {
                state.cur = modules[i];
                if (copy_module(&state, modules[i]) == -1) {
                        retval = -2;
                        goto cleanup;
                }
        }
        
        /* re-index base, for symbols were added to symbol tables  */
        if (policydb_index_classes(state.base)) {
                ERR(state.handle, "Error while indexing classes");
                goto cleanup;
        }
        if (policydb_index_others(state.handle, state.base, 0)) {
                ERR(state.handle, "Error while indexing others");
                goto cleanup;
        }

        /* at this point the base policy includes all of the modules
         * data; one could destroy the module policies for they are no
         * longer needed other than for error reporting purposes */

        if (state.verbose) {
                INFO(state.handle, "Determining which avrules to enable.");
        }
        /* enable the global branch, then the appropriate optional branches */
        base_was_enabled = b->global->branch_list->enabled;
        b->global->enabled = b->global->branch_list;
        b->global->branch_list->enabled = 1;
        enable_avrules(&state, state.base);

        /* check that each module's global requirements have been met */
        if (verify_module_requirements(&state, modules, len) == -1) {
                retval = -3;
                goto cleanup;
        }

        /* merge enabled blocks into base's global block */
        if (merge_avrules(&state, state.base->global) == -1) {
                retval = -1;
                goto cleanup;
        }

        /* strip away parts of the policy that are no longer needed */
        if (strip_symbols(&state) == -1) {
                retval = -1;
                goto cleanup;
        }
        avrule_block_list_destroy(state.base->global->next);
        state.base->global->next = NULL;

        /* reset the global branch enabled flag now that the policy
           has been reconstructed */
        b->global->branch_list->enabled = base_was_enabled;
        if (!base_was_enabled) {
                b->global->enabled = NULL;
        }
        
        /* re-index base one final time, for some symbols were removed */
        if (policydb_index_classes(state.base)) {
                ERR(state.handle, "Error while indexing classes");
                goto cleanup;
        }
        if (policydb_index_others(state.handle, state.base, 0)) {
                ERR(state.handle, "Error while indexing others");
                goto cleanup;
        }

        retval = 0;
 cleanup:
        for (i = 0; modules != NULL && i < len; i++) {
                policy_module_destroy(modules[i]);
        }
        free(modules);
        free(state.decl_id_to_decl);
        return retval;
}
