/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *          Jason Tang <jtang@tresys.com>
 *	    Joshua Brindle <jbrindle@tresys.com>
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

#include "context.h"
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/hierarchy.h>
#include <sepol/policydb/avrule_block.h>

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "debug.h"

typedef struct expand_state {
	int verbose;
	uint32_t *typemap;
	policydb_t *base;
	policydb_t *out;
	sepol_handle_t *handle;
} expand_state_t;

static int type_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id, *new_id;
        type_datum_t *type, *new_type;
       	expand_state_t *state;

        id = (char *)key;
        type = (type_datum_t *)datum;
        state = (expand_state_t*)data;

        if (!type->primary) {
                /* aliases are handled later */
                return 0;
        }
        if (!is_id_enabled(id, state->base, SYM_TYPES)) {
                /* identifier's scope is not enabled */
                return 0;
        }

        if (state->verbose)
                INFO(state->handle, "copying type or attribute %s", id);

        new_id = strdup(id);
        if (new_id == NULL) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }

        new_type = (type_datum_t *) malloc(sizeof(type_datum_t));
        if (!new_type) {
                ERR (state->handle, "Out of memory!");
                free (new_id);
                return -ENOMEM;
        }
        memset(new_type, 0, sizeof(type_datum_t));

        new_type->isattr = type->isattr;
	new_type->value = ++state->out->p_types.nprim;
	if (new_type->value > UINT16_MAX) {
                free (new_id);
                free (new_type);
                ERR (state->handle, "type space overflow");
                return -1;
	}
        if (!type->isattr) {
                new_type->primary = 1;
        }
        state->typemap[type->value - 1] = new_type->value;

        ret = hashtab_insert(state->out->p_types.table,
                             (hashtab_key_t)new_id, (hashtab_datum_t)new_type);
        if (ret) {
                free (new_id);
                free (new_type);
                ERR (state->handle, "hashtab overflow");
                return -1;
        }

        return 0;
}

static int attr_convert_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	unsigned int i;
        char *id;
        type_datum_t *type, *new_type;
       	expand_state_t *state;
	ebitmap_node_t *node;

        id = (char *)key;
        type = (type_datum_t *)datum;
        state = (expand_state_t*)data;

        if (!type->isattr)
                return 0;

        if (!is_id_enabled(id, state->base, SYM_TYPES)) {
                /* identifier's scope is not enabled */
                return 0;
        }

        if (state->verbose)
                INFO(state->handle, "converting attribute %s", id);

	new_type = hashtab_search(state->out->p_types.table, id);
	if (!new_type) {
		ERR (state->handle, "attribute %s vanished!", id);
                return -1;
	}
	ebitmap_init(&new_type->types);

	ebitmap_for_each_bit(&type->types, node, i) {
		if (!ebitmap_node_get_bit(node, i))
			continue; 
		if (!state->typemap[i])
			continue;
		if (ebitmap_set_bit(&new_type->types,
				    state->typemap[i]-1, 1)) {
			ERR (state->handle, "out of memory");
			return -1;
		}
	}

        return 0;
}

static int perm_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id, *new_id;
        symtab_t *s;
        perm_datum_t *perm, *new_perm;

        id = key;
        perm = (perm_datum_t*)datum;
        s = (symtab_t*)data;

        new_perm = (perm_datum_t*)malloc(sizeof(perm_datum_t));
        if (!new_perm) {
                return -1;
        }
        memset(new_perm, 0, sizeof(perm_datum_t));

        new_id = strdup(id);
        if (!new_id) {
                free (new_perm);
                return -1;
        }

        new_perm->value = perm->value;
        s->nprim++;

        ret = hashtab_insert(s->table, new_id, (hashtab_datum_t*)new_perm);
        if (ret) {
                free (new_id);
                free (new_perm);
                return -1;
        }

        return 0;
}

static int common_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id, *new_id;
        common_datum_t *common, *new_common;
       	expand_state_t *state;

        id = (char *)key;
        common = (common_datum_t *)datum;
        state = (expand_state_t*)data;

        if (state->verbose)
                INFO(state->handle, "copying common %s", id);

        new_common = (common_datum_t*)malloc(sizeof(common_datum_t));
        if (!new_common) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }
        memset(new_common, 0, sizeof(common_datum_t));
        if (symtab_init(&new_common->permissions, PERM_SYMTAB_SIZE)) {
                ERR (state->handle, "Out of memory!");
                free (new_common);
                return -1;
        }

        new_id = strdup(id);
        if (!new_id) {
                ERR (state->handle, "Out of memory!");
                free (new_common);
                return -1;
        }

        new_common->value = common->value;
	state->out->p_commons.nprim++;

        ret = hashtab_insert(state->out->p_commons.table, new_id, (hashtab_datum_t*)new_common);
        if (ret) {
                ERR (state->handle, "hashtab overflow");
                free (new_common);
                free (new_id);
                return -1;
        }

        if (hashtab_map(common->permissions.table, perm_copy_callback, &new_common->permissions)) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }

        return 0;
}

static int constraint_node_clone(constraint_node_t **dst, constraint_node_t *src, expand_state_t *state)
{
        constraint_node_t *new_con = NULL, *last_new_con = NULL;
        constraint_expr_t *new_expr = NULL;
        *dst = NULL;
        while (src != NULL) {
                constraint_expr_t *expr, *expr_l = NULL;
        	new_con = (constraint_node_t*)malloc(sizeof(constraint_node_t));
        	if (!new_con) {
                        goto out_of_mem;
        	}
        	memset(new_con, 0, sizeof(constraint_node_t));
        	new_con->permissions = src->permissions;
        	for (expr = src->expr; expr; expr = expr->next) {
                        if ((new_expr = calloc(1, sizeof(*new_expr))) == NULL) {
                                goto out_of_mem;
                        }
                        if (constraint_expr_init(new_expr) == -1) {
                                goto out_of_mem;
        		}
        		new_expr->expr_type = expr->expr_type;
        		new_expr->attr = expr->attr;
        		new_expr->op = expr->op;
        		if (new_expr->expr_type == CEXPR_NAMES) {
                                if (new_expr->attr & CEXPR_TYPE) {
					/* Type sets require expansion and conversion. */
					if (expand_convert_type_set(state->base,
								    state->typemap,
								    expr->type_names,
								    &new_expr->names, 1)) {
						goto out_of_mem;
					}
				} else {
					/* Other kinds of sets do not. */
                                        if (ebitmap_cpy(&new_expr->names,
							&expr->names)) {
                                                goto out_of_mem;
                                        }
                                }
        		}
        		if (expr_l) {
        			expr_l->next = new_expr;
        		} else {
        			new_con->expr = new_expr;
        		}
        		expr_l = new_expr;
                        new_expr = NULL;
        	}
                if (last_new_con == NULL) {
                        *dst = new_con;
                }
                else {
        		last_new_con->next = new_con;
        	}
        	last_new_con = new_con;
                src = src->next;
        }

        return 0;
 out_of_mem:
        ERR(state->handle, "Out of memory!");
	if (new_con)
		free(new_con);
        constraint_expr_destroy(new_expr);
        return -1;
}

static int class_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id, *new_id;
        class_datum_t *class, *new_class;
       	expand_state_t *state;

        id = (char *)key;
        class = (class_datum_t *)datum;
        state = (expand_state_t*)data;

        if (!is_id_enabled(id, state->base, SYM_CLASSES)) {
                /* identifier's scope is not enabled */
                return 0;
        }

        if (state->verbose)
                INFO(state->handle, "copying class %s", id);

        new_class = (class_datum_t*)malloc(sizeof(class_datum_t));
        if (!new_class) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }
        memset(new_class, 0, sizeof(class_datum_t));
        if (symtab_init(&new_class->permissions, PERM_SYMTAB_SIZE)) {
                ERR (state->handle, "Out of memory!");
                free (new_class);
                return -1;
        }

        new_class->value = class->value;
	state->out->p_classes.nprim++;

        new_id = strdup(id);
        if (!new_id) {
                ERR (state->handle, "Out of memory!");
                free (new_class);
                return -1;
        }

        ret = hashtab_insert(state->out->p_classes.table, new_id, (hashtab_datum_t*)new_class);
        if (ret) {
                ERR (state->handle, "hashtab overflow");
                free (new_class);
                free (new_id);
                return -1;
        }

        if (hashtab_map(class->permissions.table, perm_copy_callback, &new_class->permissions)) {
                ERR (state->handle, "hashtab overflow");
                return -1;
        }

        if (class->comkey) {
                new_class->comkey = strdup(class->comkey);
                if (!new_class->comkey)
                {
                        ERR (state->handle, "Out of memory!");
                        return -1;
                }

                new_class->comdatum = hashtab_search(state->out->p_commons.table, new_class->comkey);
                if (!new_class->comdatum)
                {
                        ERR (state->handle, "could not find common datum %s", new_class->comkey);
                        return -1;
                }
                new_class->permissions.nprim += new_class->comdatum->permissions.nprim;
        }

        /* constraints */
        if (constraint_node_clone(&new_class->constraints, class->constraints, state) == -1 ||
            constraint_node_clone(&new_class->validatetrans, class->validatetrans, state) == -1) {
                return -1;
        }
        return 0;
}

/* The aliases have to be copied after the types and attributes to be certain that
 * the out symbol table will have the type that the alias refers. Otherwise, we
 * won't be able to find the type value for the alias. We can't depend on the
 * declaration ordering because of the hash table.
 */
static int alias_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id, *new_id;
        type_datum_t *alias, *new_alias;
       	expand_state_t *state;

        id = (char *)key;
        alias = (type_datum_t *)datum;
        state = (expand_state_t*)data;

        /* ignore types and attributes */
        if (alias->primary || alias->isattr) {
                return 0;
        }

        if (state->verbose)
                INFO(state->handle, "copying alias %s", id);

        new_id = strdup(id);
        if (!new_id) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }

        new_alias = (type_datum_t *) malloc(sizeof(type_datum_t));
        if (!new_alias) {
                ERR (state->handle, "Out of memory!");
		free(new_id);
                return -ENOMEM;
        }
        memset(new_alias, 0, sizeof(type_datum_t));
        new_alias->value = state->typemap[alias->value - 1];

        ret = hashtab_insert(state->out->p_types.table,
                             (hashtab_key_t)new_id, (hashtab_datum_t) new_alias);

        if (ret) {
                ERR (state->handle, "hashtab overflow");
                free(new_alias);
                free(new_id);
                return -1;
        }

        state->typemap[alias->value - 1] = new_alias->value;
        return 0;
}

static int role_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
        char *id, *new_id;
        role_datum_t *role;
        role_datum_t *new_role;
       	expand_state_t *state;

        id = key;
        role = (role_datum_t*)datum;
        state = (expand_state_t*)data;

        if (strcmp(id, OBJECT_R) == 0)
                return 0;

        if (!is_id_enabled(id, state->base, SYM_ROLES)) {
                /* identifier's scope is not enabled */
                return 0;
        }

        if (state->verbose)
                INFO(state->handle, "copying role %s", id);

        new_role = (role_datum_t *) malloc(sizeof(role_datum_t));
        if (!new_role) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }
        memset(new_role, 0, sizeof(role_datum_t));

        new_id = strdup(id);
        if (!new_id) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }

        new_role->value = role->value;
        state->out->p_roles.nprim++;
        ret = hashtab_insert(state->out->p_roles.table,
                             (hashtab_key_t) new_id, (hashtab_datum_t) new_role);

        if (ret) {
                ERR (state->handle, "hashtab overflow");
                free(new_role);
                free(new_id);
                return -1;
        }

        if (ebitmap_cpy(&new_role->dominates, &role->dominates)) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }

        if (expand_convert_type_set(state->base, state->typemap, &role->types, &new_role->types.types, 1)) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }

        return 0;
}

static int mls_level_clone(mls_level_t *dst, mls_level_t *src) {
        dst->sens = src->sens;
        if (ebitmap_cpy(&dst->cat, &src->cat)) {
                return -1;
        }
        return 0;
}

static int user_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
       	expand_state_t *state;
        user_datum_t *user;
        user_datum_t *new_user;
        char *id, *new_id;

        id = key;
        user = (user_datum_t *)datum;
        state = (expand_state_t*)data;

        if (!is_id_enabled(id, state->base, SYM_USERS)) {
                /* identifier's scope is not enabled */
                return 0;
        }

        if (state->verbose)
                INFO(state->handle, "copying user %s", id);

        new_user = (user_datum_t *) malloc(sizeof(user_datum_t));
        if (!new_user) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }
        memset(new_user, 0, sizeof(user_datum_t));

        new_user->value = user->value;
        state->out->p_users.nprim++;

        new_id = strdup(id);
        if (!new_id) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }
        ret = hashtab_insert(state->out->p_users.table,
                             (hashtab_key_t)new_id, (hashtab_datum_t)new_user);
        if (ret) {
                ERR (state->handle, "hashtab overflow");
                user_datum_destroy(new_user);
                free(new_user);
                free(new_id);
                return -1;
        }
         
        if (role_set_expand(&user->roles, &new_user->roles.roles, state->base)) {
                ERR (state->handle, "Out of memory!");
        	return -1;
        }

        /* clone MLS stuff */
        if (mls_level_clone(&new_user->range.level[0], &user->range.level[0]) == -1 ||
            mls_level_clone(&new_user->range.level[1], &user->range.level[1]) == -1 ||
            mls_level_clone(&new_user->dfltlevel, &user->dfltlevel) == -1) {
                ERR (state->handle, "Out of memory!");
        	return -1;
        }
        return 0;
}


static int bool_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
        int ret;
       	expand_state_t *state;
        cond_bool_datum_t *bool, *new_bool;
        char *id, *new_id;

        id = key;
        bool = (cond_bool_datum_t *)datum;
        state = (expand_state_t*)data;

        if (!is_id_enabled(id, state->base, SYM_BOOLS)) {
                /* identifier's scope is not enabled */
                return 0;
        }

        if (state->verbose)
                INFO(state->handle, "copying boolean %s", id);

        new_bool = (cond_bool_datum_t*)malloc(sizeof(cond_bool_datum_t));
        if (!new_bool) {
                ERR (state->handle, "Out of memory!");
                return -1;
        }

        new_id = strdup(id);
        if (!new_id) {
                ERR (state->handle, "Out of memory!");
                free (new_bool);
                return -1;
        }

        new_bool->value = bool->value;
        state->out->p_bools.nprim++;

        ret = hashtab_insert(state->out->p_bools.table,
                             (hashtab_key_t)new_id, (hashtab_datum_t)new_bool);
        if (ret) {
                ERR (state->handle, "hashtab overflow");
                free(new_bool);
                free(new_id);
                return -1;
        }

        new_bool->state = bool->state;

        return 0;
}

static int sens_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
       	expand_state_t *state = (expand_state_t*)data;
        level_datum_t *level = (level_datum_t *)datum, *new_level = NULL;
        char *id = (char *) key, *new_id = NULL;

        if (!is_id_enabled(id, state->base, SYM_LEVELS)) {
                /* identifier's scope is not enabled */
                return 0;
        }

        if (state->verbose)
                INFO(state->handle, "copying senitivity level %s", id);

        if ((new_level = (level_datum_t*)calloc(1, sizeof(*new_level))) == NULL ||
            (new_level->level = (mls_level_t *)calloc(1, sizeof(mls_level_t))) == NULL ||
            (new_id = strdup(id)) == NULL) {
                goto out_of_mem;
        }

        if (mls_level_clone(new_level->level, level->level)) {
                goto out_of_mem;
        }
        new_level->isalias = level->isalias;
        state->out->p_levels.nprim++;

        if (hashtab_insert(state->out->p_levels.table,
                           (hashtab_key_t)new_id, (hashtab_datum_t)new_level)) {
                goto out_of_mem;
        }
        return 0;
        
 out_of_mem:
        ERR(state->handle, "Out of memory!");
        if (new_level != NULL) {
                ebitmap_destroy(&new_level->level->cat);
                free(new_level->level);
        }
        free(new_level);
        free(new_id);
        return -1;
}

static int cats_copy_callback(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
       	expand_state_t *state = (expand_state_t*)data;
        cat_datum_t *cat = (cat_datum_t *)datum, *new_cat = NULL;
        char *id = (char *)key, *new_id = NULL;

        if (!is_id_enabled(id, state->base, SYM_CATS)) {
                /* identifier's scope is not enabled */
                return 0;
        }

        if (state->verbose)
                INFO(state->handle, "copying category attribute %s", id);

        if ((new_cat = (cat_datum_t*)calloc(1, sizeof(*new_cat))) == NULL ||
            (new_id = strdup(id)) == NULL) {
                goto out_of_mem;
        }

        new_cat->value = cat->value;
        new_cat->isalias = cat->isalias;
        state->out->p_cats.nprim++;
        if (hashtab_insert(state->out->p_cats.table,
                           (hashtab_key_t)new_id, (hashtab_datum_t)new_cat)) {
                goto out_of_mem;
        }

        return 0;
        
 out_of_mem:
        ERR(state->handle, "Out of memory!");
        free(new_cat);
        free(new_id);
        return -1;
}


static int copy_role_allows(expand_state_t *state, role_allow_rule_t *rules)
{
	unsigned int i, j;
	role_allow_t *cur_allow, *n, *l;
	role_allow_rule_t *cur;
	ebitmap_t roles, new_roles;
	ebitmap_node_t *snode, *tnode;
	
	l = NULL;
	cur = rules;
	while (cur) {
		ebitmap_init(&roles);
		ebitmap_init(&new_roles);
		
		if (role_set_expand(&cur->roles, &roles, state->out)) {
                        ERR (state->handle, "Out of memory!");
			return -1;
                }
		if (role_set_expand(&cur->new_roles, &new_roles, state->out)) {
                        ERR (state->handle, "Out of memory!");
			return -1;
                }			
		ebitmap_for_each_bit(&roles, snode, i) {
			if (!ebitmap_node_get_bit(snode, i))
				continue;
			ebitmap_for_each_bit(&new_roles, tnode, j) {	
				if (!ebitmap_node_get_bit(tnode, j))
					continue;
				/* check for duplicates */
				cur_allow = state->out->role_allow;
				while (cur_allow) {
					if ((cur_allow->role == i + 1) &&
					    (cur_allow->new_role == j + 1))
					    	break;
					cur_allow = cur_allow->next;
				}
				if (cur_allow)
					continue;
				n = (role_allow_t*)malloc(sizeof(role_allow_t));
				if (!n) {
                                        ERR (state->handle, "Out of memory!");
					return -1;	
				}
				memset(n, 0, sizeof(role_allow_t));
				n->role = i + 1;
				n->new_role = j + 1;
				if (l) {
					l->next = n;	
				} else {
					state->out->role_allow = n;	
				}
				l = n;
			}
		}
		
		ebitmap_destroy(&roles);
		ebitmap_destroy(&new_roles);
		
		cur = cur->next;
	}
	
	return 0;
}

static int copy_role_trans(expand_state_t *state, role_trans_rule_t *rules)
{
	unsigned int i, j;
	role_trans_t *n, *l, *cur_trans;
	role_trans_rule_t *cur;
	ebitmap_t roles, types;
	ebitmap_node_t *rnode, *tnode;
	
	l = NULL;
	cur = rules;
	while (cur) {
		ebitmap_init(&roles);
		ebitmap_init(&types);
		
		if (role_set_expand(&cur->roles, &roles, state->out)) {
                        ERR (state->handle, "Out of memory!");
			return -1;
                }
		if (expand_convert_type_set(state->base, state->typemap, &cur->types, &types, 1)) {
                        ERR (state->handle, "Out of memory!");
			return -1;
                }
		ebitmap_for_each_bit(&roles, rnode, i) {
			if (!ebitmap_node_get_bit(rnode, i))
				continue;
			ebitmap_for_each_bit(&types, tnode, j) {
				if (!ebitmap_node_get_bit(tnode, j))
					continue;
					
				cur_trans = state->out->role_tr;
				while (cur_trans) {
					if ((cur_trans->role == i + 1) &&
					    (cur_trans->type == j + 1)) {
					 	if (cur_trans->new_role == cur->new_role) {
					 		break;
					 	} else {
					 		ERR (state->handle, "Conflicting role trans rule %s %s : %s",
					 			state->out->p_role_val_to_name[i],
					 			state->out->p_type_val_to_name[j],
					 			state->out->p_role_val_to_name[cur->new_role - 1]);
					 		return -1;
					 	}	   	
					}
					cur_trans = cur_trans->next;
				}
				if (cur_trans)
					continue;
		
				n = (role_trans_t*)malloc(sizeof(role_trans_t));
				if (!n) {
                                        ERR (state->handle, "Out of memory!");
					return -1;	
				}
				memset(n, 0, sizeof(role_trans_t));
				n->role = i + 1;
				n->type = j + 1;
				n->new_role = cur->new_role;
				if (l) {
					l->next = n;	
				} else {
					state->out->role_tr = n;	
				}
				l = n;
			}
		}
		
		ebitmap_destroy(&roles);
		ebitmap_destroy(&types);
		
		cur = cur->next;
	}
	return 0;	
}

/* Search for an AV tab node within a hash table with the given key.
 * If the node does not exist, create it and return it; otherwise
 * return the pre-existing one.
*/
static avtab_ptr_t find_avtab_node(sepol_handle_t *handle,
				   avtab_t *avtab, avtab_key_t *key,
                                   cond_av_list_t **cond)
{               
        avtab_ptr_t node;
        avtab_datum_t avdatum;
        cond_av_list_t *nl;

        node = avtab_search_node(avtab, key);

        /* If this is for conditional policies, keep searching in case
           the node is part of my conditional avtab. */
        if (cond) {     
                while (node) {
                        if (node->parse_context == cond)
                                break;
                        node = avtab_search_node_next(node, key->specified);
                }
        }

        if (!node) {
                memset(&avdatum, 0, sizeof avdatum);
                /* this is used to get the node - insertion is actually unique */
                node = avtab_insert_nonunique(avtab, key, &avdatum);
                if (!node) {
                        ERR(handle, "hash table overflow");
                        return NULL;
                }
                if (cond) {
                        node->parse_context = cond;
                        nl = (cond_av_list_t*)malloc(sizeof(cond_av_list_t));
                        if (!nl) {
                                ERR(handle, "Memory error");
                                return NULL;
                        }
                        memset(nl, 0, sizeof(cond_av_list_t));
                        nl->node = node;
                        nl->next = *cond;
                        *cond = nl;
                }
        }

        return node;
}

static int expand_terule_helper(sepol_handle_t *handle,
				policydb_t *p, uint32_t *typemap, uint32_t specified,
                                cond_av_list_t **cond, cond_av_list_t **other,
                                uint32_t stype, uint32_t ttype, class_perm_node_t *perms,
                                avtab_t *avtab, int enabled)
{
        avtab_key_t avkey;
        avtab_datum_t *avdatump;
        avtab_ptr_t node;
        class_perm_node_t *cur;
        int conflict;
        uint32_t oldtype = 0, spec = 0;

        if (specified & AVRULE_TRANSITION) {
                spec = AVTAB_TRANSITION;
        } else if (specified & AVRULE_MEMBER) {
                spec = AVTAB_MEMBER;
        } else if (specified & AVRULE_CHANGE) {
                spec = AVTAB_CHANGE;
        } else {
                assert(0); /* unreachable */
        }

        cur = perms;
        while (cur) {
                uint32_t remapped_data = typemap ? typemap[cur->data - 1] : cur->data;
                avkey.source_type = stype + 1;
                avkey.target_type = ttype + 1;
                avkey.target_class = cur->class;
		avkey.specified = spec;

                conflict = 0;
                /* check to see if the expanded TE already exists --
                 * either in the global scope or in another
                 * conditional AV tab */
                node = avtab_search_node(&p->te_avtab, &avkey);
                if (node) {
                        conflict = 1;
                } else {
                        node = avtab_search_node(&p->te_cond_avtab, &avkey);
                        if (node && node->parse_context != other) {
                                conflict = 2;
                        }
                }

                if (conflict) {
                        avdatump = &node->datum;
                        if (specified & AVRULE_TRANSITION) {
                                oldtype = avdatump->data;
                        } else if (specified & AVRULE_MEMBER) {
                                oldtype = avdatump->data;
                        } else if (specified & AVRULE_CHANGE) {
                                oldtype = avdatump->data;
                        }
                        /* ignore duplicates */
                        
                        if (oldtype == remapped_data)
                                return 1;
			ERR(handle, "conflicting TE rule for (%s, %s:%s):  old was %s, new is %s",
			    p->p_type_val_to_name[avkey.source_type - 1],
			    p->p_type_val_to_name[avkey.target_type - 1],
			    p->p_class_val_to_name[avkey.target_class - 1],
			    p->p_type_val_to_name[oldtype - 1],
			    p->p_type_val_to_name[remapped_data - 1]);
			return -1;
                }

                node = find_avtab_node(handle, avtab, &avkey, cond);
                if (!node)
                        return -1;
                 if (enabled) {
                        node->key.specified |= AVTAB_ENABLED;
                }
                else {
                        node->key.specified &= ~AVTAB_ENABLED;
                }

               avdatump = &node->datum;
                if (specified & AVRULE_TRANSITION) {
                        avdatump->data = remapped_data;
                } else if (specified & AVRULE_MEMBER) {
                        avdatump->data = remapped_data;
                } else if (specified & AVRULE_CHANGE) {
                        avdatump->data = remapped_data;
                } else {
                        assert(0);   /* should never occur */
                }

                cur = cur->next;
        }

        return 1;
}

static int expand_avrule_helper(sepol_handle_t *handle,
				uint32_t specified,
                                cond_av_list_t **cond,
                                uint32_t stype, uint32_t ttype, class_perm_node_t *perms,
                                avtab_t *avtab, int enabled)
{
        avtab_key_t avkey;
        avtab_datum_t *avdatump;
        avtab_ptr_t node;
        class_perm_node_t *cur;
        uint32_t spec = 0;

        if (specified & AVRULE_ALLOWED) {
                spec = AVTAB_ALLOWED;
        } else if (specified & AVRULE_AUDITALLOW) {
                spec = AVTAB_AUDITALLOW;
        } else if (specified & AVRULE_AUDITDENY) {
                spec = AVTAB_AUDITDENY;
        } else if (specified & AVRULE_DONTAUDIT) {
                spec = AVTAB_AUDITDENY;
        } else {
                assert(0); /* unreachable */
        }

        cur = perms;
        while (cur) {
                avkey.source_type = stype + 1;
                avkey.target_type = ttype + 1;
                avkey.target_class = cur->class;
		avkey.specified = spec;

                node = find_avtab_node(handle, avtab, &avkey, cond);
                if (!node)
                        return -1;
                if (enabled) {
                        node->key.specified |= AVTAB_ENABLED;
                }
                else {
                        node->key.specified &= ~AVTAB_ENABLED;
                }

                avdatump = &node->datum;
                if (specified & AVRULE_ALLOWED) {
                        avdatump->data |= cur->data;
                } else if (specified & AVRULE_AUDITALLOW) {
                        avdatump->data |= cur->data;
                } else if (specified & AVRULE_AUDITDENY) {
                        /* Since a '0' in an auditdeny mask represents
                         * a permission we do NOT want to audit
                         * (dontaudit), we use the '&' operand to
                         * ensure that all '0's in the mask are
                         * retained (much unlike the allow and
                         * auditallow cases).
                         */
                        avdatump->data &= cur->data;
                } else if (specified & AVRULE_DONTAUDIT) {
                        if (avdatump->data)
                                avdatump->data &= ~cur->data;
                        else
                                avdatump->data = ~cur->data;
                } else {
                        assert(0);   /* should never occur */
                }

                cur = cur->next;
        }        
	return 1;
}               

static int expand_rule_helper(sepol_handle_t *handle,
			      policydb_t *p, uint32_t *typemap,
                              avrule_t *source_rule, avtab_t *dest_avtab,
                              cond_av_list_t **cond, cond_av_list_t **other,
                              int enabled, 
                              ebitmap_t *stypes, ebitmap_t *ttypes)
{
	unsigned int i, j;
	int retval;
	ebitmap_node_t *snode, *tnode;

	ebitmap_for_each_bit(stypes, snode, i) {
                if (!ebitmap_node_get_bit(snode, i))
                        continue;
                if (source_rule->flags & RULE_SELF) {
                        if (source_rule->specified & AVRULE_AV) {
                                if ((retval =
                                     expand_avrule_helper(handle,
							  source_rule->specified,
                                                          cond,
                                                          i, i, source_rule->perms,
                                                          dest_avtab, enabled)) != 1) {
                                        return retval;
                                }
                        } else {
                                if ((retval =
                                     expand_terule_helper(handle, p,
                                                          typemap, source_rule->specified,
                                                          cond, other,
                                                          i, i, source_rule->perms,
                                                          dest_avtab, enabled)) != 1) {
                                        return retval;
                                }
                        }
                }
		ebitmap_for_each_bit(ttypes, tnode, j) {
                        if (!ebitmap_node_get_bit(tnode, j))
                                continue;
                        if (source_rule->specified & AVRULE_AV) {
                                if ((retval =
                                     expand_avrule_helper(handle,
							  source_rule->specified,
                                                          cond,
                                                          i, j, source_rule->perms,
                                                          dest_avtab, enabled)) != 1) {
                                        return retval;
                                }
                        } else {
                                if ((retval =
                                     expand_terule_helper(handle, p,
                                                          typemap, source_rule->specified,
                                                          cond, other,
                                                          i, j, source_rule->perms,
                                                          dest_avtab, enabled)) != 1) {
                                        return retval;
                                }
                        }
                }
        }

        return 1;
}

/* Expand a rule into a given avtab - checking for conflicting type
 * rules in the destination policy.  Return 1 on success, 0 if the
 * rule conflicts with something (and hence was not added), or -1 on
 * error. */
static int convert_and_expand_rule(sepol_handle_t *handle, 
				   policydb_t *source_pol, policydb_t *dest_pol,
                                   uint32_t *typemap, avrule_t *source_rule, avtab_t *dest_avtab,
                                   cond_av_list_t **cond, cond_av_list_t **other,
                                   int enabled) {
        int retval;
        ebitmap_t stypes, ttypes;
	unsigned char alwaysexpand;

        if (source_rule->specified & AVRULE_NEVERALLOW)
                return 1;

        ebitmap_init(&stypes);
        ebitmap_init(&ttypes);

	/* Force expansion for type rules and for self rules. */
	alwaysexpand = ((source_rule->specified & AVRULE_TYPE) ||
			(source_rule->flags & RULE_SELF));

        if (expand_convert_type_set(source_pol, typemap, &source_rule->stypes, &stypes, alwaysexpand))
                return -1;
        if (expand_convert_type_set(source_pol, typemap, &source_rule->ttypes, &ttypes, alwaysexpand))
                return -1;

        retval = expand_rule_helper(handle, dest_pol, typemap,
                                    source_rule, dest_avtab,
                                    cond, other,
                                    enabled,
                                    &stypes, &ttypes);
        ebitmap_destroy(&stypes);
        ebitmap_destroy(&ttypes);
        return retval;
}


static int cond_avrule_list_copy(policydb_t *source_pol, policydb_t *dest_pol,
                                 avrule_t *source_rules, avtab_t *dest_avtab,
                                 cond_av_list_t **list, cond_av_list_t **other,
                                 uint32_t *typemap, int enabled,
                                 expand_state_t *state)
{
	avrule_t *cur;
	
	cur = source_rules;
	while (cur) {
		if (convert_and_expand_rule(state->handle, 
					    source_pol, dest_pol,
                                            typemap, cur, dest_avtab,
                                            list, other,
                                            enabled) != 1) {
			return -1;
		}

		cur = cur->next;
	}

	return 0;
}

/* copy the nodes in *reverse* order -- the result is that the last
 * given conditional appears first in the policy, so as to match the
 * behavior of the upstream compiler */
static int cond_node_copy(expand_state_t *state, cond_node_t *cn)
{
	cond_node_t *new_cond;

        if (cn == NULL) {
                return 0;
        }
        if (cond_node_copy(state, cn->next)) {
                return -1;
        }
	if (cond_normalize_expr(state->base, cn)) {
                ERR (state->handle, "Error while normalizing conditional");
		return -1;
        }

	new_cond = cond_node_search(state->out, state->out->cond_list, cn);
	if (!new_cond) {
                ERR (state->handle, "Out of memory!");
		return -1;
        }

	if (cond_avrule_list_copy(state->base, state->out,
                                  cn->avtrue_list, &state->out->te_cond_avtab,
                                  &new_cond->true_list, &new_cond->false_list,
                                  state->typemap, new_cond->cur_state, state))
		return -1;
	if (cond_avrule_list_copy(state->base, state->out,
                                  cn->avfalse_list, &state->out->te_cond_avtab,
                                  &new_cond->false_list, &new_cond->true_list, 
                                  state->typemap, !new_cond->cur_state, state))
		return -1;

	return 0;
}

static int context_copy(context_struct_t *dst, context_struct_t *src, expand_state_t *state)
{
	dst->user = src->user;
	dst->role = src->role;
	dst->type = state->typemap[src->type - 1];
        return mls_context_cpy(dst, src);
}

static int ocontext_copy(expand_state_t *state)
{
	unsigned int i, j;
	ocontext_t *c, *n, *l;
	
	for (i = 0; i < OCON_NUM; i++) {	
		l = NULL;
		for (c = state->base->ocontexts[i]; c; c = c->next) {
			n = malloc(sizeof(ocontext_t));
			if (!n) {
                                ERR (state->handle, "Out of memory!");
				return -1;	
			}
			memset(n, 0, sizeof(ocontext_t));
			if (l) {
				l->next = n;
			} else {
				state->out->ocontexts[i] = n;
			}
			l = n;
                        if (context_copy(&n->context[0], &c->context[0], state)) {
                                ERR (state->handle, "Out of memory!");
                                return -1;
                        }
			switch (i) {
			case OCON_ISID:
				n->sid[0] = c->sid[0];
                                break;
			case OCON_FS:     /* FALLTHROUGH */
			case OCON_NETIF:
				n->u.name = strdup(c->u.name);
				if (!n->u.name) {
                                        ERR (state->handle, "Out of memory!");
					return -1;	
				}
                                if (context_copy(&n->context[1], &c->context[1], state)) {
						ERR (state->handle, "Out of memory!");
						return -1;
					}
					break;
                        case OCON_PORT:
                                n->u.port.protocol = c->u.port.protocol;
                                n->u.port.low_port = c->u.port.low_port;
                                n->u.port.high_port = c->u.port.high_port;
                                break;
                        case OCON_NODE:
                                n->u.node.addr = c->u.node.addr;
                                n->u.node.mask = c->u.node.mask;
                                break;
                        case OCON_FSUSE:
                                n->v.behavior = c->v.behavior;
                                n->u.name = strdup(c->u.name);
                                if (!n->u.name) {
                                        ERR (state->handle, "Out of memory!");
                                        return -1;	
                                }
                                break;
                        case OCON_NODE6:
                                for (j = 0; j < 4; j++)
                                        n->u.node6.addr[j] = c->u.node6.addr[j];
                                for (j = 0; j < 4; j++)
                                        n->u.node6.mask[j] = c->u.node6.mask[j];
                                break;
                        default:
                                /* shouldn't get here */
                                assert(0);
                        }
                }
		}
		return 0;
	}

static int genfs_copy(expand_state_t *state)
{
	ocontext_t *c, *newc, *l;
	genfs_t *genfs, *newgenfs, *end;

	end = NULL;
	for (genfs = state->base->genfs; genfs; genfs = genfs->next) {
		newgenfs = malloc(sizeof(genfs_t));
		if (!newgenfs) {
                        ERR (state->handle, "Out of memory!");
			return -1;
		}
		memset(newgenfs, 0, sizeof(genfs_t));
		newgenfs->fstype = strdup(genfs->fstype);
		if (!newgenfs->fstype) {
                        ERR (state->handle, "Out of memory!");
			return -1;			
		}

		l = NULL;
		for (c = genfs->head; c; c = c->next) {
			newc = malloc(sizeof(ocontext_t));
			if (!newc) {
                                ERR (state->handle, "Out of memory!");
				return -1;
			}
			memset(newc, 0, sizeof(ocontext_t));
			newc->u.name = strdup(c->u.name);
			if (!newc->u.name) {
                                ERR (state->handle, "Out of memory!");
				return -1;
			}
			newc->v.sclass = c->v.sclass;
			context_copy(&newc->context[0], &c->context[0], state);
			if (l)
				l->next = newc;
			else
				newgenfs->head = newc;
			l = newc;
		}
		if (!end) {
			state->out->genfs = newgenfs;
		} else {
			end->next = newgenfs;
		}
		end = newgenfs;
	}
	return 0;	
}


static int range_trans_clone(expand_state_t *state)
{
        range_trans_t *range = state->base->range_tr, *last_new_range = NULL,
				*new_range = NULL;
        state->out->range_tr = NULL;

        if (state->verbose)
                INFO(state->handle, "copying range transitions");

        while (range != NULL) {
                if ((new_range = malloc(sizeof(*new_range))) == NULL) {
                        goto out_of_mem;
                }
		memset(new_range, 0, sizeof(*new_range));
                new_range->dom = state->typemap[range->dom-1];
                new_range->type = state->typemap[range->type-1];
                if (mls_level_clone(&new_range->range.level[0], &range->range.level[0]) == -1 ||
                    mls_level_clone(&new_range->range.level[1], &range->range.level[1])) {
                        goto out_of_mem;
                }
                new_range->next = NULL;
                if (last_new_range == NULL) {
                        state->out->range_tr = last_new_range = new_range;
                }
                else {
                        last_new_range->next = new_range;
                        last_new_range = new_range;
                }
                range = range->next;
        }
        return 0;

 out_of_mem:
        ERR(state->handle, "Out of memory!");
	if(new_range) {
		ebitmap_destroy(&new_range->range.level[0].cat);
		ebitmap_destroy(&new_range->range.level[1].cat);
		free(new_range);
	}
        return -1;
}

static int type_attr_map(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *ptr)
{
  	type_datum_t *type;
	expand_state_t *state = ptr;
	policydb_t *p = state->out;
	unsigned int i;
	ebitmap_node_t *tnode;

	type = (type_datum_t *) datum;
	if (type->isattr) {
		if (ebitmap_cpy(&p->attr_type_map[type->value-1],
				&type->types)) {
			ERR(state->handle, "Out of memory!");
			return -1;
		}
		ebitmap_for_each_bit(&type->types, tnode, i) {
			if (!ebitmap_node_get_bit(tnode, i))
				continue;
			if (ebitmap_set_bit(&p->type_attr_map[i],
					    type->value - 1, 1)) {
				ERR(state->handle, "Out of memory!");
				return -1;
			}
		}
	}
	return 0;
}

static void type_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	free(key);
	type_datum_destroy((type_datum_t*) datum);
	free(datum);
}

static int type_attr_remove(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *p __attribute__ ((unused)))
{
	type_datum_t *typdatum;

	typdatum = (type_datum_t *) datum;
	if (typdatum->isattr)
		return 1;
	return 0;
}

int expand_convert_type_set(policydb_t *p, uint32_t *typemap, type_set_t *set, ebitmap_t *types, unsigned char alwaysexpand)
{
        unsigned int i;
        ebitmap_t tmp;
	ebitmap_node_t *tnode;
        
        ebitmap_init(types);
        ebitmap_init(&tmp);
        
        if (type_set_expand(set, &tmp, p, alwaysexpand))
                return -1;

	ebitmap_for_each_bit(&tmp, tnode, i) {                
                if (!ebitmap_node_get_bit(tnode, i))
                        continue;
		if (!typemap[i])
			continue;
                if (ebitmap_set_bit(types, typemap[i] - 1, 1))
                        return -1;
        }

        ebitmap_destroy(&tmp);

        return 0;
}



/* Expand a rule into a given avtab - checking for conflicting type
 * rules.  Return 1 on success, 0 if the rule conflicts with something
 * (and hence was not added), or -1 on error. */
int expand_rule(sepol_handle_t *handle,
		policydb_t *source_pol,
                avrule_t *source_rule, avtab_t *dest_avtab,
                cond_av_list_t **cond, cond_av_list_t **other,
                int enabled)
{
        int retval;
        ebitmap_t stypes, ttypes;

        if (source_rule->specified & AVRULE_NEVERALLOW)
                return 1;
        
        ebitmap_init(&stypes);
        ebitmap_init(&ttypes);

        if (type_set_expand(&source_rule->stypes, &stypes, source_pol, 1))
                return -1;
        if (type_set_expand(&source_rule->ttypes, &ttypes, source_pol, 1))
                return -1;
        retval = expand_rule_helper(handle, source_pol, NULL,
                                    source_rule, dest_avtab,
                                    cond, other, enabled, 
                                    &stypes, &ttypes);
        ebitmap_destroy(&stypes);
        ebitmap_destroy(&ttypes);
        return retval;
}

int role_set_expand(role_set_t *x, ebitmap_t *r, policydb_t *p)
{
        unsigned int i;
	ebitmap_node_t *rnode;

        ebitmap_init(r);

        if (x->flags & ROLE_STAR) {
                for (i = 0; i < p->p_roles.nprim++; i++)
                        if (ebitmap_set_bit(r, i, 1))
                                return -1;
                return 0;
        }

	ebitmap_for_each_bit(&x->roles, rnode, i) {
                if (ebitmap_node_get_bit(rnode, i)) {
                        if(ebitmap_set_bit (r, i, 1))
                                return -1;
                }
        }

        /* if role is to be complimented, invert the entire bitmap here */
        if (x->flags & ROLE_COMP) {
                for (i = 0; i < ebitmap_length(r); i++) {
                        if (ebitmap_get_bit(r, i)) {
                                if (ebitmap_set_bit(r, i, 0))
                                        return -1;
                        } else {
                                if (ebitmap_set_bit(r, i, 1))
                                        return -1;
                        }
                }
        }
        return 0;
}

/* Expand a type set into an ebitmap containing the types. This
 * handles the negset, attributes, and flags.
 * Attribute expansion depends on several factors:
 * - if alwaysexpand is 1, then they will be expanded,
 * - if the type set has a negset or flags, then they will be expanded,
 * - otherwise, they will not be expanded.
 */
int type_set_expand(type_set_t *set, ebitmap_t *t, policydb_t *p,
	             unsigned char alwaysexpand)
{
        unsigned int i;
        ebitmap_t types, neg_types;
	ebitmap_node_t *tnode;

        ebitmap_init(&types);
        ebitmap_init(t);

	if (alwaysexpand || ebitmap_length(&set->negset) || set->flags) {
		/* First go through the types and OR all the attributes to types */
		ebitmap_for_each_bit(&set->types, tnode, i) {
			if (ebitmap_node_get_bit(tnode, i)) {
				if (p->type_val_to_struct[i]->isattr) {
					if (ebitmap_union(&types, &p->type_val_to_struct[i]->types)) {
						return -1;
					}
				} else {
					if (ebitmap_set_bit(&types, i, 1)) {
						return -1;
					}
				}
			}
		}
	} else {
		/* No expansion of attributes, just copy the set as is. */
		if (ebitmap_cpy(&types, &set->types))
			return -1;
	}

        /* Now do the same thing for negset */
        ebitmap_init(&neg_types);
	ebitmap_for_each_bit(&set->negset, tnode, i) {
                if (ebitmap_node_get_bit(tnode, i)) {
                        if (p->type_val_to_struct[i] && 
			    p->type_val_to_struct[i]->isattr) {
                                if (ebitmap_union(&neg_types, &p->type_val_to_struct[i]->types)) {
                                        return -1;
                                }
                        } else {
                                if (ebitmap_set_bit(&neg_types, i, 1)) {
                                        return -1;
                                }
                        }
                }
        }

        if (set->flags & TYPE_STAR) {
                /* set all types not in neg_types */
                for (i = 0; i < p->p_types.nprim; i++) {
                        if (ebitmap_get_bit(&neg_types, i))
                                continue;
                        if (p->type_val_to_struct[i] &&
			    p->type_val_to_struct[i]->isattr)
                                continue;
                        if (ebitmap_set_bit(t, i, 1))
                                return -1;
                }
                goto out;
        }

	ebitmap_for_each_bit(&types, tnode, i) {
                if (ebitmap_node_get_bit(tnode, i) && (!ebitmap_get_bit(&neg_types, i)))
                        if (ebitmap_set_bit(t, i, 1))
                                return -1;
        }

        if (set->flags & TYPE_COMP) {
                for(i = 0; i < p->p_types.nprim; i++) {
                        if (p->type_val_to_struct[i] &&
			    p->type_val_to_struct[i]->isattr) {
                                assert(!ebitmap_get_bit(t, i));
                                continue;
                        }
                        if (ebitmap_get_bit(t, i)) {
                                if (ebitmap_set_bit(t, i, 0))
                                        return -1;
                        } else {
                                if (ebitmap_set_bit(t, i, 1))
                                        return -1;
                        }
                }
        }

out:

        ebitmap_destroy(&types);
        ebitmap_destroy(&neg_types);

	return 0;
}

static int copy_neverallow (policydb_t *source_pol, policydb_t *dest_pol,
                            uint32_t *typemap, avrule_t *source_rule)
{
	ebitmap_t stypes, ttypes;
	avrule_t *avrule;
	class_perm_node_t *cur_perm, *new_perm, *tail_perm;

	ebitmap_init(&stypes);
	ebitmap_init(&ttypes);

        if (expand_convert_type_set(source_pol, typemap, &source_rule->stypes, &stypes, 1))
                return -1;
        if (expand_convert_type_set(source_pol, typemap, &source_rule->ttypes, &ttypes, 1))
                return -1;

        avrule = (avrule_t*)malloc(sizeof(avrule_t));
        if (!avrule) 
		return -1;
        
	avrule_init(avrule);
        avrule->specified = AVRULE_NEVERALLOW;
        avrule->line = source_rule->line;
        avrule->flags = source_rule->flags;

	if (ebitmap_cpy(&avrule->stypes.types, &stypes))
		goto err;

	if (ebitmap_cpy(&avrule->ttypes.types, &ttypes))
		goto err;

	cur_perm = source_rule->perms;
	tail_perm = NULL;
	while (cur_perm) {
		new_perm = (class_perm_node_t*)malloc(sizeof(class_perm_node_t));
		if (!new_perm)
			goto err;
		class_perm_node_init(new_perm);
		new_perm->class = cur_perm->class;
		assert(new_perm->class);

		/* once we have modules with permissions we'll need to map the permissions (and classes) */
		new_perm->data = cur_perm->data;

		if (!avrule->perms)
			avrule->perms = new_perm;

		if (tail_perm)
			tail_perm->next = new_perm;
		tail_perm = new_perm;
		cur_perm = cur_perm->next;
	}

	/* just prepend the avrule to the first branch; it'll never be
           written to disk */
	if (!dest_pol->global->branch_list->avrules) 
		dest_pol->global->branch_list->avrules = avrule;
	else {
		avrule->next = dest_pol->global->branch_list->avrules;
		dest_pol->global->branch_list->avrules = avrule;
	}

	ebitmap_destroy(&stypes);
	ebitmap_destroy(&ttypes);

	return 0;

err:
	ebitmap_destroy(&stypes);
	ebitmap_destroy(&ttypes);
	ebitmap_destroy(&avrule->stypes.types);
	ebitmap_destroy(&avrule->ttypes.types);
	cur_perm = avrule->perms;
	while (cur_perm) {
		tail_perm = cur_perm->next;
		free(cur_perm);
		cur_perm = tail_perm;
	}
	free(avrule);
	return -1;
}

/* Linking should always be done before calling expand, even if
 * there is only a base since all optionals are dealt with at link time
 */
int expand_module(sepol_handle_t *handle,
		  policydb_t *base, policydb_t *out,
		  int verbose, int check)
{
	int retval = -1;
	unsigned int i;
	expand_state_t state;
        avrule_block_t *curblock;

	/* activate the global branch before expansion */
	base->global->branch_list->enabled = 1;
	base->global->enabled = base->global->branch_list;

	state.verbose = verbose;
        state.typemap = NULL;
	state.base = base;
	state.out = out;
        state.handle = handle;

        if (base->policy_type != POLICY_BASE) {
                ERR(handle, "Target of expand was not a base policy.");
                return -1;
        }

	if (policydb_index_classes(state.base)) {
                ERR (handle, "Error while indexing base classes");
                goto cleanup;
        }
	if (policydb_index_others(handle, state.base, 0)) {
                ERR (handle, "Error while indexing base symbols");
                goto cleanup;
        }
	state.out->policy_type = POLICY_KERN;
	state.out->policyvers = POLICYDB_VERSION_MAX;

	/* Copy mls state from base to out */
	out->mls = base->mls;

	if ((state.typemap = (uint32_t*)calloc(state.base->p_types.nprim, sizeof(uint32_t))) == NULL) {
                ERR (handle, "Out of memory!");
                goto cleanup;
	}

	/* order is important - types must be first */

        /* copy types */
        if (hashtab_map(state.base->p_types.table, type_copy_callback, &state)) {
                goto cleanup;
        }

	/* convert attribute type sets */
        if (hashtab_map(state.base->p_types.table, attr_convert_callback, &state)) {
                goto cleanup;
        }
                
        /* copy commons */
        if (hashtab_map(state.base->p_commons.table, common_copy_callback, &state)) {
                goto cleanup;
        }

        /* copy classes */
        if (hashtab_map(state.base->p_classes.table, class_copy_callback, &state)) {
                goto cleanup;
        }
		
	if (policydb_index_classes(out)) {
                ERR (handle, "Error while indexing out classes");
                goto cleanup;
        }

        /* copy aliases */
        if (hashtab_map(state.base->p_types.table, alias_copy_callback, &state))
                goto cleanup;

        /* copy roles */
        if (hashtab_map(state.base->p_roles.table, role_copy_callback, &state))
                goto cleanup;

        /* copy users */
        if (hashtab_map(state.base->p_users.table, user_copy_callback, &state))
                goto cleanup;

        /* copy bools */
        if (hashtab_map(state.base->p_bools.table, bool_copy_callback, &state))
                goto cleanup;

        /* now copy MLS's sensitivity level and categories */
        if (hashtab_map(state.base->p_levels.table, sens_copy_callback, &state) ||
            hashtab_map(state.base->p_cats.table, cats_copy_callback, &state)) {
                goto cleanup;
        }

	if (policydb_index_classes(out)) {
                ERR (handle, "Error while indexing out classes");
                goto cleanup;
        }
        if (policydb_index_others(handle, out, 0)) {
                ERR (handle, "Error while indexing out symbols");
                goto cleanup;
        }

        for (curblock = state.base->global; curblock != NULL; curblock = curblock->next) {
                avrule_decl_t *decl = curblock->branch_list;
                avrule_t *cur_avrule;

                /* find the first declaration that is enabled */
                while (decl != NULL) {
                        if (decl->enabled) {
                                break;
                        }
                        decl = decl->next;
                }
                if (decl == NULL) {
                        /* nothing was enabled within this block */
                        continue;
                }                
                
                /* copy role allows and role trans */
                if (copy_role_allows(&state, decl->role_allow_rules) != 0 ||
                    copy_role_trans(&state, decl->role_tr_rules) != 0) {
                        goto cleanup;
                }

                /* copy rules */
                cur_avrule = decl->avrules;
                while (cur_avrule != NULL) {
                        if (cur_avrule->specified & AVRULE_NEVERALLOW) {
                                /* copy this over directly so that assertions are checked later */
                                if (copy_neverallow(state.base, out, state.typemap, cur_avrule))
                                        ERR (handle, "Error while copying neverallow.");
                        }
                        else {
                                if (convert_and_expand_rule(state.handle, state.base, out, 
                                                            state.typemap, cur_avrule, &out->te_avtab,
                                                            NULL, NULL,
                                                            0) != 1) {
                                        goto cleanup;
                                }
                        }
                        cur_avrule = cur_avrule->next;
                }

                /* copy conditional rules */
                if (cond_node_copy(&state, decl->cond_list))
                        goto cleanup;
        }


	cond_optimize_lists(state.out->cond_list);
	evaluate_conds(state.out);
	
	/* copy ocontexts */
	if (ocontext_copy(&state))
		goto cleanup;
	
	/* copy genfs */
	if (genfs_copy(&state))
		goto cleanup;

        if (range_trans_clone(&state) == -1) {
                goto cleanup;
        }

	/* Build the type<->attribute maps and remove attributes. */
	state.out->attr_type_map = malloc(state.out->p_types.nprim*
					  sizeof(ebitmap_t));
	state.out->type_attr_map = malloc(state.out->p_types.nprim*
					  sizeof(ebitmap_t));
	if (!state.out->attr_type_map || !state.out->type_attr_map) {
		ERR(handle, "Out of memory!");
		goto cleanup;
	}
	for (i = 0; i < state.out->p_types.nprim; i++) {
		ebitmap_init(&state.out->type_attr_map[i]);
		ebitmap_init(&state.out->attr_type_map[i]);
		/* add the type itself as the degenerate case */
		if (ebitmap_set_bit(&state.out->type_attr_map[i], i, 1)) {
			ERR(handle, "Out of memory!");
			goto cleanup;
		}
	}
	if (hashtab_map(state.out->p_types.table, type_attr_map, 
			&state))
		goto cleanup;
	hashtab_map_remove_on_error(state.out->p_types.table, 
				    type_attr_remove, type_destroy, 0);

	if (check) {
		if (hierarchy_check_constraints(handle, state.out))
			goto cleanup;

		if (check_assertions(handle, state.out, state.out->global->branch_list->avrules))
			goto cleanup;
	}
	
        retval = 0;

 cleanup:
        free (state.typemap);
        return retval;
}

static int expand_avtab_insert(avtab_t *a, avtab_key_t *k, avtab_datum_t *d)
{
	avtab_ptr_t node;
	avtab_datum_t *avd;
	int rc;
	
	node = avtab_search_node(a, k);
	if (!node) {
		rc = avtab_insert(a, k, d);
		if (rc)
			ERR(NULL, "Out of memory!");
		return rc;
	}

	if ((k->specified & AVTAB_ENABLED) != 
	    (node->key.specified & AVTAB_ENABLED)) {
		node = avtab_insert_nonunique(a, k, d);
		if (!node) {
			ERR(NULL, "Out of memory!");
			return -1;
		}
		return 0;
	}

	avd = &node->datum;
	switch (k->specified & ~AVTAB_ENABLED) {
	case AVTAB_ALLOWED:
	case AVTAB_AUDITALLOW:
		avd->data |= d->data;
		break;
	case AVTAB_AUDITDENY:
		avd->data &= d->data;
		break;
	default:
		ERR(NULL, "Type conflict!");
		return -1;
	}

	return 0;
}

struct expand_avtab_data {
	avtab_t *expa;
	policydb_t *p;
  
};

static int expand_avtab_node(avtab_key_t *k, avtab_datum_t *d, void *args) 
{
	struct expand_avtab_data *ptr = args;
	avtab_t *expa = ptr->expa;
	policydb_t *p = ptr->p;
	type_datum_t *stype = p->type_val_to_struct[k->source_type-1];
	type_datum_t *ttype = p->type_val_to_struct[k->target_type-1];
	ebitmap_t *sattr = &p->attr_type_map[k->source_type-1];
	ebitmap_t *tattr = &p->attr_type_map[k->target_type-1];
	ebitmap_node_t *snode, *tnode;
	unsigned int i, j;
	avtab_key_t newkey;
	int rc;

	newkey.target_class = k->target_class;
	newkey.specified = k->specified;

	if (stype && ttype) {
		/* Both are individual types, no expansion required. */
		return expand_avtab_insert(expa, k, d);
	}

	if (stype) {
		/* Source is an individual type, target is an attribute. */
		newkey.source_type = k->source_type;
		ebitmap_for_each_bit(tattr, tnode, j) {
			if (!ebitmap_node_get_bit(tnode, j))
				continue;
			newkey.target_type = j + 1;
			rc = expand_avtab_insert(expa, &newkey, d);
			if (rc)
				return -1;
		}
		return 0;
	}

	if (ttype) {
		/* Target is an individual type, source is an attribute. */
		newkey.target_type = k->target_type;
		ebitmap_for_each_bit(sattr, snode, i) {
			if (!ebitmap_node_get_bit(snode, i))
				continue;
			newkey.source_type = i + 1;
			rc = expand_avtab_insert(expa, &newkey, d);
			if (rc)
				return -1;
		}
		return 0;
	}

	/* Both source and target type are attributes. */
	ebitmap_for_each_bit(sattr, snode, i) {
		if (!ebitmap_node_get_bit(snode, i))
			continue;
		ebitmap_for_each_bit(tattr, tnode, j) {
			if (!ebitmap_node_get_bit(tnode, j))
				continue;
			newkey.source_type = i + 1;
			newkey.target_type = j + 1;
			rc = expand_avtab_insert(expa, &newkey, d);
			if (rc)
				return -1;
		}
	}

	return 0;
}

int expand_avtab(policydb_t *p, avtab_t *a, avtab_t *expa)
{
	struct expand_avtab_data data;

	data.expa = expa;
	data.p = p;
	return avtab_map(a, expand_avtab_node, &data);
}

static int expand_cond_insert(cond_av_list_t **l, 
			      avtab_t *expa,
			      avtab_key_t *k, avtab_datum_t *d)
{
	avtab_ptr_t node;
	avtab_datum_t *avd;
	cond_av_list_t *nl;

	node = avtab_search_node(expa, k);
	if (!node ||
	    (k->specified & AVTAB_ENABLED) != (node->key.specified & AVTAB_ENABLED)) {
		node = avtab_insert_nonunique(expa, k, d);
		if (!node) {
			ERR(NULL, "Out of memory!");
			return -1;
		}
		node->parse_context = (void*)1;
		nl = (cond_av_list_t *) malloc(sizeof(*nl));
		if (!nl) {
			ERR(NULL, "Out of memory!");
			return -1;
		}
		memset(nl, 0, sizeof(*nl));
		nl->node = node;
		nl->next = *l;
		*l = nl;
		return 0;
	}

	avd = &node->datum;
	switch (k->specified & ~AVTAB_ENABLED) {
	case AVTAB_ALLOWED:
	case AVTAB_AUDITALLOW:
		avd->data |= d->data;
		break;
	case AVTAB_AUDITDENY:
		avd->data &= d->data;
		break;
	default:
		ERR(NULL, "Type conflict!");
		return -1;
	}

	return 0;
}


int expand_cond_av_node(policydb_t *p, 
			avtab_ptr_t node,
			cond_av_list_t **newl,
			avtab_t *expa)
{
	avtab_key_t *k = &node->key;
	avtab_datum_t *d = &node->datum;
	type_datum_t *stype = p->type_val_to_struct[k->source_type-1];
	type_datum_t *ttype = p->type_val_to_struct[k->target_type-1];
	ebitmap_t *sattr = &p->attr_type_map[k->source_type-1];
	ebitmap_t *tattr = &p->attr_type_map[k->target_type-1];
	ebitmap_node_t *snode, *tnode;
	unsigned int i, j;
	avtab_key_t newkey;
	int rc;

	newkey.target_class = k->target_class;
	newkey.specified = k->specified;

	if (stype && ttype) {
		/* Both are individual types, no expansion required. */
		return expand_cond_insert(newl, expa, k, d);
	}

	if (stype) {
		/* Source is an individual type, target is an attribute. */
		newkey.source_type = k->source_type;
		ebitmap_for_each_bit(tattr, tnode, j) {
			if (!ebitmap_node_get_bit(tnode, j))
				continue;
			newkey.target_type = j + 1;
			rc = expand_cond_insert(newl, expa, &newkey, d);
			if (rc)
				return -1;
		}
		return 0;
	}

	if (ttype) {
		/* Target is an individual type, source is an attribute. */
		newkey.target_type = k->target_type;
		ebitmap_for_each_bit(sattr, snode, i) {
			if (!ebitmap_node_get_bit(snode, i))
				continue;
			newkey.source_type = i + 1;
			rc = expand_cond_insert(newl, expa, &newkey, d);
			if (rc)
				return -1;
		}
		return 0;
	}

	/* Both source and target type are attributes. */
	ebitmap_for_each_bit(sattr, snode, i) {
		if (!ebitmap_node_get_bit(snode, i))
			continue;
		ebitmap_for_each_bit(tattr, tnode, j) {
			if (!ebitmap_node_get_bit(tnode, j))
				continue;
			newkey.source_type = i + 1;
			newkey.target_type = j + 1;
			rc = expand_cond_insert(newl, expa, &newkey, d);
			if (rc)
				return -1;
		}
	}

	return 0;
}

int expand_cond_av_list(policydb_t *p, cond_av_list_t *l,
			cond_av_list_t **newl, avtab_t *expa)
{
	cond_av_list_t *cur;
	avtab_ptr_t node;
	int rc;

	*newl = NULL;
	for (cur = l; cur; cur = cur->next) {
		node = cur->node;
		rc = expand_cond_av_node(p, node, newl, expa);
		if (rc)
			return rc;
	}

	return 0;
}
