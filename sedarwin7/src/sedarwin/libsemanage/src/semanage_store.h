/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *	    Joshua Brindle <jbrindle@tresys.com>
 *	    Jason Tang <jtang@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
 * Copyright (C) 2005 Red Hat, Inc.
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

#ifndef SEMANAGE_MODULE_STORE_H
#define SEMANAGE_MODULE_STORE_H

#include <sys/time.h>
#include <sepol/module.h>
#include "handle.h"

enum semanage_store_defs {
	SEMANAGE_ACTIVE,
	SEMANAGE_PREVIOUS,
	SEMANAGE_TMP,
	SEMANAGE_NUM_STORES
};

/* sandbox filenames and paths */
enum semanage_sandbox_defs {
	SEMANAGE_TOPLEVEL,
	SEMANAGE_MODULES, 
	SEMANAGE_KERNEL,
	SEMANAGE_BASE, 
	SEMANAGE_LINKED, 
	SEMANAGE_FC,
	SEMANAGE_HOMEDIR_TMPL,
	SEMANAGE_FC_TMPL,
	SEMANAGE_COMMIT_NUM_FILE,
	SEMANAGE_PORTS_LOCAL,
	SEMANAGE_INTERFACES_LOCAL,
	SEMANAGE_NODES_LOCAL,
	SEMANAGE_BOOLEANS_LOCAL,
	SEMANAGE_FC_LOCAL,
	SEMANAGE_SEUSERS_LOCAL,
	SEMANAGE_USERS_BASE_LOCAL,
	SEMANAGE_USERS_EXTRA_LOCAL,
	SEMANAGE_SEUSERS,
	SEMANAGE_USERS_EXTRA,
	SEMANAGE_STORE_NUM_PATHS
};

/* FIXME: this needs to be made a module store specific init and the
 * global configuration moved to another file.
 */
const char *semanage_conf_path(void);
int semanage_check_init(const char *root);

extern const char* semanage_fname(
	enum semanage_sandbox_defs file_enum);

extern const char *semanage_path(
	enum semanage_store_defs store, 
	enum semanage_sandbox_defs file);

int semanage_create_store(semanage_handle_t *sh, int create);

int semanage_store_access_check(semanage_handle_t *sh);

int semanage_remove_directory(const char *path);

int semanage_make_sandbox(semanage_handle_t *sh);

int semanage_get_modules_names(
	semanage_handle_t *sh,
	char ***filenames, 
	int *len);

int semanage_install_sandbox(semanage_handle_t *sh);

/* lock file routines */
int semanage_get_trans_lock(semanage_handle_t *sh);
int semanage_get_active_lock(semanage_handle_t *sh);
void semanage_release_trans_lock(semanage_handle_t *sh);
void semanage_release_active_lock(semanage_handle_t *sh);
int semanage_get_commit_number(semanage_handle_t *sh);

int semanage_link_sandbox(
	semanage_handle_t *sh, 
	sepol_module_package_t **base);

int semanage_expand_sandbox(
	semanage_handle_t *sh, 
	sepol_module_package_t *base,
	sepol_policydb_t** policydb);

int semanage_write_policydb(
	semanage_handle_t *sh,
	sepol_policydb_t* policydb);

int semanage_install_sandbox(semanage_handle_t *sh);

int semanage_verify_modules(
	semanage_handle_t *sh,
	char **module_filenames, 
	int num_modules);

int semanage_verify_linked(semanage_handle_t *sh);
int semanage_verify_kernel(semanage_handle_t *sh);
int semanage_split_fc(semanage_handle_t *sh);

#endif
