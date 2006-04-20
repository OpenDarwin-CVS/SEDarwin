/* Author: Jason Tang	  <jtang@tresys.com>
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

#include <sepol/module.h>
#include <selinux/selinux.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

#include "user_internal.h"
#include "seuser_internal.h"
#include "port_internal.h"
#include "iface_internal.h"
#include "boolean_internal.h"
#include "fcontext_internal.h"
#include "node_internal.h"

#include "debug.h"
#include "handle.h"
#include "modules.h"
#include "direct_api.h"
#include "semanage_store.h"
#include "database_policydb.h"
#include "policy.h"

static void semanage_direct_destroy(semanage_handle_t *sh);
static int semanage_direct_disconnect(semanage_handle_t *sh);
static int semanage_direct_begintrans(semanage_handle_t *sh);
static int semanage_direct_commit(semanage_handle_t *sh);
static int semanage_direct_install(semanage_handle_t *sh, char *data, size_t data_len);
static int semanage_direct_upgrade(semanage_handle_t *sh,
				   char *data, size_t data_len);
static int semanage_direct_install_base(semanage_handle_t *sh,
					char *base_data, size_t data_len);
static int semanage_direct_remove(semanage_handle_t *sh,
				  char *module_name);
static int semanage_direct_list(semanage_handle_t *sh,
				semanage_module_info_t **modinfo, int *num_modules);

static struct semanage_policy_table direct_funcs = {
	.get_serial = semanage_get_commit_number,
	.destroy = semanage_direct_destroy,
	.disconnect = semanage_direct_disconnect,
	.begin_trans = semanage_direct_begintrans,
	.commit = semanage_direct_commit,
	.install = semanage_direct_install,
	.upgrade = semanage_direct_upgrade,
	.install_base = semanage_direct_install_base,
	.remove = semanage_direct_remove,
	.list = semanage_direct_list
};

int semanage_direct_is_managed(semanage_handle_t *sh) {
	char polpath[PATH_MAX];

	snprintf(polpath, PATH_MAX, "%s%s", selinux_path(), sh->conf->store_path);
	
	if (semanage_check_init(polpath))
		goto err;

	if (semanage_access_check(sh) < 0) 
		return 0;

	return 1;

	err:
	ERR(sh, "could not check whether policy is managed");
	return STATUS_ERR;	
}

/* Check that the module store exists, creating it if necessary.
 */
int semanage_direct_connect(semanage_handle_t *sh) {
	char polpath[PATH_MAX];

	snprintf(polpath, PATH_MAX, "%s%s", selinux_path(), sh->conf->store_path);
	
	if (semanage_check_init(polpath))
		goto err;

	if (sh->create_store)
		if (semanage_create_store(sh, 1))
			goto err;

	if (semanage_access_check(sh) < SEMANAGE_CAN_READ) 
		goto err;

	sh->u.direct.translock_file_fd = -1;
	sh->u.direct.activelock_file_fd = -1;

	/* set up function pointers */
	sh->funcs = &direct_funcs;

        /* Object databases: local modifications */
	if (user_base_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_USERS_BASE_LOCAL),
		semanage_user_base_dbase_local(sh)) < 0)
		goto err;

	if (user_extra_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_USERS_EXTRA_LOCAL),
		semanage_user_extra_dbase_local(sh)) < 0)
		goto err;

	if (user_join_dbase_init(sh,
		semanage_user_base_dbase_local(sh),
		semanage_user_extra_dbase_local(sh),
		semanage_user_dbase_local(sh)) < 0)
		goto err;

	if (port_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_PORTS_LOCAL), 
		semanage_port_dbase_local(sh)) < 0)
		goto err;

	if (iface_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_INTERFACES_LOCAL),
		semanage_iface_dbase_local(sh)) < 0)
		goto err;

	if (bool_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_BOOLEANS_LOCAL),
		semanage_bool_dbase_local(sh)) < 0)
		goto err;

	if (fcontext_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_FC_LOCAL), 
		semanage_fcontext_dbase_local(sh)) < 0)
		goto err;

	if (seuser_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_SEUSERS_LOCAL),
		semanage_seuser_dbase_local(sh)) < 0)
		goto err;

	if (node_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_NODES_LOCAL),
		semanage_node_dbase_local(sh)) < 0)
		goto err;

	/* Object databases: local modifications + policy */
	if (user_base_policydb_dbase_init(sh, 
		semanage_user_base_dbase_policy(sh)) < 0)
		goto err;

	if (user_extra_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_USERS_EXTRA), 
		semanage_user_extra_dbase_policy(sh)) < 0)
		goto err;

	if (user_join_dbase_init(sh, 
		semanage_user_base_dbase_policy(sh),
		semanage_user_extra_dbase_policy(sh),
		semanage_user_dbase_policy(sh)) < 0)
		goto err;

	if (port_policydb_dbase_init(sh, semanage_port_dbase_policy(sh)) < 0)
		goto err;

	if (iface_policydb_dbase_init(sh, semanage_iface_dbase_policy(sh)) < 0)
		goto err;

	if (bool_policydb_dbase_init(sh, semanage_bool_dbase_policy(sh)) < 0)
		goto err;

	if (fcontext_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_FC), 
		semanage_fcontext_dbase_policy(sh)) < 0)
		goto err;

	if (seuser_file_dbase_init(sh, 
		semanage_fname(SEMANAGE_SEUSERS), 
		semanage_seuser_dbase_policy(sh)) < 0)
		goto err;

	if (node_policydb_dbase_init(sh, semanage_node_dbase_policy(sh)) < 0)
		goto err;

	/* Active kernel policy */
	if (bool_activedb_dbase_init(sh, semanage_bool_dbase_active(sh)) < 0)
		goto err;

	return STATUS_SUCCESS;

	err:
	ERR(sh, "could not establish direct connection");
	sepol_handle_destroy(sh->sepolh);
	return STATUS_ERR;
}

static void semanage_direct_destroy(semanage_handle_t *sh) {
	/* do nothing */
	sh = NULL;
}

static int semanage_direct_disconnect(semanage_handle_t *sh) {
	/* destroy transaction */
	if (sh->is_in_transaction) {
		/* destroy sandbox */
		if (semanage_remove_directory(semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL)) < 0) {
			ERR(sh, "Could not cleanly remove sandbox %s.", semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL));
			return -1;
		}
		semanage_release_trans_lock(sh);
	}

	/* Release object databases: local modifications */
	user_base_file_dbase_release(semanage_user_base_dbase_local(sh));
	user_extra_file_dbase_release(semanage_user_extra_dbase_local(sh));
	user_join_dbase_release(semanage_user_dbase_local(sh));
	port_file_dbase_release(semanage_port_dbase_local(sh));
	iface_file_dbase_release(semanage_iface_dbase_local(sh));
	bool_file_dbase_release(semanage_bool_dbase_local(sh));
	fcontext_file_dbase_release(semanage_fcontext_dbase_local(sh));
	seuser_file_dbase_release(semanage_seuser_dbase_local(sh));
	node_file_dbase_release(semanage_node_dbase_local(sh));

	/* Release object databases: local modifications + policy */
	user_base_policydb_dbase_release(semanage_user_base_dbase_policy(sh));
	user_extra_file_dbase_release(semanage_user_extra_dbase_policy(sh));
	user_join_dbase_release(semanage_user_dbase_policy(sh));
	port_policydb_dbase_release(semanage_port_dbase_policy(sh));
	iface_policydb_dbase_release(semanage_iface_dbase_policy(sh));
	bool_policydb_dbase_release(semanage_bool_dbase_policy(sh));
	fcontext_file_dbase_release(semanage_fcontext_dbase_policy(sh));
	seuser_file_dbase_release(semanage_seuser_dbase_policy(sh));
	node_policydb_dbase_release(semanage_node_dbase_policy(sh));

	/* Release object databases: active kernel policy */
	bool_activedb_dbase_release(semanage_bool_dbase_active(sh));

	return 0;
}

static int semanage_direct_begintrans(semanage_handle_t *sh) {
	
	if (semanage_access_check(sh) != SEMANAGE_CAN_WRITE) {
		return -1;
	}
	if (semanage_get_trans_lock(sh) < 0) {
		return -1;
	}
	if ((semanage_make_sandbox(sh)) < 0) {
		return -1;
	}
	return 0;
}

/********************* utility functions *********************/

/* Takes a module stored in 'module_data' and parses its headers.
 * Sets reference variables 'filename' to module's fully qualified
 * path name into the sandbox, 'module_name' to module's name, and
 * 'version' to module's version.  The caller is responsible for
 * free()ing 'filename', 'module_name', and 'version'; they will be
 * set to NULL upon entering this function.  Returns 0 on success, -1
 * if out of memory, or -2 if data did not represent a module.
 */
static int parse_module_headers(semanage_handle_t *sh, char *module_data,
				size_t data_len, char **module_name,
				char **version, char **filename) {
	struct sepol_policy_file *pf;
	int file_type;
	const char *module_path;
	*module_name = *version = *filename = NULL;
	
	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		return -1;
	}
	sepol_policy_file_set_mem(pf, module_data, data_len);
	sepol_policy_file_set_handle(pf, sh->sepolh);
	if (module_data == NULL ||
	    data_len == 0 ||
	    sepol_module_package_info(pf, &file_type, module_name,
				      version) == -1) {
		sepol_policy_file_free(pf);
		ERR(sh, "Could not parse module data.");
		return -2;
	}
	sepol_policy_file_free(pf);
	if (file_type != SEPOL_POLICY_MOD) {
		if (file_type == SEPOL_POLICY_BASE)
			ERR(sh, "Received a base module, expected a non-base module.");
		else
			ERR(sh, "Data did not represent a module.");
		return -2;
	}
	if ((module_path = semanage_path(SEMANAGE_TMP, SEMANAGE_MODULES)) == NULL) {
		return -1;
	}
	if (asprintf(filename, "%s/%s.pp", module_path, *module_name) == -1) {
		ERR(sh, "Out of memory!");
		return -1;
	}
	return 0;
}

/* Takes a base module stored in 'module_data' and parse its headers.
 * Returns 0 on success, -1 if out of memory, or -2 if data did not
 * represent a module.
 */
static int parse_base_headers(semanage_handle_t *sh,
			      char *module_data, size_t data_len) {
	struct sepol_policy_file *pf;
	char *module_name = NULL, *version = NULL;
	int file_type;

	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		return -1;
	}
	sepol_policy_file_set_mem(pf, module_data, data_len);
	sepol_policy_file_set_handle(pf, sh->sepolh);
	if (module_data == NULL ||
	    data_len == 0 ||
	    sepol_module_package_info(pf, &file_type,
				      &module_name, &version) == -1) {
		sepol_policy_file_free(pf);
		ERR(sh, "Could not parse base module data.");
		return -2;
	}
	sepol_policy_file_free(pf);
	free(module_name);
	free(version);
	if (file_type != SEPOL_POLICY_BASE) {
		if (file_type == SEPOL_POLICY_MOD)
			ERR(sh, "Received a non-base module, expected a base module.");
		else
			ERR(sh, "Data did not represent a module.");
		return -2;
	}
	return 0;
}

/* Writes a block of data to a file.  Returns 0 on success, -1 on
 * error. */
static int write_file(semanage_handle_t *sh,
		      const char *filename, char *data, size_t num_bytes) {
	int out;
	if ((out = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) == -1) {
		ERR(sh, "Could not open %s for writing.", filename);
		return -1;
	}
	if (write(out, data, num_bytes) == -1) {
		ERR(sh, "Error while writing to %s.", filename);
		close(out);
		return -1;
	}
	close(out);
	return 0;
}

/* Writes a module (or a base) to the file given by a fully-qualified
 * 'filename'.	Returns 0 on success, -1 if file could not be written.
 */
static int semanage_write_module(semanage_handle_t *sh,
				 const char *filename, sepol_module_package_t *package)
{
	struct sepol_policy_file *pf;
	FILE *outfile;
	int retval;
	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		return -1;
	}
	if ((outfile = fopen(filename, "wb")) == NULL) {
		sepol_policy_file_free(pf);
		ERR(sh, "Could not open %s for writing.", filename);
		return -1;
	}
	sepol_policy_file_set_fp(pf, outfile);
	sepol_policy_file_set_handle(pf, sh->sepolh);
	retval = sepol_module_package_write(package, pf);
	fclose(outfile);
	sepol_policy_file_free(pf);
	if (retval == -1) {
		ERR(sh, "Error while writing module to %s.", filename);
		return -1;
	}
	return 0;
}

/********************* direct API functions ********************/

/* Commits all changes in sandbox to the actual kernel policy.
 * Returns commit number on success, -1 on error.
 */
static int semanage_direct_commit(semanage_handle_t *sh) {
	char **mod_filenames = NULL;
	const char *linked_filename = NULL, *ofilename = NULL;
	sepol_module_package_t *base = NULL;
	int retval = -1, num_modfiles = 0, i;
	sepol_policydb_t* out = NULL;

	/* Declare some variables */
	int modified, fcontexts_modified, ports_modified, 
		seusers_modified, users_extra_modified;
	dbase_config_t* users = semanage_user_dbase_local(sh);
	dbase_config_t* users_base = semanage_user_base_dbase_local(sh);
	dbase_config_t* pusers_base = semanage_user_base_dbase_policy(sh);
	dbase_config_t* users_extra = semanage_user_extra_dbase_local(sh);
	dbase_config_t* pusers_extra = semanage_user_extra_dbase_policy(sh);
	dbase_config_t* ports = semanage_port_dbase_local(sh);
	dbase_config_t* pports = semanage_port_dbase_policy(sh);
	dbase_config_t* bools = semanage_bool_dbase_local(sh);
	dbase_config_t* pbools = semanage_bool_dbase_policy(sh);
	dbase_config_t* ifaces = semanage_iface_dbase_local(sh);
	dbase_config_t* pifaces = semanage_iface_dbase_policy(sh);
	dbase_config_t* nodes = semanage_node_dbase_local(sh);
	dbase_config_t* pnodes = semanage_node_dbase_policy(sh);
	dbase_config_t* fcontexts = semanage_fcontext_dbase_local(sh);
	dbase_config_t* pfcontexts = semanage_fcontext_dbase_policy(sh);
	dbase_config_t* seusers = semanage_seuser_dbase_local(sh);
	dbase_config_t* pseusers = semanage_seuser_dbase_policy(sh);

	/* Before we do anything else, flush the join to its component parts.
	 * This *does not* flush to disk automatically */
	if (users->dtable->is_modified(users->dbase) &&
	    users->dtable->flush(sh, users->dbase) < 0)
		goto cleanup;

	/* Decide if anything was modified */
	fcontexts_modified = fcontexts->dtable->is_modified(fcontexts->dbase);
	seusers_modified = seusers->dtable->is_modified(seusers->dbase);
	users_extra_modified = users_extra->dtable->is_modified(users_extra->dbase);
	ports_modified = ports->dtable->is_modified(ports->dbase);

	modified = sh->modules_modified;
	modified |= ports_modified;
	modified |= users->dtable->is_modified(users_base->dbase);
	modified |= bools->dtable->is_modified(bools->dbase);
	modified |= ifaces->dtable->is_modified(ifaces->dbase);
	modified |= nodes->dtable->is_modified(nodes->dbase);

	/* FIXME: get rid of these, once we support loading the existing policy,
	 * instead of rebuilding it */
	modified |= seusers_modified;
	modified |= fcontexts_modified;
	modified |= users_extra_modified;

	/* If there were policy changes, or explicitly requested, rebuild the policy */
	if (sh->do_rebuild || modified) {

		/* =================== Module expansion =============== */

		/* link all modules in the sandbox to the base module */
		if (semanage_get_modules_names(sh, &mod_filenames, &num_modfiles) != 0 ||
		    semanage_verify_modules(sh, mod_filenames, num_modfiles) == -1 ||
		    semanage_link_sandbox(sh, &base) < 0) {
			goto cleanup;
		}
	
		/* write the linked base */
		if ((linked_filename = semanage_path(SEMANAGE_TMP, SEMANAGE_LINKED)) == NULL ||
		    semanage_write_module(sh, linked_filename, base) == -1 ||
		    semanage_verify_linked(sh) != 0) {
			goto cleanup;
		}

		/* ==================== File-backed ================== */

		/* File Contexts */
		if ((ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_FC_TMPL)) == NULL ||
		    write_file(sh, ofilename, sepol_module_package_get_file_contexts(base), 
				sepol_module_package_get_file_contexts_len(base)) == -1) {
			goto cleanup;
		}

		if (semanage_split_fc(sh)) 
			goto cleanup;

		pfcontexts->dtable->drop_cache(pfcontexts->dbase);

		/* Seusers */
		if (sepol_module_package_get_seusers_len(base)) {
			if ((ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_SEUSERS)) == NULL ||
			    write_file(sh, ofilename, sepol_module_package_get_seusers(base), 
					sepol_module_package_get_seusers_len(base)) == -1) {
				goto cleanup;
			}
			pseusers->dtable->drop_cache(pseusers->dbase);

		} else {
			if (pseusers->dtable->clear(sh, pseusers->dbase) < 0)
				goto cleanup;
		}

		/* Users_extra */
		if (sepol_module_package_get_user_extra_len(base)) {
			if ((ofilename = semanage_path(SEMANAGE_TMP, SEMANAGE_USERS_EXTRA)) == NULL ||
			    write_file(sh, ofilename, sepol_module_package_get_user_extra(base), 
					sepol_module_package_get_user_extra_len(base)) == -1) {
				goto cleanup;
			}
			pusers_extra->dtable->drop_cache(pusers_extra->dbase);

		} else {
			if (pusers_extra->dtable->clear(sh, pusers_extra->dbase) < 0)
				goto cleanup;
		}

		/* ==================== Policydb-backed ================ */

		/* Create new policy object, then attach to policy databases
		 * that work with a policydb */
		if (semanage_expand_sandbox(sh, base, &out) < 0)
			goto cleanup;

		dbase_policydb_attach((dbase_policydb_t*) pusers_base->dbase, out);
		dbase_policydb_attach((dbase_policydb_t*) pports->dbase, out);
		dbase_policydb_attach((dbase_policydb_t*) pifaces->dbase, out);
		dbase_policydb_attach((dbase_policydb_t*) pbools->dbase, out);
		dbase_policydb_attach((dbase_policydb_t*) pnodes->dbase, out);

		/* ============= Apply changes, and verify  =============== */

		if (semanage_base_merge_components(sh) < 0)
			goto cleanup;

		if (semanage_write_policydb(sh, out) < 0)
			goto cleanup;

		if (semanage_verify_kernel(sh) != 0)
			goto cleanup;
	}

	/* FIXME: else if !modified, but seusers_modified, 
	 * load the existing policy instead of rebuilding */

	/* ======= Post-process: Validate non-policydb components ===== */

	/* Validate local modifications to file contexts.
	 * Note: those are still cached, even though they've been 
	 * merged into the main file_contexts. We won't check the 
	 * large file_contexts - checked at compile time */
	if (sh->do_rebuild || modified || fcontexts_modified) {
		if (semanage_fcontext_validate_local(sh, out) < 0)
			goto cleanup;
	}

	/* Validate local seusers against policy */
	if (sh->do_rebuild || modified || seusers_modified) {
		if (semanage_seuser_validate_local(sh, out) < 0) 
			goto cleanup;
	}

	/* Validate local ports for overlap */
	if (sh->do_rebuild || ports_modified) {
		if (semanage_port_validate_local(sh) < 0)
			goto cleanup;
	}

	/* ================== Write non-policydb components ========= */

	/* Commit changes to components */
	if (semanage_commit_components(sh) < 0)
		goto cleanup;

	retval = semanage_install_sandbox(sh);

 cleanup:
	for (i = 0; mod_filenames != NULL && i < num_modfiles; i++) {
		free(mod_filenames[i]);
	}

	/* Detach from policydb, so it can be freed */
	dbase_policydb_detach((dbase_policydb_t*) pusers_base->dbase);
	dbase_policydb_detach((dbase_policydb_t*) pports->dbase);
	dbase_policydb_detach((dbase_policydb_t*) pifaces->dbase);
	dbase_policydb_detach((dbase_policydb_t*) pnodes->dbase);
	dbase_policydb_detach((dbase_policydb_t*) pbools->dbase);

	free(mod_filenames);
	sepol_module_package_free(base);
	sepol_policydb_free(out);
	semanage_release_trans_lock(sh);

	/* regardless if the commit was successful or not, remove the
	   sandbox if it is still there */
	semanage_remove_directory(semanage_path(SEMANAGE_TMP, SEMANAGE_TOPLEVEL));
	return retval;
}


/* Writes a module to the sandbox's module directory, overwriting any
 * previous module stored within.  Note that module data are not
 * free()d by this function; caller is responsible for deallocating it
 * if necessary.  Returns 0 on success, -1 if out of memory, -2 if the
 * data does not represent a valid module file, -3 if error while
 * writing file. */
static int semanage_direct_install(semanage_handle_t *sh,
				   char *data, size_t data_len) {
	
	int retval;
	char *module_name = NULL, *version = NULL, *filename = NULL;
	if ((retval = parse_module_headers(sh, data, data_len,
					   &module_name, &version, &filename)) != 0) {
		goto cleanup;
	}
	if (write_file(sh, filename, data, data_len) == -1) {
		retval = -3;
	}
	retval = 0;
 cleanup:
	free(version);
	free(filename);
	free(module_name);
	return retval;
}

/* Similar to semanage_direct_install(), except that it checks that
 * there already exists a module with the same name and that the
 * module is an older version then the one in 'data'.  Returns 0 on
 * success, -1 if out of memory, -2 if the data does not represent a
 * valid module file, -3 if error while writing file or reading
 * modules directory, -4 if there does not exist an older module or if
 * the previous module is same or newer than 'data'.
 */
static int semanage_direct_upgrade(semanage_handle_t *sh,
				   char *data, size_t data_len) {
	int i, retval, num_modules = 0;
	char *module_name = NULL, *version = NULL, *filename = NULL;
	semanage_module_info_t *modinfo = NULL;
	if ((retval = parse_module_headers(sh, data, data_len,
					   &module_name, &version, &filename)) != 0) {
		goto cleanup;
	}
	if (semanage_direct_list(sh, &modinfo, &num_modules) < 0) {
		goto cleanup;
	}
	retval = -4;
	for (i = 0; i < num_modules; i++) {
		semanage_module_info_t *m = semanage_module_list_nth(modinfo, i);
		if (strcmp(semanage_module_get_name(m), module_name) == 0) {
			if (semanage_strverscmp(version, semanage_module_get_version(m)) > 0) {
				retval = 0;
				break;
			}
			else {
				ERR(sh, "Previous module %s is same or newer.", module_name);
				retval = -4;
				goto cleanup;
			}
		}
	}
	if (retval == -4) {
		ERR(sh, "There does not already exist a module named %s.", module_name);
		goto cleanup;
	}
	if (write_file(sh, filename, data, data_len) == -1) {
		retval = -3;
	}
 cleanup:
	free(version);
	free(filename);
	free(module_name);
	for (i = 0; modinfo != NULL && i < num_modules; i++) {
		semanage_module_info_t *m = semanage_module_list_nth(modinfo, i);
		semanage_module_info_datum_destroy(m);
	}
	free(modinfo);
	return retval;
}

/* Writes a base module into a sandbox, overwriting any previous base
 * module.  Note that 'module_data' is not free()d by this function;
 * caller is responsible for deallocating it if necessary.  Returns 0
 * on success, -1 if out of memory, -2 if the data does not represent
 * a valid base module file, -3 if error while writing file.
 */
static int semanage_direct_install_base(semanage_handle_t *sh,
					char *base_data, size_t data_len) {
	int retval = -1;
	const char *filename = NULL;
	if ((retval = parse_base_headers(sh, base_data, data_len)) != 0) {
		goto cleanup;
	}
	if ((filename = semanage_path(SEMANAGE_TMP, SEMANAGE_BASE)) == NULL) {
		goto cleanup;
	}
	if (write_file(sh, filename, base_data, data_len) == -1) {
		retval = -3;
	}
	retval = 0;
 cleanup:
	return retval;
}

/* Removes a module from the sandbox.  Returns 0 on success, -1 if out
 * of memory, -2 if module not found or could not be removed. */
static int semanage_direct_remove(semanage_handle_t *sh,
				  char *module_name) {
	int i, retval = -1;
	char **module_filenames = NULL;
	int num_mod_files;
	size_t name_len = strlen(module_name);
	if (semanage_get_modules_names(sh, &module_filenames, &num_mod_files) == -1) {
		return -1;
	}
	for (i = 0; i < num_mod_files; i++) {
		char *base = strrchr(module_filenames[i], '/');
		if (base == NULL) {
			ERR(sh, "Could not read module names.");
			retval = -2;
			goto cleanup;
		}
		base++;
		if (memcmp(module_name, base, name_len) == 0 &&
		    strcmp(base + name_len, ".pp") == 0) {
			if (unlink(module_filenames[i]) == -1) {
				ERR(sh, "Could not remove module file %s.", module_filenames[i]);
				retval = -2;
			}
			retval = 0;
			goto cleanup;
		}
	}
	ERR(sh, "Module %s was not found.", module_name);
	retval = -2;				/* module not found */
 cleanup:
	for (i = 0; module_filenames != NULL && i < num_mod_files; i++) {
		free(module_filenames[i]);
	}
	free(module_filenames);
	return retval;
}


/* Allocate an array of module_info structures for each readable
 * module within the store.  Note that if the calling program has
 * already begun a transaction then this function will get a list of
 * modules within the sandbox.	The caller is responsible for calling
 * semanage_module_info_datum_destroy() on each element of the array
 * as well as free()ing the entire list.
 */
static int semanage_direct_list(semanage_handle_t *sh,
				semanage_module_info_t **modinfo, int *num_modules) {
	struct sepol_policy_file *pf = NULL;
	int i, retval = -1;
	char **module_filenames = NULL;
	int num_mod_files;
	*modinfo = NULL;
	*num_modules = 0;

        /* get the read lock when reading from the active
           (non-transaction) directory */
	if (!sh->is_in_transaction) 
		if (semanage_get_active_lock(sh) < 0) 
			return -1;

	if (semanage_get_modules_names(sh, &module_filenames, &num_mod_files) == -1) {
		goto cleanup;
	}
	if (num_mod_files == 0) {
		retval = semanage_get_commit_number(sh);
		goto cleanup;
	}

	if (sepol_policy_file_create(&pf)) {
		ERR(sh, "Out of memory!");
		goto cleanup;
	}
	sepol_policy_file_set_handle(pf, sh->sepolh);
	
	if ((*modinfo = calloc(num_mod_files, sizeof(**modinfo))) == NULL) {
		ERR(sh, "Out of memory!");
		goto cleanup;
	}
	
	for (i = 0; i < num_mod_files; i++) {
		FILE *fp;
		char *name = NULL, *version = NULL;
		int type;
		if ((fp = fopen(module_filenames[i], "rb")) == NULL) {
			/* could not open this module file, so don't
			 * report it */
			continue;
		}
		sepol_policy_file_set_fp(pf, fp);
		if (sepol_module_package_info(pf, &type, &name, &version)) {
			fclose(fp);
			free(name);
			free(version);
			continue;
		}
		fclose(fp);
		if (type == SEPOL_POLICY_MOD) {
			(*modinfo)[*num_modules].name = name;
			(*modinfo)[*num_modules].version = version;
			(*num_modules)++;
		}
		else {
			/* file was not a module, so don't report it */
			free(name);
			free(version);
		}
	}
	retval = semanage_get_commit_number(sh);
	
 cleanup:
	sepol_policy_file_free(pf);
	for (i = 0; module_filenames != NULL && i < num_mod_files; i++) {
		free(module_filenames[i]);
	}
	free(module_filenames);
        if (!sh->is_in_transaction) {
                semanage_release_active_lock(sh);
        }
	return retval;
}

int semanage_direct_access_check(semanage_handle_t *sh) {
	char polpath[PATH_MAX];	

	snprintf(polpath, PATH_MAX, "%s%s", selinux_path(), sh->conf->store_path);

	if (semanage_check_init(polpath))
		return -1;

	return semanage_store_access_check(sh);
}
