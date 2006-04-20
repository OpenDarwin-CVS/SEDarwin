/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_user_base;
struct semanage_user_key;
typedef struct semanage_user_base record_t;
typedef struct semanage_user_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_policydb;
typedef struct dbase_policydb dbase_t;
#define DBASE_DEFINED

#include <sepol/users.h>
#include <semanage/handle.h>
#include "user_internal.h"
#include "debug.h"
#include "database_policydb.h"

/* USER BASE record: POLICYDB extension: method table */
record_policydb_table_t SEMANAGE_USER_BASE_POLICYDB_RTABLE = {
	.add         = NULL,
	.modify      = sepol_user_modify,
	.set         = NULL,
	.query       = sepol_user_query, 
	.count       = sepol_user_count,
	.exists      = sepol_user_exists,
	.iterate     = sepol_user_iterate,
};

int user_base_policydb_dbase_init(
	semanage_handle_t* handle, 
	dbase_config_t* dconfig) {

	if (dbase_policydb_init(
		handle, 
		"policy.kern",
		&SEMANAGE_USER_BASE_RTABLE, 
		&SEMANAGE_USER_BASE_POLICYDB_RTABLE, 
		&dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_POLICYDB_DTABLE;
	return STATUS_SUCCESS;
}

void user_base_policydb_dbase_release(
	dbase_config_t* dconfig) {

	dbase_policydb_release(dconfig->dbase);
}
