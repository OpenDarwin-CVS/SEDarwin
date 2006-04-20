/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_bool;
struct semanage_bool_key;
typedef struct semanage_bool record_t;
typedef struct semanage_bool_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_policydb;
typedef struct dbase_policydb dbase_t;
#define DBASE_DEFINED

#include <sepol/booleans.h>
#include <semanage/handle.h>
#include "boolean_internal.h"
#include "debug.h"
#include "database_policydb.h"

/* BOOLEAN RECRORD (SEPOL): POLICYDB extension: method table */
record_policydb_table_t SEMANAGE_BOOL_POLICYDB_RTABLE = {
	.add         = NULL, 
	.modify      = NULL,
	.set         = sepol_bool_set,
	.query       = sepol_bool_query,
	.count       = sepol_bool_count,
	.exists      = sepol_bool_exists, 
	.iterate     = sepol_bool_iterate,
};

int bool_policydb_dbase_init(
	semanage_handle_t* handle,
	dbase_config_t* dconfig) {

	if (dbase_policydb_init(
		handle, 
		"policy.kern",
		&SEMANAGE_BOOL_RTABLE, 
		&SEMANAGE_BOOL_POLICYDB_RTABLE, 
		&dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_POLICYDB_DTABLE;
	return STATUS_SUCCESS;
}

void bool_policydb_dbase_release(
	dbase_config_t* dconfig) {

	dbase_policydb_release(dconfig->dbase);
}
