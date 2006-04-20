/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_iface;
struct semanage_iface_key;
typedef struct semanage_iface record_t;
typedef struct semanage_iface_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_policydb;
typedef struct dbase_policydb dbase_t;
#define DBASE_DEFINED

#include <sepol/interfaces.h>
#include <semanage/handle.h>
#include "iface_internal.h"
#include "debug.h"
#include "database_policydb.h"

/* INTERFACE RECRORD (SEPOL): POLICYDB extension: method table */
record_policydb_table_t SEMANAGE_IFACE_POLICYDB_RTABLE = {
	.add         = NULL,
	.modify      = sepol_iface_modify,
	.set         = NULL,
	.query       = sepol_iface_query,
        .count       = sepol_iface_count,
	.exists      = sepol_iface_exists, 
	.iterate     = sepol_iface_iterate,
};

int iface_policydb_dbase_init(
	semanage_handle_t* handle, 
	dbase_config_t* dconfig) {

	if (dbase_policydb_init(
		handle, 
		"policy.kern",
		&SEMANAGE_IFACE_RTABLE, 
		&SEMANAGE_IFACE_POLICYDB_RTABLE, 
		&dconfig->dbase) < 0)
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_POLICYDB_DTABLE;
	return STATUS_SUCCESS;
}

void iface_policydb_dbase_release(
	dbase_config_t* dconfig) {

	dbase_policydb_release(dconfig->dbase);
}
