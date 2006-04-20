/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_port;
struct semanage_port_key;
typedef struct semanage_port record_t;
typedef struct semanage_port_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_policydb;
typedef struct dbase_policydb dbase_t;
#define DBASE_DEFINED

#include <sepol/ports.h>
#include <semanage/handle.h>
#include "port_internal.h"
#include "debug.h"
#include "database_policydb.h"

/* PORT RECORD (SEPOL): POLICYDB extension : method table */
record_policydb_table_t SEMANAGE_PORT_POLICYDB_RTABLE = {
	.add         = NULL, 
	.modify      = sepol_port_modify,
	.set         = NULL, 
	.query       = sepol_port_query,
        .count       = sepol_port_count,
	.exists      = sepol_port_exists,
	.iterate     = sepol_port_iterate,
};

int port_policydb_dbase_init(
	semanage_handle_t* handle, 
	dbase_config_t* dconfig) {

	if (dbase_policydb_init(
		handle, 
		"policy.kern",
		&SEMANAGE_PORT_RTABLE,
		&SEMANAGE_PORT_POLICYDB_RTABLE, 
		&dconfig->dbase) < 0) 
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_POLICYDB_DTABLE;

	return STATUS_SUCCESS;
}

void port_policydb_dbase_release(
	dbase_config_t* dconfig) {

	dbase_policydb_release(dconfig->dbase);
}
