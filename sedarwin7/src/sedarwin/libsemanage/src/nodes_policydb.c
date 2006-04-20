/* Copyright (C) 2005 Red Hat, Inc. */

struct semanage_node;
struct semanage_node_key;
typedef struct semanage_node record_t;
typedef struct semanage_node_key record_key_t;
#define DBASE_RECORD_DEFINED

struct dbase_policydb;
typedef struct dbase_policydb dbase_t;
#define DBASE_DEFINED

#include <sepol/nodes.h>
#include <semanage/handle.h>
#include "node_internal.h"
#include "debug.h"
#include "database_policydb.h"

/* NODE RECORD (SEPOL): POLICYDB extension : method table */
record_policydb_table_t SEMANAGE_NODE_POLICYDB_RTABLE = {
	.add         = NULL, 
	.modify      = sepol_node_modify,
	.set         = NULL, 
	.query       = sepol_node_query,
        .count       = sepol_node_count,
	.exists      = sepol_node_exists,
	.iterate     = sepol_node_iterate,
};

int node_policydb_dbase_init(
	semanage_handle_t* handle, 
	dbase_config_t* dconfig) {

	if (dbase_policydb_init(
		handle, 
		"policy.kern",
		&SEMANAGE_NODE_RTABLE,
		&SEMANAGE_NODE_POLICYDB_RTABLE, 
		&dconfig->dbase) < 0) 
		return STATUS_ERR;

	dconfig->dtable = &SEMANAGE_POLICYDB_DTABLE;

	return STATUS_SUCCESS;
}

void node_policydb_dbase_release(
	dbase_config_t* dconfig) {

	dbase_policydb_release(dconfig->dbase);
}
