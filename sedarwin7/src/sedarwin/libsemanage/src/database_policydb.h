/* Copyright (C) 2005 Red Hat, Inc. */

#ifndef _SEMANAGE_DATABASE_POLICYDB_INTERNAL_H_
#define _SEMANAGE_DATABASE_POLICYDB_INTERNAL_H_

#include <sepol/handle.h>
#include <sepol/policydb.h>
#include "database.h"
#include "handle.h"

struct dbase_policydb;
typedef struct dbase_policydb dbase_policydb_t;

/* POLICYDB extension to RECORD interface - method table */
typedef struct record_policydb_table {

	/* Add policy record */
	int (*add) (
		sepol_handle_t* handle,
		sepol_policydb_t* policydb, 
		const record_key_t* rkey,
		const record_t* record);

	/* Modify policy record, or add if 
	 * the key isn't found */
	int (*modify) (
		sepol_handle_t* handle,
		sepol_policydb_t* policydb, 
		const record_key_t* rkey,
		const record_t* record);

	/* Set policy record */
	int (*set) (
		sepol_handle_t* handle,
		sepol_policydb_t* policydb,
		const record_key_t* rkey,
		const record_t* record);

	/* Query policy record  - return the record
	 * or NULL if it isn't found */
	int (*query) (
		sepol_handle_t* handle,
		const sepol_policydb_t* policydb,
		const record_key_t* rkey,
		record_t** response);

	/* Count records */
	int (*count) (
		sepol_handle_t* handle,
		const sepol_policydb_t* policydb,
		unsigned int* response);

	/* Check if a record exists */
	int (*exists) (
		sepol_handle_t* handle,
		const sepol_policydb_t* policydb,
		const record_key_t* rkey,
		int* response);
		
	/* Iterate over records */
	int (*iterate) (
		sepol_handle_t* handle,
		const sepol_policydb_t* policydb,
		int (*fn)(
			const record_t* record, 
			void* fn_arg),
		void* arg);

} record_policydb_table_t;

/* Initialize database */
extern int dbase_policydb_init(
	semanage_handle_t* handle,
	const char* suffix,
	record_table_t* rtable,
	record_policydb_table_t* rptable,
	dbase_policydb_t** dbase);

/* Attach to a shared policydb.
 * This implies drop_cache().
 * and prevents flush() and drop_cache()
 * until detached. */ 
extern void dbase_policydb_attach(
	dbase_policydb_t* dbase,
	sepol_policydb_t* policydb);

/* Detach from a shared policdb.
 * This implies drop_cache. */
extern void dbase_policydb_detach(
	dbase_policydb_t* dbase);

/* Release allocated resources */
extern void dbase_policydb_release(
	dbase_policydb_t* dbase);

/* POLICYDB database - method table implementation */
extern dbase_table_t SEMANAGE_POLICYDB_DTABLE;

#endif
