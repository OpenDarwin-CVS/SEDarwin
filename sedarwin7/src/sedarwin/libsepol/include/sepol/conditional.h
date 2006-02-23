/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *          Frank Mayer <mayerf@tresys.com>
 *
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

#ifndef _CONDITIONAL_H_
#define _CONDITIONAL_H_

#include <sepol/flask_types.h>
#include <sepol/avtab.h>
#include <sepol/symtab.h>
#include <sepol/policydb.h>

#define COND_EXPR_MAXDEPTH 10

/* this is the max unique bools in a conditional expression
 * for which we precompute all outcomes for the expression.
 *
 * NOTE - do _NOT_ use value greater than 5 because
 * cond_node_t->expr_pre_comp can only hold at most 32 values
 */
#define COND_MAX_BOOLS 5

/*
 * A conditional expression is a list of operators and operands
 * in reverse polish notation.
 */
typedef struct cond_expr {
#define COND_BOOL	1 /* plain bool */
#define COND_NOT	2 /* !bool */
#define COND_OR		3 /* bool || bool */
#define COND_AND	4 /* bool && bool */
#define COND_XOR	5 /* bool ^ bool */
#define COND_EQ		6 /* bool == bool */
#define COND_NEQ	7 /* bool != bool */
#define COND_LAST	8
	uint32_t expr_type;
	uint32_t bool;
	struct cond_expr *next;
} cond_expr_t;

/*
 * Each cond_node_t contains a list of rules to be enabled/disabled
 * depending on the current value of the conditional expression. This 
 * struct is for that list.
 */
typedef struct cond_av_list {
	avtab_ptr_t node;
	struct cond_av_list *next;
} cond_av_list_t;

/*
 * A cond node represents a conditional block in a policy. It
 * contains a conditional expression, the current state of the expression,
 * two lists of rules to enable/disable depending on the value of the
 * expression (the true list corresponds to if and the false list corresponds
 * to else)..
 */
typedef struct cond_node {
	int cur_state;
	cond_expr_t *expr;
	/* these fields are not written to binary policy */
	int nbools;
	uint32_t bool_ids[COND_MAX_BOOLS];
	uint32_t expr_pre_comp;
	/*                                               */
	cond_av_list_t *true_list;
	cond_av_list_t *false_list;
	struct cond_node *next;
} cond_node_t;

int cond_evaluate_expr(policydb_t *p, cond_expr_t *expr);

int cond_normalize_expr(policydb_t *p, cond_node_t *cn);
cond_node_t *cond_node_search(policydb_t *p,cond_node_t *cn);
int evaluate_conds(policydb_t *p);

void cond_optimize_lists(cond_list_t *cl);

int cond_policydb_init(policydb_t* p);
void cond_policydb_destroy(policydb_t* p);

int cond_init_bool_indexes(policydb_t* p);
int cond_destroy_bool(hashtab_key_t key, hashtab_datum_t datum, void *p);

int cond_index_bool(hashtab_key_t key, hashtab_datum_t datum, void *datap);

int cond_read_bool(policydb_t *p, hashtab_t h, struct policy_file *fp);
int cond_read_list(policydb_t *p, void *fp);

void cond_compute_av(avtab_t *ctab, avtab_key_t *key, struct av_decision *avd);

#endif /* _CONDITIONAL_H_ */
