
/*
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil> 
 */

/* Updated: David Caplan, <dac@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *  	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 */

/* FLASK */

%{
#include <sys/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sepol/policydb.h>
#include <sepol/services.h>
#include <sepol/conditional.h>
#include <sepol/flask.h>
#include "queue.h"
#include "checkpolicy.h"

/* 
 * We need the following so we have a valid error return code in yacc
 * when we have a parse error for a conditional rule.  We can't check 
 * for NULL (ie 0) because that is a potentially valid return.
 */
static cond_av_list_t *conditional_unused_error_code;
#define COND_ERR (cond_av_list_t *)&conditional_unused_error_code

#define TRUE 1
#define FALSE 0

policydb_t *policydbp;
queue_t id_queue = 0;
unsigned int pass;
char *curfile = 0;
unsigned int curline; 

extern unsigned long policydb_lineno;

extern char yytext[];
extern int yywarn(char *msg);
extern int yyerror(char *msg);

static char errormsg[255];

static int insert_separator(int push);
static int insert_id(char *id,int push);
static int define_class(void);
static int define_initial_sid(void);
static int define_common_perms(void);
static int define_av_perms(int inherits);
static int define_sens(void);
static int define_dominance(void);
static int define_category(void);
static int define_level(void);
static int define_common_base(void);
static int define_av_base(void);
static int define_attrib(void);
static int define_typealias(void);
static int define_type(int alias);
static int define_compute_type(int which);
static int define_te_avtab(int which);
static int define_role_types(void);
static role_datum_t *merge_roles_dom(role_datum_t *r1,role_datum_t *r2);
static role_datum_t *define_role_dom(role_datum_t *r);
static int define_role_trans(void);
static int define_role_allow(void);
static int define_constraint(constraint_expr_t *expr);
static int define_bool();
static int define_conditional(cond_expr_t *expr,cond_av_list_t *t_list, cond_av_list_t *f_list );
static cond_expr_t *define_cond_expr(uint32_t expr_type, void *arg1, void* arg2);
static cond_av_list_t *define_cond_pol_list(cond_av_list_t *avlist, cond_av_list_t *stmt);
static cond_av_list_t *define_cond_compute_type(int which);
static cond_av_list_t *define_cond_te_avtab(int which);
static cond_av_list_t *cond_list_append(cond_av_list_t *sl, avtab_key_t *key, avtab_datum_t *datum);
static void cond_reduce_insert_list(cond_av_list_t *new, cond_av_list_t **active, cond_av_list_t **inactive, int state ); 
static uintptr_t define_cexpr(uint32_t expr_type, uintptr_t arg1, uintptr_t arg2);
static int define_user(void);
static int parse_security_context(context_struct_t *c);
static int define_initial_sid_context(void);
static int define_fs_use(int behavior);
static int define_genfs_context(int has_type);
static int define_fs_context(unsigned int major, unsigned int minor);
static int define_port_context(unsigned int low, unsigned int high);
static int define_netif_context(void);
static int define_ipv4_node_context(unsigned int addr, unsigned int mask);
static int define_ipv6_node_context(void);
%}

%union {
	unsigned int val;
	uintptr_t valptr;
	void *ptr;
}

%type <ptr> cond_expr cond_expr_prim cond_pol_list
%type <ptr> cond_allow_def cond_auditallow_def cond_auditdeny_def cond_dontaudit_def
%type <ptr> cond_transition_def cond_te_avtab_def cond_rule_def
%type <ptr> role_def roles
%type <valptr> cexpr cexpr_prim op roleop
%type <val> ipv4_addr_def number

%token PATH
%token CLONE
%token COMMON
%token CLASS
%token CONSTRAIN
%token INHERITS
%token SID
%token ROLE
%token ROLES
%token TYPEALIAS
%token TYPE
%token TYPES
%token ALIAS
%token ATTRIBUTE
%token BOOL
%token IF
%token ELSE
%token TYPE_TRANSITION
%token TYPE_MEMBER
%token TYPE_CHANGE
%token ROLE_TRANSITION
%token SENSITIVITY
%token DOMINANCE
%token DOM DOMBY INCOMP
%token CATEGORY
%token LEVEL
%token RANGES
%token USER
%token NEVERALLOW
%token ALLOW
%token AUDITALLOW
%token AUDITDENY
%token DONTAUDIT
%token SOURCE
%token TARGET
%token SAMEUSER
%token FSCON PORTCON NETIFCON NODECON 
%token FSUSEXATTR FSUSETASK FSUSETRANS
%token GENFSCON
%token U1 U2 R1 R2 T1 T2
%token NOT AND OR XOR
%token CTRUE CFALSE
%token IDENTIFIER
%token USER_IDENTIFIER
%token NUMBER
%token EQUALS
%token NOTEQUAL
%token IPV6_ADDR

%left OR
%left XOR
%left AND
%right NOT
%left EQUALS NOTEQUAL
%%
policy			: classes initial_sids access_vectors
                          { if (pass == 1) { if (policydb_index_classes(policydbp)) return -1; } }
			  opt_mls te_rbac users opt_constraints 
                         { if (pass == 1) { if (policydb_index_bools(policydbp)) return -1;}
			   if (pass == 2) { if (policydb_index_others(policydbp, 1)) return -1;} } 
			  initial_sid_contexts opt_fs_contexts fs_uses opt_genfs_contexts net_contexts 
			;
classes			: class_def 
			| classes class_def
			;
class_def		: CLASS identifier
			{if (define_class()) return -1;}
			;
initial_sids 		: initial_sid_def 
			| initial_sids initial_sid_def
			;
initial_sid_def		: SID identifier
                        {if (define_initial_sid()) return -1;}
			;
access_vectors		: opt_common_perms av_perms
			;
opt_common_perms        : common_perms
                        |
                        ;
common_perms		: common_perms_def
			| common_perms common_perms_def
			;
common_perms_def	: COMMON identifier '{' identifier_list '}'
			{if (define_common_perms()) return -1;}
			;
av_perms		: av_perms_def
			| av_perms av_perms_def
			;
av_perms_def		: CLASS identifier '{' identifier_list '}'
			{if (define_av_perms(FALSE)) return -1;}
                        | CLASS identifier INHERITS identifier 
			{if (define_av_perms(TRUE)) return -1;}
                        | CLASS identifier INHERITS identifier '{' identifier_list '}'
			{if (define_av_perms(TRUE)) return -1;}
			;
opt_mls			: mls
                        | 
			;
mls			: sensitivities dominance opt_categories levels base_perms
			;
sensitivities	 	: sensitivity_def 
			| sensitivities sensitivity_def
			;
sensitivity_def		: SENSITIVITY identifier alias_def ';'
			{if (define_sens()) return -1;}
			| SENSITIVITY identifier ';'
			{if (define_sens()) return -1;}
	                ;
alias_def		: ALIAS names
			;
dominance		: DOMINANCE identifier 
			{if (define_dominance()) return -1;}
                        | DOMINANCE '{' identifier_list '}' 
			{if (define_dominance()) return -1;}
			;
opt_categories          : categories
                        |
                        ;
categories 		: category_def 
			| categories category_def
			;
category_def		: CATEGORY identifier alias_def ';'
			{if (define_category()) return -1;}
			| CATEGORY identifier ';'
			{if (define_category()) return -1;}
			;
levels	 		: level_def 
			| levels level_def
			;
level_def		: LEVEL identifier ':' id_comma_list ';'
			{if (define_level()) return -1;}
			| LEVEL identifier ';' 
			{if (define_level()) return -1;}
						;
base_perms		: opt_common_base av_base
			;
opt_common_base         : common_base
                        |
                        ;
common_base		: common_base_def
			| common_base common_base_def
			;
common_base_def	        : COMMON identifier '{' perm_base_list '}'
	                {if (define_common_base()) return -1;}
			;
av_base		        : av_base_def
			| av_base av_base_def
			;
av_base_def		: CLASS identifier '{' perm_base_list '}'
	                {if (define_av_base()) return -1;}
                        | CLASS identifier
	                {if (define_av_base()) return -1;}
			;
perm_base_list		: perm_base
			| perm_base_list perm_base
			;
perm_base		: identifier ':' identifier
			{if (insert_separator(0)) return -1;}
                        | identifier ':' '{' identifier_list '}'
			{if (insert_separator(0)) return -1;}
			;
te_rbac			: te_rbac_decl
			| te_rbac te_rbac_decl
			;
te_rbac_decl		: te_decl
			| rbac_decl
			| ';'
                        ;
rbac_decl		: role_type_def
                        | role_dominance
                        | role_trans_def
 			| role_allow_def
			;
te_decl			: attribute_def
                        | type_def
                        | typealias_def
                        | bool_def
                        | transition_def
                        | te_avtab_def
                        | cond_stmt_def
			;
attribute_def           : ATTRIBUTE identifier ';'
                        { if (define_attrib()) return -1;}
                        ;
type_def		: TYPE identifier alias_def opt_attr_list ';'
                        {if (define_type(1)) return -1;}
	                | TYPE identifier opt_attr_list ';'
                        {if (define_type(0)) return -1;}
    			;
typealias_def           : TYPEALIAS identifier alias_def ';'
			{if (define_typealias()) return -1;}
			;
opt_attr_list           : ',' id_comma_list
			| 
			;
bool_def                : BOOL identifier bool_val ';'
                        {if (define_bool()) return -1;}
                        ;
bool_val                : CTRUE
 			{ if (insert_id("T",0)) return -1; }
                        | CFALSE
			{ if (insert_id("F",0)) return -1; }
                        ;
cond_stmt_def           : IF cond_expr '{' cond_pol_list '}'
                        { if (pass == 2) { if (define_conditional((cond_expr_t*)$2, (cond_av_list_t*)$4,(cond_av_list_t*) 0) < 0) return -1;  }}
                        | IF cond_expr '{' cond_pol_list '}' ELSE '{' cond_pol_list '}'
                        { if (pass == 2) { if (define_conditional((cond_expr_t*)$2,(cond_av_list_t*)$4,(cond_av_list_t*)$8) < 0 ) return -1;  }}       
                        | IF cond_expr '{' cond_pol_list '}' ELSE '{' '}'
                        { if (pass == 2) { if (define_conditional((cond_expr_t*)$2,(cond_av_list_t*)$4,(cond_av_list_t*) 0) < 0 ) return -1;  }}       
                        | IF cond_expr '{' '}' ELSE '{' cond_pol_list '}'
                        { if (pass == 2) { if (define_conditional((cond_expr_t*)$2,(cond_av_list_t*) 0,(cond_av_list_t*) $7) < 0 ) return -1;  }}       
                        | IF cond_expr '{' '}' ELSE '{' '}'
                        /* do nothing */
                        | IF cond_expr '{' '}' 
                        /* do nothing */
                        ;
cond_expr               : '(' cond_expr ')'
			{ $$ = $2;}
			| NOT cond_expr
			{ $$ = define_cond_expr(COND_NOT, $2, 0);
			  if ($$ == 0) return -1; }
			| cond_expr AND cond_expr
			{ $$ = define_cond_expr(COND_AND, $1, $3);
			  if ($$ == 0) return  -1; }
			| cond_expr OR cond_expr
			{ $$ = define_cond_expr(COND_OR, $1, $3);
			  if ($$ == 0) return   -1; }
			| cond_expr XOR cond_expr
			{ $$ = define_cond_expr(COND_XOR, $1, $3);
			  if ($$ == 0) return  -1; }
			| cond_expr EQUALS cond_expr
			{ $$ = define_cond_expr(COND_EQ, $1, $3);
			  if ($$ == 0) return  -1; }
			| cond_expr NOTEQUAL cond_expr
			{ $$ = define_cond_expr(COND_NEQ, $1, $3);
			  if ($$ == 0) return  -1; }
			| cond_expr_prim
			{ $$ = $1; }
			;
cond_expr_prim          : identifier
                        { $$ = define_cond_expr(COND_BOOL,0, 0);
			  if ($$ == COND_ERR) return   -1; }
                        ;
cond_pol_list           : cond_rule_def
                        { $$ = define_cond_pol_list((cond_av_list_t *) 0, (cond_av_list_t *)$1);}
                        | cond_pol_list cond_rule_def 
                        { $$ = define_cond_pol_list((cond_av_list_t *)$1, (cond_av_list_t *)$2); }
			;
cond_rule_def           : cond_transition_def
                        { $$ = $1; }
                        | cond_te_avtab_def
                        { $$ = $1; }
                        ;
cond_transition_def	: TYPE_TRANSITION names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(AVTAB_TRANSITION) ;
                          if ($$ == COND_ERR) return -1;}
                        | TYPE_MEMBER names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(AVTAB_MEMBER) ;
                          if ($$ ==  COND_ERR) return -1;}
                        | TYPE_CHANGE names names ':' names identifier ';'
                        { $$ = define_cond_compute_type(AVTAB_CHANGE) ;
                          if ($$ == COND_ERR) return -1;}
    			;
cond_te_avtab_def	: cond_allow_def
                          { $$ = $1; }
			| cond_auditallow_def
			  { $$ = $1; }
			| cond_auditdeny_def
			  { $$ = $1; }
			| cond_dontaudit_def
			  { $$ = $1; }
			;
cond_allow_def		: ALLOW names names ':' names names  ';'
			{ $$ = define_cond_te_avtab(AVTAB_ALLOWED) ;
                          if ($$ == COND_ERR) return -1; }
		        ;
cond_auditallow_def	: AUDITALLOW names names ':' names names ';'
			{ $$ = define_cond_te_avtab(AVTAB_AUDITALLOW) ;
                          if ($$ == COND_ERR) return -1; }
		        ;
cond_auditdeny_def	: AUDITDENY names names ':' names names ';'
			{ $$ = define_cond_te_avtab(AVTAB_AUDITDENY) ;
                          if ($$ == COND_ERR) return -1; }
		        ;
cond_dontaudit_def	: DONTAUDIT names names ':' names names ';'
			{ $$ = define_cond_te_avtab(-AVTAB_AUDITDENY);
                          if ($$ == COND_ERR) return -1; }
		        ;
transition_def		: TYPE_TRANSITION names names ':' names identifier ';'
                        {if (define_compute_type(AVTAB_TRANSITION)) return -1;}
                        | TYPE_MEMBER names names ':' names identifier ';'
                        {if (define_compute_type(AVTAB_MEMBER)) return -1;}
                        | TYPE_CHANGE names names ':' names identifier ';'
                        {if (define_compute_type(AVTAB_CHANGE)) return -1;}
    			;
te_avtab_def		: allow_def
			| auditallow_def
			| auditdeny_def
			| dontaudit_def
			| neverallow_def
			;
allow_def		: ALLOW names names ':' names names  ';'
			{if (define_te_avtab(AVTAB_ALLOWED)) return -1; }
		        ;
auditallow_def		: AUDITALLOW names names ':' names names ';'
			{if (define_te_avtab(AVTAB_AUDITALLOW)) return -1; }
		        ;
auditdeny_def		: AUDITDENY names names ':' names names ';'
			{if (define_te_avtab(AVTAB_AUDITDENY)) return -1; }
		        ;
dontaudit_def		: DONTAUDIT names names ':' names names ';'
			{if (define_te_avtab(-AVTAB_AUDITDENY)) return -1; }
		        ;
neverallow_def		: NEVERALLOW names names ':' names names  ';'
			{if (define_te_avtab(-AVTAB_ALLOWED)) return -1; }
		        ;
role_type_def		: ROLE identifier TYPES names ';'
			{if (define_role_types()) return -1;}
                        ;
role_dominance		: DOMINANCE '{' roles '}'
			;
role_trans_def		: ROLE_TRANSITION names names identifier ';'
			{if (define_role_trans()) return -1; }
			;
role_allow_def		: ALLOW names names ';'
			{if (define_role_allow()) return -1; }
			;
roles			: role_def
			{ $$ = $1; }
			| roles role_def
			{ $$ = merge_roles_dom((role_datum_t*)$1, (role_datum_t*)$2); if ($$ == 0) return -1;}
			;
role_def		: ROLE identifier_push ';'
                        {$$ = define_role_dom(NULL); if ($$ == 0) return -1;}
			| ROLE identifier_push '{' roles '}'
                        {$$ = define_role_dom((role_datum_t*)$4); if ($$ == 0) return -1;}
			;
opt_constraints         : constraints
                        |
                        ;
constraints		: constraint_def
			| constraints constraint_def
			;
constraint_def		: CONSTRAIN names names cexpr ';'
			{ if (define_constraint((constraint_expr_t*)$4)) return -1; }
			;
cexpr			: '(' cexpr ')'
			{ $$ = $2; }
			| NOT cexpr
			{ $$ = define_cexpr(CEXPR_NOT, $2, 0);
			  if ($$ == 0) return -1; }
			| cexpr AND cexpr
			{ $$ = define_cexpr(CEXPR_AND, $1, $3);
			  if ($$ == 0) return -1; }
			| cexpr OR cexpr
			{ $$ = define_cexpr(CEXPR_OR, $1, $3);
			  if ($$ == 0) return -1; }
			| cexpr_prim
			{ $$ = $1; }
			;
cexpr_prim		: U1 op U2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_USER, $2);
			  if ($$ == 0) return -1; }
			| R1 roleop R2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| T1 op T2
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_TYPE, $2);
			  if ($$ == 0) return -1; }
			| U1 op { if (insert_separator(1)) return -1; } user_names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_USER, $2);
			  if ($$ == 0) return -1; }
			| U2 op { if (insert_separator(1)) return -1; } user_names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_USER | CEXPR_TARGET), $2);
			  if ($$ == 0) return -1; }
			| R1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| R2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), $2);
			  if ($$ == 0) return -1; }
			| T1 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, $2);
			  if ($$ == 0) return -1; }
			| T2 op { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), $2);
			  if ($$ == 0) return -1; }
			| SAMEUSER
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_USER, CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| SOURCE ROLE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_ROLE, CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| TARGET ROLE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_ROLE | CEXPR_TARGET), CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| ROLE roleop
			{ $$ = define_cexpr(CEXPR_ATTR, CEXPR_ROLE, $2);
			  if ($$ == 0) return -1; }
			| SOURCE TYPE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, CEXPR_TYPE, CEXPR_EQ);
			  if ($$ == 0) return -1; }
			| TARGET TYPE { if (insert_separator(1)) return -1; } names_push
			{ $$ = define_cexpr(CEXPR_NAMES, (CEXPR_TYPE | CEXPR_TARGET), CEXPR_EQ);
			  if ($$ == 0) return -1; }
			;
op			: EQUALS
			{ $$ = CEXPR_EQ; }
			| NOTEQUAL
			{ $$ = CEXPR_NEQ; }
			;
roleop			: op 
			{ $$ = $1; }
			| DOM
			{ $$ = CEXPR_DOM; }
			| DOMBY
			{ $$ = CEXPR_DOMBY; }
			| INCOMP
			{ $$ = CEXPR_INCOMP; }
			;
users			: user_def
			| users user_def
			;
user_id			: identifier
			| user_identifier
			;
user_def		: USER user_id ROLES names opt_user_ranges ';'
	                {if (define_user()) return -1;}
			;
opt_user_ranges		: RANGES user_ranges 
			|
			;
user_ranges		: mls_range_def
			| '{' user_range_def_list '}' 
			;
user_range_def_list	: mls_range_def
			| user_range_def_list mls_range_def
			;
initial_sid_contexts	: initial_sid_context_def
			| initial_sid_contexts initial_sid_context_def
			;
initial_sid_context_def	: SID identifier security_context_def
			{if (define_initial_sid_context()) return -1;}
			;
opt_fs_contexts         : fs_contexts 
                        |
                        ;
fs_contexts		: fs_context_def
			| fs_contexts fs_context_def
			;
fs_context_def		: FSCON number number security_context_def security_context_def
			{if (define_fs_context($2,$3)) return -1;}
			;
net_contexts		: opt_port_contexts opt_netif_contexts opt_node_contexts 
			;
opt_port_contexts       : port_contexts
                        |
                        ;
port_contexts		: port_context_def
			| port_contexts port_context_def
			;
port_context_def	: PORTCON identifier number security_context_def
			{if (define_port_context($3,$3)) return -1;}
			| PORTCON identifier number '-' number security_context_def
			{if (define_port_context($3,$5)) return -1;}
			;
opt_netif_contexts      : netif_contexts 
                        |
                        ;
netif_contexts		: netif_context_def
			| netif_contexts netif_context_def
			;
netif_context_def	: NETIFCON identifier security_context_def security_context_def
			{if (define_netif_context()) return -1;} 
			;
opt_node_contexts       : node_contexts 
                        |
                        ;
node_contexts		: node_context_def
			| node_contexts node_context_def
			;
node_context_def	: NODECON ipv4_addr_def ipv4_addr_def security_context_def
			{if (define_ipv4_node_context($2,$3)) return -1;}
			| NODECON ipv6_addr ipv6_addr security_context_def
			{if (define_ipv6_node_context()) return -1;}
			;
fs_uses                 : fs_use_def
                        | fs_uses fs_use_def
                        ;
fs_use_def              : FSUSEXATTR identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_XATTR)) return -1;}
                        | FSUSETASK identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_TASK)) return -1;}
                        | FSUSETRANS identifier security_context_def ';'
                        {if (define_fs_use(SECURITY_FS_USE_TRANS)) return -1;}
                        ;
opt_genfs_contexts      : genfs_contexts
                        | 
                        ;
genfs_contexts	        : genfs_context_def
			| genfs_contexts genfs_context_def
			;
genfs_context_def	: GENFSCON identifier path '-' identifier security_context_def
			{if (define_genfs_context(1)) return -1;}
			| GENFSCON identifier path '-' '-' {insert_id("-", 0);} security_context_def
			{if (define_genfs_context(1)) return -1;}
                        | GENFSCON identifier path security_context_def
			{if (define_genfs_context(0)) return -1;}
			;
ipv4_addr_def		: number '.' number '.' number '.' number
			{ 
			  unsigned int addr;
	  		  unsigned char *p = ((unsigned char *)&addr);

			  p[0] = $1 & 0xff;				
			  p[1] = $3 & 0xff;
			  p[2] = $5 & 0xff;
			  p[3] = $7 & 0xff;
			  $$ = addr;
			}
    			;
security_context_def	: user_id ':' identifier ':' identifier opt_mls_range_def
	                ;
opt_mls_range_def	: ':' mls_range_def
			|	
			;
mls_range_def		: mls_level_def '-' mls_level_def
			{if (insert_separator(0)) return -1;}
	                | mls_level_def
			{if (insert_separator(0)) return -1;}
	                ;
mls_level_def		: identifier ':' id_comma_list
			{if (insert_separator(0)) return -1;}
	                | identifier 
			{if (insert_separator(0)) return -1;}
	                ;
id_comma_list           : identifier
			| id_comma_list ',' identifier
			;
tilde			: '~'
			;
asterisk		: '*'
			;
names           	: identifier
			{ if (insert_separator(0)) return -1; }
			| nested_id_set
			{ if (insert_separator(0)) return -1; }
			| asterisk
                        { if (insert_id("*", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
			| tilde identifier
                        { if (insert_id("~", 0)) return -1;
			  if (insert_separator(0)) return -1; }
			| tilde nested_id_set
	 		{ if (insert_id("~", 0)) return -1; 
			  if (insert_separator(0)) return -1; }
                        | identifier '-' { if (insert_id("-", 0)) return -1; } identifier 
			{ if (insert_separator(0)) return -1; }
			;
tilde_push              : tilde
                        { if (insert_id("~", 1)) return -1; }
			;
asterisk_push           : asterisk
                        { if (insert_id("*", 1)) return -1; }
			;
names_push		: identifier_push
			| '{' identifier_list_push '}'
			| asterisk_push
			| tilde_push identifier_push
			| tilde_push '{' identifier_list_push '}'
			;
identifier_list_push	: identifier_push
			| identifier_list_push identifier_push
			;
identifier_push		: IDENTIFIER
			{ if (insert_id(yytext, 1)) return -1; }
			;
identifier_list		: identifier
			| identifier_list identifier
			;
nested_id_set           : '{' nested_id_list '}'
                        ;
nested_id_list          : nested_id_element | nested_id_list nested_id_element
                        ;
nested_id_element       : identifier | '-' { if (insert_id("-", 0)) return -1; } identifier | nested_id_set
                        ;
identifier		: IDENTIFIER
			{ if (insert_id(yytext,0)) return -1; }
			;
user_identifier		: USER_IDENTIFIER
			{ if (insert_id(yytext,0)) return -1; }
			;
user_identifier_push	: USER_IDENTIFIER
			{ if (insert_id(yytext, 1)) return -1; }
			;
user_identifier_list_push : user_identifier_push
			| identifier_list_push user_identifier_push
			| user_identifier_list_push identifier_push
			| user_identifier_list_push user_identifier_push
			;
user_names_push		: names_push
			| user_identifier_push
			| '{' user_identifier_list_push '}'
			| tilde_push user_identifier_push
			| tilde_push '{' user_identifier_list_push '}'
			;
path     		: PATH
			{ if (insert_id(yytext,0)) return -1; }
			;
number			: NUMBER 
			{ $$ = strtoul(yytext,NULL,0); }
			;
ipv6_addr		: IPV6_ADDR
			{ if (insert_id(yytext,0)) return -1; }
			;
%%
#define DEBUG 1

static int insert_separator(int push)
{
	int error;

	if (push)
		error = queue_push(id_queue, 0);
	else
		error = queue_insert(id_queue, 0);

	if (error) {
		yyerror("queue overflow");
		return -1;
	}
	return 0;
}

static int insert_id(char *id, int push)
{
	char *newid = 0;
	int error;

	newid = (char *) malloc(strlen(id) + 1);
	if (!newid) {
		yyerror("out of memory");
		return -1;
	}
	strcpy(newid, id);
	if (push)
		error = queue_push(id_queue, (queue_element_t) newid);
	else
		error = queue_insert(id_queue, (queue_element_t) newid);

	if (error) {
		yyerror("queue overflow");
		free(newid);
		return -1;
	}
	return 0;
}


static int define_class(void)
{
	char *id = 0;
	class_datum_t *datum = 0;
	int ret;


	if (pass == 2) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no class name for class definition?");
		return -1;
	}
	datum = (class_datum_t *) malloc(sizeof(class_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(datum, 0, sizeof(class_datum_t));
	datum->value = ++policydbp->p_classes.nprim;

	ret = hashtab_insert(policydbp->p_classes.table,
			     (hashtab_key_t) id, (hashtab_datum_t) datum);

	if (ret == HASHTAB_PRESENT) {
		--policydbp->p_classes.nprim;
		yyerror("duplicate class definition");
		goto bad;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		goto bad;
	}
	return 0;

      bad:
	if (id)
		free(id);
	if (datum)
		free(datum);
	return -1;
}

static int define_initial_sid(void)
{
	char *id = 0;
	ocontext_t *newc = 0, *c, *head;


	if (pass == 2) {
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no sid name for SID definition?");
		return -1;
	}
	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		goto bad;
	}
	memset(newc, 0, sizeof(ocontext_t));
	newc->u.name = id;
	context_init(&newc->context[0]);
	head = policydbp->ocontexts[OCON_ISID];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate initial SID %s", id);
			yyerror(errormsg);
			goto bad;
		}
	}

	if (head) {
		newc->sid[0] = head->sid[0] + 1;
	} else {
		newc->sid[0] = 1;
	}
	newc->next = head;
	policydbp->ocontexts[OCON_ISID] = newc;

	return 0;

      bad:
	if (id)
		free(id);
	if (newc)
		free(newc);
	return -1;
}

static int define_common_perms(void)
{
	char *id = 0, *perm = 0;
	common_datum_t *comdatum = 0;
	perm_datum_t *perdatum = 0;
	int ret;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no common name for common perm definition?");
		return -1;
	}
	comdatum = (common_datum_t *) malloc(sizeof(common_datum_t));
	if (!comdatum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(comdatum, 0, sizeof(common_datum_t));
	comdatum->value = ++policydbp->p_commons.nprim;
	ret = hashtab_insert(policydbp->p_commons.table,
			 (hashtab_key_t) id, (hashtab_datum_t) comdatum);

	if (ret == HASHTAB_PRESENT) {
		yyerror("duplicate common definition");
		goto bad;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		goto bad;
	}
	if (symtab_init(&comdatum->permissions, PERM_SYMTAB_SIZE)) {
		yyerror("out of memory");
		goto bad;
	}
	while ((perm = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) malloc(sizeof(perm_datum_t));
		if (!perdatum) {
			yyerror("out of memory");
			goto bad_perm;
		}
		memset(perdatum, 0, sizeof(perm_datum_t));
		perdatum->value = ++comdatum->permissions.nprim;

#ifdef CONFIG_SECURITY_SELINUX_MLS
		/*
		 * By default, we set all four base permissions on this
		 * permission. This means that if base_permissions is not
		 * explicitly defined for this permission, then this
		 * permission will only be granted in the equivalent case.
		 */
		perdatum->base_perms = MLS_BASE_READ | MLS_BASE_WRITE |
		    MLS_BASE_READBY | MLS_BASE_WRITEBY;
#endif

		if (perdatum->value >= (sizeof(access_vector_t) * 8)) {
			yyerror("too many permissions to fit in an access vector");
			goto bad_perm;
		}
		ret = hashtab_insert(comdatum->permissions.table,
				     (hashtab_key_t) perm,
				     (hashtab_datum_t) perdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "duplicate permission %s in common %s",
				perm, id);
			yyerror(errormsg);
			goto bad_perm;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad_perm;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (comdatum)
		free(comdatum);
	return -1;

      bad_perm:
	if (perm)
		free(perm);
	if (perdatum)
		free(perdatum);
	return -1;
}


static int define_av_perms(int inherits)
{
	char *id;
	class_datum_t *cladatum;
	common_datum_t *comdatum;
	perm_datum_t *perdatum = 0, *perdatum2 = 0;
	int ret;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no tclass name for av perm definition?");
		return -1;
	}
	cladatum = (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						    (hashtab_key_t) id);
	if (!cladatum) {
		sprintf(errormsg, "class %s is not defined", id);
		yyerror(errormsg);
		goto bad;
	}
	free(id);

	if (cladatum->comdatum || cladatum->permissions.nprim) {
		yyerror("duplicate access vector definition");
		return -1;
	}
	if (symtab_init(&cladatum->permissions, PERM_SYMTAB_SIZE)) {
		yyerror("out of memory");
		return -1;
	}
	if (inherits) {
		id = (char *) queue_remove(id_queue);
		if (!id) {
			yyerror("no inherits name for access vector definition?");
			return -1;
		}
		comdatum = (common_datum_t *) hashtab_search(policydbp->p_commons.table,
						     (hashtab_key_t) id);

		if (!comdatum) {
			sprintf(errormsg, "common %s is not defined", id);
			yyerror(errormsg);
			goto bad;
		}
		cladatum->comkey = id;
		cladatum->comdatum = comdatum;

		/*
		 * Class-specific permissions start with values 
		 * after the last common permission.
		 */
		cladatum->permissions.nprim += comdatum->permissions.nprim;
	}
	while ((id = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) malloc(sizeof(perm_datum_t));
		if (!perdatum) {
			yyerror("out of memory");
			goto bad;
		}
		memset(perdatum, 0, sizeof(perm_datum_t));
		perdatum->value = ++cladatum->permissions.nprim;

#ifdef CONFIG_SECURITY_SELINUX_MLS
		/*
		 * By default, we set all four base permissions on this
		 * permission. This means that if base_permissions is not
		 * explicitly defined for this permission, then this
		 * permission will only be granted in the equivalent case.
		 */
		perdatum->base_perms = MLS_BASE_READ | MLS_BASE_WRITE |
		    MLS_BASE_READBY | MLS_BASE_WRITEBY;
		/* actual value set in define_av_base */
#endif

		if (perdatum->value >= (sizeof(access_vector_t) * 8)) {
			yyerror("too many permissions to fit in an access vector");
			goto bad;
		}
		if (inherits) {
			/*
			 * Class-specific permissions and 
			 * common permissions exist in the same
			 * name space.
			 */
			perdatum2 = (perm_datum_t *) hashtab_search(cladatum->comdatum->permissions.table,
						     (hashtab_key_t) id);
			if (perdatum2) {
				sprintf(errormsg, "permission %s conflicts with an inherited permission", id);
				yyerror(errormsg);
				goto bad;
			}
		}
		ret = hashtab_insert(cladatum->permissions.table,
				     (hashtab_key_t) id,
				     (hashtab_datum_t) perdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "duplicate permission %s", id);
			yyerror(errormsg);
			goto bad;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (perdatum)
		free(perdatum);
	return -1;
}


static int define_sens(void)
{
#ifdef CONFIG_SECURITY_SELINUX_MLS
	char *id;
	mls_level_t *level = 0;
	level_datum_t *datum = 0, *aliasdatum = 0;
	int ret;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no sensitivity name for sensitivity definition?");
		return -1;
	}
	level = (mls_level_t *) malloc(sizeof(mls_level_t));
	if (!level) {
		yyerror("out of memory");
		goto bad;
	}
	memset(level, 0, sizeof(mls_level_t));
	level->sens = 0;	/* actual value set in define_dominance */
	++policydbp->p_levels.nprim;
	ebitmap_init(&level->cat);	/* actual value set in define_level */

	datum = (level_datum_t *) malloc(sizeof(level_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(datum, 0, sizeof(level_datum_t));
	datum->isalias = FALSE;
	datum->level = level;

	ret = hashtab_insert(policydbp->p_levels.table,
			     (hashtab_key_t) id, (hashtab_datum_t) datum);

	if (ret == HASHTAB_PRESENT) {
		--policydbp->p_levels.nprim;
		sprintf(errormsg, "duplicate definition for sensitivity %s", id);
		yyerror(errormsg);
		goto bad;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		goto bad;
	}

	while ((id = queue_remove(id_queue))) {
		aliasdatum = (level_datum_t *) malloc(sizeof(level_datum_t));
		if (!aliasdatum) {
			yyerror("out of memory");
			goto bad_alias;
		}
		memset(aliasdatum, 0, sizeof(level_datum_t));
		aliasdatum->isalias = TRUE;
		aliasdatum->level = level;

		ret = hashtab_insert(policydbp->p_levels.table,
		       (hashtab_key_t) id, (hashtab_datum_t) aliasdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "duplicate definition for level %s", id);
			yyerror(errormsg);
			goto bad_alias;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad_alias;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (level)
		free(level);
	if (datum)
		free(datum);
	return -1;

      bad_alias:
	if (id)
		free(id);
	if (aliasdatum)
		free(aliasdatum);
	return -1;
#else
	yyerror("sensitivity definition in non-MLS configuration");
	return -1;
#endif
}

static int define_dominance(void)
{
#ifdef CONFIG_SECURITY_SELINUX_MLS
	level_datum_t *datum;
	int order;
	char *id;

	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	order = 0;
	while ((id = (char *) queue_remove(id_queue))) {
		datum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						     (hashtab_key_t) id);
		if (!datum) {
			sprintf(errormsg, "unknown sensitivity %s used in dominance definition", id);
			yyerror(errormsg);
			free(id);
			continue;
		}
		if (datum->level->sens != 0) {
			sprintf(errormsg, "sensitivity %s occurs multiply in dominance definition", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		datum->level->sens = ++order;

		/* no need to keep sensitivity name */
		free(id);
	}

	if (order != policydbp->p_levels.nprim) {
		yyerror("all sensitivities must be specified in dominance definition");
		return -1;
	}
	return 0;
#else
	yyerror("dominance definition in non-MLS configuration");
	return -1;
#endif
}

static int define_category(void)
{
#ifdef CONFIG_SECURITY_SELINUX_MLS
	char *id;
	cat_datum_t *datum = 0, *aliasdatum = 0;
	int ret;

	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no category name for category definition?");
		return -1;
	}
	datum = (cat_datum_t *) malloc(sizeof(cat_datum_t));
	if (!datum) {
		yyerror("out of memory");
		goto bad;
	}
	memset(datum, 0, sizeof(cat_datum_t));
	datum->isalias = FALSE;
	datum->value = ++policydbp->p_cats.nprim;

	ret = hashtab_insert(policydbp->p_cats.table,
			     (hashtab_key_t) id, (hashtab_datum_t) datum);

	if (ret == HASHTAB_PRESENT) {
		--policydbp->p_cats.nprim;
		sprintf(errormsg, "duplicate definition for category %s", id);
		yyerror(errormsg);
		goto bad;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		goto bad;
	}

	while ((id = queue_remove(id_queue))) {
		aliasdatum = (cat_datum_t *) malloc(sizeof(cat_datum_t));
		if (!aliasdatum) {
			yyerror("out of memory");
			goto bad_alias;
		}
		memset(aliasdatum, 0, sizeof(cat_datum_t));
		aliasdatum->isalias = TRUE;
		aliasdatum->value = datum->value;

		ret = hashtab_insert(policydbp->p_cats.table,
		       (hashtab_key_t) id, (hashtab_datum_t) aliasdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "duplicate definition for category %s", id);
			yyerror(errormsg);
			goto bad_alias;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			goto bad_alias;
		}
	}

	return 0;

      bad:
	if (id)
		free(id);
	if (datum)
		free(datum);
	return -1;

      bad_alias:
	if (id)
		free(id);
	if (aliasdatum)
		free(aliasdatum);
	return -1;
#else
	yyerror("category definition in non-MLS configuration");
	return -1;
#endif
}


static int define_level(void)
{
#ifdef CONFIG_SECURITY_SELINUX_MLS
	int n;
	char *id, *levid;
	level_datum_t *levdatum;
	cat_datum_t *catdatum;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no level name for level definition?");
		return -1;
	}
	levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						    (hashtab_key_t) id);
	if (!levdatum) {
		sprintf(errormsg, "unknown sensitivity %s used in level definition", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	if (ebitmap_length(&levdatum->level->cat)) {
		sprintf(errormsg, "sensitivity %s used in multiple level definitions", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	levid = id;
	n = 1;
	while ((id = queue_remove(id_queue))) {
		catdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
						     (hashtab_key_t) id);
		if (!catdatum) {
			sprintf(errormsg, "unknown category %s used in level definition", id);
			yyerror(errormsg);
			free(id);
			continue;
		}
		if (ebitmap_set_bit(&levdatum->level->cat, catdatum->value - 1, TRUE)) {
			yyerror("out of memory");
			free(id);
			free(levid);
			return -1;
		}
		/* no need to keep category name */
		free(id);

		n = n * 2;
	}

	free(levid);

	policydbp->nlevels += n;

	return 0;
#else
	yyerror("level definition in non-MLS configuration");
	return -1;
#endif
}


static int define_common_base(void)
{
#ifdef CONFIG_SECURITY_SELINUX_MLS
	char *id, *perm, *base;
	common_datum_t *comdatum;
	perm_datum_t *perdatum;


	if (pass == 2) {
		id = queue_remove(id_queue); free(id);
		while ((id = queue_remove(id_queue))) {
			free(id);
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
		}
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no common name for common base definition?");
		return -1;
	}
	comdatum = (common_datum_t *) hashtab_search(policydbp->p_commons.table,
						     (hashtab_key_t) id);
	if (!comdatum) {
		sprintf(errormsg, "common %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	while ((perm = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) hashtab_search(comdatum->permissions.table,
						   (hashtab_key_t) perm);
		if (!perdatum) {
			sprintf(errormsg, "permission %s is not defined for common %s", perm, id);
			yyerror(errormsg);
			free(id);
			free(perm);
			return -1;
		}

		/*
		 * An explicit definition of base_permissions for this
		 * permission.  Reset the value to zero.
		 */
		perdatum->base_perms = 0;

		while ((base = queue_remove(id_queue))) {
			if (!strcmp(base, "read"))
				perdatum->base_perms |= MLS_BASE_READ;
			else if (!strcmp(base, "write"))
				perdatum->base_perms |= MLS_BASE_WRITE;
			else if (!strcmp(base, "readby"))
				perdatum->base_perms |= MLS_BASE_READBY;
			else if (!strcmp(base, "writeby"))
				perdatum->base_perms |= MLS_BASE_WRITEBY;
			else if (strcmp(base, "none")) {
				sprintf(errormsg, "base permission %s is not defined", base);
				yyerror(errormsg);
				free(base);
				return -1;
			}
			free(base);
		}

		free(perm);
	}

	free(id);

	return 0;
#else
	yyerror("MLS base permission definition in non-MLS configuration");
	return -1;
#endif
}


#ifdef CONFIG_SECURITY_SELINUX_MLS
static int common_base_set(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	perm_datum_t *perdatum;
	class_datum_t *cladatum;

	perdatum = (perm_datum_t *) datum;
	cladatum = (class_datum_t *) p;

	if (perdatum->base_perms & MLS_BASE_READ)
		cladatum->mlsperms.read |= (1 << (perdatum->value - 1));

	if (perdatum->base_perms & MLS_BASE_WRITE)
		cladatum->mlsperms.write |= (1 << (perdatum->value - 1));

	if (perdatum->base_perms & MLS_BASE_READBY)
		cladatum->mlsperms.readby |= (1 << (perdatum->value - 1));

	if (perdatum->base_perms & MLS_BASE_WRITEBY)
		cladatum->mlsperms.writeby |= (1 << (perdatum->value - 1));

	return 0;
}
#endif

static int define_av_base(void)
{
#ifdef CONFIG_SECURITY_SELINUX_MLS
	char *id, *base;
	class_datum_t *cladatum;
	perm_datum_t *perdatum;

	if (pass == 2) {
		id = queue_remove(id_queue); free(id);
		while ((id = queue_remove(id_queue))) {
			free(id);
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
		}
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no tclass name for av base definition?");
		return -1;
	}
	cladatum = (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						    (hashtab_key_t) id);
	if (!cladatum) {
		sprintf(errormsg, "class %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	free(id);

	/*
	 * Determine which common permissions should be included in each MLS
	 * vector for this access vector definition.
	 */
	if (cladatum->comdatum)
		hashtab_map(cladatum->comdatum->permissions.table, common_base_set, cladatum);

	while ((id = queue_remove(id_queue))) {
		perdatum = (perm_datum_t *) hashtab_search(cladatum->permissions.table,
						     (hashtab_key_t) id);
		if (!perdatum) {
			sprintf(errormsg, "permission %s is not defined", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		/*
		 * An explicit definition of base_permissions for this
		 * permission.  Reset the value to zero.
		 */
		perdatum->base_perms = 0;

		while ((base = queue_remove(id_queue))) {
			if (!strcmp(base, "read")) {
				perdatum->base_perms |= MLS_BASE_READ;
			} else if (!strcmp(base, "write")) {
				perdatum->base_perms |= MLS_BASE_WRITE;
			} else if (!strcmp(base, "readby")) {
				perdatum->base_perms |= MLS_BASE_READBY;
			} else if (!strcmp(base, "writeby")) {
				perdatum->base_perms |= MLS_BASE_WRITEBY;
			} else if (strcmp(base, "none")) {
				sprintf(errormsg, "base permission %s is not defined", base);
				yyerror(errormsg);
				free(base);
				continue;
			}
			free(base);
		}

		free(id);
	}

	/* Set MLS base permission masks */
	hashtab_map(cladatum->permissions.table, common_base_set, cladatum);

	return 0;
#else
	yyerror("MLS base permission definition in non-MLS configuration");
	return -1;
#endif
}

static int define_attrib(void)
{
	char *id;
	type_datum_t *attr;
	int ret;


	if (pass == 2) {
		free(queue_remove(id_queue));
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		return -1;
	}

	attr = hashtab_search(policydbp->p_types.table, id);
	if (attr) {
		sprintf(errormsg, "duplicate declaration for attribute %s\n",
			id);
		yyerror(errormsg);
		return -1;
	}

	attr = (type_datum_t *) malloc(sizeof(type_datum_t));
	if (!attr) {
		yyerror("out of memory");
		return -1;
	}
	memset(attr, 0, sizeof(type_datum_t));
	attr->isattr = TRUE;
	ret = hashtab_insert(policydbp->p_types.table,
			     id, (hashtab_datum_t) attr);
	if (ret) {
		yyerror("hash table overflow");
		return -1;
	}

	return 0;
}

static int define_typealias(void)
{
	char *id;
	type_datum_t *t, *aliasdatum;;
	int ret;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for typealias definition?");
		return -1;
	}

	t = hashtab_search(policydbp->p_types.table, id);
	if (!t || t->isattr) {
		sprintf(errormsg, "unknown type %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	while ((id = queue_remove(id_queue))) {
		aliasdatum = (type_datum_t *) malloc(sizeof(type_datum_t));
		if (!aliasdatum) {
			yyerror("out of memory");
			return -1;
		}
		memset(aliasdatum, 0, sizeof(type_datum_t));
		aliasdatum->value = t->value;

		ret = hashtab_insert(policydbp->p_types.table,
				     (hashtab_key_t) id, (hashtab_datum_t) aliasdatum);

		if (ret == HASHTAB_PRESENT) {
			sprintf(errormsg, "name conflict for type alias %s", id);
			yyerror(errormsg);
			free(aliasdatum);
			free(id);
			return -1;
		}
		if (ret == HASHTAB_OVERFLOW) {
			yyerror("hash table overflow");
			free(aliasdatum);
			free(id);
			return -1;
		}
	}
	return 0;
}

static int define_type(int alias)
{
	char *id;
	type_datum_t *datum, *aliasdatum, *attr;
	int ret, newattr = 0;


	if (pass == 2) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		if (alias) {
			while ((id = queue_remove(id_queue))) 
				free(id);
		}
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for type definition?");
		return -1;
	}

	datum = (type_datum_t *) malloc(sizeof(type_datum_t));
	if (!datum) {
		yyerror("out of memory");
		free(id);
		return -1;
	}
	memset(datum, 0, sizeof(type_datum_t));
	datum->primary = TRUE;
	datum->value = ++policydbp->p_types.nprim;

	ret = hashtab_insert(policydbp->p_types.table,
			     (hashtab_key_t) id, (hashtab_datum_t) datum);

	if (ret == HASHTAB_PRESENT) {
		--policydbp->p_types.nprim;
		free(datum);
		sprintf(errormsg, "name conflict for type %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		free(datum);
		free(id);
		return -1;
	}

	if (alias) { 
		while ((id = queue_remove(id_queue))) {
			aliasdatum = (type_datum_t *) malloc(sizeof(type_datum_t));
			if (!aliasdatum) {
				yyerror("out of memory");
				return -1;
			}
			memset(aliasdatum, 0, sizeof(type_datum_t));
			aliasdatum->value = datum->value;

			ret = hashtab_insert(policydbp->p_types.table,
					     (hashtab_key_t) id, (hashtab_datum_t) aliasdatum);

			if (ret == HASHTAB_PRESENT) {
				sprintf(errormsg, "name conflict for type alias %s", id);
				yyerror(errormsg);
				free(aliasdatum);
				free(id);
				return -1;
			}
			if (ret == HASHTAB_OVERFLOW) {
				yyerror("hash table overflow");
				free(aliasdatum);
				free(id);
				return -1;
			}
		}
	}

	while ((id = queue_remove(id_queue))) {
#ifdef CONFIG_SECURITY_SELINUX_MLS
		if (!strcmp(id, "mlstrustedreader")) {
			if (ebitmap_set_bit(&policydbp->trustedreaders, datum->value - 1, TRUE)) {
				yyerror("out of memory");
				free(id);
				return -1;
			}
		} else if (!strcmp(id, "mlstrustedwriter")) {
			if (ebitmap_set_bit(&policydbp->trustedwriters, datum->value - 1, TRUE)) {
				yyerror("out of memory");
				free(id);
				return -1;
			}
		} else if (!strcmp(id, "mlstrustedobject")) {
			if (ebitmap_set_bit(&policydbp->trustedobjects, datum->value - 1, TRUE)) {
				yyerror("out of memory");
				free(id);
				return -1;
			}
		}
#endif
		attr = hashtab_search(policydbp->p_types.table, id);
		if (!attr) {
			sprintf(errormsg, "attribute %s is not declared", id);
#if 1
			/* treat it as a fatal error */
			yyerror(errormsg);
			return -1;
#else
			/* Warn but automatically define the attribute.
			   Useful for quickly finding all those attributes you
			   forgot to declare. */
			yywarn(errormsg);
			attr = (type_datum_t *) malloc(sizeof(type_datum_t));
			if (!attr) {
				yyerror("out of memory");
				return -1;
			}
			memset(attr, 0, sizeof(type_datum_t));
			attr->isattr = TRUE;
			ret = hashtab_insert(policydbp->p_types.table,
					     id, (hashtab_datum_t) attr);
			if (ret) {
				yyerror("hash table overflow");
				return -1;
			}
			newattr = 1;
#endif
		} else {
			newattr = 0;
		}

		if (!attr->isattr) {
			sprintf(errormsg, "%s is a type, not an attribute", id);
			yyerror(errormsg);
			return -1;
		}

		if (!newattr)
			free(id);

		ebitmap_set_bit(&attr->types, datum->value - 1, TRUE);
	}

	return 0;
}

struct val_to_name {
	unsigned int val;
	char *name;
};

static int type_val_to_name_helper(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	type_datum_t *typdatum;
	struct val_to_name *v = p;

	typdatum = (type_datum_t *) datum;

	if (v->val == typdatum->value) {
		v->name = key;
		return 1;
	}

	return 0;
}

static char *type_val_to_name(unsigned int val) 
{
	struct val_to_name v;
	int rc;

	v.val = val;
	rc = hashtab_map(policydbp->p_types.table, 
			 type_val_to_name_helper, &v);
	if (rc)
		return v.name;
	return NULL;
}


static int set_types(ebitmap_t *set,
		     ebitmap_t *negset,
		     char *id,
		     int *add)
{
	type_datum_t *t;
	unsigned int i;

	if (strcmp(id, "*") == 0) {
		/* set all types not in negset */
		for (i = 0; i < policydbp->p_types.nprim; i++) {
			if (!ebitmap_get_bit(negset, i))
				ebitmap_set_bit(set, i, TRUE);
		}
		free(id);
		return 0;
	}

	if (strcmp(id, "~") == 0) {
		/* complement the set */
		for (i = 0; i < policydbp->p_types.nprim; i++) {
			if (ebitmap_get_bit(set, i))
				ebitmap_set_bit(set, i, FALSE);
			else 
				ebitmap_set_bit(set, i, TRUE);
		}
		free(id);
		return 0;
	}

	if (strcmp(id, "-") == 0) {
		*add = 0;
		free(id);
		return 0;
	}	

	t = hashtab_search(policydbp->p_types.table, id);
	if (!t) {
		sprintf(errormsg, "unknown type %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	if (t->isattr) {
		/* set or clear all types with this attribute,
		   but do not set anything explicitly cleared previously */
		for (i = ebitmap_startbit(&t->types); i < ebitmap_length(&t->types); i++) {
			if (!ebitmap_get_bit(&t->types, i)) 
				continue;		
			if (!(*add)) {
				ebitmap_set_bit(set, i, FALSE);
				ebitmap_set_bit(negset, i, TRUE);
			} else if (!ebitmap_get_bit(negset, i)) {
				ebitmap_set_bit(set, i, TRUE);
#if VERBOSE
			} else {
				char *name = type_val_to_name(i+1);
				sprintf(errormsg, "ignoring %s due to prior -%s", name, name);
				yywarn(errormsg);
#endif
			}
		}
	} else {
		/* set or clear one type, but do not set anything
		   explicitly cleared previously */	
		if (!(*add)) {
			ebitmap_set_bit(set, t->value - 1, FALSE);
			ebitmap_set_bit(negset, t->value - 1, TRUE);
		} else if (!ebitmap_get_bit(negset, t->value - 1)) {
			ebitmap_set_bit(set, t->value - 1, TRUE);
#if VERBOSE
		} else {
			sprintf(errormsg, "ignoring %s due to prior -%s", id, id);
			yywarn(errormsg);
#endif
		}
	}

	free(id);
	*add = 1;
	return 0;
}


static int define_compute_type(int which)
{
	char *id;
	avtab_key_t avkey;
	avtab_datum_t avdatum, *avdatump;
	type_datum_t *datum;
	class_datum_t *cladatum;
	ebitmap_t stypes, ttypes, tclasses, negset;
	uint32_t newtype = 0;
	int ret, add = 1;
	unsigned int i, j, k;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	ebitmap_init(&stypes);
	ebitmap_init(&ttypes);
	ebitmap_init(&tclasses);

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (set_types(&stypes, &negset, id, &add))
			return -1;
	}
	ebitmap_destroy(&negset);

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (set_types(&ttypes, &negset, id, &add))
			return -1;
	}
	ebitmap_destroy(&negset);

	while ((id = queue_remove(id_queue))) {
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			sprintf(errormsg, "unknown class %s", id);
			yyerror(errormsg);
			goto bad;
		}
		ebitmap_set_bit(&tclasses, cladatum->value - 1, TRUE);
		free(id);
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no newtype?");
		goto bad;
	}
	datum = (type_datum_t *) hashtab_search(policydbp->p_types.table,
						(hashtab_key_t) id);
	if (!datum || datum->isattr) {
		sprintf(errormsg, "unknown type %s", id);
		yyerror(errormsg);
		goto bad;
	}

	for (i = ebitmap_startbit(&stypes); i < ebitmap_length(&stypes); i++) {
		if (!ebitmap_get_bit(&stypes, i)) 
			continue;
		for (j = ebitmap_startbit(&ttypes); j < ebitmap_length(&ttypes); j++) {
			if (!ebitmap_get_bit(&ttypes, j)) 
				continue;
			for (k = ebitmap_startbit(&tclasses); k < ebitmap_length(&tclasses); k++) {
				if (!ebitmap_get_bit(&tclasses, k)) 
					continue;
				avkey.source_type = i + 1;
				avkey.target_type = j + 1;
				avkey.target_class = k + 1;
				avdatump = avtab_search(&policydbp->te_avtab, &avkey, AVTAB_TYPE);
				if (avdatump) {
					switch (which) {
					case AVTAB_TRANSITION:
						newtype = avtab_transition(avdatump);
						break;
					case AVTAB_MEMBER:
						newtype = avtab_member(avdatump);
						break;
					case AVTAB_CHANGE:
						newtype = avtab_change(avdatump);
						break;
					}
					if ( (avdatump->specified & which) &&
					     (newtype != datum->value) ) {
						sprintf(errormsg, "conflicting rule for (%s, %s:%s):  default was %s, is now %s", type_val_to_name(i+1), type_val_to_name(j+1), policydbp->p_class_val_to_name[k],
							type_val_to_name(newtype),
							type_val_to_name(datum->value));
						yywarn(errormsg);
					}
					avdatump->specified |= which;
					switch (which) {
					case AVTAB_TRANSITION:
						avtab_transition(avdatump) = datum->value;
						break;
					case AVTAB_MEMBER:
						avtab_member(avdatump) = datum->value;
						break;
					case AVTAB_CHANGE:
						avtab_change(avdatump) = datum->value;
						break;
					}
				} else {
					memset(&avdatum, 0, sizeof avdatum);
					avdatum.specified |= which;
					switch (which) {
					case AVTAB_TRANSITION:
					        avtab_transition(&avdatum) = datum->value;
						break;
					case AVTAB_MEMBER:
						avtab_member(&avdatum) = datum->value;
						break;
					case AVTAB_CHANGE:
						avtab_change(&avdatum) = datum->value;
						break;
					}
					ret = avtab_insert(&policydbp->te_avtab, &avkey, &avdatum);
					if (ret) {
						yyerror("hash table overflow");
						goto bad;
					}
				}
			}
		}
	}

	return 0;

      bad:
	return -1;
}

static cond_av_list_t *define_cond_compute_type(int which)
{
	char *id;
	cond_av_list_t *sub_list;
	avtab_key_t avkey;
	avtab_datum_t avdatum, *avdatump;
	type_datum_t *datum;
	class_datum_t *cladatum;
	ebitmap_t stypes, ttypes, tclasses, negset;
	uint32_t newtype = 0;
	int i, j, k, add = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		while ((id = queue_remove(id_queue)))
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return (cond_av_list_t *)1; /* any non-NULL value */
	}
	
	ebitmap_init(&stypes);
	ebitmap_init(&ttypes);
	ebitmap_init(&tclasses);

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (set_types(&stypes, &negset, id, &add))
			return  COND_ERR;
	}
	ebitmap_destroy(&negset);

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (set_types(&ttypes, &negset, id, &add))
			return COND_ERR;
	}
	ebitmap_destroy(&negset);

	while ((id = queue_remove(id_queue))) {
		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			sprintf(errormsg, "unknown class %s", id);
			yyerror(errormsg);
			goto bad;
		}
		ebitmap_set_bit(&tclasses, cladatum->value - 1, TRUE);
		free(id);
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no newtype?");
		goto bad;
	}
	datum = (type_datum_t *) hashtab_search(policydbp->p_types.table,
						(hashtab_key_t) id);
	if (!datum || datum->isattr) {
		sprintf(errormsg, "unknown type %s", id);
		yyerror(errormsg);
		goto bad;
	}

	/* create sub_list to be passed back and appended to true or false list */
	sub_list = (cond_av_list_t *) 0;

	for (i = ebitmap_startbit(&stypes); i < ebitmap_length(&stypes); i++) {
		if (!ebitmap_get_bit(&stypes, i)) 
			continue;
		for (j = ebitmap_startbit(&ttypes); j < ebitmap_length(&ttypes); j++) {
			if (!ebitmap_get_bit(&ttypes, j)) 
				continue;
			for (k = ebitmap_startbit(&tclasses); k < ebitmap_length(&tclasses); k++) {
				if (!ebitmap_get_bit(&tclasses, k)) 
					continue;
				avkey.source_type = i + 1;
				avkey.target_type = j + 1;
				avkey.target_class = k + 1;
				avdatump = avtab_search(&policydbp->te_avtab, &avkey, AVTAB_TYPE);
				
				/* does rule exist in base policy? */
				if ((avdatump) && (avdatump->specified & which)) {
					switch (which) {
					case AVTAB_TRANSITION:
						newtype = avtab_transition(avdatump);
						break;
					case AVTAB_MEMBER:
						newtype = avtab_member(avdatump);
						break;
					case AVTAB_CHANGE:
						newtype = avtab_change(avdatump);
						break;
					}
					if ( (newtype != datum->value) ) {
						sprintf(errormsg, "conflicting type rule for conditional "
							"(%s, %s:%s) in base: default is %s, conditional %s "
							"will be ignored", 
							type_val_to_name(i+1), 
							type_val_to_name(j+1), 
							policydbp->p_class_val_to_name[k],
							type_val_to_name(newtype),
							type_val_to_name(datum->value));
						yywarn(errormsg);
					} else {
						sprintf(errormsg, "conditional type rule (%s, %s:%s): "
							"has same default, %s, as rule in base policy; "
							"conditional %s will be ignored", 
							type_val_to_name(i+1), 
							type_val_to_name(j+1), 
							policydbp->p_class_val_to_name[k],
							type_val_to_name(newtype),
							type_val_to_name(datum->value));
						yywarn(errormsg);
					}
				}
				/* rule does not exist in base policy */
				else {
					
					memset(&avdatum, 0, sizeof avdatum);
					avdatum.specified |= which;
					switch (which) {
					case AVTAB_TRANSITION:
					        avtab_transition(&avdatum) = datum->value;
						break;
					case AVTAB_MEMBER:
						avtab_member(&avdatum) = datum->value;
						break;
					case AVTAB_CHANGE:
						avtab_change(&avdatum) = datum->value;
						break;
					}
					/* add rule to sub list */
					sub_list = cond_list_append(sub_list, &avkey, &avdatum);
					if (sub_list == COND_ERR) {
						yyerror("list overflow");
						goto bad;
					}
				}
			}
		}
	}
	
	return sub_list;

      bad:
	return COND_ERR;
}

static cond_av_list_t *cond_list_append(cond_av_list_t *sl, avtab_key_t *key, avtab_datum_t *datum) {

	cond_av_list_t  *n, *end;

	n = (cond_av_list_t *) malloc(sizeof(cond_av_list_t));
	if (!n) {
		  yyerror("out of memory");
		  return COND_ERR;
	}
	memset(n, 0, sizeof(cond_av_list_t));
	if (sl) {
		for(end=sl; end->next != NULL; end = end->next);
		end->next = n;
	}
	else sl = n;
	n->next = NULL;
	
	/* construct new node */
	n->node = (avtab_ptr_t) malloc(sizeof(struct avtab_node));
	if (!n->node) {
		yyerror("out of memory");
		return COND_ERR;
	}
	memset(n->node, 0, sizeof(struct avtab_node));
	n->node->key = *key;
	n->node->datum = *datum;
	/* the next two fields get filled in when we add to true/false list  */
	n->node->next = (avtab_ptr_t) 0;
	n->node->parse_context = (void *) 0;
	
	return(sl);
}


static int perm_name(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	struct val_to_name *v = data;
	perm_datum_t *perdatum;

	perdatum = (perm_datum_t *) datum;

	if (v->val == perdatum->value) {
		v->name = key;
		return 1;
	}

	return 0;
}


char *av_to_string(uint32_t tclass, access_vector_t av)
{
	struct val_to_name v;
	static char avbuf[1024];
	class_datum_t *cladatum;
	char *perm = NULL, *p;
	unsigned int i;
	int rc;

	cladatum = policydbp->class_val_to_struct[tclass-1];
	p = avbuf;
	for (i = 0; i < cladatum->permissions.nprim; i++) {
		if (av & (1 << i)) {
			v.val = i+1;
			rc = hashtab_map(cladatum->permissions.table,
					 perm_name, &v);
			if (!rc && cladatum->comdatum) {
				rc = hashtab_map(
					cladatum->comdatum->permissions.table,
					perm_name, &v);
			}
			if (rc)
				perm = v.name;
			if (perm) {
				sprintf(p, " %s", perm);
				p += strlen(p);
			}
		}
	}

	return avbuf;
}

static int define_bool()
{
	char *id, *name;
	cond_bool_datum_t *datum;
	int ret;


	if (pass == 2) {
		while ((id = queue_remove(id_queue)))
			free(id);
		return 0;
	}		

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no identifier for bool definition?");
		return -1;
	}
	name = id;

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no default value for bool definition?");
		free(name);
		return -1;
	}

	datum = (cond_bool_datum_t *) malloc(sizeof(cond_bool_datum_t));
	if (!datum) {
		yyerror("out of memory");
		free(id);
		free(name);
		return -1;
	}
	memset(datum, 0, sizeof(cond_bool_datum_t));
	datum->state = (int)(id[0] == 'T') ? 1 : 0;
	datum->value = ++policydbp->p_bools.nprim;

	ret = hashtab_insert(policydbp->p_bools.table,
			     (hashtab_key_t) name, (hashtab_datum_t) datum);

	if (ret == HASHTAB_PRESENT) {
		--policydbp->p_bools.nprim;
		free(datum);
		sprintf(errormsg, "name conflict for bool %s", id);
		yyerror(errormsg);
		free(id);
		free(name);
		return -1;
	}
	if (ret == HASHTAB_OVERFLOW) {
		yyerror("hash table overflow");
		free(datum);
		free(id);
		free(name);
		return -1;
	}
	return 0;
}

static cond_av_list_t *define_cond_pol_list( cond_av_list_t *avlist, cond_av_list_t *sl )
{
	cond_av_list_t *end;

	if (pass == 1) {
		/* return something so we get through pass 1 */
		return (cond_av_list_t *)1;
	}

	/* if we've started collecting sub lists, prepend to start of collection
	   because it's probably less iterations than appending. */
	if (!sl) return avlist;
	else if (!avlist) return sl;
	else {
		end = sl;
		while (end->next) end = end->next;
		end->next = avlist;
	} 
	return sl;
}

static int te_avtab_helper(int which, unsigned int stype, unsigned int ttype, 
			   ebitmap_t *tclasses, access_vector_t *avp)

{
	avtab_key_t avkey;
	avtab_datum_t avdatum, *avdatump;
	int ret;
	unsigned int k;

	if (which == -AVTAB_ALLOWED) {
		yyerror("neverallow should not reach this function.");
		return -1;
	}

	for (k = ebitmap_startbit(tclasses); k < ebitmap_length(tclasses); k++) {
		if (!ebitmap_get_bit(tclasses, k)) 
			continue;
		avkey.source_type = stype + 1;
		avkey.target_type = ttype + 1;
		avkey.target_class = k + 1;
		avdatump = avtab_search(&policydbp->te_avtab, &avkey, AVTAB_AV);
		if (!avdatump) {
			memset(&avdatum, 0, sizeof avdatum);
			avdatum.specified = (which > 0) ? which : -which;
			ret = avtab_insert(&policydbp->te_avtab, &avkey, &avdatum);
			if (ret) {
				yyerror("hash table overflow");
				return -1;
			}
			avdatump = avtab_search(&policydbp->te_avtab, &avkey, AVTAB_AV);
			if (!avdatump) {
				yyerror("inserted entry vanished!");
				return -1;
			}
		}

		avdatump->specified |= ((which > 0) ? which : -which);

		switch (which) {
		case AVTAB_ALLOWED:
			avtab_allowed(avdatump) |= avp[k];
			break;
		case AVTAB_AUDITALLOW:
			avtab_auditallow(avdatump) |= avp[k];
			break;
		case AVTAB_AUDITDENY:
			avtab_auditdeny(avdatump) |= avp[k];
			break;
		case -AVTAB_AUDITDENY:
			if (avtab_auditdeny(avdatump))
				avtab_auditdeny(avdatump) &= ~avp[k];
			else
				avtab_auditdeny(avdatump) = ~avp[k];
			break;
		}
	}

	return 0;
}

static  cond_av_list_t *cond_te_avtab_helper(int which, int stype, int ttype, 
			   ebitmap_t *tclasses, access_vector_t *avp )

{
	cond_av_list_t *sl;
	avtab_key_t avkey;
	avtab_datum_t avdatum;
	int  k;

	if (which == -AVTAB_ALLOWED) {
		yyerror("neverallow should not reach this function.");
		return COND_ERR;
	}

	/* create sub_list to be passed back and appended to true or false list */
	sl = (cond_av_list_t *) 0;

	for (k = ebitmap_startbit(tclasses); k < ebitmap_length(tclasses); k++) {
		if (!ebitmap_get_bit(tclasses, k)) 
			continue;
		/* build the key */
		avkey.source_type = stype + 1;
		avkey.target_type = ttype + 1;
		avkey.target_class = k + 1;
		
		/* build the datum */
		memset(&avdatum, 0, sizeof avdatum);
		avdatum.specified = (which > 0) ? which : -which;

		switch (which) {
		case AVTAB_ALLOWED:
			avtab_allowed(&avdatum) = avp[k];
			break;
		case AVTAB_AUDITALLOW:
			avtab_auditallow(&avdatum) = avp[k];
			break;
		case AVTAB_AUDITDENY:
			yyerror("AUDITDENY statements are not allowed in a conditional block; use DONTAUDIT");
			return COND_ERR;
		case -AVTAB_AUDITDENY:
			avtab_auditdeny(&avdatum) = ~avp[k];
			break;
		}

		/* add to temporary list */
		sl = cond_list_append(sl, &avkey, &avdatum);

		if (sl == COND_ERR) {
			yyerror("list overflow");
			return COND_ERR;
		}
	}

	return sl;
}

static cond_av_list_t *define_cond_te_avtab(int which)
{
	char *id;
	cond_av_list_t *sub_list, *final_list, *tail;
	class_datum_t *cladatum;
	perm_datum_t *perdatum;
	ebitmap_t stypes, ttypes, tclasses, negset;
	access_vector_t *avp;
	int i, j, hiclass, self = 0, add = 1;
	int suppress = 0;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		return (cond_av_list_t *) 1; /* any non-NULL value */
	}

	ebitmap_init(&stypes);
	ebitmap_init(&ttypes);
	ebitmap_init(&tclasses);

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (set_types(&stypes, &negset, id, &add))
			return COND_ERR;
	}
	ebitmap_destroy(&negset);

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (strcmp(id, "self") == 0) {
			self = 1;
			continue;
		}
		if (set_types(&ttypes, &negset, id, &add))
			return COND_ERR;
	}
	ebitmap_destroy(&negset);

	hiclass = 0;
	while ((id = queue_remove(id_queue))) {
		uint32_t classvalue;

		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) 	{
			sprintf(errormsg, "unknown class %s used in rule", id);
			yyerror(errormsg);
			goto bad;
		}
		
		if (policyvers < POLICYDB_VERSION_NLCLASS &&
		    (cladatum->value >= SECCLASS_NETLINK_ROUTE_SOCKET &&
		     cladatum->value <= SECCLASS_NETLINK_DNRT_SOCKET)) {
			sprintf(errormsg, "remapping class %s to netlink_socket "
			        "for policy version %d", id, policyvers);
			yywarn(errormsg);
			classvalue = SECCLASS_NETLINK_SOCKET;
			suppress = 1;
		} else 
			classvalue = cladatum->value;
		
		ebitmap_set_bit(&tclasses, classvalue - 1, TRUE);	
		if (classvalue > hiclass)
			hiclass = classvalue;
		free(id);
	}

	avp = malloc(hiclass * sizeof(access_vector_t));
	if (!avp) {
		yyerror("out of memory");
		return COND_ERR;
	}
	for (i = 0; i < hiclass; i++)
		avp[i] = 0;
	while ((id = queue_remove(id_queue))) {
		for (i = ebitmap_startbit(&tclasses); i < ebitmap_length(&tclasses); i++) {
			if (!ebitmap_get_bit(&tclasses, i)) 
				continue;
			cladatum = policydbp->class_val_to_struct[i];

			if (strcmp(id, "*") == 0) {
				/* set all permissions in the class */
				avp[i] = ~0;
				continue;
			}

			if (strcmp(id, "~") == 0) {
				/* complement the set */
				if (which == -AVTAB_AUDITDENY) 
					yywarn("dontaudit rule with a ~?");
				avp[i] = ~avp[i];
				continue;
			}

			perdatum = hashtab_search(cladatum->permissions.table,
						  id);
			if (!perdatum) {
				if (cladatum->comdatum) {
					perdatum = hashtab_search(cladatum->comdatum->permissions.table,
								  id);
				}
			}
			if (!perdatum) {
				sprintf(errormsg, "permission %s is not defined for class %s", id, policydbp->p_class_val_to_name[i]);
				if (!suppress)
				  yyerror(errormsg);
				continue;
			}

			avp[i] |= (1 << (perdatum->value - 1));
		}

		free(id);
	}

	sub_list = NULL;
	tail = NULL;
	final_list = NULL;

	if (self) {
		for (i = ebitmap_startbit(&stypes); i < ebitmap_length(&stypes); i++) {
			if (!ebitmap_get_bit(&stypes, i)) 
				continue;
			if (self) {
				if ((sub_list = cond_te_avtab_helper(which, i, i, &tclasses, avp )) == COND_ERR)
					return COND_ERR;
				if (final_list) {
					tail->next = sub_list;
					while (tail->next != NULL)
						tail = tail->next;
				} else {
					final_list = sub_list;
					tail = final_list;
					while (tail->next != NULL)
						tail = tail->next;
				}
			}
		}
	}
	for (i = ebitmap_startbit(&stypes); i < ebitmap_length(&stypes); i++) {
		if (!ebitmap_get_bit(&stypes, i)) 
			continue;
		for (j = ebitmap_startbit(&ttypes); j < ebitmap_length(&ttypes); j++) {
			if (!ebitmap_get_bit(&ttypes, j)) 
				continue;
			if ((sub_list = cond_te_avtab_helper(which, i, j, &tclasses, avp)) == COND_ERR)
				return COND_ERR;
			if (final_list) {
				tail->next = sub_list;
				while (tail->next != NULL)
					tail = tail->next;
			} else {
				final_list = sub_list;
				tail = final_list;
				while (tail->next != NULL)
					tail = tail->next;
			}
		}
	}

	ebitmap_destroy(&stypes);
	ebitmap_destroy(&ttypes);
	ebitmap_destroy(&tclasses);
	free(avp);
	
	return final_list;
 bad:
	return COND_ERR;
}


static int define_te_avtab(int which)
{
	char *id;
	class_datum_t *cladatum;
	perm_datum_t *perdatum;
	ebitmap_t stypes, ttypes, tclasses, negset;
	access_vector_t *avp;
	unsigned int i, j, hiclass;
	int self = 0, add = 1;
	te_assert_t *newassert;
	int suppress = 0;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	ebitmap_init(&stypes);
	ebitmap_init(&ttypes);
	ebitmap_init(&tclasses);

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (set_types(&stypes, &negset, id, &add))
			return -1;
	}
	ebitmap_destroy(&negset);

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (strcmp(id, "self") == 0) {
			self = 1;
			continue;
		}
		if (set_types(&ttypes, &negset, id, &add))
			return -1;
	}
	ebitmap_destroy(&negset);

	hiclass = 0;
	while ((id = queue_remove(id_queue))) {
		uint32_t classvalue;

		cladatum = hashtab_search(policydbp->p_classes.table, id);
		if (!cladatum) {
			sprintf(errormsg, "unknown class %s used in rule", id);
			yyerror(errormsg);
			goto bad;
		}
		
		if (policyvers < POLICYDB_VERSION_NLCLASS &&
		    (cladatum->value >= SECCLASS_NETLINK_ROUTE_SOCKET &&
		     cladatum->value <= SECCLASS_NETLINK_DNRT_SOCKET)) {
			sprintf(errormsg, "remapping class %s to netlink_socket "
			        "for policy version %d", id, policyvers);
			yywarn(errormsg);
			classvalue = SECCLASS_NETLINK_SOCKET;
			suppress = 1;
		} else
			classvalue = cladatum->value;
				
		ebitmap_set_bit(&tclasses, classvalue - 1, TRUE);	
		if (classvalue > hiclass)
			hiclass = classvalue;
		free(id);
	}

	avp = malloc(hiclass * sizeof(access_vector_t));
	if (!avp) {
		yyerror("out of memory");
		return -1;
	}
	for (i = 0; i < hiclass; i++)
		avp[i] = 0;

	while ((id = queue_remove(id_queue))) {
		for (i = ebitmap_startbit(&tclasses); i < ebitmap_length(&tclasses); i++) {
			if (!ebitmap_get_bit(&tclasses, i)) 
				continue;
			cladatum = policydbp->class_val_to_struct[i];

			if (strcmp(id, "*") == 0) {
				/* set all permissions in the class */
				avp[i] = ~0U;
				continue;
			}

			if (strcmp(id, "~") == 0) {
				/* complement the set */
				if (which == -AVTAB_AUDITDENY) 
					yywarn("dontaudit rule with a ~?");
				avp[i] = ~avp[i];
				continue;
			}

			perdatum = hashtab_search(cladatum->permissions.table,
						  id);
			if (!perdatum) {
				if (cladatum->comdatum) {
					perdatum = hashtab_search(cladatum->comdatum->permissions.table,
								  id);
				}
			}
			if (!perdatum) {
				sprintf(errormsg, "permission %s is not defined for class %s", id, policydbp->p_class_val_to_name[i]);
				if (!suppress)
				  yyerror(errormsg);
				continue;
			}

			avp[i] |= (1 << (perdatum->value - 1));
		}

		free(id);
	}

	if (which == -AVTAB_ALLOWED) {
		newassert = malloc(sizeof(te_assert_t));
		if (!newassert) {
			yyerror("out of memory");
			return -1;
		}
		memset(newassert, 0, sizeof(te_assert_t));
		newassert->stypes = stypes;
		newassert->ttypes = ttypes;
		newassert->tclasses = tclasses;
		newassert->self = self;
		newassert->avp = avp;
		newassert->line = policydb_lineno;
		newassert->next = te_assertions;
		te_assertions = newassert;
		return 0;
	}

	for (i = ebitmap_startbit(&stypes); i < ebitmap_length(&stypes); i++) {
		if (!ebitmap_get_bit(&stypes, i)) 
			continue;
		if (self) {
			if (te_avtab_helper(which, i, i, &tclasses, avp))
				return -1;
		}
		for (j = ebitmap_startbit(&ttypes); j < ebitmap_length(&ttypes); j++) {
			if (!ebitmap_get_bit(&ttypes, j)) 
				continue;
			if (te_avtab_helper(which, i, j, &tclasses, avp))
				return -1;
		}
	}

	ebitmap_destroy(&stypes);
	ebitmap_destroy(&ttypes);
	ebitmap_destroy(&tclasses);
	free(avp);

	return 0;
 bad:
	return -1;
}


static int role_val_to_name_helper(hashtab_key_t key, hashtab_datum_t datum, void *p)
{
	struct val_to_name *v = p;
	role_datum_t *roldatum;

	roldatum = (role_datum_t *) datum;

	if (v->val == roldatum->value) {
		v->name = key;
		return 1;
	}

	return 0;
}


static char *role_val_to_name(unsigned int val) 
{
	struct val_to_name v;
	int rc;

	v.val = val;
	rc = hashtab_map(policydbp->p_roles.table, 
			 role_val_to_name_helper, &v);
	if (rc)
		return v.name;
	return NULL;
}

static int define_role_types(void)
{
	role_datum_t *role;
	char *role_id, *id;
	int ret, add = 1;
	ebitmap_t negset;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	role_id = queue_remove(id_queue);

	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       role_id);
	if (!role) {
		role = (role_datum_t *) malloc(sizeof(role_datum_t));
		if (!role) {
			yyerror("out of memory");
			free(role_id);
			return -1;
		}
		memset(role, 0, sizeof(role_datum_t));
		role->value = ++policydbp->p_roles.nprim;
		ebitmap_set_bit(&role->dominates, role->value-1, TRUE);
		ret = hashtab_insert(policydbp->p_roles.table,
				     (hashtab_key_t) role_id, (hashtab_datum_t) role);

		if (ret) {
			yyerror("hash table overflow");
			free(role);
			free(role_id);
			return -1;
		}
	} else
		free(role_id);

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (set_types(&role->types, &negset, id, &add))
			return -1;
	}
	ebitmap_destroy(&negset);

	return 0;
}


static role_datum_t *
 merge_roles_dom(role_datum_t * r1, role_datum_t * r2)
{
	role_datum_t *new;

	if (pass == 1) {
		return (role_datum_t *)1; /* any non-NULL value */
	}

	new = malloc(sizeof(role_datum_t));
	if (!new) {
		yyerror("out of memory");
		return NULL;
	}
	memset(new, 0, sizeof(role_datum_t));
	new->value = 0;		/* temporary role */
	if (ebitmap_or(&new->dominates, &r1->dominates, &r2->dominates)) {
		yyerror("out of memory");
		return NULL;
	}
	if (ebitmap_or(&new->types, &r1->types, &r2->types)) {
		yyerror("out of memory");
		return NULL;
	}
	if (!r1->value) {
		/* free intermediate result */
		ebitmap_destroy(&r1->types);
		ebitmap_destroy(&r1->dominates);
		free(r1);
	}
	if (!r2->value) {
		/* free intermediate result */
		yyerror("right hand role is temporary?");
		ebitmap_destroy(&r2->types);
		ebitmap_destroy(&r2->dominates);
		free(r2);
	}
	return new;
}


static role_datum_t *
 define_role_dom(role_datum_t * r)
{
	role_datum_t *role;
	char *role_id;
	unsigned int i;
	int ret;

	if (pass == 1) {
		role_id = queue_remove(id_queue);
		free(role_id);
		return (role_datum_t *)1; /* any non-NULL value */
	}

	role_id = queue_remove(id_queue);
	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       role_id);
	if (!role) {
		role = (role_datum_t *) malloc(sizeof(role_datum_t));
		if (!role) {
			yyerror("out of memory");
			free(role_id);
			return NULL;
		}
		memset(role, 0, sizeof(role_datum_t));
		role->value = ++policydbp->p_roles.nprim;
		ebitmap_set_bit(&role->dominates, role->value-1, TRUE);
		ret = hashtab_insert(policydbp->p_roles.table,
				     (hashtab_key_t) role_id, (hashtab_datum_t) role);

		if (ret) {
			yyerror("hash table overflow");
			free(role);
			free(role_id);
			return NULL;
		}
	}
	if (r) {
		for (i = ebitmap_startbit(&r->dominates); i < ebitmap_length(&r->dominates); i++) {
			if (ebitmap_get_bit(&r->dominates, i))
				ebitmap_set_bit(&role->dominates, i, TRUE);
		}
		for (i = ebitmap_startbit(&r->types); i < ebitmap_length(&r->types); i++)	{
			if (ebitmap_get_bit(&r->types, i))
				ebitmap_set_bit(&role->types, i, TRUE);
		}
		if (!r->value) {
			/* free intermediate result */
			ebitmap_destroy(&r->types);
			ebitmap_destroy(&r->dominates);
			free(r);
		}
	}
	return role;
}


static int set_roles(ebitmap_t *set,
		     char *id)
{
	role_datum_t *r;
	unsigned int i;

	if (strcmp(id, "*") == 0) {
		/* set all roles */
		for (i = 0; i < policydbp->p_roles.nprim; i++) 
			ebitmap_set_bit(set, i, TRUE);
		free(id);
		return 0;
	}

	if (strcmp(id, "~") == 0) {
		/* complement the set */
		for (i = 0; i < policydbp->p_roles.nprim; i++) {
			if (ebitmap_get_bit(set, i))
				ebitmap_set_bit(set, i, FALSE);
			else 
				ebitmap_set_bit(set, i, TRUE);
		}
		free(id);
		return 0;
	}

	r = hashtab_search(policydbp->p_roles.table, id);
	if (!r) {
		sprintf(errormsg, "unknown role %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	/* set one role */
	ebitmap_set_bit(set, r->value - 1, TRUE);
	free(id);
	return 0;
}


static int define_role_trans(void)
{
	char *id;
	role_datum_t *role;
	ebitmap_t roles, types, negset;
	struct role_trans *tr = 0;
	unsigned int i, j;
	int add = 1;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		id = queue_remove(id_queue);
		free(id);
		return 0;
	}

	ebitmap_init(&roles);
	ebitmap_init(&types);

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&roles, id))
			return -1;
	}

	ebitmap_init(&negset);
	while ((id = queue_remove(id_queue))) {
		if (set_types(&types, &negset, id, &add))
			return -1;
	}
	ebitmap_destroy(&negset);

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no new role in transition definition?");
		goto bad;
	}
	role = hashtab_search(policydbp->p_roles.table, id);
	if (!role) {
		sprintf(errormsg, "unknown role %s used in transition definition", id);
		yyerror(errormsg);
		goto bad;
	}

	for (i = ebitmap_startbit(&roles); i < ebitmap_length(&roles); i++) {
		if (!ebitmap_get_bit(&roles, i)) 
			continue;
		for (j = ebitmap_startbit(&types); j < ebitmap_length(&types); j++) {
			if (!ebitmap_get_bit(&types, j)) 
				continue;

			for (tr = policydbp->role_tr; tr; tr = tr->next) {
				if (tr->role == (i+1) && tr->type == (j+1)) {
					sprintf(errormsg, "duplicate role transition defined for (%s,%s)", 
						role_val_to_name(i+1), type_val_to_name(j+1));
					yyerror(errormsg);
					goto bad;
				}
			}

			tr = malloc(sizeof(struct role_trans));
			if (!tr) {
				yyerror("out of memory");
				return -1;
			}
			memset(tr, 0, sizeof(struct role_trans));
			tr->role = i+1;
			tr->type = j+1;
			tr->new_role = role->value;
			tr->next = policydbp->role_tr;
			policydbp->role_tr = tr;
		}
	}

	return 0;

 bad:
	return -1;
}


static int define_role_allow(void)
{
	char *id;
	ebitmap_t roles, new_roles;
	struct role_allow *ra = 0;
	unsigned int i, j;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	ebitmap_init(&roles);
	ebitmap_init(&new_roles);

	while ((id = queue_remove(id_queue))) {
		if (set_roles(&roles, id))
			return -1;
	}


	while ((id = queue_remove(id_queue))) {
		if (set_roles(&new_roles, id))
			return -1;
	}

	for (i = ebitmap_startbit(&roles); i < ebitmap_length(&roles); i++) {
		if (!ebitmap_get_bit(&roles, i)) 
			continue;
		for (j = ebitmap_startbit(&new_roles); j < ebitmap_length(&new_roles); j++) {
			if (!ebitmap_get_bit(&new_roles, j)) 
				continue;

			for (ra = policydbp->role_allow; ra; ra = ra->next) {
				if (ra->role == (i+1) && ra->new_role == (j+1))
					break;
			}

			if (ra) 
				continue;

			ra = malloc(sizeof(struct role_allow));
			if (!ra) {
				yyerror("out of memory");
				return -1;
			}
			memset(ra, 0, sizeof(struct role_allow));
			ra->role = i+1;
			ra->new_role = j+1;
			ra->next = policydbp->role_allow;
			policydbp->role_allow = ra;
		}
	}

	return 0;
}


static int define_constraint(constraint_expr_t * expr)
{
	struct constraint_node *node;
	char *id;
	class_datum_t *cladatum;
	perm_datum_t *perdatum;
	ebitmap_t classmap;
	constraint_expr_t *e;
	unsigned int i;
	int depth;

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
		while ((id = queue_remove(id_queue))) 
			free(id);
		return 0;
	}

	depth = -1;
	for (e = expr; e; e = e->next) {
		switch (e->expr_type) {
		case CEXPR_NOT:
			if (depth < 0) {
				yyerror("illegal constraint expression");
				return -1;
			}
			break;
		case CEXPR_AND:
		case CEXPR_OR:
			if (depth < 1) {
				yyerror("illegal constraint expression");
				return -1;
			}
			depth--;
			break;
		case CEXPR_ATTR:
		case CEXPR_NAMES:
			if (depth == (CEXPR_MAXDEPTH-1)) {
				yyerror("constraint expression is too deep");
				return -1;
			}
			depth++;
			break;
		default:
			yyerror("illegal constraint expression");
			return -1;
		}
	}
	if (depth != 0) {
		yyerror("illegal constraint expression");
		return -1;
	}

	ebitmap_init(&classmap);
	while ((id = queue_remove(id_queue))) {
		cladatum = (class_datum_t *) hashtab_search(policydbp->p_classes.table,
						     (hashtab_key_t) id);
		if (!cladatum) {
			sprintf(errormsg, "class %s is not defined", id);
			ebitmap_destroy(&classmap);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		if (ebitmap_set_bit(&classmap, cladatum->value - 1, TRUE)) {
			yyerror("out of memory");
			ebitmap_destroy(&classmap);
			free(id);
			return -1;
		}
		node = malloc(sizeof(struct constraint_node));
		if (!node) {
			yyerror("out of memory");
			return -1;
		}
		memset(node, 0, sizeof(constraint_node_t));
		node->expr = expr;
		node->permissions = 0;

		node->next = cladatum->constraints;
		cladatum->constraints = node;

		free(id);
	}

	while ((id = queue_remove(id_queue))) {
		for (i = ebitmap_startbit(&classmap); i < ebitmap_length(&classmap); i++) {
			if (ebitmap_get_bit(&classmap, i)) {
				cladatum = policydbp->class_val_to_struct[i];
				node = cladatum->constraints;

				perdatum = (perm_datum_t *) hashtab_search(cladatum->permissions.table,
						     (hashtab_key_t) id);
				if (!perdatum) {
					if (cladatum->comdatum) {
						perdatum = (perm_datum_t *) hashtab_search(cladatum->comdatum->permissions.table,
						     (hashtab_key_t) id);
					}
					if (!perdatum) {
						sprintf(errormsg, "permission %s is not defined", id);
						yyerror(errormsg);
						free(id);
						ebitmap_destroy(&classmap);
						return -1;
					}
				}
				node->permissions |= (1 << (perdatum->value - 1));
			}
		}
		free(id);
	}

	ebitmap_destroy(&classmap);

	return 0;
}

static uintptr_t
 define_cexpr(uint32_t expr_type, uintptr_t arg1, uintptr_t arg2)
{
	struct constraint_expr *expr, *e1 = NULL, *e2;
	user_datum_t *user;
	role_datum_t *role;
	ebitmap_t negset;
	char *id;
	uint32_t val;
	int add = 1;

	if (pass == 1) {
		if (expr_type == CEXPR_NAMES) {
			while ((id = queue_remove(id_queue))) 
				free(id);
		}
		return 1; /* any non-NULL value */
	}

	expr = malloc(sizeof(struct constraint_expr));
	if (!expr) {
		yyerror("out of memory");
		return 0;
	}
	memset(expr, 0, sizeof(constraint_expr_t));
	expr->expr_type = expr_type;

	switch (expr_type) {
	case CEXPR_NOT:
		e1 = NULL;
		e2 = (struct constraint_expr *) arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			free(expr);
			return 0;
		}
		e1->next = expr;
		return arg1;
	case CEXPR_AND:
	case CEXPR_OR:
		e1 = NULL;
		e2 = (struct constraint_expr *) arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			free(expr);
			return 0;
		}
		e1->next = (struct constraint_expr *) arg2;

		e1 = NULL;
		e2 = (struct constraint_expr *) arg2;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal constraint expression");
			free(expr);
			return 0;
		}
		e1->next = expr;
		return arg1;
	case CEXPR_ATTR:
		expr->attr = arg1;
		expr->op = arg2;
		return (uintptr_t)expr;
	case CEXPR_NAMES:
		expr->attr = arg1;
		expr->op = arg2;
		ebitmap_init(&negset);
		while ((id = (char *) queue_remove(id_queue))) {
			if (expr->attr & CEXPR_USER) {
				user = (user_datum_t *) hashtab_search(policydbp->p_users.table,
								       (hashtab_key_t) id);
				if (!user) {
					sprintf(errormsg, "unknown user %s", id);
					yyerror(errormsg);
					free(expr);
					return 0;
				}
				val = user->value;
			} else if (expr->attr & CEXPR_ROLE) {
				role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
								       (hashtab_key_t) id);
				if (!role) {
					sprintf(errormsg, "unknown role %s", id);
					yyerror(errormsg);
					free(expr);
					return 0;
				}
				val = role->value;
			} else if (expr->attr & CEXPR_TYPE) {
				if (set_types(&expr->names, &negset, id, &add)) {
					free(expr);
					return 0;
				}
				continue;
			} else {
				yyerror("invalid constraint expression");
				free(expr);
				return 0;
			}
			if (ebitmap_set_bit(&expr->names, val - 1, TRUE)) {
				yyerror("out of memory");
				ebitmap_destroy(&expr->names);
				free(expr);
				return 0;
			}
			free(id);
		}
		ebitmap_destroy(&negset);
		return (uintptr_t)expr;
	default:
		yyerror("invalid constraint expression");
		free(expr);
		return 0;
	}

	yyerror("invalid constraint expression");
	free(expr);
	return 0;
}

static int define_conditional(cond_expr_t *expr, cond_av_list_t *t, cond_av_list_t *f )
{
	cond_expr_t *e;
	cond_node_t *cn, tmp, *cn_new;
	int depth;


	/* expression cannot be NULL */
	if ( !expr) {
		yyerror("illegal conditional expression");
		return -1;
	}
	if (!t) {
		if (!f) {
			yyerror("must have at least one rule");
			return -1;
		}
		/* Invert */
		t = f;
		f = 0;
		expr = define_cond_expr(COND_NOT, expr, 0);
		if (!expr) {
			yyerror("unable to invert");
			return -1;
		}
	}

	/* verify expression */
	depth = -1;
	for (e = expr; e; e = e->next) {
		switch (e->expr_type) {
		case COND_NOT:
			if (depth < 0) {
				yyerror("illegal conditional expression; Bad NOT");
				return -1;
			}
			break;
		case COND_AND:
		case COND_OR:
		case COND_XOR:
		case COND_EQ:
		case COND_NEQ:
			if (depth < 1) {
				yyerror("illegal conditional expression; Bad binary op");
				return -1;
			}
			depth--;
			break;
		case COND_BOOL:
			if (depth == (COND_EXPR_MAXDEPTH-1)) {
				yyerror("conditional expression is like totally too deep");
				return -1;
			}
			depth++;
			break;
		default:
			yyerror("illegal conditional expression");
			return -1;
		}
	}
	if (depth != 0) {
		yyerror("illegal conditional expression");
		return -1;
	}

        /*  use tmp conditional node to partially build new node */
	cn = &tmp;
	cn->expr = expr;
	cn->true_list = t;
	cn->false_list = f;
      
	/* normalize/precompute expression */
	if (cond_normalize_expr(policydbp, cn) < 0) {
		yyerror("problem normalizing conditional expression");
		return -1;
	}

	/* get the existing conditional node, or a new one*/
	cn_new = cond_node_search(policydbp, cn);
	if(cn_new) {
		cond_reduce_insert_list (cn->true_list, &cn_new->true_list, &cn_new->false_list, cn_new->cur_state);
		cond_reduce_insert_list (cn->false_list, &cn_new->false_list, &cn_new->true_list, !cn_new->cur_state);
	} else { 
		yyerror("could not get a conditional node");
		return -1;
	}


	return 0;
}


/*  Set the ENABLE bit and parse_context for each rule and check rules to see if they already exist.
 * Insert rules into the conditional db when appropriate.
 *  
 * new - list of rules to potentially add/insert
 * active - list to add rule to, and address to use as parse_context
 * inactive - opposite rule list in same conditional
 * state - whether rules in new are on or off by default.
 *
 * There are 4 possible conditions for a TYPE_* rule.  Allow rules are always inserted or
 * OR'd with existing allow rules on the same side of the same conditional.
 *
 * 1) Not present anywhere -> add it
 * 2) Already in cond, same side -> warn, replace default in prev rule, delete this rule
 * 3) Just added to opp side -> search again (we may still add this rule)
 * 4) In another conditional (either side) -> warn, delete this rule
 */
static void cond_reduce_insert_list(cond_av_list_t *new, cond_av_list_t **active, cond_av_list_t **inactive, int state)
{
	int add_rule = 1;
	cond_av_list_t *c, *top;
	avtab_ptr_t dup;
	uint32_t old_data = 0, new_data = 0;

	top = c = new; 
	/* loop through all the rules in the list */
	while(c) {

                /* is conditional rule a TYPE_* rule that's already in a conditional? */
                /* [note that we checked to see if it's in the base when we parsed the rule] */
		if ((c->node->datum.specified & AVTAB_TYPE) &&
		    ((dup = avtab_search_node(&policydbp->te_cond_avtab, &c->node->key, c->node->datum.specified & AVTAB_TYPE)) != NULL) ){
			do {
				/* is the rule we found in the current rule list or the equivalent */
				if (dup->parse_context == active) {
					/* change original default */
					switch(c->node->datum.specified & AVTAB_TYPE) {
					case AVTAB_TRANSITION:
						old_data = avtab_transition(&dup->datum);
						new_data = avtab_transition(&c->node->datum);
						avtab_transition(&dup->datum) = new_data;
						break;
					case AVTAB_MEMBER:
						old_data = avtab_member(&dup->datum);
						new_data = avtab_member(&c->node->datum);
						avtab_member(&dup->datum) = new_data;
						break;
					case AVTAB_CHANGE:
						old_data = avtab_change(&dup->datum);
						new_data = avtab_change(&c->node->datum);
						avtab_change(&dup->datum) = new_data;
						break;
					}
					sprintf(errormsg, "duplicate type rule on same side of conditional for (%s, %s:%s); overwrote original default %s with %s",
						type_val_to_name(c->node->key.source_type), 
						type_val_to_name(c->node->key.target_type), 
						policydbp->p_class_val_to_name[c->node->key.target_class],
						type_val_to_name(old_data),
						type_val_to_name(new_data));					
					yywarn(errormsg);
					add_rule = 0;
					break;
				}
				/* if the rule we found is in the opposite rule list that's OK*/
				if (dup->parse_context == inactive) {
					continue;
				} else {
					/* the rule we found must be in another conditional */
					sprintf(errormsg, "discarding conflicting conditional type rule for (%s, %s:%s); may only be in one conditional",
						type_val_to_name(c->node->key.source_type), 
						type_val_to_name(c->node->key.target_type), 
						policydbp->p_class_val_to_name[c->node->key.target_class]);
					yywarn(errormsg);
					add_rule = 0;
					break;
				}
			} while ( (dup = avtab_search_node_next(dup, c->node->datum.specified & AVTAB_TYPE)) != NULL);

		} /* end dealing with TYPE_* rules */
		else if ( (c->node->datum.specified & AVTAB_AV ) &&
		     ((dup = avtab_search_node(&policydbp->te_cond_avtab, &c->node->key, c->node->datum.specified & AVTAB_AV)) != NULL) ){
			do {
				/* we only care if the same AV rule is on the same side of the same conditional */
				if (dup->parse_context == active) {
					/* add to original */
					switch(c->node->datum.specified & AVTAB_AV) {
					case AVTAB_ALLOWED:
						new_data = avtab_allowed(&c->node->datum);
						avtab_allowed(&dup->datum) |= new_data;
						break;
					case AVTAB_AUDITALLOW:
						new_data = avtab_auditallow(&c->node->datum);
						avtab_auditallow(&dup->datum) |= new_data;
						break;
					case AVTAB_AUDITDENY:
						new_data = avtab_auditdeny(&c->node->datum);
						/* Since a '0' in an auditdeny mask represents a 
						 * permission we do NOT want to audit (dontaudit), we use
						 * the '&' operand to ensure that all '0's in the mask
						 * are retained (much unlike the allow and auditallow cases).
						 */
						avtab_auditdeny(&dup->datum) &= new_data;
						break;
					}
					add_rule = 0;
					break;
				}
			} while ( (dup = avtab_search_node_next(dup, c->node->datum.specified & AVTAB_AV)) != NULL);
		} /* end dealing with ALLOW rules */

		top = c->next;
		/* Either insert the rule into the policy and active list, or discard the rule */
		if (add_rule) {
			c->node = avtab_insert_with_parse_context(&policydbp->te_cond_avtab, 
								  &c->node->key,
								  &c->node->datum,
								  active);
			/* set whether the rule is enabled/disabled */
			if (state) {
				c->node->datum.specified |= AVTAB_ENABLED;
			} else {
				c->node->datum.specified &= ~AVTAB_ENABLED;
			}

			/* prepend new rule to active list */
 			c->next = *active; 
 			*active = c; 
		} else {
			/* discard rule */
			free(c->node);
			free(c);
			
			add_rule = 1;
		}
                /* next rule */
		c = top;
		
	} /* while */
}

static cond_expr_t *
 define_cond_expr(uint32_t expr_type, void* arg1, void* arg2)
{
	struct cond_expr *expr, *e1 = NULL, *e2;
	cond_bool_datum_t *bool_var;
	char *id;

	/* expressions are handled in the second pass */
	if (pass == 1) {
		if (expr_type == COND_BOOL) {
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
		}
		return (cond_expr_t *)1; /* any non-NULL value */
	}

	/* create a new expression struct */
	expr = malloc(sizeof(struct cond_expr));
	if (!expr) {
		yyerror("out of memory");
		return NULL;
	}
	memset(expr, 0, sizeof(cond_expr_t));
	expr->expr_type = expr_type;

	/* create the type asked for */
	switch (expr_type) {
	case COND_NOT:
		e1 = NULL;
		e2 = (struct cond_expr *) arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal conditional NOT expression");
			free(expr);
			return NULL;
		}
		e1->next = expr;
		return (struct cond_expr *) arg1;
	case COND_AND:
	case COND_OR:
	case COND_XOR:
	case COND_EQ:
	case COND_NEQ:
		e1 = NULL;
		e2 = (struct cond_expr *) arg1;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal left side of conditional binary op expression");
			free(expr);
			return NULL;
		}
		e1->next = (struct cond_expr *) arg2;

		e1 = NULL;
		e2 = (struct cond_expr *) arg2;
		while (e2) {
			e1 = e2;
			e2 = e2->next;
		}
		if (!e1 || e1->next) {
			yyerror("illegal right side of conditional binary op expression");
			free(expr);
			return NULL ;
		}
		e1->next = expr;
		return (struct cond_expr *) arg1;
	case COND_BOOL:
		id = (char *) queue_remove(id_queue) ;
		if (!id) {
			yyerror("bad conditional; expected boolean id");
			free(id);
			free(expr);
			return NULL;
		}
		bool_var = (cond_bool_datum_t *) hashtab_search(policydbp->p_bools.table,
								(hashtab_key_t) id);
		if (!bool_var) {
			sprintf(errormsg, "unknown boolean %s in conditional expression", id);
			yyerror(errormsg);
			free(expr);
			free(id);
			return NULL ;
		}
		expr->bool = bool_var->value;
		free(id);
		return expr;
	default:
		yyerror("illegal conditional expression");
		return NULL;
	}
}


static int set_user_roles(ebitmap_t *set,
			  char *id)
{
	role_datum_t *r;
	unsigned int i;

	if (strcmp(id, "*") == 0) {
		/* set all roles */
		for (i = 0; i < policydbp->p_roles.nprim; i++) 
			ebitmap_set_bit(set, i, TRUE);
		free(id);
		return 0;
	}

	if (strcmp(id, "~") == 0) {
		/* complement the set */
		for (i = 0; i < policydbp->p_roles.nprim; i++) {
			if (ebitmap_get_bit(set, i))
				ebitmap_set_bit(set, i, FALSE);
			else 
				ebitmap_set_bit(set, i, TRUE);
		}
		free(id);
		return 0;
	}

	r = hashtab_search(policydbp->p_roles.table, id);
	if (!r) {
		sprintf(errormsg, "unknown role %s", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}

	/* set the role and every role it dominates */
	for (i = ebitmap_startbit(&r->dominates); i < ebitmap_length(&r->dominates); i++) {
		if (ebitmap_get_bit(&r->dominates, i))
			ebitmap_set_bit(set, i, TRUE);
	}
	free(id);
	return 0;
}


static int define_user(void)
{
	char *id;
	user_datum_t *usrdatum;
	int ret;
#ifdef CONFIG_SECURITY_SELINUX_MLS
	mls_range_list_t *rnode;
	level_datum_t *levdatum;
	cat_datum_t *catdatum;
	int relation, l;
	char *levid;
#endif

	if (pass == 1) {
		while ((id = queue_remove(id_queue))) 
			free(id);
#ifdef CONFIG_SECURITY_SELINUX_MLS
		while ((id = queue_remove(id_queue))) { 
			free(id);
			for (l = 0; l < 2; l++) {
				while ((id = queue_remove(id_queue))) { 
					free(id);
				}
			}
		}
#endif
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no user name for user definition?");
		return -1;
	}
	usrdatum = (user_datum_t *) hashtab_search(policydbp->p_users.table,
						   (hashtab_key_t) id);
	if (!usrdatum) {
		usrdatum = (user_datum_t *) malloc(sizeof(user_datum_t));
		if (!usrdatum) {
			yyerror("out of memory");
			free(id);
			return -1;
		}
		memset(usrdatum, 0, sizeof(user_datum_t));
		usrdatum->value = ++policydbp->p_users.nprim;
		ebitmap_init(&usrdatum->roles);
		ret = hashtab_insert(policydbp->p_users.table,
				     (hashtab_key_t) id, (hashtab_datum_t) usrdatum);
		if (ret) {
			yyerror("hash table overflow");
			free(usrdatum);
			free(id);
			return -1;
		}
	} else
		free(id);

	while ((id = queue_remove(id_queue))) {
		if (set_user_roles(&usrdatum->roles, id))
			continue;
	}

#ifdef CONFIG_SECURITY_SELINUX_MLS
	id = queue_remove(id_queue);
	if (!id) {
		rnode = (mls_range_list_t *) malloc(sizeof(mls_range_list_t));
		if (!rnode) {
			yyerror("out of memory");
			free(id);
			return -1;
		}
		memset(rnode, 0, sizeof(mls_range_list_t));
		levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
							    (hashtab_key_t) "unclassified");
		if (!levdatum) {
			yyerror("no range for user");
			return -1;
		}
		rnode->range.level[0].sens = levdatum->level->sens;
		rnode->range.level[1].sens = levdatum->level->sens;
		rnode->next = usrdatum->ranges;
		usrdatum->ranges = rnode;
		goto skip_mls;
	} 
	do {
		rnode = (mls_range_list_t *) malloc(sizeof(mls_range_list_t));
		if (!rnode) {
			yyerror("out of memory");
			free(id);
			return -1;
		}
		memset(rnode, 0, sizeof(mls_range_list_t));

		for (l = 0; l < 2; l++) {
			levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						     (hashtab_key_t) id);
			if (!levdatum) {
				sprintf(errormsg, "unknown sensitivity %s used in user range definition", id);
				yyerror(errormsg);
				free(rnode);
				free(id);
				continue;
			}
			rnode->range.level[l].sens = levdatum->level->sens;
			ebitmap_init(&rnode->range.level[l].cat);

			levid = id;

			while ((id = queue_remove(id_queue))) {
				catdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
						     (hashtab_key_t) id);
				if (!catdatum) {
					sprintf(errormsg, "unknown category %s used in user range definition", id);
					yyerror(errormsg);
					free(id);
					continue;
				}
				if (!(ebitmap_get_bit(&levdatum->level->cat, catdatum->value - 1))) {
					sprintf(errormsg, "category %s cannot be associated with level %s", id, levid);
					yyerror(errormsg);
					free(id);
					continue;
				}
				if (ebitmap_set_bit(&rnode->range.level[l].cat, catdatum->value - 1, TRUE)) {
					yyerror("out of memory");
					free(id);
					free(levid);
					ebitmap_destroy(&rnode->range.level[l].cat);
					free(rnode);
					return -1;
				}

				/*
				 * no need to keep category name
				 */
				free(id);
			}

			/*
			 * no need to keep sensitivity name
			 */
			free(levid);

			id = queue_remove(id_queue);
			if (!id)
				break;
		}

		if (l == 0) {
			rnode->range.level[1].sens = rnode->range.level[0].sens;
			if (ebitmap_cpy(&rnode->range.level[1].cat, &rnode->range.level[0].cat)) {
				yyerror("out of memory");
				free(id);
				ebitmap_destroy(&rnode->range.level[0].cat);
				free(rnode);
				return -1;
			}
		}
		relation = mls_level_relation(rnode->range.level[1], rnode->range.level[0]);
		if (!(relation & (MLS_RELATION_DOM | MLS_RELATION_EQ))) {
			/* high does not dominate low */
			yyerror("high does not dominate low");
			ebitmap_destroy(&rnode->range.level[0].cat);
			ebitmap_destroy(&rnode->range.level[1].cat);
			free(rnode);
			return -1;
		}
		rnode->next = usrdatum->ranges;
		usrdatum->ranges = rnode;
	} while ((id = queue_remove(id_queue)));
skip_mls:
#endif

	return 0;
}


static int parse_security_context(context_struct_t * c)
{
	char *id;
	role_datum_t *role;
	type_datum_t *typdatum;
	user_datum_t *usrdatum;
#ifdef CONFIG_SECURITY_SELINUX_MLS
	char *levid;
	level_datum_t *levdatum;
	cat_datum_t *catdatum;
	int l;
#endif

	if (pass == 1) {
		id = queue_remove(id_queue); free(id); /* user  */
		id = queue_remove(id_queue); free(id); /* role  */
		id = queue_remove(id_queue); free(id); /* type  */
#ifdef CONFIG_SECURITY_SELINUX_MLS
		id = queue_remove(id_queue); free(id); 
		for (l = 0; l < 2; l++) {
			while ((id = queue_remove(id_queue))) {
				free(id);
			}
		}
#endif 
		return 0;
	}

	context_init(c);

	/* extract the user */
	id = queue_remove(id_queue);
	if (!id) {
		yyerror("no effective user?");
		goto bad;
	}
	usrdatum = (user_datum_t *) hashtab_search(policydbp->p_users.table,
						   (hashtab_key_t) id);
	if (!usrdatum) {
		sprintf(errormsg, "user %s is not defined", id);
		yyerror(errormsg);
		free(id);
		goto bad;
	}
	c->user = usrdatum->value;

	/* no need to keep the user name */
	free(id);

	/* extract the role */
	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no role name for sid context definition?");
		return -1;
	}
	role = (role_datum_t *) hashtab_search(policydbp->p_roles.table,
					       (hashtab_key_t) id);
	if (!role) {
		sprintf(errormsg, "role %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	c->role = role->value;

	/* no need to keep the role name */
	free(id);


	/* extract the type */
	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no type name for sid context definition?");
		return -1;
	}
	typdatum = (type_datum_t *) hashtab_search(policydbp->p_types.table,
						   (hashtab_key_t) id);
	if (!typdatum || typdatum->isattr) {
		sprintf(errormsg, "type %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	c->type = typdatum->value;

	/* no need to keep the type name */
	free(id);

#ifdef CONFIG_SECURITY_SELINUX_MLS
	/* extract the low sensitivity */
	id = (char *) queue_head(id_queue);
	if (!id || strcmp(id, "system_u") == 0 /* hack */) {
		/* No MLS component to the security context.  Try
		   to use a default 'unclassified' value. */
		levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
							    (hashtab_key_t) "unclassified");
		if (!levdatum) {
			yyerror("no sensitivity name for sid context definition?");
			return -1;
		}
		c->range.level[0].sens = levdatum->level->sens;
		c->range.level[1].sens = levdatum->level->sens;
		goto skip_mls;
	}

	id = (char *) queue_remove(id_queue);
	for (l = 0; l < 2; l++) {
		levdatum = (level_datum_t *) hashtab_search(policydbp->p_levels.table,
						     (hashtab_key_t) id);
		if (!levdatum) {
			sprintf(errormsg, "Sensitivity %s is not defined", id);
			yyerror(errormsg);
			free(id);
			return -1;
		}
		c->range.level[l].sens = levdatum->level->sens;

		/* extract low category set */
		levid = id;
		while ((id = queue_remove(id_queue))) {
			catdatum = (cat_datum_t *) hashtab_search(policydbp->p_cats.table,
						     (hashtab_key_t) id);
			if (!catdatum) {
				sprintf(errormsg, "unknown category %s used in initial sid context", id);
				yyerror(errormsg);
				free(levid);
				free(id);
				goto bad;
			}
			if (ebitmap_set_bit(&c->range.level[l].cat,
					     catdatum->value - 1, TRUE)) {
				yyerror("out of memory");
				free(levid);
				free(id);
				goto bad;
			}
			/* no need to keep category name */
			free(id);
		}

		/* no need to keep the sensitivity name */
		free(levid);

		/* extract high sensitivity */
		id = (char *) queue_remove(id_queue);
		if (!id)
			break;
	}

	if (l == 0) {
		c->range.level[1].sens = c->range.level[0].sens;
		if (ebitmap_cpy(&c->range.level[1].cat, &c->range.level[0].cat)) {

			yyerror("out of memory");
			goto bad;
		}
	}
skip_mls:
#endif

	if (!policydb_context_isvalid(policydbp, c)) {
		yyerror("invalid security context");
		goto bad;
	}
	return 0;

      bad:
	context_destroy(c);

	return -1;
}


static int define_initial_sid_context(void)
{
	char *id;
	ocontext_t *c, *head;

	if (pass == 1) {
		id = (char *) queue_remove(id_queue); free(id);
		parse_security_context(NULL);
		return 0;
	}

	id = (char *) queue_remove(id_queue);
	if (!id) {
		yyerror("no sid name for SID context definition?");
		return -1;
	}
	head = policydbp->ocontexts[OCON_ISID];
	for (c = head; c; c = c->next) {
		if (!strcmp(id, c->u.name))
			break;
	}

	if (!c) {
		sprintf(errormsg, "SID %s is not defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	if (c->context[0].user) {
		sprintf(errormsg, "The context for SID %s is multiply defined", id);
		yyerror(errormsg);
		free(id);
		return -1;
	}
	/* no need to keep the sid name */
	free(id);

	if (parse_security_context(&c->context[0]))
		return -1;

	return 0;
}

static int define_fs_context(unsigned int major, unsigned int minor)
{
	ocontext_t *newc, *c, *head;

	if (pass == 1) {
		parse_security_context(NULL);
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *) malloc(6);
	if (!newc->u.name) {
		yyerror("out of memory");
		free(newc);
		return -1;
	}
	sprintf(newc->u.name, "%02x:%02x", major, minor);

	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[1])) {
		context_destroy(&newc->context[0]);
		free(newc->u.name);
		free(newc);
		return -1;
	}
	head = policydbp->ocontexts[OCON_FS];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate entry for file system %s", newc->u.name);
			yyerror(errormsg);
			context_destroy(&newc->context[0]);
			context_destroy(&newc->context[1]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_FS] = newc;

	return 0;
}

static int define_port_context(unsigned int low, unsigned int high)
{
	ocontext_t *newc;
	char *id;

	if (pass == 1) {
		id = (char *) queue_remove(id_queue); free(id);
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	id = (char *) queue_remove(id_queue);
	if (!id) {
		free(newc);
		return -1;
	}
	if ((strcmp(id, "tcp") == 0) || (strcmp(id, "TCP") == 0)) {
		newc->u.port.protocol = IPPROTO_TCP;
	} else if ((strcmp(id, "udp") == 0) || (strcmp(id, "UDP") == 0)) {
		newc->u.port.protocol = IPPROTO_UDP;
	} else {
		sprintf(errormsg, "unrecognized protocol %s", id);
		yyerror(errormsg);
		free(newc);
		return -1;
	}

	newc->u.port.low_port = low;
	newc->u.port.high_port = high;

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}
	newc->next = policydbp->ocontexts[OCON_PORT];
	policydbp->ocontexts[OCON_PORT] = newc;
	return 0;
}

static int define_netif_context(void)
{
	ocontext_t *newc, *c, *head;

	if (pass == 1) {
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *) queue_remove(id_queue);
	if (!newc->u.name) {
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}
	if (parse_security_context(&newc->context[1])) {
		context_destroy(&newc->context[0]);
		free(newc->u.name);
		free(newc);
		return -1;
	}
	head = policydbp->ocontexts[OCON_NETIF];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate entry for network interface %s", newc->u.name);
			yyerror(errormsg);
			context_destroy(&newc->context[0]);
			context_destroy(&newc->context[1]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_NETIF] = newc;
	return 0;
}

static int define_ipv4_node_context(unsigned int addr, unsigned int mask)
{
	ocontext_t *newc, *c, *l, *head;

	if (pass == 1) {
		parse_security_context(NULL);
		return 0;
	}

	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.node.addr = addr;
	newc->u.node.mask = mask;

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		return -1;
	}
	/* Place this at the end of the list, to retain
	   the matching order specified in the configuration. */
	head = policydbp->ocontexts[OCON_NODE];
	for (l = NULL, c = head; c; l = c, c = c->next);

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_NODE] = newc;

	return 0;
}

#define s6_addr32 __u6_addr.__u6_addr32

static int define_ipv6_node_context(void)
{
	char *id;
	int rc = 0;
	struct in6_addr addr, mask;
	ocontext_t *newc, *c, *l, *head;
	
	if (pass == 1) {
		free(queue_remove(id_queue));
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		goto out;
	}
	
	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv6 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET6, id, &addr);
	free (id);
	if (rc < 1) {
		yyerror("failed to parse ipv6 address");
		if (rc == 0)
			rc = -1;
		goto out;
	}

	id = queue_remove(id_queue);
	if (!id) {
		yyerror("failed to read ipv6 address");
		rc = -1;
		goto out;
	}

	rc = inet_pton(AF_INET6, id, &mask);
	free(id);
	if (rc < 1) {
		yyerror("failed to parse ipv6 mask");
		if (rc == 0)
			rc = -1;
		goto out;
	}
	
	newc = malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		rc = -1;
		goto out;
	}

	memset(newc, 0, sizeof(ocontext_t));
	memcpy(&newc->u.node6.addr[0], &addr.s6_addr32[0], 16);
	memcpy(&newc->u.node6.mask[0], &mask.s6_addr32[0], 16);

	if (parse_security_context(&newc->context[0])) {
		free(newc);
		rc = -1;
		goto out;
	}

	/* Place this at the end of the list, to retain
	   the matching order specified in the configuration. */
	head = policydbp->ocontexts[OCON_NODE6];
	for (l = NULL, c = head; c; l = c, c = c->next);

	if (l)
		l->next = newc;
	else
		policydbp->ocontexts[OCON_NODE6] = newc;

	rc = 0;
out:
	return rc;
}

static int define_fs_use(int behavior)
{
	ocontext_t *newc, *c, *head;

	if (pass == 1) {
		free(queue_remove(id_queue));
		parse_security_context(NULL);
		return 0;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *) queue_remove(id_queue);
	if (!newc->u.name) {
		free(newc);
		return -1;
	}
	newc->v.behavior = behavior;
	if (parse_security_context(&newc->context[0])) {
		free(newc->u.name);
		free(newc);
		return -1;
	}

	head = policydbp->ocontexts[OCON_FSUSE];

	for (c = head; c; c = c->next) {
		if (!strcmp(newc->u.name, c->u.name)) {
			sprintf(errormsg, "duplicate fs_use entry for filesystem type %s", newc->u.name);
			yyerror(errormsg);
			context_destroy(&newc->context[0]);
			free(newc->u.name);
			free(newc);
			return -1;
		}
	}

	newc->next = head;
	policydbp->ocontexts[OCON_FSUSE] = newc;
	return 0;
}

static int define_genfs_context_helper(char *fstype, int has_type)
{
	struct genfs *genfs_p, *genfs, *newgenfs;
	ocontext_t *newc, *c, *head, *p;
	char *type = NULL;
	int len, len2;

	if (pass == 1) {
		free(fstype);
		free(queue_remove(id_queue));
		if (has_type)
			free(queue_remove(id_queue));
		parse_security_context(NULL);
		return 0;
	}

	for (genfs_p = NULL, genfs = policydbp->genfs; 
	     genfs; genfs_p = genfs, genfs = genfs->next) {
		if (strcmp(fstype, genfs->fstype) <= 0)
			break;
	}

	if (!genfs || strcmp(fstype, genfs->fstype)) {
		newgenfs = malloc(sizeof(struct genfs));
		if (!newgenfs) {
			yyerror("out of memory");
			return -1;
		}
		memset(newgenfs, 0, sizeof(struct genfs));
		newgenfs->fstype = fstype;
		newgenfs->next = genfs;
		if (genfs_p) 
			genfs_p->next = newgenfs;
		else
			policydbp->genfs = newgenfs;
		genfs = newgenfs;
	}

	newc = (ocontext_t *) malloc(sizeof(ocontext_t));
	if (!newc) {
		yyerror("out of memory");
		return -1;
	}
	memset(newc, 0, sizeof(ocontext_t));

	newc->u.name = (char *) queue_remove(id_queue);
	if (!newc->u.name) 
		goto fail;
	if (has_type) {
		type = (char *) queue_remove(id_queue);
		if (!type) 
			goto fail;
		if (type[1] != 0) {
			sprintf(errormsg, "invalid type %s", type);
			yyerror(errormsg);
			goto fail;
		}
		switch (type[0]) {
		case 'b':
			newc->v.sclass = SECCLASS_BLK_FILE;
			break;
		case 'c':
			newc->v.sclass = SECCLASS_CHR_FILE;
			break;
		case 'd':
			newc->v.sclass = SECCLASS_DIR;
			break;
		case 'p':
			newc->v.sclass = SECCLASS_FIFO_FILE;
			break;
		case 'l':
			newc->v.sclass = SECCLASS_LNK_FILE;
			break;
		case 's':
			newc->v.sclass = SECCLASS_SOCK_FILE;
			break;
		case '-':
			newc->v.sclass = SECCLASS_FILE;
			break;
		default:
			sprintf(errormsg, "invalid type %s", type);
			yyerror(errormsg);
			goto fail;
		}
	}
	if (parse_security_context(&newc->context[0])) 
		goto fail;

	head = genfs->head;

	for (p = NULL, c = head; c; p = c, c = c->next) {
		if (!strcmp(newc->u.name, c->u.name) && 
		    (!newc->v.sclass || !c->v.sclass || newc->v.sclass == c->v.sclass)) {
			sprintf(errormsg, "duplicate entry for genfs entry (%s, %s)", fstype, newc->u.name);
			yyerror(errormsg);
			goto fail;
		}
		len = strlen(newc->u.name);
		len2 = strlen(c->u.name);
		if (len > len2)
			break;
	}

	newc->next = c;
	if (p) 
		p->next = newc;
	else
		genfs->head = newc;
	return 0;
fail:
	if (type)
		free(type);
	context_destroy(&newc->context[0]);
	if (fstype)
		free(fstype);
	if (newc->u.name)
		free(newc->u.name);
	free(newc);
	return -1;
}

static int define_genfs_context(int has_type)
{
	return define_genfs_context_helper(queue_remove(id_queue), has_type);
}

/* FLASK */


