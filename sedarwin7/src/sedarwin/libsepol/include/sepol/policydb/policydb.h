
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/*
 * Updated: Joshua Brindle <jbrindle@tresys.com>
 *	    Karl MacMillan <kmacmillan@tresys.com>
 *	    Jason Tang <jtang@tresys.com>
 *	    
 *	Module support
 *
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Updated: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 * 	Added conditional policy language extensions
 *
 * Updated: Red Hat, Inc.  James Morris <jmorris@redhat.com>
 *
 *      Fine-grained netlink support
 *      IPv6 support
 *      Code cleanup
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 * Copyright (C) 2003 - 2004 Red Hat, Inc.
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

/* FLASK */

/*
 * A policy database (policydb) specifies the 
 * configuration data for the security policy.
 */

#ifndef _SEPOL_POLICYDB_POLICYDB_H_
#define _SEPOL_POLICYDB_POLICYDB_H_

#include <stdio.h>
#include <stddef.h>

#include <sepol/policydb.h>

#include <sepol/policydb/flask_types.h>
#include <sepol/policydb/symtab.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/context.h>
#include <sepol/policydb/constraint.h>
#include <sepol/policydb/sidtab.h>

#define ERRMSG_LEN 1024

/*
 * A datum type is defined for each kind of symbol 
 * in the configuration data:  individual permissions, 
 * common prefixes for access vectors, classes,
 * users, roles, types, sensitivities, categories, etc.
 */

/* type set preserves data needed by modules such as *, ~ and attributes */
typedef struct type_set {
	ebitmap_t types;
	ebitmap_t negset;
#define TYPE_STAR 1
#define TYPE_COMP 2
	uint32_t flags;
} type_set_t;

typedef struct role_set {
	ebitmap_t roles;
#define ROLE_STAR 1
#define ROLE_COMP 2
	uint32_t flags;
} role_set_t;

/* Permission attributes */
typedef struct perm_datum {
	uint32_t value;		/* permission bit + 1 */
} perm_datum_t;

/* Attributes of a common prefix for access vectors */
typedef struct common_datum {
	uint32_t value;		/* internal common value */
	symtab_t permissions;	/* common permissions */
} common_datum_t;

/* Class attributes */
typedef struct class_datum {
	uint32_t value;		/* class value */
	char *comkey;		/* common name */
	common_datum_t *comdatum;	/* common datum */
	symtab_t permissions;	/* class-specific permission symbol table */
	constraint_node_t *constraints;	/* constraints on class permissions */
	constraint_node_t *validatetrans;	/* special transition rules */
} class_datum_t;

/* Role attributes */
typedef struct role_datum {
	uint32_t value;		/* internal role value */
	ebitmap_t dominates;	/* set of roles dominated by this role */
	type_set_t types;	/* set of authorized types for role */
	ebitmap_t cache; /* This is an expanded set used for context validation during parsing */
} role_datum_t;

typedef struct role_trans {
	uint32_t role;		/* current role */
	uint32_t type;		/* program executable type */
	uint32_t new_role;		/* new role */
	struct role_trans *next;
} role_trans_t;

typedef struct role_allow {
	uint32_t role;		/* current role */
	uint32_t new_role;		/* new role */
	struct role_allow *next;
} role_allow_t;

/* Type attributes */
typedef struct type_datum {
	uint32_t value;		/* internal type value */
	unsigned char primary;	/* primary name? */
	unsigned char isattr;   /* is this a type attribute? */
	ebitmap_t types;        /* types with this attribute */
} type_datum_t;

/* User attributes */
typedef struct user_datum {
	uint32_t value;		/* internal user value */
	role_set_t roles;	/* set of authorized roles for user */
	mls_range_t range;	/* MLS range (min. - max.) for user */
	mls_level_t dfltlevel;	/* default login MLS level for user */
	ebitmap_t cache; /* This is an expanded set used for context validation during parsing */
} user_datum_t;


/* Sensitivity attributes */
typedef struct level_datum {
	mls_level_t *level;	/* sensitivity and associated categories */
	unsigned char isalias;  /* is this sensitivity an alias for another? */
	unsigned char defined;
} level_datum_t;

/* Category attributes */
typedef struct cat_datum {
	uint32_t value;		/* internal category bit + 1 */
	unsigned char isalias;  /* is this category an alias for another? */
} cat_datum_t;

typedef struct range_trans {
	uint32_t dom;			/* current process domain */
	uint32_t type;			/* program executable type */
	mls_range_t range;		/* new range */
	struct range_trans *next;
} range_trans_t;

/* Boolean data type */
typedef struct cond_bool_datum {
	uint32_t value;		/* internal type value */
	int state;
} cond_bool_datum_t;

struct cond_node;

typedef struct cond_node cond_list_t;
struct cond_av_list;

typedef struct class_perm_node {
	uint32_t class;
	uint32_t data; /* permissions or new type */
	struct class_perm_node *next;
} class_perm_node_t; 

typedef struct avrule {
/* these typedefs are almost exactly the same as those in avtab.h - they are
 * here because of the need to include neverallow and dontaudit messages */
#define AVRULE_ALLOWED     1
#define AVRULE_AUDITALLOW  2
#define AVRULE_AUDITDENY   4
#define AVRULE_DONTAUDIT   8
#define AVRULE_AV         (AVRULE_ALLOWED | AVRULE_AUDITALLOW | AVRULE_AUDITDENY | AVRULE_DONTAUDIT)
#define AVRULE_TRANSITION 16
#define AVRULE_MEMBER     32
#define AVRULE_CHANGE     64
#define AVRULE_TYPE       (AVRULE_TRANSITION | AVRULE_MEMBER | AVRULE_CHANGE)
#define AVRULE_NEVERALLOW 128
        uint32_t specified;
#define RULE_SELF 1
        uint32_t flags;
        type_set_t stypes;
        type_set_t ttypes;
        class_perm_node_t *perms;
        unsigned long line;  /* line number from policy.conf where
                              * this rule originated  */
        struct avrule *next;
} avrule_t;

typedef struct role_trans_rule {
        role_set_t roles; /* current role */
        type_set_t types; /* program executable type */
        uint32_t new_role;              /* new role */
        struct role_trans_rule *next;
} role_trans_rule_t;

typedef struct role_allow_rule {
        role_set_t roles; /* current role */
        role_set_t new_roles; /* new roles */
        struct role_allow_rule *next;
} role_allow_rule_t;

/*
 * The configuration data includes security contexts for 
 * initial SIDs, unlabeled file systems, TCP and UDP port numbers, 
 * network interfaces, and nodes.  This structure stores the
 * relevant data for one such entry.  Entries of the same kind
 * (e.g. all initial SIDs) are linked together into a list.
 */
typedef struct ocontext {
	union {
		char *name;	/* name of initial SID, fs, netif, fstype, path */
		struct {
			uint8_t protocol;
			uint16_t low_port;
			uint16_t high_port;
		} port;		/* TCP or UDP port information */
		struct {
			uint32_t addr;
			uint32_t mask;
		} node;		/* node information */
		struct {
			uint32_t addr[4];
			uint32_t mask[4];
		} node6;	/* IPv6 node information */
	} u;
	union {
		uint32_t sclass;  /* security class for genfs */
		uint32_t behavior;  /* labeling behavior for fs_use */
	} v;
	context_struct_t context[2];	/* security context(s) */
	sepol_security_id_t sid[2];	/* SID(s) */
	struct ocontext *next;
} ocontext_t;

typedef struct genfs {
	char *fstype;
	struct ocontext *head;
	struct genfs *next;
} genfs_t;

/* symbol table array indices */
#define SYM_COMMONS 0
#define SYM_CLASSES 1
#define SYM_ROLES   2
#define SYM_TYPES   3
#define SYM_USERS   4
#define SYM_BOOLS   5
#define SYM_LEVELS  6
#define SYM_CATS    7
#define SYM_NUM     8

/* object context array indices */
#define OCON_ISID  0	/* initial SIDs */
#define OCON_FS    1	/* unlabeled file systems */
#define OCON_PORT  2	/* TCP and UDP port numbers */
#define OCON_NETIF 3	/* network interfaces */
#define OCON_NODE  4	/* nodes */
#define OCON_FSUSE 5	/* fs_use */
#define OCON_NODE6 6	/* IPv6 nodes */
#define OCON_NUM   7

/* section: module information */

/* scope_index_t holds all of the symbols that are in scope in a
 * particular situation.  The bitmaps are indices (and thus must
 * subtract one) into the global policydb->scope array. */
typedef struct scope_index {
        ebitmap_t scope[SYM_NUM];
#define p_classes_scope scope[SYM_CLASSES]
#define p_roles_scope scope[SYM_ROLES]
#define p_types_scope scope[SYM_TYPES]
#define p_users_scope scope[SYM_USERS]
#define p_bools_scope scope[SYM_BOOLS]
#define p_sens_scope scope[SYM_LEVELS]
#define p_cat_scope scope[SYM_CATS]

        /* this array maps from class->value to the permissions within
         * scope.  if bit (perm->value - 1) is set in map
         * class_perms_map[class->value - 1] then that permission is
         * enabled for this class within this decl.  */
        ebitmap_t *class_perms_map;
        /* total number of classes in class_perms_map array */
        uint32_t class_perms_len;
} scope_index_t;

/* a list of declarations for a particular avrule_decl */

/* These two structs declare a block of policy that has TE and RBAC
 * statements and declarations.  The root block (the global policy)
 * can never have an ELSE branch. */
typedef struct avrule_decl {
        uint32_t decl_id;
        int enabled;    /* flag set during linking if this decl is enabled;
                           parent avrule_block->enabled will point to me */
        cond_list_t *cond_list;
        avrule_t *avrules;
        role_trans_rule_t *role_tr_rules;
        role_allow_rule_t *role_allow_rules;
        scope_index_t required;    /* symbols needed to activate this block */
        scope_index_t declared;    /* symbols declared within this block */

        /* for additive statements (type attribute, roles, and users) */
    	symtab_t symtab[SYM_NUM];

        struct avrule_decl *next;
} avrule_decl_t;

typedef struct avrule_block {
        avrule_decl_t *branch_list;
        avrule_decl_t *enabled; /* pointer to which branch is enabled.  this is
                                   used in linking and never written to disk */
        struct avrule_block *next;
} avrule_block_t;

/* Every identifier has its own scope datum.  The datum describes if
 * the item is to be included into the final policy during
 * expansion. */
typedef struct scope_datum {
/* Required for this decl */
#define SCOPE_REQ  1
/* Declared in this decl */
#define SCOPE_DECL 2
        uint32_t scope;
        uint32_t *decl_ids;
        uint32_t decl_ids_len;
        /* decl_ids is a list of avrule_decl's that declare/require
         * this symbol.  If scope==SCOPE_DECL then this is a list of
         * declarations.  If the symbol may only be declared once
         * (types, bools) then decl_ids_len will be exactly 1.  For
         * implicitly declared things (roles, users) then decl_ids_len
         * will be at least 1. */
} scope_datum_t;

/* The policy database */
typedef struct policydb {
#define POLICY_KERN SEPOL_POLICY_KERN
#define POLICY_BASE SEPOL_POLICY_BASE
#define POLICY_MOD SEPOL_POLICY_MOD
	uint32_t policy_type;
	char *name;
	char *version;
	
	/* Whether this policydb is mls, should always be set */
	int mls;	

	/* symbol tables */
	symtab_t symtab[SYM_NUM];
#define p_commons symtab[SYM_COMMONS]
#define p_classes symtab[SYM_CLASSES]
#define p_roles symtab[SYM_ROLES]
#define p_types symtab[SYM_TYPES]
#define p_users symtab[SYM_USERS]
#define p_bools symtab[SYM_BOOLS]
#define p_levels symtab[SYM_LEVELS]
#define p_cats symtab[SYM_CATS]

	/* symbol names indexed by (value - 1) */
	char **sym_val_to_name[SYM_NUM];
#define p_common_val_to_name sym_val_to_name[SYM_COMMONS]
#define p_class_val_to_name sym_val_to_name[SYM_CLASSES]
#define p_role_val_to_name sym_val_to_name[SYM_ROLES]
#define p_type_val_to_name sym_val_to_name[SYM_TYPES]
#define p_user_val_to_name sym_val_to_name[SYM_USERS]
#define p_bool_val_to_name sym_val_to_name[SYM_BOOLS]
#define p_sens_val_to_name sym_val_to_name[SYM_LEVELS]
#define p_cat_val_to_name sym_val_to_name[SYM_CATS]

	/* class, role, and user attributes indexed by (value - 1) */
	class_datum_t **class_val_to_struct;
	role_datum_t **role_val_to_struct;
	user_datum_t **user_val_to_struct;
	type_datum_t **type_val_to_struct;

        
        /* module stuff section -- used in parsing and for modules */

        /* keep track of the scope for every identifier.  these are
         * hash tables, where the key is the identifier name and value
         * a scope_datum_t.  as a convenience, one may use the
         * p_*_macros (cf. struct scope_index_t declaration). */
        symtab_t scope[SYM_NUM];

        /* module rule storage */
        avrule_block_t *global;

        
	/* compiled storage of rules - use for the kernel policy */
        
	/* type enforcement access vectors and transitions */
	avtab_t te_avtab;

	/* bools indexed by (value - 1) */
	cond_bool_datum_t **bool_val_to_struct;
	/* type enforcement conditional access vectors and transitions */
	avtab_t te_cond_avtab;
	/* linked list indexing te_cond_avtab by conditional */
	cond_list_t* cond_list;

	/* role transitions */
	role_trans_t *role_tr;

	/* role allows */
	role_allow_t *role_allow;

	/* security contexts of initial SIDs, unlabeled file systems,
	   TCP or UDP port numbers, network interfaces and nodes */
	ocontext_t *ocontexts[OCON_NUM];

        /* security contexts for files in filesystems that cannot support
	   a persistent label mapping or use another 
	   fixed labeling behavior. */
  	genfs_t *genfs;

	/* range transitions */
	range_trans_t *range_tr;

	ebitmap_t *type_attr_map;

	ebitmap_t *attr_type_map; /* not saved in the binary policy */

	unsigned policyvers;
} policydb_t;

struct sepol_policydb 
{
	struct policydb p;
};

extern int policydb_init(policydb_t * p);

extern int policydb_from_image(sepol_handle_t *handle,
			       void* data, size_t len, policydb_t* policydb);

extern int policydb_to_image(sepol_handle_t *handle, 
			     policydb_t* policydb, void **newdata, size_t *newlen);

extern int policydb_index_classes(policydb_t * p);

extern int policydb_index_bools(policydb_t * p);

extern int policydb_index_others(sepol_handle_t *handle, policydb_t * p, unsigned int verbose);

extern int policydb_reindex_users(policydb_t * p);

extern void policydb_destroy(policydb_t * p);

extern int policydb_load_isids(policydb_t *p, sidtab_t *s);

/* Deprecated */
extern int policydb_context_isvalid(
	const policydb_t *p, 
	const context_struct_t *c);

extern void symtabs_destroy(symtab_t *symtab);
extern int scope_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p);
typedef void (*hashtab_destroy_func_t) (hashtab_key_t k, hashtab_datum_t d, void *args);
extern hashtab_destroy_func_t get_symtab_destroy_func(int sym_num);

extern void class_perm_node_init(class_perm_node_t *x);
extern void type_set_init(type_set_t *x);
extern void type_set_destroy(type_set_t *x);
extern int type_set_cpy(type_set_t *dst, type_set_t *src);
extern int type_set_or_eq(type_set_t *dst, type_set_t *other);
extern void role_set_init(role_set_t *x);
extern void role_set_destroy(role_set_t *x);
extern void avrule_init(avrule_t *x);
extern void avrule_destroy(avrule_t *x);
extern void avrule_list_destroy(avrule_t *x);
extern void role_trans_rule_init(role_trans_rule_t *x);
extern void role_trans_rule_list_destroy(role_trans_rule_t *x);

extern void role_datum_init(role_datum_t *x);
extern void role_datum_destroy(role_datum_t *x);
extern void role_allow_rule_init(role_allow_rule_t *x);
extern void role_allow_rule_destroy(role_allow_rule_t *x);
extern void role_allow_rule_list_destroy(role_allow_rule_t *x);
extern void type_datum_init(type_datum_t *x);
extern void type_datum_destroy(type_datum_t *x);
extern void user_datum_init(user_datum_t *x);
extern void user_datum_destroy(user_datum_t *x);

extern int check_assertions(sepol_handle_t *handle,
			    policydb_t *p, avrule_t *avrules);

extern int symtab_insert(policydb_t *x, uint32_t sym,
                  hashtab_key_t key, hashtab_datum_t datum,
                  uint32_t scope, uint32_t avrule_decl_id,
                  uint32_t *value);

extern char *sepol_av_to_string(policydb_t *policydbp, uint32_t tclass, 
			 sepol_access_vector_t av);

/* A policy "file" may be a memory region referenced by a (data, len) pair
   or a file referenced by a FILE pointer. */
typedef struct policy_file {
#define PF_USE_MEMORY  0
#define PF_USE_STDIO   1
#define PF_LEN         2 /* total up length in len field */ 
	unsigned type;
	char *data;
	size_t len;
	size_t size;
	FILE *fp;
	struct sepol_handle *handle;
        unsigned char buffer[BUFSIZ];
} policy_file_t;

struct sepol_policy_file
{
	struct policy_file pf;
};

extern int policydb_read(policydb_t * p, struct policy_file * fp, unsigned int verbose);
extern int avrule_read_list(policydb_t *p, avrule_t **avrules, struct policy_file *fp);

extern int policydb_write(struct policydb *p, struct policy_file *pf);

#define PERM_SYMTAB_SIZE 32

/* Identify specific policy version changes */
#define POLICYDB_VERSION_BASE		15
#define POLICYDB_VERSION_BOOL		16
#define POLICYDB_VERSION_IPV6		17
#define POLICYDB_VERSION_NLCLASS	18
#define POLICYDB_VERSION_VALIDATETRANS	19
#define POLICYDB_VERSION_MLS		19
#define POLICYDB_VERSION_AVTAB		20

/* Range of policy versions we understand*/
#define POLICYDB_VERSION_MIN	POLICYDB_VERSION_BASE
#define POLICYDB_VERSION_MAX	POLICYDB_VERSION_AVTAB

/* Module versions and specific changes*/
#define MOD_POLICYDB_VERSION_BASE	   4
#define MOD_POLICYDB_VERSION_VALIDATETRANS 5
#define MOD_POLICYDB_VERSION_MLS	   5

#define MOD_POLICYDB_VERSION_MIN MOD_POLICYDB_VERSION_BASE
#define MOD_POLICYDB_VERSION_MAX MOD_POLICYDB_VERSION_MLS

#define POLICYDB_CONFIG_MLS    1

#define OBJECT_R "object_r"
#define OBJECT_R_VAL 1

#define POLICYDB_MAGIC SELINUX_MAGIC
#define POLICYDB_STRING "SE Linux"
#define POLICYDB_MOD_MAGIC SELINUX_MOD_MAGIC
#define POLICYDB_MOD_STRING "SE Linux Module"

#endif	/* _POLICYDB_H_ */

/* FLASK */

