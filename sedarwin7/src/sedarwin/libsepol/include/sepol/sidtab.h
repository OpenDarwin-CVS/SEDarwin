
/* Author : Stephen Smalley, <sds@epoch.ncsc.mil> */

/* FLASK */

/*
 * A security identifier table (sidtab) is a hash table
 * of security context structures indexed by SID value.
 */

#ifndef _SIDTAB_H_
#define _SIDTAB_H_

#include <sepol/context.h>

typedef struct sidtab_node {
	security_id_t sid;		/* security identifier */
	context_struct_t context;	/* security context structure */
	struct sidtab_node *next;
} sidtab_node_t;

typedef struct sidtab_node *sidtab_ptr_t;

#define SIDTAB_HASH_BITS 7
#define SIDTAB_HASH_BUCKETS (1 << SIDTAB_HASH_BITS)
#define SIDTAB_HASH_MASK (SIDTAB_HASH_BUCKETS-1)

#define SIDTAB_SIZE SIDTAB_HASH_BUCKETS

typedef struct {
	sidtab_ptr_t *htable;
	unsigned int nel;	/* number of elements */
	unsigned int next_sid;	/* next SID to allocate */
	unsigned char shutdown;
} sidtab_t;

int sepol_sidtab_init(sidtab_t *s);

int sepol_sidtab_insert(sidtab_t * s, security_id_t sid, context_struct_t * context);

context_struct_t *sepol_sidtab_search(sidtab_t * s, security_id_t sid);

int sepol_sidtab_map(sidtab_t * s,
	       int (*apply) (security_id_t sid,
			     context_struct_t * context,
			     void *args),
	       void *args);

void sepol_sidtab_map_remove_on_error(sidtab_t * s,
				int (*apply) (security_id_t sid,
					      context_struct_t * context,
					      void *args),
				void *args);

int sepol_sidtab_context_to_sid(sidtab_t * s,		/* IN */
			  context_struct_t * context,	/* IN */
			  security_id_t * sid);		/* OUT */

void sepol_sidtab_hash_eval(sidtab_t *h, char *tag);

void sepol_sidtab_destroy(sidtab_t *s);

void sepol_sidtab_set(sidtab_t *dst, sidtab_t *src);

void sepol_sidtab_shutdown(sidtab_t *s);

#endif	/* _SIDTAB_H_ */

/* FLASK */

