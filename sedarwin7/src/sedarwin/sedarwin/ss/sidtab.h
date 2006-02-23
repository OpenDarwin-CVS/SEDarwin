/*
 * A security identifier table (sidtab) is a hash table
 * of security context structures indexed by SID value.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
#ifndef _SS_SIDTAB_H_
#define _SS_SIDTAB_H_

#include <sedarwin/ss/context.h>
#include <sedarwin/linux-compat.h>
#include <sedarwin/flask_types.h>

#include <sys/lock.h>

#ifndef __APPLE__
#include <sys/mutex.h>
#endif

struct sidtab_node {
	security_id_t sid;		/* security identifier */
	struct context context;	/* security context structure */
	struct sidtab_node *next;
};

#define SIDTAB_HASH_BITS 7
#define SIDTAB_HASH_BUCKETS (1 << SIDTAB_HASH_BITS)
#define SIDTAB_HASH_MASK (SIDTAB_HASH_BUCKETS-1)

#define SIDTAB_SIZE SIDTAB_HASH_BUCKETS

struct sidtab {
	struct sidtab_node **htable;
	unsigned int nel;	/* number of elements */
	unsigned int next_sid;	/* next SID to allocate */
	unsigned char shutdown;
#ifdef _KERNEL
	spinlock_t lock;
#endif
};

int sidtab_init(struct sidtab *s);
int sidtab_insert(struct sidtab *s, security_id_t sid, struct context *context);
struct context *sidtab_search(struct sidtab *s, security_id_t sid);

int sidtab_map(struct sidtab *s,
	       int (*apply) (security_id_t sid,
			     struct context *context,
			     void *args),
	       void *args);

void sidtab_map_remove_on_error(struct sidtab *s,
				int (*apply) (security_id_t sid,
					      struct context *context,
					      void *args),
				void *args);

int sidtab_context_to_sid(struct sidtab *s,
			  struct context *context,
			  security_id_t *sid);

void sidtab_hash_eval(struct sidtab *h, char *tag);
void sidtab_destroy(struct sidtab *s);
void sidtab_set(struct sidtab *dst, struct sidtab *src);
void sidtab_shutdown(struct sidtab *s);

#endif	/* _SS_SIDTAB_H_ */


