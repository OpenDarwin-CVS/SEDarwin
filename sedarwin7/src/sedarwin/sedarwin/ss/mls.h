
/* Author : Stephen Smalley (NAI Labs), <ssmalley@nai.com> */

/* FLASK */

/*
 * Multi-level security (MLS) policy operations.
 */

#ifndef _MLS_H_
#define _MLS_H_

#include <sedarwin/ss/context.h>
#include <sedarwin/ss/policydb.h>
#include <sedarwin/ss/services.h>

#ifdef CONFIG_SECURITY_SELINUX_MLS

void mls_compute_av(context_struct_t * scontext,
		    context_struct_t * tcontext,
		    class_datum_t * tclass,
		    access_vector_t * allowed);

int mls_compute_context_len(context_struct_t * context);

int mls_sid_to_context(context_struct_t * context,
		       char **scontext);

int mls_context_isvalid(policydb_t *p, context_struct_t * c);

int mls_context_to_sid(char oldc,
	               char **scontext,
		       context_struct_t * context);

int mls_convert_context(policydb_t * oldp,
			policydb_t * newp,
			context_struct_t * context);

int mls_compute_sid(context_struct_t *scontext,
		    context_struct_t *tcontext,
		    security_class_t tclass,
		    __u32 specified,
		    context_struct_t *newcontext);

int sens_index(hashtab_key_t key, hashtab_datum_t datum, void *datap);
int cat_index(hashtab_key_t key, hashtab_datum_t datum, void *datap);
int sens_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p);
int cat_destroy(hashtab_key_t key, hashtab_datum_t datum, void *p);
int sens_read(policydb_t * p, hashtab_t h, FILE * fp);
int cat_read(policydb_t * p, hashtab_t h, FILE * fp);

#define mls_for_user_ranges(user, usercon) { \
mls_range_list_t *ranges; \
for (ranges = user->ranges; ranges; ranges = ranges->next) { \
usercon.range = ranges->range; 

#define mls_end_user_ranges } } 

#define mls_symtab_names , "levels", "categories"
#define mls_symtab_sizes , 16, 16
#define mls_index_f ,sens_index, cat_index
#define mls_destroy_f ,sens_destroy, cat_destroy
#define mls_read_f ,sens_read, cat_read
#define mls_write_f ,sens_write, cat_write
#define mls_policydb_index_others(p) printf(", %d levels", p->nlevels);

#define mls_set_config(config) config |= POLICYDB_CONFIG_MLS

void mls_user_destroy(user_datum_t *usrdatum);
int mls_read_range(context_struct_t *c, FILE * fp);
int mls_read_perm(perm_datum_t *perdatum, FILE *fp);
int mls_read_class(class_datum_t *cladatum,  FILE * fp);
int mls_read_user(user_datum_t *usrdatum, FILE *fp);
int mls_read_nlevels(policydb_t *p, FILE *fp);
int mls_read_trusted(policydb_t *p, FILE *fp);

#else

#define	mls_compute_av(scontext, tcontext, tclass_datum, allowed)
#define mls_compute_context_len(context) 0
#define	mls_sid_to_context(context, scontextpp)
#define mls_context_isvalid(p, c) 1
#define	mls_context_to_sid(oldc, context_str, context) 0
#define mls_convert_context(oldp, newp, c) 0
#define mls_compute_sid(scontext, tcontext, tclass, specified, newcontextp) 0
#define mls_for_user_ranges(user, usercon) 
#define mls_end_user_ranges
#define mls_symtab_names
#define mls_symtab_sizes
#define mls_index_f
#define mls_destroy_f  
#define mls_read_f 
#define mls_write_f 
#define mls_policydb_index_others(p) 
#define mls_set_config(config) 
#define mls_user_destroy(usrdatum) 
#define mls_read_range(c, fp) 0
#define mls_read_perm(p, fp) 0
#define mls_read_class(c, fp) 0
#define mls_read_user(u, fp) 0
#define mls_read_nlevels(p, fp) 0
#define mls_read_trusted(p, fp) 0

#endif

#ifndef __KERNEL__

#ifdef CONFIG_SECURITY_SELINUX_MLS

int mls_write_range(context_struct_t * c,
		    FILE * fp);

int mls_write_class(class_datum_t * cladatum,
		    FILE * fp);

#define mls_write_perm(buf, items, perdatum) \
     buf[items++] = cpu_to_le32(perdatum->base_perms);

int mls_write_user(user_datum_t *usrdatum, FILE *fp);

int mls_write_nlevels(policydb_t *p, FILE *fp);
int mls_write_trusted(policydb_t *p, FILE *fp);

int sens_write(hashtab_key_t key, hashtab_datum_t datum, void *p);
int cat_write(hashtab_key_t key, hashtab_datum_t datum, void *p);

#else

#define mls_write_range(c, fp) 0
#define mls_write_class(c, fp) 0
#define mls_write_perm(buf, items, perdatum) 
#define mls_write_user(u, fp) 0
#define mls_write_nlevels(p, fp) 0
#define mls_write_trusted(p, fp) 0

#endif

#endif

#endif

