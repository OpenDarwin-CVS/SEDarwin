#ifndef _SEPOL_POLICYDB_H_
#define _SEPOL_POLICYDB_H_

#include <stddef.h>
#include <stdio.h>

#include <sepol/handle.h>

struct sepol_policy_file;
typedef struct sepol_policy_file sepol_policy_file_t;

struct sepol_policydb;
typedef struct sepol_policydb sepol_policydb_t;

/* Policy file public interfaces. */

/* Create and free memory associated with a policy file. */
extern int sepol_policy_file_create(sepol_policy_file_t **pf);
extern void sepol_policy_file_free(sepol_policy_file_t *pf);

/*
 * Set the policy file to represent a binary policy memory image.
 * Subsequent operations using the policy file will read and write
 * the image located at the specified address with the specified length.
 * If 'len' is 0, then merely compute the necessary length upon  
 * subsequent policydb write operations in order to determine the
 * necessary buffer size to allocate.
 */
extern void sepol_policy_file_set_mem(sepol_policy_file_t *pf,
				      char *data,
				      size_t len);

/*
 * Get the size of the buffer needed to store a policydb write
 * previously done on this policy file.
 */
extern int sepol_policy_file_get_len(sepol_policy_file_t *pf,
				     size_t *len);

/*
 * Set the policy file to represent a FILE.
 * Subsequent operations using the policy file will read and write
 * to the FILE.
 */
extern void sepol_policy_file_set_fp(sepol_policy_file_t *pf,
				     FILE *fp);

/*
 * Associate a handle with a policy file, for use in
 * error reporting from subsequent calls that take the
 * policy file as an argument.
 */
extern void sepol_policy_file_set_handle(sepol_policy_file_t *pf,
					 sepol_handle_t *handle);

/* Policydb public interfaces. */

/* Create and free memory associated with a policydb. */
extern int sepol_policydb_create(sepol_policydb_t **p);
extern void sepol_policydb_free(sepol_policydb_t *p);

/* Legal types of policies that the policydb can represent. */
#define SEPOL_POLICY_KERN	0
#define SEPOL_POLICY_BASE	1
#define SEPOL_POLICY_MOD	2

/*
 * Range of policy versions for the kernel policy type supported
 * by this library.
 */
extern int sepol_policy_kern_vers_min(void);
extern int sepol_policy_kern_vers_max(void);

/*
 * Set the policy type as specified, and automatically initialize the
 * policy version accordingly to the maximum version supported for the
 * policy type.  
 * Returns -1 if the policy type is not legal.
 */
extern int sepol_policydb_set_typevers(sepol_policydb_t *p, unsigned int type);

/*
 * Set the policy version to a different value.
 * Returns -1 if the policy version is not in the supported range for
 * the (previously set) policy type.
 */
extern int sepol_policydb_set_vers(sepol_policydb_t *p, unsigned int vers);

/* 
 * Read a policydb from a policy file.
 * This automatically sets the type and version based on the 
 * image contents.
 */
extern int sepol_policydb_read(sepol_policydb_t *p,
			       sepol_policy_file_t *pf);

/*
 * Write a policydb to a policy file.
 * The generated image will be in the binary format corresponding 
 * to the policy version associated with the policydb.
 */
extern int sepol_policydb_write(sepol_policydb_t *p,
				sepol_policy_file_t *pf);

/*
 * Extract a policydb from a binary policy memory image.  
 * This is equivalent to sepol_policydb_read with a policy file
 * set to refer to memory.
 */
extern int sepol_policydb_from_image(sepol_handle_t *handle,
				     void* data, size_t len, 
				     sepol_policydb_t *p);


/*
 * Generate a binary policy memory image from a policydb.  
 * This is equivalent to sepol_policydb_write with a policy file
 * set to refer to memory, but internally handles computing the 
 * necessary length and allocating an appropriately sized memory
 * buffer for the caller.  
 */
extern int sepol_policydb_to_image(sepol_handle_t *handle,
				   sepol_policydb_t *p, 
				   void **newdata, 
				   size_t *newlen);

extern int sepol_policydb_mls_enabled(
	const sepol_policydb_t* p);

#endif
