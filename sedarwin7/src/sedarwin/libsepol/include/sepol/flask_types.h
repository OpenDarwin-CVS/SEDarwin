
/* -*- linux-c -*- */

/*
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil> 
 */

#ifndef _LINUX_FLASK_TYPES_H_
#define _LINUX_FLASK_TYPES_H_

/*
 * The basic Flask types and constants.
 */

#include <sys/types.h>
#include <stdint.h>

/*
 * A security context is a set of security attributes 
 * associated with each subject and object controlled
 * by the security policy.  The security context type
 * is defined as a variable-length string that can be
 * interpreted by any application or user with an 
 * understanding of the security policy.
 */
typedef char* security_context_t;

/*
 * An access vector (AV) is a collection of related permissions
 * for a pair of SIDs.  The bits within an access vector
 * are interpreted differently depending on the class of
 * the object.  The access vector interpretations are specified
 * in flask/access_vectors, and the corresponding constants
 * for permissions are defined in the automatically generated
 * header file av_permissions.h.
 */
typedef uint32_t access_vector_t;

/*
 * Each object class is identified by a fixed-size value.
 * The set of security classes is specified in flask/security_classes, 
 * with the corresponding constants defined in the automatically 
 * generated header file flask.h.
 */
typedef uint16_t security_class_t;
#define SECCLASS_NULL			0x0000 /* no class */

#define SELINUX_MAGIC 0xf97cff8c 

typedef uint32_t security_id_t;
#define SECSID_NULL 0

struct av_decision {
	access_vector_t allowed;
	access_vector_t decided;
	access_vector_t auditallow;
	access_vector_t auditdeny;
	uint32_t seqno;
};

#endif

