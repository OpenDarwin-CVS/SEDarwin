#ifndef _SEBSD_SYSCALLS_H_
#define _SEBSD_SYSCALLS_H_

#include <sedarwin/linux-compat.h>

/*
 * TBD: Should we really try to line up with SELinux?
 */
#define	SEBSDCALL_LOAD_POLICY		7
#define	SEBSDCALL_LOAD_MIGSCS		12	/* XXX */
#define	SEBSDCALL_GET_BOOLS	        8
#define	SEBSDCALL_GET_BOOL		9
#define	SEBSDCALL_SET_BOOL		10
#define	SEBSDCALL_COMMIT_BOOLS		11
#define	SEBSDCALL_GETUSERSIDS		6
#define	SEBSDCALL_GETFILESIDS           5
#define	SEBSDCALL_CHANGE_SID            4

#define	SEBSDCALL_NUM			7

/* Structure definitions for compute_av call. */
struct security_query {
	char *scontext;
	char *tcontext;
	security_class_t tclass;
	access_vector_t requested;
};

struct security_response {
	access_vector_t allowed;
	access_vector_t decided;
	access_vector_t auditallow;
	access_vector_t auditdeny;
	access_vector_t notify;
	u32 seqno;
};

struct sebsd_get_bools {
	int len;
	char *out;
};

#endif /* _SEBSD_SYSCALLS_H_ */
