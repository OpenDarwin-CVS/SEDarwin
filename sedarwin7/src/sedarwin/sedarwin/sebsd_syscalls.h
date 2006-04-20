#ifndef _SEBSD_SYSCALLS_H_
#define	_SEBSD_SYSCALLS_H_

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

#define	SEBSDCALL_NUM			7

/* Structure definitions for compute_av call. */
struct security_query {
	char	*scontext;
	char	*tcontext;
	u16	 tclass;
	u32	 requested;
};

struct security_response {
	u32	 allowed;
	u32	 decided;
	u32	 auditallow;
	u32	 auditdeny;
	u32	 notify;
	u32	 seqno;
};

struct sebsd_get_bools {
	int	 len;
	char	*out;
};

struct lp_args {
        void    *data;
        size_t   len;
};

#endif /* _SEBSD_SYSCALLS_H_ */
