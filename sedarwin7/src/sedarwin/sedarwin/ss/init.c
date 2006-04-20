
/* Author : Stephen Smalley (NAI Labs), <ssmalley@nai.com> */

/* FLASK */

/*
 * Initialize the security server by reading the policy
 * database and initializing the SID table.
 */


#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#include <kern/lock.h>

#include <sedarwin/linux-compat.h>
#include <sedarwin/sebsd.h>
#include <sedarwin/ss/global.h>
#include <sedarwin/ss/policydb.h>
#include <sedarwin/ss/services.h>
#include <sedarwin/ss/security.h>

int security_init(void)
{
	int rc;
	caddr_t  lh, tmp;
	void    *policy_data;
	size_t   policy_len;

	printf("security:  starting up (compiled " __DATE__ ")\n");

	if (!preload_find_data("sebsd_policy", &policy_len, &policy_data))
		goto loaderr;

#ifdef __APPLE__
	/* Initialize security server locks. */
	policy_rwlock = lock_alloc(TRUE, ETAP_NO_TRACE, ETAP_NO_TRACE);
	load_sem = mutex_alloc(ETAP_NO_TRACE);
#endif

	printf("security:  reading policy configuration\n");

	rc = security_load_policy(policy_data, policy_len);
	if (rc) {
		printf("security:  error while reading policy, cannot initialize.\n");
		return EINVAL;
	}

	return 0;

loaderr:
	printf("security:  policy not supplied by bootloader\n");
	return EINVAL;
}

/* FLASK */
