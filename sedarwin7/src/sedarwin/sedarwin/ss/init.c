
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
#ifndef __APPLE__
#include <sys/linker.h>
#else
#include <mach/kmod.h>
#include <string.h> /* TMP */

struct lpargs
{
  int   size;
  void *data;
};

extern kmod_info_t *kmod;

#endif

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

#ifndef __APPLE__

	lh = preload_search_by_type ("sebsd_policy");
	if (lh == NULL)
		goto loaderr;

	tmp = preload_search_info (lh, MODINFO_ADDR);
	if (tmp == NULL)
		goto loaderr;
	policy_data = *(void **) tmp;
	tmp = preload_search_info (lh, MODINFO_SIZE);
	if (tmp == NULL)
		goto loaderr;
	policy_len = *(size_t *) tmp;

#else
	if (!preload_find_data ("sebsd_policy", &policy_len, &policy_data))
	  goto loaderr;
#endif

	printf("security:  reading policy configuration\n");

	rc = security_load_policy (policy_data, policy_len);
	if (rc) {
		printf("security:  error while reading policy, cannot initialize.\n");
		return EINVAL;
	}
	
	return rc;

loaderr:
	printf("security:  policy not supplied by bootloader\n");
	return EINVAL;
}

/* FLASK */

