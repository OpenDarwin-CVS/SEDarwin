#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "selinux_internal.h"
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include "policy.h"

int is_selinux_enabled(void)
{
	int error, i;
	size_t isize = sizeof(i);

	/* We don't care about the actual value. */
	error = sysctlbyname("security.mac.sebsd.enforcing",
	    &i, &isize, NULL, 0);
	return (!error || errno != ENOENT);
}
hidden_def(is_selinux_enabled)

/*
 * Function: is_selinux_mls_enabled()
 * Return:   1 on success
 *	     0 on failure
 */
int is_selinux_mls_enabled(void)
{
	int i = 0;
	size_t isize = sizeof(i);

	sysctlbyname("security.mac.sebsd.mls", &i, &isize, NULL, 0);
	return (i == 1);
}
hidden_def(is_selinux_mls_enabled);
