#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"
#include "policy.h"
#include <stdio.h>
#include <limits.h>

int security_getenforce(void)
{
	int i, error;
	size_t isize = sizeof(i);

	error = sysctlbyname("security.mac.sebsd.enforcing",
	    &i, &isize, NULL, 0);
	if (error)
		return (-1);
	return (i);
}
hidden_def(security_getenforce)
