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

int security_setenforce(int value)
{
	int error, i;
	size_t osize = sizeof(i);
	
	if (!(value == 0 || value == 1))
		return -1;
	error = sysctlbyname("security.mac.sebsd.enforcing",
	    &i, &osize, &value, sizeof(int));
	if (error)
		return -1;
	return 0;
}

hidden_def(security_setenforce)
