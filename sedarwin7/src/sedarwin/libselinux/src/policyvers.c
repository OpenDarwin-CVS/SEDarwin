#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include "dso.h"

#define DEFAULT_POLICY_VERSION 15

int security_policyvers(void)
{
	int policyvers;
	size_t len;

	len = sizeof(policyvers);
	if (sysctlbyname("security.mac.sebsd.policyvers", &policyvers, &len,
	    NULL, 0) == -1 || len != sizeof(policyvers))
		policyvers = DEFAULT_POLICY_VERSION;

	return policyvers;
}
hidden_def(security_policyvers)

