#include <sys/types.h>
#include "dso.h"

/*
 * SELinux's init(8) uses this to disable the SELinux module before
 * the policy is loaded.  In SEDarwin we would just not load the
 * module so this function is a no-op.
 */
int security_disable(void)
{
	return -1;
}
hidden_def(security_disable);

