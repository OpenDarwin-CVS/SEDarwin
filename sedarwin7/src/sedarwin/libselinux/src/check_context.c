#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/security.h>
#include <selinux/selinux.h>
#include <sedarwin/sebsd.h>

int security_check_context(security_context_t con)
{
	kern_return_t kr;
	char *buf;

	if (asprintf(&buf, "%s/%s", SEBSD_ID_STRING, con) == -1)
		return (-1);

	kr = mac_check_name_port_access(mach_task_self(), buf, mach_task_self(),
	    "file", "read");
	free(buf);
	if (kr == KERN_INVALID_ARGUMENT)
		return (-1);
	else
		return (0);
}
