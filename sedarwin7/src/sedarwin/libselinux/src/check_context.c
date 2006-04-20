#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "selinux_internal.h"
#include "policy.h"
#include <limits.h>

int security_check_context_raw(security_context_t con)
{
	char path[PATH_MAX];
	int fd, ret;

	snprintf(path, sizeof path, "%s/context", selinux_mnt);
	fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;

	ret = write(fd, con, strlen(con)+1);
	close(fd);
	if (ret < 0)
		return -1;
	return 0;
}
hidden_def(security_check_context_raw)

int security_check_context(security_context_t con)
{
	int ret;
	security_context_t rcon = con;

	if (context_translations && trans_to_raw_context(con, &rcon))
		return -1;

 	ret = security_check_context_raw(rcon);

	if (context_translations)
		freecon(rcon);

	return ret;
}
hidden_def(security_check_context)
