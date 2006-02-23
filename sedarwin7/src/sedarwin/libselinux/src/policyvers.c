#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include "policy.h"
#include <limits.h>

#define DEFAULT_POLICY_VERSION 15

int security_policyvers(void)
{
	int fd, ret;
	char path[PATH_MAX];
	char buf[20];
	unsigned vers = DEFAULT_POLICY_VERSION;

	snprintf(path, sizeof path, "%s/policyvers", selinux_mnt);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return vers;
		else
			return -1;
	}
	memset(buf, 0, sizeof buf);
	ret = read(fd, buf, sizeof buf-1);
	close(fd);
	if (ret < 0)
		return -1;

	if (sscanf(buf, "%u", &vers) != 1)
		return -1;

	return vers;
}
