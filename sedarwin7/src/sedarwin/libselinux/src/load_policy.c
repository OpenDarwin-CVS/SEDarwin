#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <selinux/selinux.h>
#include "policy.h"
#include <limits.h>

int security_load_policy(void *data, size_t len)
{
	char path[PATH_MAX];
	int fd, ret;
	
	snprintf(path, sizeof path, "%s/load", selinux_mnt);
	fd = open(path, O_RDWR);
	if (fd < 0) 
		return -1;

	ret = write(fd, data, len);
	close(fd);
	if (ret < 0)
		return -1;
	return 0;
}

