#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <asm/page.h>
#include <stdio.h>
#include "policy.h"

int is_selinux_enabled(void)
{
	char *buf;
	size_t size;
	int fd;
	ssize_t ret;
	int enabled = 0;
	security_context_t con;

	fd = open("/proc/filesystems", O_RDONLY);
	if (fd < 0)
		return -1;

	size = PAGE_SIZE;
	buf = malloc(size);
	if (!buf) {
		enabled = -1;
		goto out;
	}
		
	memset(buf, 0, size);

	ret = read(fd, buf, size - 1);
	if (ret < 0) {
		enabled = -1;
		goto out2;
	}

	if (!strstr(buf, "selinuxfs"))
		goto out2;

	enabled = 1;

	if (getcon(&con) == 0) {
		if (!strcmp(con, "kernel"))
			enabled = 0;
		freecon(con);
	}
out2:
	free(buf);
out:
	close(fd);
	return enabled;
}

/*
 * Function: is_selinux_mls_enabled()
 * Return:   1 on success
 *	     0 on failure
 */
int is_selinux_mls_enabled(void)
{
	char buf[20], path[PATH_MAX];
	int fd, ret, enabled = 0;

	snprintf(path, sizeof path, "%s/mls", selinux_mnt);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return enabled;

	memset(buf, 0, sizeof buf);

	ret = read(fd, buf, sizeof buf-1);
	close(fd);
	if (ret < 0)
		return enabled;

	if (!strcmp(buf, "1"))
		enabled = 1;

	return enabled;
}
