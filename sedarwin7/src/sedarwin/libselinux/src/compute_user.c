#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <asm/page.h>
#include <selinux/selinux.h>
#include "policy.h"
#include <limits.h>
#include <selinux/context.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

int security_compute_user(security_context_t scon,
			  const char *user,
			  security_context_t **con)
{
	context_t cs;
	security_context_t ucon;
	struct av_decision avd;
	char path[PATH_MAX];
	char **ary;
	char *buf, *ptr;
	size_t size;
	int fd, ret;
	unsigned int i, nel;

	snprintf(path, sizeof path, "%s/user", selinux_mnt);
	fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;

	size = PAGE_SIZE;
	buf = malloc(size);
	if (!buf) {
		ret = -1;
		goto out;
	}
	snprintf(buf, size, "%s %s", scon, user);

	ret = write(fd, buf, strlen(buf));
	if (ret < 0) 
		goto out2;

	memset(buf, 0, size);
	ret = read(fd, buf, size-1);
	if (ret < 0)
		goto out2;

	if (sscanf(buf, "%u", &nel) != 1) {
		ret = -1;
		goto out2;
	}

	/* Manually check and insert the context with the same domain
	   to address the current bug in the kernel code that is omitting
	   such entries, until we can fix the kernel code. */
	cs = context_new(scon);
	if (!cs) {
		ret = -1;
		goto out2;
	}

	if (context_user_set(cs, user)) {
		ret = -1;
		goto out3;
	}
	ucon = context_str(cs);

	ary = malloc((nel+2)*sizeof(char*));
	if (!ary) {
		ret = -1;
		goto out3;
	}

	i = 0;
	ret = security_compute_av(scon, ucon, SECCLASS_PROCESS, PROCESS__TRANSITION, &avd);
	if (!ret && (avd.allowed & PROCESS__TRANSITION)) {
		ary[i] = strdup(ucon);
		if (!ary[i]) {
			ret = -1;
			freeconary(ary);
			goto out3;
		}
		i++;
		nel++;
	}

	ptr = buf + strlen(buf) + 1;
	for (; i < nel; i++) {
		ary[i] = strdup(ptr);
		if (!ary[i]) {
			freeconary(ary);
			ret = -1;
			goto out3;
		}
		ptr += strlen(ptr) + 1;
	}
	ary[nel] = NULL;
	*con = ary;
	ret = 0;
out3:
	context_free(cs);
out2:
	free(buf);
out:
	close(fd);
	return ret;
}
