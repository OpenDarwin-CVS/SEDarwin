#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <errno.h>
#include <asm/page.h>
#include "policy.h"

int getfscreatecon(security_context_t *context)
{
	char *buf;
	size_t size;
	int fd;
	ssize_t ret;

	fd = open("/proc/self/attr/fscreate", O_RDONLY);
	if (fd < 0)
		return -1;

	size = PAGE_SIZE;
	buf = malloc(size);
	if (!buf) {
		ret = -1;
		goto out;
	}
	memset(buf, 0, size);

	ret = read(fd, buf, size-1);
	if (ret < 0)
		goto out2;

	if (ret == 0) {
		*context = NULL;
		goto out2;
	}

	*context = strdup(buf);
	if (!(*context)) {
		ret = -1;
		goto out2;
	}
	ret = 0;
out2:			
	free(buf);
out:
	close(fd);
	return ret;
}
