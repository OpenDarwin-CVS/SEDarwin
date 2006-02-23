#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "policy.h"

int getfilecon(const char *path, security_context_t *context)
{
	char *buf;
	ssize_t size;
	ssize_t ret;

	size = INITCONTEXTLEN+1;
	buf = malloc(size);
	if (!buf) 
		return -1;
	memset(buf, 0, size);

	ret = getxattr(path, XATTR_NAME_SELINUX, buf, size-1);
	if (ret < 0 && errno == ERANGE) {
		char *newbuf;

		size = getxattr(path, XATTR_NAME_SELINUX, NULL, 0);
		if (size < 0)
			goto out;

		size++;
		newbuf = realloc(buf, size);
		if (!newbuf)
			goto out;

		buf = newbuf;
		memset(buf, 0, size);
		ret = getxattr(path, XATTR_NAME_SELINUX, buf, size-1); 
	}
out:			
	if (ret < 0)
		free(buf);
	else
		*context = buf;
	return ret;
}
