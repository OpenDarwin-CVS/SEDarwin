#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"
#include "policy.h"
#include <limits.h>

#ifdef notyet
int security_canonicalize_context_raw(security_context_t con,
				      security_context_t *canoncon)
{
	char path[PATH_MAX];
	char *buf;
	size_t size;
	int fd, ret;

	snprintf(path, sizeof path, "%s/context", selinux_mnt);
	fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;

	size = getpagesize();
	buf = malloc(size);
	if (!buf) {
		ret = -1;
		goto out;
	}
	strncpy(buf, con, size);

	ret = write(fd, buf, strlen(buf)+1);
	if (ret < 0)
		goto out2;

	memset(buf, 0, size);
	ret = read(fd, buf, size-1);
	if (ret < 0 && errno == EINVAL) {
		/* Fall back to the original context for kernels
		   that do not support the extended interface. */
		strncpy(buf, con, size);
	}

	*canoncon = strdup(buf);
	if (!(*canoncon)) {
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
hidden_def(security_canonicalize_context_raw)
#endif
	
int security_canonicalize_context(security_context_t con,
				  security_context_t *canoncon)
{

/* 
 * XXX: This isn't supported by the kernel module yet.  For now we jump
 * straight to the fall-back clause in security_canonicalize_context_raw()
 * and return an unaltered context.
 */
	*canoncon = strdup(con);
	return 0;
	
#ifdef notyet
	int ret;
	security_context_t rcon = con;
	security_context_t rcanoncon;

	if (context_translations && trans_to_raw_context(con, &rcon))
		return -1;

 	ret = security_canonicalize_context_raw(rcon, &rcanoncon);

	if (context_translations) {
		freecon(rcon);
		if (!ret) {
			if (raw_to_trans_context(rcanoncon, canoncon)) {
				*canoncon = NULL;
				ret = -1;
			}
			freecon(rcanoncon);
		}
	} else if (!ret) {
		*canoncon = rcanoncon;
	}

	return ret;
#endif
}
hidden_def(security_canonicalize_context)
