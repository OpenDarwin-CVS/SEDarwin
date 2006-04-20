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

int security_compute_create_raw(security_context_t scon,
                                security_context_t tcon,
                                security_class_t tclass,
                                security_context_t *newcon)
{
	char path[PATH_MAX];
	char *buf;
	size_t size;
	int fd, ret;

	snprintf(path, sizeof path, "%s/create", selinux_mnt);
	fd = open(path, O_RDWR);
	if (fd < 0)
		return -1;

	size = getpagesize();
	buf = malloc(size);
	if (!buf) {
		ret = -1;
		goto out;
	}
	snprintf(buf, size, "%s %s %hu", scon, tcon, tclass);

	ret = write(fd, buf, strlen(buf));
	if (ret < 0) 
		goto out2;

	memset(buf, 0, size);
	ret = read(fd, buf, size-1);
	if (ret < 0)
		goto out2;

	*newcon = strdup(buf);
	if (!(*newcon)) {
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
hidden_def(security_compute_create_raw)

int security_compute_create(security_context_t scon,
                            security_context_t tcon,
                            security_class_t tclass,
                            security_context_t *newcon)
{
	int ret;
	security_context_t rscon = scon;
	security_context_t rtcon = tcon;
	security_context_t rnewcon;

	if (context_translations) {
		if (trans_to_raw_context(scon, &rscon))
			return -1;
		if (trans_to_raw_context(tcon, &rtcon)) {
			freecon(rscon);
			return -1;
		}
	}

 	ret = security_compute_create_raw(rscon, rtcon, tclass, &rnewcon);

	if (context_translations) {
		freecon(rscon);
		freecon(rtcon);
		if (!ret) {
			if (raw_to_trans_context(rnewcon, newcon)) {
				*newcon = NULL;
				ret = -1;
			}
			freecon(rnewcon);
		}
	} else if (!ret)
		*newcon = rnewcon;

	return ret;
}
hidden_def(security_compute_create)
