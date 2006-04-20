#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include "selinux_internal.h"
#include "policy.h"

#ifndef SO_PEERSEC
#define SO_PEERSEC 31
#endif

int getpeercon_raw(int fd, security_context_t *context)
{
	return fgetfilecon(fd, context);
}
hidden_def(getpeercon_raw)

int getpeercon(int fd, security_context_t *context)
{
	int ret;
	security_context_t rcontext;

 	ret = getpeercon_raw(fd, &rcontext);

	if (context_translations && !ret) {
		if (raw_to_trans_context(rcontext, context)) {
			*context = NULL;
			ret = -1;
		}
		freecon(rcontext);
	} else if (!ret)
		*context = rcontext;

	return ret;
}
