#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/xattr.h>
#include "policy.h"

int lsetfilecon(const char *path, security_context_t context)
{
	return lsetxattr(path, XATTR_NAME_SELINUX, context, strlen(context)+1, 0);
}
