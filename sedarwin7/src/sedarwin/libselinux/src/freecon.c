#include <unistd.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <errno.h>

void freecon(security_context_t con)
{
	free(con);
}
