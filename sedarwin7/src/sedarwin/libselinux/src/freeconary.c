#include <unistd.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <errno.h>

void freeconary(security_context_t *con)
{
	char **ptr;

	if (!con)
		return;

	for (ptr = con; *ptr; ptr++) {
		free(*ptr);
	}
	free(con);
}
