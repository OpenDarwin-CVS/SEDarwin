#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "selinux_internal.h"
#include "policy.h"
#include <sys/mac.h>

int getpidcon_raw(pid_t pid, security_context_t *context)
{
        int   r = 1;
        mac_t mac;
        char *string;

	if (mac_prepare(&mac, "sebsd"))
		return r;
	
        if (mac_get_pid(pid, mac) ||
            mac_to_text(mac, &string))
                goto out;

        *context = strdup(string + strlen("sebsd/"));
        free(string);
        r = 0;
out:
        mac_free(mac);
        return r;
}
hidden_def(getpidcon_raw)

int getpidcon(pid_t pid, security_context_t *context)
{
	int ret;
	security_context_t rcontext;

 	ret = getpidcon_raw(pid, &rcontext);

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
