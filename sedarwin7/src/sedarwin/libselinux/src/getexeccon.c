#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "selinux_internal.h"
#include "policy.h"
#include <sys/mac.h>

int getexeccon_raw(security_context_t *context)
{
        int   r = 1;
        mac_t mac;
        char *string;

	if (mac_prepare(&mac, "sebsd"))
		return r;
	
        if (mac_get_proc(mac) ||
            mac_to_text(mac, &string))
                goto out;

        *context = strdup(string + strlen("sebsd/"));
        free(string);
        r = 0;
out:
        mac_free(mac);
        return r;
}
hidden_def(getexeccon_raw)

int getexeccon(security_context_t *context)
{
	int ret;
	security_context_t rcontext;

 	ret = getexeccon_raw(&rcontext);

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
