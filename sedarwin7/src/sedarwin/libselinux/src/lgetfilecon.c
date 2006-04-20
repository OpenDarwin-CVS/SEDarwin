#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "selinux_internal.h"
#include "policy.h"
#include <sys/mac.h>

int lgetfilecon_raw(const char *path, security_context_t *context)
{
        int   r = -1;
        mac_t mac;
        char *string;

        if (mac_prepare(&mac, "sebsd"))
	       return r;
        if (mac_get_link(path, mac) ||
            mac_to_text(mac, &string))
                goto out;

        *context = strdup(string + strlen("sebsd/"));
        r = strlen(*context);
        free(string);
out:
        mac_free(mac);
        return r;
}
hidden_def(lgetfilecon_raw)

int lgetfilecon(const char *path, security_context_t *context)
{
	int ret;
	security_context_t rcontext;

 	ret = lgetfilecon_raw(path, &rcontext);

	if (context_translations && ret > 0) {
		if (raw_to_trans_context(rcontext, context)) {
			*context = NULL;
			ret = -1;
		}
		freecon(rcontext);
	} else if (ret > 0)
		*context = rcontext;

	return ret;
}
