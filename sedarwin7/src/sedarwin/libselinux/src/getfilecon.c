#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "selinux_internal.h"
#include <stdlib.h>
#include <errno.h>
#include "policy.h"
#include <sys/mac.h>

int getfilecon_raw(const char *path, security_context_t *context)
{
        int   r = -1;
        mac_t mac;
        char *string;

	if (mac_prepare(&mac, "sebsd"))
		return r;
	
        if (mac_get_file(path, mac) ||
            mac_to_text(mac, &string))
                goto out;

        *context = strdup(string + strlen("sebsd/"));
        r = strlen(*context);
        free(string);
out:
        mac_free(mac);
        return r;
}
hidden_def(getfilecon_raw)

int getfilecon(const char *path, security_context_t *context)
{
	int ret;
	security_context_t rcontext;

 	ret = getfilecon_raw(path, &rcontext);

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
hidden_def(getfilecon)
