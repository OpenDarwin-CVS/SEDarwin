#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "selinux_internal.h"
#include <stdlib.h>
#include <errno.h>
#include "policy.h"
#include <sedarwin/linux-compat.h>
#include <sedarwin/sebsd.h>
#include <sys/mac.h>

int getcon_raw(security_context_t *context)
{
        mac_t label;
        char *string;
        int error;
	int ret = 0;

        error = mac_prepare(&label, SEBSD_ID_STRING);
	if (error)
		return -1;
        error = mac_get_proc(label);
        if (error) {
		ret = -1;
		goto out;
	}
        error = mac_to_text(label, &string);
	if (error || string == NULL) {
		ret = -1;
		goto out;
	}
        *context = strdup(string + sizeof("sebsd/") - 1);
        free(string);
out:
	mac_free(label);
	return ret;
}
hidden_def(getcon_raw)

int getcon(security_context_t *context)
{
	int ret;
	security_context_t rcontext;

 	ret = getcon_raw(&rcontext);

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
hidden_def(getcon)
