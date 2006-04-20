#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "selinux_internal.h"
#include "policy.h"
#include <limits.h>

int security_compute_relabel_raw(security_context_t scon,
                                 security_context_t tcon,
                                 security_class_t tclass,
                                 security_context_t *newcon)
{
        char *arguments;
        ssize_t arguments_len;
        size_t newcontext_len;
        int error;

        arguments_len = asprintf(&arguments, "%s%c%s%c%s", scon, 0,
            tcon, 0, "12");
        if (arguments_len == -1)
                return (-1);
        memcpy(&arguments[arguments_len - 2], &tclass, sizeof(tclass));
bigger:
        newcontext_len = 0;
        if (sysctlbyname("security.mac.sebsd.change_sid", NULL, &newcontext_len,            arguments, arguments_len) == -1) {
                free(arguments);
                return (-1);
        }
        *newcon = malloc(newcontext_len);
        if (*newcon == NULL) {
                free(arguments);
                return (-1);
        }
        error = sysctlbyname("security.mac.sebsd.change_sid", *newcon,
            &newcontext_len, arguments, arguments_len);
	/*
	 * We could possibly race and not have a large enough space
	 * for the current set of contexts.
	 */
        if (error == -1 && errno == ENOMEM) {
                free(*newcon);
                goto bigger;
        }
        free(arguments);
        if (error == -1) {
                free(*newcon);
                return (-1);
        }
        return (0);

}
hidden_def(security_compute_relabel_raw)

int security_compute_relabel(security_context_t scon,
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

 	ret = security_compute_relabel_raw(rscon, rtcon, tclass, &rnewcon);

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
