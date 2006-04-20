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

int security_compute_av_raw(security_context_t scon,
                            security_context_t tcon,
                            security_class_t tclass,
                            access_vector_t requested,
                            struct av_decision *avd)
{
        char *arguments;
        size_t avd_len;
        ssize_t arguments_len;

        arguments_len = asprintf(&arguments, "%s%c%s%c%s", scon, 0,
            tcon, 0, "1212345678");
        if (arguments_len == -1)
                return (-1);
        memcpy(&arguments[arguments_len - (2 + 8)], &tclass,
            sizeof(tclass));
        memcpy(&arguments[arguments_len - 2], &requested,
            sizeof(requested));
        avd_len = sizeof(*avd);
        if (sysctlbyname("security.mac.sebsd.compute_av", avd,
            &avd_len, arguments, arguments_len) == -1) {
                free(arguments);
                return (-1);
        }
        if (avd_len != sizeof(*avd)) {
                free(arguments);
                errno = ENOMEM;
                return (-1);
        }
        free(arguments);
        return (0);
}
hidden_def(security_compute_av_raw)

int security_compute_av(security_context_t scon,
                        security_context_t tcon,
                        security_class_t tclass,
                        access_vector_t requested,
                        struct av_decision *avd)
{
	int ret;
	security_context_t rscon = scon;
	security_context_t rtcon = tcon;

	if (context_translations) {
		if (trans_to_raw_context(scon, &rscon))
			return -1;
		if (trans_to_raw_context(tcon, &rtcon)) {
			freecon(rscon);
			return -1;
		}
	}

 	ret = security_compute_av_raw(rscon, rtcon, tclass, requested, avd);

	if (context_translations) {
		freecon(rscon);
		freecon(rtcon);
	}

	return ret;
}
hidden_def(security_compute_av)
