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

int security_compute_user_raw(security_context_t scon,
                              const char *user,
                              security_context_t **con)
{
        char *arguments, *contexts, *s, **contextarray;
        ssize_t arguments_len;
        size_t contexts_len, n;
        int error;

        arguments_len = asprintf(&arguments, "%s%c%s%c", scon, 0,
            user, 0);
        if (arguments_len == -1)
                return (-1);
bigger:
        contexts_len = 0;
        if (sysctlbyname("security.mac.sebsd.user_sids", NULL, &contexts_len,
            arguments, arguments_len) == -1) {
                free(arguments);
                return (-1);
        }
        contexts = malloc(contexts_len);
        if (contexts == NULL) {
                free(arguments);
                return (-1);
        }
        error = sysctlbyname("security.mac.sebsd.user_sids", contexts,
            &contexts_len, arguments, arguments_len);
        /*
         * We could possibly race and not have a large enough space
         * for the current set of contexts.
         */
        if (error == -1 && errno == ENOMEM) {
                free(contexts);
                goto bigger;
        }
        free(arguments);
        if (error == -1) {
                free(contexts);
                return (-1);
        }
        n = 0;
        for (s = contexts; s < &contexts[contexts_len - 1]; s += strlen(s) + 1)
                n++;
        if (!n) {
                free(contexts);
                return (-1);
        }
        contextarray = calloc(n + 1, sizeof(char *));
        if (contextarray == NULL) {
                free(contexts);
                return (-1);
        }
        n = 0;
        for (s = contexts; s < &contexts[contexts_len - 1];
            s += strlen(s) + 1) {
                contextarray[n] = strdup(s);
                /* upon failure here, just free everything */
                if (contextarray[n] == NULL) {
                        while (n > 0) 
                                free(contextarray[--n]);
			free(contextarray);
			free(contexts);
			return (-1);
                }
                n++;
        }
	free(contexts);
	contextarray[n] = NULL;
        *con = contextarray;
        return (0);
}	
hidden_def(security_compute_user_raw)

int security_compute_user(security_context_t scon,
                          const char *user,
                          security_context_t **con)
{
	int ret;
	security_context_t rscon = scon;

	if (context_translations && trans_to_raw_context(scon, &rscon))
		return -1;

 	ret = security_compute_user_raw(rscon, user, con);

	if (context_translations) {
		freecon(rscon);
		if (!ret) {
			security_context_t *ptr, tmpcon;
			for (ptr = *con; *ptr; ptr++) {
				if (raw_to_trans_context(*ptr, &tmpcon)) {
					freeconary(*con);
					*con = NULL;
					return -1;
				}
				freecon(*ptr);
				*ptr = tmpcon;
			}
		}
	}

	return ret;
}
hidden_def(security_compute_user)
