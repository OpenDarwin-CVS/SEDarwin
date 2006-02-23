#include <unistd.h>
#include <string.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <errno.h>
#include <sedarwin/sebsd.h>
#include <sys/mac.h>

int getcon(security_context_t *context)
{
	mac_t label;
	char *text;
	int ret;

	if (mac_prepare(&label, SEBSD_ID_STRING))
		return (-1);
	if (mac_get_proc(label)) {
		mac_free(label);
		return (-1);
	}
	ret = mac_to_text(label, &text);
	if (ret == 0) {
		*context = strdup(text+1+strlen(SEBSD_ID_STRING));
		free(text);
	} else
		*context = NULL;

	mac_free(label);
	return ret;
}
