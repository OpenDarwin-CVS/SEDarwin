
#include "sebsd.h"
#include <sys/mac.h>

int getfilecon(const char *path, security_context_t *con)
{
	int   r = 1;
	mac_t mac;
	char *string;

	if (mac_prepare(&mac, "sebsd") ||
	    mac_get_file(path, mac) ||
	    mac_to_text(mac, &string))
		goto out;

	*con = strdup(string + strlen("sebsd/"));
	free(string);
	r = 0;
out:
	mac_free(mac);
	return r;
}

int lgetfilecon(const char *path, security_context_t *con)
{
	int   r = 1;
	mac_t mac;
	char *string;

	if (mac_prepare(&mac, "sebsd") ||
	    mac_get_link(path, mac) ||
	    mac_to_text(mac, &string))
		goto out;

	*con = strdup(string + strlen("sebsd/"));
	free(string);
	r = 0;
out:
	mac_free(mac);
	return r;
}

int fgetfilecon(int fd, security_context_t *con)
{
	int   r = 1;
	mac_t mac;
	char *string;

	if (mac_prepare(&mac, "sebsd") ||
	    mac_get_fd(fd, mac) ||
	    mac_to_text(mac, &string))
		goto out;

	*con = strdup(string + strlen("sebsd/"));
	free(string);
	r = 0;
out:
	mac_free(mac);
	return r;
}

int setfilecon(const char *path, security_context_t con)
{
	mac_t mac;
	char  tmp[strlen(con) + strlen("sebsd/0")];
	int   r;

	if (mac_prepare(&mac, "sebsd"))
		return 1;

	strcpy(tmp, "sebsd/");
	strcat(tmp, con);
	if (mac_from_text(&mac, tmp)) {
		mac_free(mac);
		return 1;
	}
	r = mac_set_file(path, mac);
	mac_free(mac);
	return r;
}

int lsetfilecon(const char *path, security_context_t con)
{
	mac_t mac;
	char  tmp[strlen(con) + strlen("sebsd/0")];
	int   r;

	if (mac_prepare(&mac, "sebsd"))
		return 1;

	strcpy(tmp, "sebsd/");
	strcat(tmp, con);
	if (mac_from_text(&mac, tmp)) {
		mac_free(mac);
		return 1;
	}
	r = mac_set_link(path, mac);
	mac_free(mac);
	return r;
}

int fsetfilecon(int fd, security_context_t con)
{
	mac_t mac;
	char  tmp[strlen(con) + strlen("sebsd/0")];
	int   r;

	if (mac_prepare(&mac, "sebsd"))
		return 1;

	strcpy(tmp, "sebsd/");
	strcat(tmp, con);
	if (mac_from_text(&mac, tmp)) {
		mac_free(mac);
		return 1;
	}
	r = mac_set_fd(fd, mac);
	mac_free(mac);
	return r;
}
