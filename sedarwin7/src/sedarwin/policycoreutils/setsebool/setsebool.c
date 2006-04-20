#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>
#include <selinux/selinux.h>
#include <semanage/handle.h>
#include <semanage/booleans_local.h>
#include <semanage/booleans_active.h>
#include <semanage/boolean_record.h>
#include <errno.h>

int permanent = 0;

int setbool(char **list, size_t start, size_t end);


void usage(void)
{
	fputs("\nUsage:  setsebool [ -P ] boolean value | bool1=val1 bool2=val2...\n\n", stderr);
	exit(1);
}

int main(int argc, char **argv)
{
	size_t rc, start;

	if (argc < 2) 
		usage();

	if (is_selinux_enabled() <= 0) {
		fputs("setsebool:  SELinux is disabled.\n", stderr);
		return 1;
	}

	if (strcmp(argv[1], "-P") == 0) {
		permanent = 1;
		if (argc < 3) 
			usage();
		start = 2;
	}
	else
		start = 1;

	/* Check to see which way we are being called. If a '=' is passed,
	   we'll enforce the list syntax. If not we'll enforce the original
	   syntax for backward compatibility. */
	if (strchr(argv[start], '=') == 0) {
		int len;
		char *bool_list[1];

		if ((argc - start) != 2)
			usage();

		/* Add 1 for the '=' */
		len = strlen(argv[start]) + strlen(argv[start+1]) + 2;
		bool_list[0]=(char *)malloc(len);
		if (bool_list[0] == 0) {
			fputs("Out of memory - aborting\n", stderr);
			return 1;
		}
		snprintf(bool_list[0], len, "%s=%s", argv[start], 
							argv[start+1]);
		rc = setbool(bool_list, 0, 1);
		free(bool_list[0]);
	}
	else 
		rc = setbool(argv, start, argc);

	return rc;
}

/* Apply boolean changes to policy via libselinux */
static int selinux_set_boolean_list(
	size_t boolcnt, 
	SELboolean *boollist, 
	int permanent) {

	if (security_set_boolean_list(boolcnt, boollist, permanent)) {
		if (errno == ENOENT)
			fprintf(stderr, "Could not change active booleans: "
				"Invalid boolean\n");
		else if (errno)
			perror("Could not change active booleans");
	
		return -1;
	}
	
	return 0;
}

/* Apply (permanent) boolean changes to policy via libsemanage */
static int semanage_set_boolean_list(
	size_t boolcnt, 
	SELboolean *boollist,
	int permanent) {

	size_t j;
	semanage_handle_t* handle = NULL;
	semanage_bool_t* boolean = NULL;
	semanage_bool_key_t* bool_key = NULL;
	int managed;

	handle = semanage_handle_create();
	if (handle == NULL) {
		fprintf(stderr, "Could not create semanage library handle\n"); 
		goto err;
	}

	managed = semanage_is_managed(handle);
	if (managed < 0) {
		fprintf(stderr, "Error when checking whether policy is managed\n"); 
		goto err;

	} else if (managed == 0) {
		if (selinux_set_boolean_list(boolcnt, boollist, 1) < 0)
			goto err;
		goto out;
	}

	if (semanage_connect(handle) < 0)
		goto err;

	if (semanage_begin_transaction(handle) < 0)
		goto err;

	for (j = 0; j < boolcnt; j++) {
		
		if (semanage_bool_create(handle, &boolean) < 0) 
			goto err;

		if (semanage_bool_set_name(handle, boolean, boollist[j].name) < 0)
			goto err;

		semanage_bool_set_value(boolean, boollist[j].value);

		if (semanage_bool_key_extract(handle, boolean, &bool_key) < 0)
			goto err;

		if (permanent && semanage_bool_modify_local(handle, bool_key, boolean) < 0)
			goto err;

		if (semanage_bool_set_active(handle, bool_key, boolean) < 0) {
			fprintf(stderr, "Could not change boolean %s\n", boollist[j].name);
			goto err;
		}
		semanage_bool_key_free(bool_key);
		semanage_bool_free(boolean);
		bool_key = NULL;
		boolean = NULL;
	}	

	semanage_set_reload(handle, 0);
	if (semanage_commit(handle) < 0)
		goto err;

	semanage_disconnect(handle);

        out:
	semanage_handle_destroy(handle);
	return 0;

	err:
	semanage_bool_key_free(bool_key);
	semanage_bool_free(boolean);
	semanage_handle_destroy(handle);
	fprintf(stderr, "Could not change policy booleans\n");
	return -1;
}

/* Given an array of strings in the form "boolname=value", a start index,
   and a finish index...walk the list and set the bool. */
int setbool(char **list, size_t start, size_t end)
{
	char *name, *value_ptr;
	int j=0, value;
	size_t i = start;
	size_t boolcnt=end-start;
	struct passwd *pwd;
	SELboolean *vallist=calloc(boolcnt, sizeof(SELboolean));
	if (!vallist)
		goto omem;

	while (i < end) {
		name = list[i];
		value_ptr = strchr(list[i], '=');
		if (value_ptr == 0) {
			fprintf(stderr, 
			"setsebool: '=' not found in boolean expression %s\n",
				list[i]);
			goto err;
		}
		*value_ptr = 0;
		value_ptr++;
		if (strcmp(value_ptr, "1") == 0 || 
				strcasecmp(value_ptr, "true") == 0)
			value = 1;
		else if (strcmp(value_ptr, "0") == 0 || 
				strcasecmp(value_ptr, "false") == 0)
			value = 0;
		else {
			fprintf(stderr, "setsebool: illegal value "
					"%s for boolean %s\n",
					value_ptr, name);
			goto err;
		}

		vallist[j].value = value;
		vallist[j].name = strdup(name);
		if (!vallist[j].name)
			goto omem;
		i++;
		j++;

		/* Now put it back */
		value_ptr--;
		*value_ptr = '=';
	} 

	if (semanage_set_boolean_list(boolcnt, vallist, permanent) < 0)
		goto err;

	/* Now log what was done */
	pwd = getpwuid(getuid());
	i = start;
	while (i < end) {
		name = list[i];
		value_ptr = strchr(name, '=');
		*value_ptr = 0;
		value_ptr++;
		if (pwd && pwd->pw_name)
			syslog(LOG_NOTICE,
				"The %s policy boolean was changed to %s by %s",
				name, value_ptr, pwd->pw_name);
		else
			syslog(LOG_NOTICE,
				"The %s policy boolean was changed to %s by uid:%d",
				name, value_ptr, getuid());
		i++;
	}

	for (i=0; i < boolcnt; i++)
		free(vallist[i].name);
	free(vallist);
	return 0;
		
	omem:
	fprintf(stderr, "setsebool: out of memory");
		
	err:
	for (i=0; i < boolcnt; i++) 
		free(vallist[i].name);
	free(vallist);
	return -1;
}

