/*
 * Author: Karl MacMillan <kmacmillan@tresys.com>
 *
 * Modified:  
 *   Dan Walsh <dwalsh@redhat.com> - Added security_load_booleans().
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fnmatch.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include <selinux/selinux.h>
#include <sedarwin/sebsd_syscalls.h>
#include "policy.h"

int security_get_boolean_names(char ***names, int *len)
{
	struct sebsd_get_bools gb;
	int i, err, rc = -1;
	char **n;
	int num = 0;
	char *p, *q;

	gb.out = NULL;
	gb.len = 0;

	err = mac_syscall("sebsd", SEBSDCALL_GET_BOOLS, &gb);

	if (err && errno != ENOMEM)
		return (-1);
	gb.out = malloc (gb.len);

	err = mac_syscall("sebsd", SEBSDCALL_GET_BOOLS, &gb);
	if (err)
		goto out;

	for (p = gb.out; p-gb.out < gb.len; p++)
		if (*p == ';')
			num++;

	n = (char**)malloc(sizeof(char*) * num);
	if (!n)
		goto out;

	p = gb.out;
	for (i = 0; i < num; i++) {
		p += 2;
		for (q = p; *q != ';'; q++);

		n[i] = (char*)malloc(sizeof(char) * (1+q-p));
		if (!n[i])
			goto bad;
		strncpy(n[i], p, q-p);
		n[i][q-p] = 0;
		p = q+1;
	}
	rc = 0;
	*names = n;
	*len = num;
	goto out;

bad:
	for (i = 0; i < *len; i++) {
		if (n[i])
			free(n[i]);
	}
	free(n);
out:
	if (gb.out)
		free(gb.out);

	return rc;
}

int security_get_boolean_pending(const char *name)
{
	int r = mac_syscall("sebsd", SEBSDCALL_GET_BOOL, name);
	if (r < 0)
		return -1;
	return (r & 2) >> 1;
}

int security_get_boolean_active(const char *name)
{
	int r = mac_syscall("sebsd", SEBSDCALL_GET_BOOL, name);
	if (r < 0)
		return -1;
	return (r & 1);
}

struct lp_args
{
	void  *data;
	size_t len;
};

int security_set_boolean(const char *name, int value)
{
	struct lp_args args;
	char str[strlen(name) + 2];

	str[0] = value + '0';
	strcpy (str+1, name);
	args.data = str;
	args.len = 1+strlen(str);
	int err = mac_syscall("sebsd", SEBSDCALL_SET_BOOL, &args);
	if (err)
		perror (name);
	return err;
}

int security_commit_booleans(void)
{
	return mac_syscall ("sebsd", SEBSDCALL_COMMIT_BOOLS, NULL);
}

static char *strtrim(char *dest, char *source, int size) {
	int i=0;
	char *ptr=source;
	i=0;
	while(isspace(*ptr) && i < size) {
		ptr++;
		i++;
	}
	strncpy(dest,ptr,size);
	for(i=strlen(dest)-1; i> 0; i--) {
		if (!isspace(dest[i])) break;
	}
	dest[i+1]='\0';
	return dest;
}

int security_load_booleans(char *path) {
	FILE *boolf;
	char buffer[BUFSIZ];
	char name[BUFSIZ];
	char name1[BUFSIZ];
	int val;
	int errors=0;

	boolf = fopen(path ? path : selinux_booleans_path(),"r");
	if (boolf == NULL) 
		return -1;

        while (fgets(buffer, sizeof(buffer), boolf)) {
		char *tok=strtok(buffer,"=");
		if (tok) {
			strncpy(name1,tok, BUFSIZ-1);
			strtrim(name,name1,BUFSIZ-1);
			if ( name[0]=='#' ) continue;
			tok=strtok(NULL,"\0");
			if (tok) {
				while (isspace(*tok)) tok++;
				val = -1;
				if (isdigit(tok[0]))
					val=atoi(tok);
				else if (!strncmp(tok, "true", sizeof("true")-1))
					val = 1;
				else if (!strncmp(tok, "false", sizeof("false")-1))
					val = 0;
				if (val != 0 && val != 1) {
					fprintf(stderr,"illegal value for boolean %s=%s\n", name, tok);
					errors++;
					continue;
				}

				if (security_set_boolean(name, val) < 0) {
					fprintf(stderr,"error setting boolean %s to value %d \n", name, val);
					errors++;
				}
			}
		}
	}
	fclose(boolf);

	if (security_commit_booleans() < 0)
		return -1;

	if (errors)
		errno = EINVAL;
	return errors ? -1 : 0;
}
