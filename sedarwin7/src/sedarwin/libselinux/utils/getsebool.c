#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <selinux/selinux.h>

void usage(char *progname) 
{
	fprintf(stderr, "usage:  %s -a or %s boolean...\n", progname, progname);
	exit(1);
}

int main(int argc, char **argv)
{
	int i, rc = 0, active, pending, len = 0, opt;
	char **names;

	while ((opt = getopt(argc, argv, "a")) > 0) {
		switch (opt) {
		case 'a':
			if (argc > 2)
				usage(argv[0]);
			rc = security_get_boolean_names(&names, &len);
			if (rc) {
				fprintf(stderr, "%s:  Unable to get boolean names:  %s\n", argv[0], strerror(errno));
				exit(1);
			}
			if (!len) {
				printf("No booleans\n");
				exit(0);
			}
			break;
		default:
			usage(argv[0]);
		}
	}

	if (!len) {
		if (argc < 2) 
			usage(argv[0]);
		len = argc - 1;
		names = malloc(sizeof(char *)*len);
		if (!names) {
			fprintf(stderr, "%s:  out of memory\n", argv[0]);
			exit(2);
		}
		for (i = 0; i < len; i++) {
			names[i] = strdup(argv[i+1]);
			if (!names[i]) {
				fprintf(stderr, "%s:  out of memory\n", argv[0]);
				exit(2);
			}
		}
	}

	for (i = 0; i < len; i++) {
		active = security_get_boolean_active(names[i]);
		if (active < 0) {
			fprintf(stderr, "Error getting active value for %s\n",
				names[i]);
			rc = -1;
			goto out;
		}
		pending = security_get_boolean_pending(names[i]);
		if (pending < 0) {
			fprintf(stderr, "Error getting active value for %s\n",
				names[i]);
			rc = -1;
			goto out;
		}
		printf("%s --> active: %d pending: %d\n", names[i],
		       active, pending);
	}

out:
	for (i = 0; i < len; i++)
		free(names[i]);
	free(names);
	exit(rc);
}
