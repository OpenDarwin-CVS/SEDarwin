#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <selinux/selinux.h>


int main(int argc, char **argv)
{
	int rc, value;

	if (argc != 3) {
		fprintf(stderr, "usage:  %s boolean value\n", argv[0]);
		exit(1);
	}

	if (strcmp(argv[2], "1") == 0 || strcasecmp(argv[2], "true") == 0)
		value = 1;
	else if (strcmp(argv[2], "0") == 0 || strcasecmp(argv[2], "false") == 0)
		value = 0;
	else {
		fprintf(stderr, "%s:  illegal boolean value %s\n", argv[0], argv[2]);
		exit(1);
	}

	rc = security_set_boolean(argv[1], value);

	if (rc) {
		fprintf(stderr, "error setting boolean %s to value %d\n",
			argv[1], value);
		exit(2);
	}

	rc = security_commit_booleans();

	if (rc) {
		fprintf(stderr, "error committing booleans\n");
		exit(3);
	}

	exit(0);
}
