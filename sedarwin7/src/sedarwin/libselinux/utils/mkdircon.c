#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <selinux/selinux.h>

int main(int argc, char **argv) 
{
	int rc;
	int i;

	if (argc < 3) {
		fprintf(stderr, "usage:  %s context dirname...\n",
			argv[0]);
		exit(1);
	}

	rc = setfscreatecon(argv[1]);
	if (rc < 0) {
		fprintf(stderr, "%s:  setfscreatecon(%s) failed\n", 
			argv[0], argv[1]);
		exit(2);
	}

	for (i = 2; i < argc; i++) {
		rc = mkdir(argv[i], 0755);
		if (rc < 0) {
			perror(argv[i]);
			exit(3);
		}
	}
	exit(0);
}
