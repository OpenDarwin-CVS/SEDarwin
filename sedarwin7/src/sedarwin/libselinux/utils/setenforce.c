#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int main(int argc, char **argv) 
{
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage:  %s value\n", argv[0]);
		exit(1);
	}

	rc = security_setenforce(atoi(argv[1]));
	if (rc < 0) {
		fprintf(stderr, "%s:  setenforce() failed\n", argv[0]);
		exit(2);
	}
	exit(0);
}
