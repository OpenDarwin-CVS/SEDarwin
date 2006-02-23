#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int main(int argc __attribute__ ((unused)), char **argv) 
{
	char *buf;
	int rc;

	rc = getcon(&buf);
	if (rc < 0) {
		fprintf(stderr, "%s:  getcon() failed\n", argv[0]);
		exit(2);
	}

	printf("%s\n", buf);
	freecon(buf);
	exit(0);
}
