#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <selinux/selinux.h>

int main(int argc, char **argv) 
{
	int rc;

	if (argc < 3) {
		fprintf(stderr, "usage:  %s context program args...\n",
			argv[0]);
		exit(1);
	}

	rc = setexeccon(argv[1]);
	if (rc < 0) {
		fprintf(stderr, "%s:  setexeccon(%s) failed\n", 
			argv[0], argv[1]);
		exit(2);
	}

	execvp(argv[2], &argv[2]); 
	perror("execv");
	exit(3);
}
