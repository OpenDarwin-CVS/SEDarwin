#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int main(int argc, char **argv) 
{
	int rc;

	rc = security_disable();
	if (rc < 0) {
		perror("disable");
		exit(2);
	}
	exit(0);
}
