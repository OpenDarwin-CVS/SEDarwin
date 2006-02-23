#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int main(int argc __attribute__((unused)), char **argv) 
{
	int rc;

	rc = is_selinux_enabled();
	if (rc < 0) {
		fprintf(stderr, "%s:  is_selinux_enabled() failed\n", argv[0]);
		exit(2);
	}
	if (rc == 1) { 
		rc = security_getenforce();
		if (rc < 0) {
			fprintf(stderr, "%s:  getenforce() failed\n", argv[0]);
			exit(2);
		}

		if (rc)
			printf("Enforcing\n");
		else
			printf("Permissive\n");
	} else {
		printf("Disabled\n");
	}
	
	exit(0);
}
