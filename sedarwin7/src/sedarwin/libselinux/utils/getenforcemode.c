#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int main(int argc __attribute__ ((unused)), char **argv) 
{
	int ret;
	int enforce;
	ret = selinux_getenforcemode(&enforce);
	if (ret) {
		fprintf(stderr, "%s:  selinux_getenforcemode() failed\n", argv[0]);
		exit(2);
	}

	switch(enforce) {
	case 1:
	  printf("Enforcing\n");
	  break;

	case 0:
	  printf("Permissive\n");
	  break;

	case -1:
	  printf("Disabled\n");
	  break;

	}
	exit(0);
}
