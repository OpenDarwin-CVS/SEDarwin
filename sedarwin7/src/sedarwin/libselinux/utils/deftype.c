#include <stdio.h>
#include <stdlib.h>
#include <selinux/get_default_type.h>

int main(int argc, char **argv) 
{
	char *type;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage:  %s role\n", argv[0]);
		exit(1);
	}
	rc = get_default_type(argv[1], &type);
	if (rc < 0) {
		fprintf(stderr, "%s:  get_default_type(%s) failed\n", argv[0], argv[1]);		
		exit(2);
	}
	
	printf("%s\n", type);
	free(type);
	exit(0);
}
