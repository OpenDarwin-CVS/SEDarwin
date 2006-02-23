/*
 * genpolbools old-policy booleans new-policy
 *
 * Given an existing binary policy and a boolean configuration, generate a 
 * new binary policy with the specified initial boolean values and rules
 * enabled based on a re-evaluation of the new boolean values.
 */ 

#include <sepol/policydb.h>
#include <sepol/services.h>
#include <sepol/conditional.h>
#include <sepol/sepol.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

void usage(char *progname)
{
	printf("usage:  %s old-policy booleans new-policy\n", progname);
	exit(1);
}

int main(int argc, char **argv)
{
	struct stat sb;
	FILE *outfp;
	int fd, rc;
	void *map;

	if (argc != 4) 
		usage(argv[0]);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
			argv[1], strerror(errno));
		exit(1);
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Can't stat '%s':  %s\n",
			argv[1], strerror(errno));
		exit(1);
	}
	map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Can't map '%s':  %s\n",
			argv[1], strerror(errno));
		exit(1);
	}

	if (sepol_genbools(map, sb.st_size, argv[2]) < 0) {
		fprintf(stderr, "Error while processing %s:  %s\n",
			argv[2], strerror(errno));
		exit(1);
	}

	outfp = fopen(argv[3], "w");
	if (!outfp) {
		perror(argv[3]);
		exit(1);
	}
	rc = fwrite(map, sb.st_size, 1, outfp);
	if (rc != 1) {
		fprintf(stderr, "%s:  error writing %s\n",
			argv[0], argv[3]);
		exit(1);
	}
	fclose(outfp);
	exit(0);
}
