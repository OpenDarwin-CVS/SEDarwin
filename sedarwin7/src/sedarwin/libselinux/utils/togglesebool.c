/*
 * Copyright 1999-2004 Gentoo Technologies, Inc.
 * Distributed under the terms of the GNU General Public License v2
 * $Header$
 */
#include <stdio.h>
#include <libgen.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <string.h>

int main(int argc, char **argv) {

	int rc, i, commit=0;

	if(argc < 2) {
		printf("Usage:  %s boolname1 [boolname2 ...]\n",basename(argv[0]));
		return 1;
	}

	for(i=1; i<argc; i++) {
		printf("%s: ",argv[i]);
		rc=security_get_boolean_active(argv[i]);
		switch(rc) {
			case 1:
				if(security_set_boolean(argv[i],0) >= 0) {
					printf("inactive\n");
					commit++;
				} else {
					printf("%s\n",strerror(errno));
				}
				break;
			case 0:
				if(security_set_boolean(argv[i],1) >= 0) {
					printf("active\n");
					commit++;
				} else {
					printf("%s\n",strerror(errno));
				}
				break;
			default:
				if(errno==ENOENT)
					printf("Boolean does not exist\n");
				else
					printf("%s\n",strerror(errno));
				break;
		}
	}

	if(commit > 0) {
		if(security_commit_booleans() < 0) {
			printf("Commit failed. (%s)  No change to booleans.\n",strerror(errno));
			return 1;
		} else {
			return 0;
		}
	} else {
		return 1;
	}
}
