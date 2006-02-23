#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <selinux/selinux.h>
#include <selinux/get_context_list.h>

int main(int argc, char **argv) 
{
	security_context_t *list, usercon;
	int ret;

	if (argc != 3) {
		fprintf(stderr, "usage:  %s user context\n", argv[0]);
		exit(1);
	}

	ret = get_ordered_context_list(argv[1], argv[2], &list);
	if (ret > 0) {
		ret = query_user_context(list, &usercon);
		if (ret < 0) {
			fprintf(stderr, "%s:  query_user_context failed\n", argv[0]);
			exit(3);
		}
	} else {
		printf("Unable to obtain contexts for %s from %s\n",
		       argv[1], argv[2]);
		ret = manual_user_enter_context(argv[1], &usercon);
		if (ret < 0) {
			fprintf(stderr, "%s:  manual_user_enter_context failed\n", argv[0]);
			exit(4);
		}
	}

	freeconary(list);

	printf("Selected %s\n", usercon);

	free(usercon);

	exit(0);
}
