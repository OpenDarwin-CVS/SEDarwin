#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <asm/page.h>
#include <stdio.h>

char *selinux_mnt = NULL;

static void init_selinuxmnt(void) __attribute__ ((constructor));

static void init_selinuxmnt(void)
{
	char *buf, *bufp, *p;
	size_t size;
	FILE *fp;

	if (selinux_mnt)
		return;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return;

	size = PAGE_SIZE;
	buf = malloc(size);
	if (!buf)
		goto out;
		
	memset(buf, 0, size);

	while(( bufp = fgets(buf, size, fp)))
	{
		char *tmp;
		p = strchr(buf, ' ');
		if (!p)
			goto out2;
		p++;
		tmp = strchr(p, ' ');
		if (!tmp)
			goto out2;
		if(!strncmp(tmp + 1, "selinuxfs ", 10)) {
			*tmp = '\0';
			break;
		}
	}

	if (!bufp)
		goto out2;

	selinux_mnt = strdup(p);

out2:
	free(buf);
out:
	fclose(fp);
	return;

}
 
