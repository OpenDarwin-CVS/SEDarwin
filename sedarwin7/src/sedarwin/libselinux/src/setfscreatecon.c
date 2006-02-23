#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <selinux/selinux.h>

int setfscreatecon(char *context)
{
	int fd;
	ssize_t ret;

	fd = open("/proc/self/attr/fscreate", O_RDWR);
	if (fd < 0)
		return -1;
	if (context) 
		ret = write(fd, context, strlen(context)+1);
	else
		ret = write(fd, NULL, 0); /* clear */
	close(fd);
	if (ret < 0)
		return -1;
	else
		return 0;
}
