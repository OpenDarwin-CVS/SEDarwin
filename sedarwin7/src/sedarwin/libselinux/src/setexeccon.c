#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <selinux/selinux.h>

int setexeccon(security_context_t context)
{
	int fd;
	ssize_t ret;

	fd = open("/proc/self/attr/exec", O_RDWR);
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
