#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sedarwin/sebsd_syscalls.h>
#include <sedarwin/sebsd.h>

int
selinux_load_migscs(const char *path)
{
        FILE           *fp;
        struct lp_args  la;

        fp = fopen (path, "rb");
        if (fp == NULL)
                return errno;

        fseek(fp, 0, SEEK_END);
        la.len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if ((la.data = malloc(la.len)) == NULL)
                return (ENOMEM);
        if (fread(la.data, la.len, 1, fp) != 1)
                return (EIO);

        return (mac_syscall(SEBSD_ID_STRING, SEBSDCALL_LOAD_MIGSCS, &la));
}
