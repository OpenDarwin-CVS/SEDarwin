/*
 * $Id$
 */

#include <sys/cdefs.h>
#include <sys/syscall.h>
#include <unistd.h>

pid_t _getlcid(pid_t pid);
int _setlcid(pid_t pid, pid_t lcid);

pid_t
_getlcid(pid_t pid)
{
        return (syscall(SYS_getlcid, pid));
}

int
_setlcid(pid_t pid, pid_t lcid)
{
        return (syscall(SYS_setlcid, pid, lcid));
}

__weak_reference(_getlcid, getlcid);
__weak_reference(_setlcid, setlcid);
