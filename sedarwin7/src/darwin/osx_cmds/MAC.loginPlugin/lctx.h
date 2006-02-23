/*
 * $Id$
 */

#define SYS_getlcid     404
#define SYS_setlcid     405

static __inline pid_t
getlcid(pid_t pid)
{
        return (syscall(SYS_getlcid, pid));
}

static __inline int
setlcid(pid_t pid, pid_t lcid)
{
        return (syscall(SYS_setlcid, pid, lcid));
}

#define LCID_PROC_SELF  (0)
#define LCID_REMOVE     (-1)
#define LCID_CREATE     (0)
