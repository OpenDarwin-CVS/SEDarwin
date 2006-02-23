/*-
 * Copyright (c) 1999-2002 Robert N. M. Watson
 * Copyright (c) 2001-2005 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/sys/mac.h,v 1.40 2003/04/18 19:57:37 rwatson Exp $
 */
/*
 * Userland/kernel interface for Mandatory Access Control.
 *
 * The POSIX.1e implementation page may be reached at:
 * http://www.trustedbsd.org/
 */

#ifndef _SYS_MAC_H
#define	_SYS_MAC_H

#include <mach/_label.h>

#ifndef _POSIX_MAC
#define	_POSIX_MAC
#endif

/*
 * MAC framework-related constants and limits.
 */
#define	MAC_MAX_POLICY_NAME		32
#define	MAC_MAX_LABEL_ELEMENT_NAME	32
#define	MAC_MAX_LABEL_ELEMENT_DATA	4096
#define	MAC_MAX_LABEL_BUF_LEN		8192
#define MAC_MAX_MANAGED_NAMESPACES	4

struct mac {
	size_t		 m_buflen;
	char		*m_string;
};

typedef struct mac	*mac_t;

#ifndef KERNEL

/*
 * Location of the userland MAC framework configuration file.  mac.conf
 * binds policy names to shared libraries that understand those policies,
 * as well as setting defaults for MAC-aware applications.
 */
#define	MAC_CONFFILE	"/etc/mac.conf"

/*
 * Extended non-POSIX.1e interfaces that offer additional services
 * available from the userland and kernel MAC frameworks.
 */
__BEGIN_DECLS
int	 mac_execve(char *fname, char **argv, char **envv, mac_t _label);
int	 mac_free(mac_t _label);
int	 mac_from_text(mac_t *_label, const char *_text);
int	 mac_get_fd(int _fd, mac_t _label);
int	 mac_get_file(const char *_path, mac_t _label);
int	 mac_get_lcid(pid_t _lcid, mac_t _label);
int	 mac_get_lctx(mac_t _label);
int	 mac_get_link(const char *_path, mac_t _label);
int	 mac_get_pid(pid_t _pid, mac_t _label);
int	 mac_get_proc(mac_t _label);
int	 mac_getsockopt_peerlabel(struct ucred *cred, struct socket *so,
	     struct mac *extmac);
int	 mac_is_present(const char *_policyname);
int	 mac_prepare(mac_t *_label, const char *_elements);
int	 mac_prepare_file_label(mac_t *_label);
int	 mac_prepare_ifnet_label(mac_t *_label);
int	 mac_prepare_process_label(mac_t *_label);
int	 mac_set_fd(int _fildes, const mac_t _label);
int	 mac_set_file(const char *_path, mac_t _label);
int	 mac_set_lctx(mac_t _label);
int	 mac_set_link(const char *_path, mac_t _label);
int	 mac_set_proc(const mac_t _label);
int	 mac_syscall(const char *_policyname, int _call, void *_arg);
int	 mac_to_text(mac_t mac, char **_text);
__END_DECLS

#else /* _KERNEL */

/*
 * Kernel functions to manage and evaluate labels.
 */
struct auditinfo;
struct attrlist;
struct componentname;
struct devnode;
struct lctx;
struct mount;
struct pseminfo;
struct pshminfo;
struct proc;
struct semid_kernel;
struct shmid_kernel;
struct uthread;
struct timespec;
struct ucred;
struct uio;
struct vattr;
struct vnode;
struct socket;
struct sockaddr;
struct mbuf;
struct vop_setlabel_args;

/*
 * Label operations.
 */
void	mac_init_cred(struct ucred *);
void	mac_init_devfsdirent(struct devnode *);
int	mac_init_mbuf_socket(struct mbuf *);
void	mac_init_mount(struct mount *);
void	mac_init_posix_sem(struct pseminfo *);
void	mac_init_posix_shm(struct pshminfo *);
void	mac_init_proc(struct proc *);
int	mac_init_socket(struct socket *, int waitok);
void	mac_init_sysv_sem(struct semid_kernel*);
void	mac_init_sysv_shm(struct shmid_kernel*);
void	mac_init_vnode(struct vnode *);
void	mac_copy_vnode_label(struct label *, struct label *label);
void	mac_copy_devfs_label(struct label *, struct label *label);
void	mac_copy_cred_to_task(struct label *cred, struct label *task);
void	mac_copy_mbuf_socket_label(struct label *from, struct label *to);
void	mac_copy_socket_label(struct label *from, struct label *to);
void	mac_update_task_label(struct label *plabel, void *task);
void	mac_destroy_cred(struct ucred *);
void	mac_destroy_devfsdirent(struct devnode *);
void	mac_destroy_mbuf_socket(struct mbuf *);
void	mac_destroy_mount(struct mount *);
void	mac_destroy_posix_sem(struct pseminfo *);
void	mac_destroy_posix_shm(struct pshminfo *);
void	mac_destroy_proc(struct proc *);
void	mac_destroy_socket(struct socket *);
void	mac_destroy_sysv_sem(struct semid_kernel *);
void	mac_destroy_sysv_shm(struct shmid_kernel *);
void	mac_destroy_vnode(struct vnode *);

struct label	*mac_cred_label_alloc(void);
void		 mac_cred_label_free(struct label *label);
int		 mac_get_cred_audit_labels(struct proc *p, struct mac *mac);
struct label	*mac_vnode_label_alloc(void);
void		 mac_vnode_label_free(struct label *label);
int		 mac_get_vnode_audit_labels(struct vnode *vp, 
			struct mac *mac);
struct label	*mac_lctx_label_alloc(void);
void		 mac_lctx_label_free(struct label *label);

#define mac_update_task_from_cred(cred, task)				\
	mac_update_task_label(((cred)->cr_label), task)

/*
 * Labeling event operations: file system objects, and things that
 * look a lot like file system objects.
 */
void	mac_associate_vnode_devfs(struct mount *mp, struct devnode *de,
	    struct vnode *vp);
int	mac_associate_vnode_extattr(struct mount *mp, struct vnode *vp);
void	mac_associate_vnode_singlelabel(struct mount *mp, struct vnode *vp);
void	mac_create_devfs_device(struct ucred *cr, struct mount *mp, dev_t dev,
	    struct devnode *de, const char *fullpath);
void	mac_create_devfs_directory(struct mount *mp, char *dirname,
	    int dirnamelen, struct devnode *de, const char *fullpath);
void	mac_create_devfs_symlink(struct ucred *cred, struct mount *mp,
	    struct devnode *dd, struct devnode *de,
	    const char *fullpath);
int	mac_create_vnode_extattr(struct ucred *cred, struct mount *mp,
	    struct vnode *dvp, struct vnode *vp, struct componentname *cnp);
void	mac_create_mount(struct ucred *cred, struct mount *mp);
void	mac_relabel_vnode(struct ucred *cred, struct vnode *vp,
	    struct label *newlabel);
void	mac_update_devfsdirent(struct mount *mp, struct devnode *de,
	    struct vnode *vp);

/*
 * Labeling event operations: Posix IPC primitives
 */
void	mac_create_posix_sem(struct ucred *cred, struct pseminfo *psem,
	    const char *name);
void	mac_create_posix_shm(struct ucred *cred, struct pshminfo *pshm,
	    const char *name);

/*
 * Labeling event operations: sockets and network IPC
 *
 * Note: all functions involving sockets (and other network objects yet to be
 * implemented) hold (and rely on) the NETWORK_FUNNEL as opposed to the
 * KERNEL_FUNNEL.  When reading/writing kernel network objects, be sure to
 * hold the NETWORK_FUNNEL.  When reading/writing other types of kernel
 * objects (vnode for example), be sure to hold the KERNEL_FUNNEL. 
 *
 * XXX: Note that cred can be NULL in mac_create_socket() in Darwin.
 */
void	mac_create_socket(struct ucred *cred, struct socket *so);
void	mac_create_socket_from_socket(struct socket *oldsocket,
	    struct socket *newsocket);
void	mac_create_mbuf_from_socket(struct socket *so, struct mbuf *m);
void	mac_set_socket_peer_from_socket(struct socket *peersocket,
	    struct socket *socket_to_modify);
void	mac_relabel_socket(struct ucred *cred, struct socket *so,
	    struct label *l);

/*
 * Labeling event operations: System V IPC primitives
 */
void	mac_create_sysv_msgmsg(struct ucred *cred, 
	    struct msqid_kernel *msqkptr, struct msg *msgptr);
void	mac_create_sysv_msgqueue(struct ucred *cred,
	    struct msqid_kernel *msqkptr);
void	mac_create_sysv_sem(struct ucred *cred,
	    struct semid_kernel *semakptr);
void	mac_create_sysv_shm(struct ucred *cred,
	    struct shmid_kernel *shmsegptr);

/*
 * Labeling event operations: processes.
 */
void	mac_relabel_cred(struct ucred *cred, struct label *newlabel);
void	mac_create_cred(struct ucred *cred_parent, struct ucred *cred_child);
int	mac_execve_enter(struct mac *mac_p,
	    struct label *execlabel);
#if 0
void	mac_execve_exit(struct image_params *imgp); 
#endif
void	mac_execve_transition(struct ucred *old, struct ucred *newcred,
	    struct vnode *vp, struct label *scriptvnodelabel,
	    struct label *execlabel);
int	mac_execve_will_transition(struct ucred *old, struct vnode *vp,
	    struct label *scriptvnodelabel, struct label *execlabel,
	    struct proc *p);
void	mac_create_proc0(struct ucred *cred);
void	mac_create_proc1(struct ucred *cred);
#if 0
void	mac_thread_userret(struct uthread *td);
#endif

void	mac_relabel_lctx(struct lctx *l, struct label *newlabel);

/*
 * Label cleanup operation: This is the inverse complement for the mac_create
 * and associate type of hooks.  This hook lets the policy module(s) perform
 * a cleanup/flushing operation on the label associated with the objects,
 * without freeing up the space allocated.  This hook is useful in cases
 * where it is desirable to remove any labeling reference when recycling any
 * object to a pool.  This hook does not replace the mac_destroy hooks.
 */
void	mac_cleanup_sysv_sem(struct semid_kernel *semakptr);
void	mac_cleanup_sysv_shm(struct shmid_kernel *shmsegptr);

/*
 * Access control checks.
 */
int	mac_check_service_access(struct label *subj, struct label *obj,
	    const char *serv, const char *perm);
int	mac_check_cred_relabel(struct ucred *cred, struct label *newlabel);
int	mac_check_cred_visible(struct ucred *u1, struct ucred *u2);
int	mac_check_lctx_relabel(struct lctx *l, struct label *newlabel);
int	mac_check_posix_sem_create(struct ucred *cred, const char *name);
int	mac_check_posix_sem_open(struct ucred *cred, struct pseminfo *ps);
int	mac_check_posix_sem_post(struct ucred *cred, struct pseminfo *ps);
int	mac_check_posix_sem_unlink(struct ucred *cred, struct pseminfo *ps,
	    const char *name);
int	mac_check_posix_sem_wait(struct ucred *cred, struct pseminfo *ps);
int	mac_check_posix_shm_create(struct ucred *cred, const char *name);
int	mac_check_posix_shm_open(struct ucred *cred, struct pshminfo *ps);
int	mac_check_posix_shm_mmap(struct ucred *cred, struct pshminfo *ps,
	    int prot, int flags);
int	mac_check_posix_shm_stat(struct ucred *cred, struct pshminfo *ps);
int	mac_check_posix_shm_truncate(struct ucred *cred, struct pshminfo *ps,
	    size_t s);
int	mac_check_posix_shm_unlink(struct ucred *cred, struct pshminfo *ps,
	    const char *name);
int	mac_check_sysv_semctl(struct ucred *cred,
	    struct semid_kernel *semakptr, int cmd);
int	mac_check_fcntl(struct ucred *cred, struct file *fd, int cmd,
	    int arg);
int	mac_check_get_fd(struct ucred *cred, struct file *fd, char *elements,
	    int len);
	    
/* 
 * Note: mac_check_ioctl is currently not called and will probably be broken into
 * more granular checks.
 */
int	mac_check_ioctl(struct ucred *cred, struct file *fd, int com,
	    void *data);
int	mac_check_ipc_semctl(struct ucred *cred,
	    struct semid_kernel *semakptr, int cmd);
int	mac_check_sysv_semget(struct ucred *cred,
	   struct semid_kernel *semakptr);
int	mac_check_sysv_semop(struct ucred *cred,struct semid_kernel *semakptr,
	    size_t accesstype);
int	mac_check_sysv_shmat(struct ucred *cred,
	    struct shmid_kernel *shmsegptr, int shmflg);
int	mac_check_sysv_shmctl(struct ucred *cred,
	    struct shmid_kernel *shmsegptr, int cmd);
int	mac_check_sysv_shmdt(struct ucred *cred,
	    struct shmid_kernel *shmsegptr);
int	mac_check_sysv_shmget(struct ucred *cred,
	    struct shmid_kernel *shmsegptr, int shmflg);
int	mac_check_mount_stat(struct ucred *cred, struct mount *mp);
int	mac_check_proc_debug(struct ucred *cred, struct proc *proc);
int	mac_check_proc_getaudit(struct ucred *cred);
int	mac_check_proc_getauid(struct ucred *cred);
int	mac_check_proc_sched(struct ucred *cred, struct proc *proc);
int	mac_check_proc_setaudit(struct ucred *cred, struct auditinfo *ai);
int	mac_check_proc_setauid(struct ucred *cred, uid_t auid);
int	mac_check_proc_signal(struct ucred *cred, struct proc *proc,
	    int signum);
int	mac_check_proc_wait(struct ucred *cred, struct proc *proc);
int	mac_check_proc_setlcid(struct proc *, struct proc *, pid_t, pid_t);
int	mac_check_proc_getlcid(struct proc *, struct proc *, pid_t);
int	mac_check_set_fd(struct ucred *cred, struct file *fp, char *buf,
	    int buflen);
int     mac_check_socket_accept(struct ucred *cred, struct socket *so,
	    struct sockaddr *addr);
int	mac_check_socket_bind(struct ucred *cred, struct socket *so,
	    struct sockaddr *addr);
int	mac_check_socket_connect(struct ucred *cred, struct socket *so,
	    struct sockaddr *addr);
int	mac_check_socket_deliver(struct socket *so, struct mbuf *m);
int	mac_check_socket_listen(struct ucred *cred, struct socket *so);
int     mac_check_socket_poll(struct ucred *cred, struct socket *so);
int	mac_check_socket_receive(struct ucred *cred, struct socket *so);
int	mac_check_socket_relabel(struct ucred *cred, struct socket *so,
	    struct label *l);
int     mac_check_socket_select(struct ucred *cred, struct socket *so);
int	mac_check_socket_send(struct ucred *cred, struct socket *so);
int	mac_check_socket_stat(struct ucred *cred, struct socket *so);
int	mac_check_system_acct(struct ucred *cred, struct vnode *vp);
int	mac_check_system_audit(struct ucred *cred, void *record, int length);
int	mac_check_system_auditctl(struct ucred *cred, struct vnode *vp);
int	mac_check_system_auditon(struct ucred *cred, int cmd);
int	mac_check_system_nfsd(struct ucred *cred);
int	mac_check_system_reboot(struct ucred *cred, int howto);
int	mac_check_system_settime(struct ucred *cred);
int	mac_check_system_swapon(struct ucred *cred, struct vnode *vp);
int	mac_check_system_swapoff(struct ucred *cred, struct vnode *vp);
int	mac_check_system_sysctl(struct ucred *cred, int *name,
	    u_int namelen, void *oldctl, size_t *oldlenp, int inkernel,
	    void *newctl, size_t newlen);
int	mac_check_vnode_access(struct ucred *cred, struct vnode *vp,
	    int acc_mode);
int	mac_check_vnode_chdir(struct ucred *cred, struct vnode *dvp);
int	mac_check_vnode_chroot(struct ucred *cred, struct vnode *dvp);
int	mac_check_vnode_create(struct ucred *cred, struct vnode *dvp,
	    struct componentname *cnp, struct vattr *vap);
int	mac_check_vnode_delete(struct ucred *cred, struct vnode *dvp,
	    struct vnode *vp, struct componentname *cnp);
int	mac_check_vnode_deleteextattr(struct ucred *cred, struct vnode *vp,
	    int attrnamespace, const char *name);
int	mac_check_vnode_exchangedata(struct ucred *cred, struct vnode *v1,
            struct vnode *v2);
int	mac_check_vnode_exec(struct ucred *cred, struct vnode *vp,
	    struct label *execlabel);
int     mac_check_vnode_getattrlist(struct ucred *cred, struct vnode *vp,
            struct attrlist *alist, struct uio *attrblk);
int	mac_check_vnode_getextattr(struct ucred *cred, struct vnode *vp,
	    int attrnamespace, const char *name, struct uio *uio);
int	mac_check_vnode_link(struct ucred *cred, struct vnode *dvp,
	    struct vnode *vp, struct componentname *cnp);
int	mac_check_vnode_listextattr(struct ucred *cred, struct vnode *vp,
	    int attrnamespace);
int	mac_check_vnode_lookup(struct ucred *cred, struct vnode *dvp,
	    struct componentname *cnp);
int	mac_check_vnode_mmap(struct ucred *cred, struct vnode *vp,
	    int prot, int flags, int *maxprot);
int	mac_check_vnode_mprotect(struct ucred *cred, struct vnode *vp,
	    int prot);
int	mac_check_vnode_open(struct ucred *cred, struct vnode *vp,
	    int acc_mode);
int	mac_check_vnode_poll(struct ucred *active_cred,
	    struct ucred *file_cred, struct vnode *vp);
int	mac_check_vnode_read(struct ucred *active_cred,
	    struct ucred *file_cred, struct vnode *vp);
int	mac_check_vnode_readdir(struct ucred *cred, struct vnode *vp);
int	mac_check_vnode_readlink(struct ucred *cred, struct vnode *vp);
int	mac_check_vnode_rename_from(struct ucred *cred, struct vnode *dvp,
	    struct vnode *vp, struct componentname *cnp);
int	mac_check_vnode_rename_to(struct ucred *cred, struct vnode *dvp,
	    struct vnode *vp, int samedir, struct componentname *cnp);
int	mac_check_vnode_revoke(struct ucred *cred, struct vnode *vp);
int     mac_check_vnode_select(struct ucred *cred, struct vnode *vp);
int     mac_check_vnode_setattrlist(struct ucred *cred, struct vnode *vp,
            struct attrlist *alist, struct uio *attrblk);
int	mac_check_vnode_setextattr(struct ucred *cred, struct vnode *vp,
	    int attrnamespace, const char *name, struct uio *uio);
int	mac_check_vnode_setflags(struct ucred *cred, struct vnode *vp,
	    u_long flags);
int	mac_check_vnode_setmode(struct ucred *cred, struct vnode *vp,
	    mode_t mode);
int	mac_check_vnode_setowner(struct ucred *cred, struct vnode *vp,
	    uid_t uid, gid_t gid);
int	mac_check_vnode_setutimes(struct ucred *cred, struct vnode *vp,
	    struct timespec atime, struct timespec mtime);
int	mac_check_vnode_stat(struct ucred *active_cred,
	    struct ucred *file_cred, struct vnode *vp);
int	mac_check_vnode_write(struct ucred *active_cred,
	    struct ucred *file_cred, struct vnode *vp);
	
#if 0
void	mac_cred_mmapped_drop_perms(struct thread *td, struct ucred *cred);
#endif

/*  
 * mac_audit_{pre,post}select() allow MAC policies to control whether a given
 * event will be audited.  For 10.3.3, these functions take precedence over
 * the existing pre/post-selection selection in Darwin.  That aspect of the
 * sematics of these functions will probably change for version 10.3.4 as
 * that version has a more complete implementation of the audit subsystem.
 */
int	mac_audit_preselect(struct ucred *cred, unsigned short syscode,
	    void *args);
int	mac_audit_postselect(struct ucred *cred, unsigned short syscode,
	    void *args, int error, int retval, int mac_forced);

void	mac_proc_create_lctx(struct proc *, struct lctx *);
void	mac_proc_join_lctx(struct proc *, struct lctx *);
void	mac_proc_leave_lctx(struct proc *, struct lctx *);

/*
 * Calls to help various file systems implement labeling functionality
 * using their existing EA implementation.
 */
int	vop_stdsetlabel_ea(struct vop_setlabel_args *ap);

/* 
 * The semantics of this function are slightly different than the standard
 * copy operation.  On the first call for a given socket, the peer label has 
 * been newly allocated.  On successive calls, the peer label is in use and
 * would be clobbered by a normal copy operation.  It was decided to implement
 * it this way because its performance has a significant impact on network
 * performance.  A destroy-init-copy sequence is too inefficient here. 
 * Some policies may be able to replace data inline, which is more efficient.
 * It is up to the policies to determine the most efficient action to take.
 */
void	mac_set_socket_peer_from_mbuf(struct mbuf *m, struct socket *so);

/*
 * Accessor methods for special labels.
 */
struct label *  mac_get_mbuf_unknown_source(void);
struct label *  mac_get_tcp_label(void);
struct label *  mac_get_mbuf_failed_label(void);

#endif /* !_KERNEL */

#endif /* !_SYS_MAC_H */
