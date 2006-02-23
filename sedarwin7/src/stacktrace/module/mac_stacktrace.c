/*-
 * Copyright (c) 2005 SPARTA, Inc.
 * Copyright (c) 2004 Networks Associates Technology, Inc.
 * All rights reserved.
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
 */
/*
 * Stacktrace module that prints a stack trace for all MAC Framework policy
 * entry points.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <stdarg.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>

#include <sys/mac.h>
#include <sys/mac_policy.h>

#include <mach/kmod.h>
#include <kern/lock.h>
#include <kern/kalloc.h>
#include "stacktrace_syscalls.h"

#if 0
SYSCTL_DECL(_security_mac);

SYSCTL_NODE(_security_mac, OID_AUTO, stacktrace, CTLFLAG_RW, 0,
    "mac_stacktrace policy controls");

static int	stacktrace_enabled = 1;
SYSCTL_INT(_security_mac_stacktrace, OID_AUTO, enabled, CTLFLAG_RW,
    &stacktrace_enabled, 0, "mac_stacktrace debugging policy");
#endif

#define MAC_STACKTRACE_LABEL_NAME_COUNT	1
#define MAC_STACKTRACE_LABEL_NAME	"stacktrace"

static	int stack_slot;	/* allocated by framework */

/*
 * Define a struct for each function with a unique number and enable flag.
 */
struct function_info {
	short	num;
	short	onoff;
};

#define	TRACE_DATA(name, num, onoff)	static struct function_info name##_td = { num, onoff }


TRACE_DATA(destroy, 0, STACKTRACE_ON);
TRACE_DATA(init, 1, STACKTRACE_ON);
TRACE_DATA(init_bsd, 2, STACKTRACE_ON);
TRACE_DATA(init_cred_label, 3, STACKTRACE_ON);
TRACE_DATA(init_lctx_label, 4, STACKTRACE_ON);
TRACE_DATA(init_devfsdirent_label, 5, STACKTRACE_ON);
TRACE_DATA(init_mbuf_failed_label, 6, STACKTRACE_ON);
TRACE_DATA(init_mbuf_socket_label, 7, STACKTRACE_ON);
TRACE_DATA(init_mount_label, 8, STACKTRACE_ON);
TRACE_DATA(init_mount_fs_label, 9, STACKTRACE_ON);
TRACE_DATA(init_port_label, 10, STACKTRACE_ON);
TRACE_DATA(init_posix_sem_label, 11, STACKTRACE_ON);
TRACE_DATA(init_posix_shm_label, 12, STACKTRACE_ON);
TRACE_DATA(init_proc_label, 13, STACKTRACE_ON);
TRACE_DATA(init_socket_label, 14, STACKTRACE_ON);
TRACE_DATA(init_socket_peer_label, 15, STACKTRACE_ON);
TRACE_DATA(init_sysv_sem_label, 16, STACKTRACE_ON);
TRACE_DATA(init_sysv_shm_label, 17, STACKTRACE_ON);
TRACE_DATA(init_task_label, 18, STACKTRACE_ON);
TRACE_DATA(init_tcp_label, 19, STACKTRACE_ON);
TRACE_DATA(init_mbuf_unknown_source_label, 20, STACKTRACE_ON);
TRACE_DATA(init_vnode_label, 21, STACKTRACE_ON);
TRACE_DATA(destroy_cred_label, 22, STACKTRACE_ON);
TRACE_DATA(destroy_lctx_label, 23, STACKTRACE_ON);
TRACE_DATA(destroy_devfsdirent_label, 24, STACKTRACE_ON);
TRACE_DATA(destroy_mbuf_socket_label, 25, STACKTRACE_ON);
TRACE_DATA(destroy_mount_label, 26, STACKTRACE_ON);
TRACE_DATA(destroy_mount_fs_label, 27, STACKTRACE_ON);
TRACE_DATA(destroy_port_label, 28, STACKTRACE_ON);
TRACE_DATA(destroy_posix_sem_label, 29, STACKTRACE_ON);
TRACE_DATA(destroy_posix_shm_label, 30, STACKTRACE_ON);
TRACE_DATA(destroy_proc_label, 31, STACKTRACE_ON);
TRACE_DATA(destroy_socket_label, 32, STACKTRACE_ON);
TRACE_DATA(destroy_socket_peer_label, 33, STACKTRACE_ON);
TRACE_DATA(destroy_sysv_sem_label, 34, STACKTRACE_ON);
TRACE_DATA(destroy_sysv_shm_label, 35, STACKTRACE_ON);
TRACE_DATA(destroy_task_label, 36, STACKTRACE_ON);
TRACE_DATA(destroy_vnode_label, 37, STACKTRACE_ON);
TRACE_DATA(cleanup_sysv_sem_label, 38, STACKTRACE_ON);
TRACE_DATA(cleanup_sysv_shm_label, 39, STACKTRACE_ON);
TRACE_DATA(copy_cred_to_task, 40, STACKTRACE_ON);
TRACE_DATA(update_port_from_cred_label, 41, STACKTRACE_ON);
TRACE_DATA(copy_vnode_label, 42, STACKTRACE_ON);
TRACE_DATA(copy_devfs_label, 43, STACKTRACE_ON);
TRACE_DATA(copy_mbuf_socket_label, 44, STACKTRACE_ON);
TRACE_DATA(copy_port_label, 45, STACKTRACE_ON);
TRACE_DATA(externalize_cred_label, 46, STACKTRACE_ON);
TRACE_DATA(externalize_cred_audit_label, 47, STACKTRACE_ON);
TRACE_DATA(externalize_lctx_label, 48, STACKTRACE_ON);
TRACE_DATA(externalize_vnode_label, 49, STACKTRACE_ON);
TRACE_DATA(externalize_vnode_audit_label, 50, STACKTRACE_ON);
TRACE_DATA(internalize_cred_label, 51, STACKTRACE_ON);
TRACE_DATA(internalize_lctx_label, 52, STACKTRACE_ON);
TRACE_DATA(internalize_vnode_label, 53, STACKTRACE_ON);
TRACE_DATA(associate_vnode_devfs, 54, STACKTRACE_ON);
TRACE_DATA(associate_vnode_extattr, 55, STACKTRACE_ON);
TRACE_DATA(associate_vnode_singlelabel, 56, STACKTRACE_ON);
TRACE_DATA(create_devfs_device, 57, STACKTRACE_ON);
TRACE_DATA(create_devfs_directory, 58, STACKTRACE_ON);
TRACE_DATA(create_devfs_symlink, 59, STACKTRACE_ON);
TRACE_DATA(create_vnode_extattr, 60, STACKTRACE_ON);
TRACE_DATA(create_mount, 61, STACKTRACE_ON);
TRACE_DATA(relabel_vnode, 62, STACKTRACE_ON);
TRACE_DATA(setlabel_vnode_extattr, 63, STACKTRACE_ON);
TRACE_DATA(update_devfsdirent, 64, STACKTRACE_ON);
TRACE_DATA(copy_socket_label, 65, STACKTRACE_ON);
TRACE_DATA(create_socket, 66, STACKTRACE_ON);
TRACE_DATA(create_socket_from_socket, 67, STACKTRACE_ON);
TRACE_DATA(create_mbuf_from_socket, 68, STACKTRACE_ON);
TRACE_DATA(externalize_socket_label, 69, STACKTRACE_ON);
TRACE_DATA(externalize_socket_peer_label, 70, STACKTRACE_ON);
TRACE_DATA(internalize_socket_label, 71, STACKTRACE_ON);
TRACE_DATA(relabel_socket, 72, STACKTRACE_ON);
TRACE_DATA(set_socket_peer_from_socket, 73, STACKTRACE_ON);
TRACE_DATA(set_socket_peer_from_mbuf, 74, STACKTRACE_ON);
TRACE_DATA(create_port, 75, STACKTRACE_ON);
TRACE_DATA(create_kernel_port, 76, STACKTRACE_ON);
TRACE_DATA(update_port_kobject, 77, STACKTRACE_ON);
TRACE_DATA(create_posix_sem, 78, STACKTRACE_ON);
TRACE_DATA(create_posix_shm, 79, STACKTRACE_ON);
TRACE_DATA(create_sysv_sem, 80, STACKTRACE_ON);
TRACE_DATA(create_sysv_shm, 81, STACKTRACE_ON);
TRACE_DATA(create_cred, 82, STACKTRACE_ON);
TRACE_DATA(create_task, 83, STACKTRACE_ON);
TRACE_DATA(create_kernel_task, 84, STACKTRACE_ON);
TRACE_DATA(execve_transition, 85, STACKTRACE_ON);
TRACE_DATA(execve_will_transition, 86, STACKTRACE_ON);
TRACE_DATA(create_proc0, 87, STACKTRACE_ON);
TRACE_DATA(create_proc1, 88, STACKTRACE_ON);
TRACE_DATA(relabel_cred, 89, STACKTRACE_ON);
TRACE_DATA(request_object_label, 90, STACKTRACE_ON);
TRACE_DATA(proc_create_lctx, 91, STACKTRACE_ON);
TRACE_DATA(proc_join_lctx, 92, STACKTRACE_ON);
TRACE_DATA(proc_leave_lctx, 93, STACKTRACE_ON);
TRACE_DATA(relabel_lctx, 94, STACKTRACE_ON);
TRACE_DATA(check_service_access, 95, STACKTRACE_ON);
TRACE_DATA(check_cred_relabel, 96, STACKTRACE_ON);
TRACE_DATA(check_lctx_relabel, 97, STACKTRACE_ON);
TRACE_DATA(check_port_relabel, 98, STACKTRACE_ON);
TRACE_DATA(check_port_send, 99, STACKTRACE_ON);
TRACE_DATA(check_port_make_send, 100, STACKTRACE_ON);
TRACE_DATA(check_port_copy_send, 101, STACKTRACE_ON);
TRACE_DATA(check_port_hold_send, 102, STACKTRACE_ON);
TRACE_DATA(check_port_hold_receive, 103, STACKTRACE_ON);
TRACE_DATA(check_port_move_receive, 104, STACKTRACE_ON);
TRACE_DATA(check_cred_visible, 105, STACKTRACE_ON);
TRACE_DATA(check_fcntl, 106, STACKTRACE_ON);
TRACE_DATA(check_get_fd, 107, STACKTRACE_ON);
TRACE_DATA(check_ioctl, 108, STACKTRACE_ON);
TRACE_DATA(check_ipc_method, 109, STACKTRACE_ON);
TRACE_DATA(check_posix_sem_create, 110, STACKTRACE_ON);
TRACE_DATA(check_posix_sem_open, 111, STACKTRACE_ON);
TRACE_DATA(check_posix_sem_post, 112, STACKTRACE_ON);
TRACE_DATA(check_posix_sem_unlink, 113, STACKTRACE_ON);
TRACE_DATA(check_posix_sem_wait, 114, STACKTRACE_ON);
TRACE_DATA(check_posix_shm_create, 115, STACKTRACE_ON);
TRACE_DATA(check_posix_shm_open, 116, STACKTRACE_ON);
TRACE_DATA(check_posix_shm_mmap, 117, STACKTRACE_ON);
TRACE_DATA(check_posix_shm_stat, 118, STACKTRACE_ON);
TRACE_DATA(check_posix_shm_truncate, 119, STACKTRACE_ON);
TRACE_DATA(check_posix_shm_unlink, 120, STACKTRACE_ON);
TRACE_DATA(check_sysv_semctl, 121, STACKTRACE_ON);
TRACE_DATA(check_sysv_semget, 122, STACKTRACE_ON);
TRACE_DATA(check_sysv_semop, 123, STACKTRACE_ON);
TRACE_DATA(check_sysv_shmat, 124, STACKTRACE_ON);
TRACE_DATA(check_sysv_shmctl, 125, STACKTRACE_ON);
TRACE_DATA(check_sysv_shmdt, 126, STACKTRACE_ON);
TRACE_DATA(check_sysv_shmget, 127, STACKTRACE_ON);
TRACE_DATA(check_mount_stat, 128, STACKTRACE_ON);
TRACE_DATA(check_proc_debug, 129, STACKTRACE_ON);
TRACE_DATA(check_proc_sched, 130, STACKTRACE_ON);
TRACE_DATA(check_proc_signal, 131, STACKTRACE_ON);
TRACE_DATA(check_proc_wait, 132, STACKTRACE_ON);
TRACE_DATA(check_set_fd, 133, STACKTRACE_ON);
TRACE_DATA(check_socket_accept, 134, STACKTRACE_ON);
TRACE_DATA(check_socket_bind, 135, STACKTRACE_ON);
TRACE_DATA(check_socket_connect, 136, STACKTRACE_ON);
TRACE_DATA(check_socket_deliver, 137, STACKTRACE_ON);
TRACE_DATA(check_socket_listen, 138, STACKTRACE_ON);
TRACE_DATA(check_socket_poll, 139, STACKTRACE_ON);
TRACE_DATA(check_socket_receive, 140, STACKTRACE_ON);
TRACE_DATA(check_socket_relabel, 141, STACKTRACE_ON);
TRACE_DATA(check_socket_select, 142, STACKTRACE_ON);
TRACE_DATA(check_socket_send, 143, STACKTRACE_ON);
TRACE_DATA(check_socket_stat, 144, STACKTRACE_ON);
TRACE_DATA(check_system_acct, 145, STACKTRACE_ON);
TRACE_DATA(check_system_nfsd, 146, STACKTRACE_ON);
TRACE_DATA(check_system_reboot, 147, STACKTRACE_ON);
TRACE_DATA(check_system_settime, 148, STACKTRACE_ON);
TRACE_DATA(check_system_swapon, 149, STACKTRACE_ON);
TRACE_DATA(check_system_swapoff, 150, STACKTRACE_ON);
TRACE_DATA(check_system_sysctl, 151, STACKTRACE_ON);
TRACE_DATA(check_vnode_access, 152, STACKTRACE_ON);
TRACE_DATA(check_vnode_chdir, 153, STACKTRACE_ON);
TRACE_DATA(check_vnode_chroot, 154, STACKTRACE_ON);
TRACE_DATA(check_vnode_create, 155, STACKTRACE_ON);
TRACE_DATA(check_vnode_delete, 156, STACKTRACE_ON);
TRACE_DATA(check_vnode_deleteextattr, 157, STACKTRACE_ON);
TRACE_DATA(check_vnode_exchangedata, 158, STACKTRACE_ON);
TRACE_DATA(check_vnode_exec, 159, STACKTRACE_ON);
TRACE_DATA(check_vnode_getattrlist, 160, STACKTRACE_ON);
TRACE_DATA(check_vnode_getextattr, 161, STACKTRACE_ON);
TRACE_DATA(check_vnode_link, 162, STACKTRACE_ON);
TRACE_DATA(check_vnode_listextattr, 163, STACKTRACE_ON);
TRACE_DATA(check_vnode_lookup, 164, STACKTRACE_ON);
TRACE_DATA(check_vnode_mmap, 165, STACKTRACE_ON);
TRACE_DATA(check_vnode_mmap_downgrade, 166, STACKTRACE_ON);
TRACE_DATA(check_vnode_mprotect, 167, STACKTRACE_ON);
TRACE_DATA(check_vnode_open, 168, STACKTRACE_ON);
TRACE_DATA(check_vnode_poll, 169, STACKTRACE_ON);
TRACE_DATA(check_vnode_read, 170, STACKTRACE_ON);
TRACE_DATA(check_vnode_readdir, 171, STACKTRACE_ON);
TRACE_DATA(check_vnode_readlink, 172, STACKTRACE_ON);
TRACE_DATA(check_vnode_relabel, 173, STACKTRACE_ON);
TRACE_DATA(check_vnode_rename_from, 174, STACKTRACE_ON);
TRACE_DATA(check_vnode_rename_to, 175, STACKTRACE_ON);
TRACE_DATA(check_vnode_revoke, 176, STACKTRACE_ON);
TRACE_DATA(check_vnode_select, 177, STACKTRACE_ON);
TRACE_DATA(check_vnode_setattrlist, 178, STACKTRACE_ON);
TRACE_DATA(check_vnode_setextattr, 179, STACKTRACE_ON);
TRACE_DATA(check_vnode_setflags, 180, STACKTRACE_ON);
TRACE_DATA(check_vnode_setmode, 181, STACKTRACE_ON);
TRACE_DATA(check_vnode_setowner, 182, STACKTRACE_ON);
TRACE_DATA(check_vnode_setutimes, 183, STACKTRACE_ON);
TRACE_DATA(check_vnode_stat, 184, STACKTRACE_ON);
TRACE_DATA(check_vnode_write, 185, STACKTRACE_ON);
TRACE_DATA(check_system_audit, 186, STACKTRACE_ON);
TRACE_DATA(check_system_auditon, 187, STACKTRACE_ON);
TRACE_DATA(check_system_auditctl, 188, STACKTRACE_ON);
TRACE_DATA(check_proc_getauid, 189, STACKTRACE_ON);
TRACE_DATA(check_proc_getlcid, 190, STACKTRACE_ON);
TRACE_DATA(check_proc_setauid, 191, STACKTRACE_ON);
TRACE_DATA(check_proc_setlcid, 192, STACKTRACE_ON);
TRACE_DATA(check_proc_getaudit, 193, STACKTRACE_ON);
TRACE_DATA(check_proc_setaudit, 194, STACKTRACE_ON);
TRACE_DATA(audit_preselect, 195, STACKTRACE_ON);
TRACE_DATA(audit_postselect, 196, STACKTRACE_ON);
/*
 * Buffer control.
 */
static size_t	 bufsize = RBSIZE;	// The current buffer size.
static char	*buffer_basep = NULL;	// ptr to base of buffer
static char	*buffer_workp = NULL;	// ptr to current free loc in buffer
// TODO: allocate buffer dynamically
static short	 global_fullbuffer_action = FULLBUFF_STOP;	// FULLBUFF_RESET or FULLBUFF_STOP
static int	 global_resets = 0;	// count of times buffer wrapped
static int	 global_ncalls = 0;	// count of total stacktraces
static int	 global_naxdepth = 0;	// highest recursion level
// TODO add a timestamp for time of last call
// TODO add a timestamp for time of last reset
static short	 global_enable = STACKTRACE_OFF;	// STACKTRACE_ON, STACKTRACE_OFF or STACKTRACE_FULL; starts OFF till init_bsd

/*
 * Initialize buffer pointers.
 * Sets global: buffer_basep, buffer_workp
 */
static void
initpointers(void)
{
	struct stacktrace_buf_head *buffer_headp;

	if (buffer_basep == NULL) {
		buffer_basep = (char *)kalloc(bufsize);
		if (buffer_basep == NULL)
			printf("stacktrace: cannot kalloc %d\n", bufsize);
		printf("stacktrace: kalloc %d %x\n", bufsize, buffer_basep);
	}
	buffer_headp = (struct stacktrace_buf_head *)buffer_basep;
	buffer_workp = &(buffer_headp->next);
	printf("stacktrace: buffer reset %x\n", buffer_workp);
	// TODO add a timestamp for buffer reset
} // initpointers


/*
 * Return 1 if a pointer could be a stack frame pointer.
 */
static int
validstackptr(const char *sp, const char *prevsp)
{

	if ((sp != 0) && (((vm_address_t)sp & 0xf) == 0) &&
	    ((vm_address_t)sp < 0xb0000000) && (sp > prevsp))
		return (1);
	else
		return (0);
} // validstackptr

/*
 * Internal routine that does the trace, inspired by kernel debug macros and
 * model_dep code in osfmk/ppc.  This is a PPC only version for now.
 */
// Static trace buffers, one per recursion depth
struct onetracehead {
	short	function;
	short	ntracelines;
};

struct onetraceline {
	long	stackloc;
	long	codeloc;
};

struct onestacktrace {
	struct onetracehead	tracehead;
	struct onetraceline	tracelines[10];
};

#define MAXDEPTH 11
static struct	onestacktrace tempbuff[MAXDEPTH];
static int	recursion_depth = 0;

// dcls for packing trace into return structure
struct allocated_traceline {
	struct onetraceline	t;
	struct onetraceline	next_traceline; // not real storage, just get addr
};

struct allocated_tracehead {
    struct onetracehead h;
    struct onetraceline first_traceline; // not real storage, just get addr
};

// byte offsets of items in stack frame, should dcl as struct
#define PPCLROFFSET 8
#define PPCBACKPTROFFSET 0

static void
trace(struct function_info *trace_argsp)
{
	int call_depth;
	
	if ((global_enable == STACKTRACE_ON) &&
	    (trace_argsp->onoff == STACKTRACE_ON) &&
	    (buffer_basep != NULL)) {
		call_depth = hw_atomic_add(&recursion_depth, 1);
		if (call_depth > global_naxdepth)
			global_naxdepth = call_depth;
		if (call_depth >= MAXDEPTH)
			printf("mac_stacktrace: recursion %d", call_depth);
		else {	// maxdepth ok
			global_ncalls++;
			// TODO set timestamp for time of last call
			// Perform the trace into one of the ten temp buffers.
			tempbuff[call_depth].tracehead.function = trace_argsp->num;
			int nlines = 0;
			int bytesize = sizeof(struct onetracehead);
			char *mysp;
			char *prevsp = 0;
			char *stackframe_return_ptr;
			__asm__ volatile("mr %0,r1" : "=r" (mysp));	// Get current stack ptr. PPC only.
			if (validstackptr(mysp, prevsp)) {
				prevsp = mysp;
				mysp = (char *)(*((int *)(mysp+PPCBACKPTROFFSET)));	// Skip stack frame of trace.
				if (validstackptr(mysp, prevsp)) {
					prevsp = mysp;
					mysp = (char *)(*((int *)(mysp+PPCBACKPTROFFSET)));	// Skip stack frame of mac_stacktrace.
					while (validstackptr(mysp, prevsp)) {
						stackframe_return_ptr = (char *)(*((int *)(mysp+PPCLROFFSET)));	// PPC offset of link reg.
						tempbuff[call_depth].tracelines[nlines].stackloc = (long)mysp;
						tempbuff[call_depth].tracelines[nlines].codeloc = (long)stackframe_return_ptr;
						nlines++;
						bytesize += sizeof(struct onetraceline);
						prevsp = mysp;	// to check that sp keeps increasing
						mysp = (char *)(*((int *)(mysp+PPCBACKPTROFFSET)));	// PPC offset of back ptr.
					} // while
				}
			}
			// Done with tracing, is there room to add this trace to the buffer?
			if ((buffer_workp+sizeof(struct stacktrace_buf_head)+bytesize) > (buffer_basep+bufsize)) {
				if (global_fullbuffer_action == FULLBUFF_RESET) {
					initpointers();	// Reset the buffer to empty.
					global_resets++;
				} else if (global_fullbuffer_action == FULLBUFF_STOP)
					global_enable = STACKTRACE_FULL;
					printf("stacktrace: buffer full, tracing disabled\n");
			}
			// copy the temp slot into buffer, hopefully no page fault
			// TODO lock buffer, disable tracing
			struct allocated_tracehead *thp = (struct allocated_tracehead *)buffer_workp;
			thp->h.function = tempbuff[call_depth].tracehead.function;	// Put the header in the buffer.
			struct allocated_traceline *tlp = (struct allocated_traceline *)&(thp->first_traceline);
			int i;

			for (i = 0; i < nlines; i++) {
				tlp->t.stackloc = tempbuff[call_depth].tracelines[i].stackloc;
				tlp->t.codeloc = tempbuff[call_depth].tracelines[i].codeloc;
				tlp = (struct allocated_traceline *)&(tlp->next_traceline);
			}
			thp->h.ntracelines = nlines;
			buffer_workp = (char *)tlp; // Point to new free space.
			// TODO enable tracing, unlock buffer
			hw_atomic_sub(&recursion_depth, 1);
		} // maxdepth ok
	} // if global_enable
} // trace

// ================================================================
/*
 * Syscall machinery.
 */
static int
stacktrace_syscall(struct proc *td, int call, void *args, int *retv)
{
	struct stacktrace_user_args p;
	int err = EINVAL;

	switch(call) {
	case STACKTRACECALL_ORDER:
		/*
		 * Command stacktrace module to control tracing.
		 */
		if (copyin(args, &p, sizeof(struct stacktrace_user_args)))
			return (EFAULT);
		if (p.version != STACKTRACE_INTERFACE_VERSION)
			return (err);

		switch (p.param) {
		case STACKTRACE_ON:
			/*
			 * If tracing goes from off too on, reset the buffer.
			 */
			if (global_enable != STACKTRACE_ON) {
				initpointers();
				global_enable = STACKTRACE_ON;
			}
			err = 0;
	    		break;

		case STACKTRACE_OFF:






	    		global_enable = STACKTRACE_OFF;
			err = 0;
			break;

		case FULLBUFF_RESET:
			global_fullbuffer_action = FULLBUFF_RESET;
			err = 0;
			break;

		case FULLBUFF_STOP:
			global_fullbuffer_action = FULLBUFF_STOP;
			err = 0;
			break;

		default:
			err = EINVAL;
			break;
		}
		break;

	case STACKTRACECALL_GETBUF:
		/*
		 * deliver the buffer to userland and reset it.
		 */
		if (copyin(args, &p, sizeof(struct stacktrace_user_args)))
			return (EFAULT);
		if (p.version != STACKTRACE_INTERFACE_VERSION)
			return (err);
		if (p.bufmaxsize < 0)
			return (err);
		if (buffer_basep == NULL)	/* Early call? */
			return (err);
		short prev_global_enable = global_enable;
		/*
		 * Disable tracing in case of page faults during copyout().
		 */
		global_enable = STACKTRACE_OFF;

		/*
		 * Calculate number of bytes used in buffer.
		 */
		int nbytes = (buffer_workp - buffer_basep);
		if (p.bufmaxsize < nbytes)
			nbytes = p.bufmaxsize;	/* Don't overrun user. */
		struct stacktrace_buf_head *buffer_headp =
		    (struct stacktrace_buf_head *)buffer_basep;
		buffer_headp->version = STACKTRACE_INTERFACE_VERSION;
		buffer_headp->ncalls = global_ncalls;
		buffer_headp->bufwraps = global_resets;
		buffer_headp->maxdepth = global_naxdepth;

		/*
		 * TODO: Return timestamps for the last reset and last call,
		 * .. also buffersize, global_fullbuffer_action, and
		 * global_enable.
		 */
		printf("stacktrace: copyout %d %d\n", nbytes, global_ncalls);
		err = copyout(buffer_basep, p.userbuffp, nbytes);
		initpointers(); // reset buffer to empty

		/*
		 * Restore master trace setting following copyout() and
		 * buffer reset.  If we had disabled tracing due to a full
		 * buffer, enable it now that the buffer has been flushed.
		 */
		global_enable = (prev_global_enable == STACKTRACE_FULL) ?
		    STACKTRACE_ON : prev_global_enable;
		break;

    	default:
		err = EINVAL;
		break;
	}

	return (err);
} // stacktrace_syscall

// ================================================================

static void
stacktrace_init_bsd (struct mac_policy_conf *mpc)
{
	/*
	 * We don't trace anything before this call.  Thus we miss two calls:
	 * to init and init_task_label (from machine_startup -> setup_main).
	 */
	global_enable = STACKTRACE_ON;
	initpointers();
	trace(&init_bsd_td);
}

static void
stacktrace_destroy(struct mac_policy_conf *mpc) 
{
	trace(&destroy_td);
}

static void
stacktrace_init(struct mac_policy_conf *mpc) 
{
	trace(&init_td);
}

static void
stacktrace_init_cred_label(struct label *label) 
{
	trace(&init_cred_label_td);
}

static void
stacktrace_init_lctx_label(struct label *label) 
{
	trace(&init_lctx_label_td);
}

static void
stacktrace_init_devfsdirent_label(struct label *label) 
{
	trace(&init_devfsdirent_label_td);
}

static void
stacktrace_init_mbuf_failed_label(struct label *label) 
{
	trace(&init_mbuf_failed_label_td);
}

static int
stacktrace_init_mbuf_socket_label(struct label *label, int waitok) 
{
	trace(&init_mbuf_socket_label_td);
	return (0);
}

static void
stacktrace_init_mount_label(struct label *label) 
{
	trace(&init_mount_label_td);
}

static void
stacktrace_init_mount_fs_label(struct label *label) 
{
	trace(&init_mount_fs_label_td);
}

static void
stacktrace_init_port_label(struct label *label) 
{
	trace(&init_port_label_td);
}

static void
stacktrace_init_posix_sem_label(struct label *label) 
{
	trace(&init_posix_sem_label_td);
}

static void
stacktrace_init_posix_shm_label(struct label *label) 
{
	trace(&init_posix_shm_label_td);
}

static void
stacktrace_init_proc_label(struct label *label) 
{
	trace(&init_proc_label_td);
}

static int
stacktrace_init_socket_label(struct label *label, int waitok) 
{
	trace(&init_socket_label_td);
	return (0);
}

static int
stacktrace_init_socket_peer_label(struct label *label, int waitok) 
{
	trace(&init_socket_peer_label_td);
	return (0);
}

static void
stacktrace_init_sysv_sem_label(struct label *label) 
{
	trace(&init_sysv_sem_label_td);
}

static void
stacktrace_init_sysv_shm_label(struct label *label) 
{
	trace(&init_sysv_shm_label_td);
}

static void
stacktrace_init_task_label(struct label *label) 
{
	trace(&init_task_label_td);
}

static void
stacktrace_init_tcp_label(struct label *label) 
{
	trace(&init_tcp_label_td);
}

static void
stacktrace_init_mbuf_unknown_source_label(struct label *label) 
{
	trace(&init_mbuf_unknown_source_label_td);
}

static void
stacktrace_init_vnode_label(struct label *label) 
{
	trace(&init_vnode_label_td);
}

static void
stacktrace_destroy_cred_label(struct label *label) 
{
	trace(&destroy_cred_label_td);
}

static void
stacktrace_destroy_lctx_label(struct label *label) 
{
	trace(&destroy_lctx_label_td);
}

static void
stacktrace_destroy_devfsdirent_label(struct label *label) 
{
	trace(&destroy_devfsdirent_label_td);
}

static void
stacktrace_destroy_mbuf_socket_label(struct label *label) 
{
	trace(&destroy_mbuf_socket_label_td);
}

static void
stacktrace_destroy_mount_label(struct label *label) 
{
	trace(&destroy_mount_label_td);
}

static void
stacktrace_destroy_mount_fs_label(struct label *label) 
{
	trace(&destroy_mount_fs_label_td);
}

static void
stacktrace_destroy_port_label(struct label *label) 
{
	trace(&destroy_port_label_td);
}

static void
stacktrace_destroy_posix_sem_label(struct label *label) 
{
	trace(&destroy_posix_sem_label_td);
}

static void
stacktrace_destroy_posix_shm_label(struct label *label) 
{
	trace(&destroy_posix_shm_label_td);
}

static void
stacktrace_destroy_proc_label(struct label *label) 
{
	trace(&destroy_proc_label_td);
}

static void
stacktrace_destroy_socket_label(struct label *label) 
{
	trace(&destroy_socket_label_td);
}

static void
stacktrace_destroy_socket_peer_label(struct label *label) 
{
	trace(&destroy_socket_peer_label_td);
}

static void
stacktrace_destroy_sysv_sem_label(struct label *label) 
{
	trace(&destroy_sysv_sem_label_td);
}

static void
stacktrace_destroy_sysv_shm_label(struct label *label) 
{
	trace(&destroy_sysv_shm_label_td);
}

static void
stacktrace_destroy_task_label(struct label *label) 
{
	trace(&destroy_task_label_td);
}

static void
stacktrace_destroy_vnode_label(struct label *label) 
{
	trace(&destroy_vnode_label_td);
}

static void
stacktrace_cleanup_sysv_sem_label(struct label *label) 
{
	trace(&cleanup_sysv_sem_label_td);
}

static void
stacktrace_cleanup_sysv_shm_label(struct label *shmlabel) 
{
	trace(&cleanup_sysv_shm_label_td);
}

static void
stacktrace_copy_cred_to_task(struct label *cred, struct label *task) 
{
	trace(&copy_cred_to_task_td);
}

static void
stacktrace_update_port_from_cred_label(struct label *cred, struct label *task) 
{
	trace(&update_port_from_cred_label_td);
}

static void
stacktrace_copy_vnode_label(struct label *src, struct label *dest) 
{
	trace(&copy_vnode_label_td);
}

static void
stacktrace_copy_devfs_label(struct label *src, struct label *dest) 
{
	trace(&copy_devfs_label_td);
}

static void
stacktrace_copy_mbuf_socket_label(struct label *src, struct label *dest) 
{
	trace(&copy_mbuf_socket_label_td);
}

static void
stacktrace_copy_port_label(struct label *src, struct label *dest) 
{
	trace(&copy_port_label_td);
}

static int
stacktrace_externalize_cred_label(struct label *label, char *element_name, struct sbuf *sb) 
{
	trace(&externalize_cred_label_td);
	return (0);
}

static int
stacktrace_externalize_cred_audit_label(struct label *label, char *element_name, struct sbuf *sb) 
{
	trace(&externalize_cred_audit_label_td);
	return (0);
}

static int
stacktrace_externalize_lctx_label(struct label *label, char *element_name, struct sbuf *sb) 
{
	trace(&externalize_lctx_label_td);
	return (0);
}

static int
stacktrace_externalize_vnode_label(struct label *label, char *element_name, struct sbuf *sb) 
{
	trace(&externalize_vnode_label_td);
	return (0);
}

static int
stacktrace_externalize_vnode_audit_label(struct label *label, char *element_name, struct sbuf *sb) 
{
	trace(&externalize_vnode_audit_label_td);
	return (0);
}

static int
stacktrace_internalize_cred_label(struct label *label, char *element_name, char *element_data) 
{
	trace(&internalize_cred_label_td);
	return (0);
}

static int
stacktrace_internalize_lctx_label(struct label *label, char *element_name, char *element_data) 
{
	trace(&internalize_lctx_label_td);
	return (0);
}

static int
stacktrace_internalize_vnode_label(struct label *label, char *element_name, char *element_data) 
{
	trace(&internalize_vnode_label_td);
	return (0);
}

static void
stacktrace_associate_vnode_devfs(struct mount *mp, struct label *fslabel, struct devnode *de, struct label *delabel, struct vnode *vp, struct label *vlabel) 
{
	trace(&associate_vnode_devfs_td);
}

static int
stacktrace_associate_vnode_extattr(struct mount *mp, struct label *fslabel, struct vnode *vp, struct label *vlabel) 
{
	trace(&associate_vnode_extattr_td);
	return (0);
}

static void
stacktrace_associate_vnode_singlelabel(struct mount *mp, struct label *fslabel, struct vnode *vp, struct label *vlabel) 
{
	trace(&associate_vnode_singlelabel_td);
}

static void
stacktrace_create_devfs_device(struct ucred *cred, struct mount *mp, dev_t dev, struct devnode *de, struct label *label, const char *fullpath) 
{
	trace(&create_devfs_device_td);
}

static void
stacktrace_create_devfs_directory(struct mount *mp, char *dirname, int dirnamelen, struct devnode *de, struct label *label, const char *fullpath) 
{
	trace(&create_devfs_directory_td);
}

static void
stacktrace_create_devfs_symlink(struct ucred *cred, struct mount *mp, struct devnode *dd, struct label *ddlabel, struct devnode *de, struct label *delabel, const char *fullpath) 
{
	trace(&create_devfs_symlink_td);
}

static int
stacktrace_create_vnode_extattr(struct ucred *cred, struct mount *mp, struct label *fslabel, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *vlabel, struct componentname *cnp) 
{
	trace(&create_vnode_extattr_td);
	return (0);
}

static void
stacktrace_create_mount(struct ucred *cred, struct mount *mp, struct label *mntlabel, struct label *fslabel) 
{
	trace(&create_mount_td);
}

static void
stacktrace_relabel_vnode(struct ucred *cred, struct vnode *vp, struct label *vnodelabel, struct label *label) 
{
	trace(&relabel_vnode_td);
}

static int
stacktrace_setlabel_vnode_extattr(struct ucred *cred, struct vnode *vp, struct label *vlabel, struct label *intlabel) 
{
	trace(&setlabel_vnode_extattr_td);
	return (0);
}

static void
stacktrace_update_devfsdirent(struct mount *mp, struct devnode *de, struct label *delabel, struct vnode *vp, struct label *vnodelabel) 
{
	trace(&update_devfsdirent_td);
}

static void
stacktrace_copy_socket_label(struct label *src, struct label *dest) 
{
	trace(&copy_socket_label_td);
}

static void
stacktrace_create_socket(struct ucred *cred, struct socket *so, struct label *solabel) 
{
	trace(&create_socket_td);
}

static void
stacktrace_create_socket_from_socket(struct socket *oldsock, struct label *oldlabel, struct socket *newsock, struct label *newlabel) 
{
	trace(&create_socket_from_socket_td);
}

static void
stacktrace_create_mbuf_from_socket(struct socket *so, struct label *so_label, struct mbuf *m, struct label *m_label) 
{
	trace(&create_mbuf_from_socket_td);
}

static int
stacktrace_externalize_socket_label(struct label *label, char *element_name, struct sbuf *sb) 
{
	trace(&externalize_socket_label_td);
	return (0);
}

static int
stacktrace_externalize_socket_peer_label(struct label *label, char *element_name, struct sbuf *sb) 
{
	trace(&externalize_socket_peer_label_td);
	return (0);
}

static int
stacktrace_internalize_socket_label(struct label *label, char *element_name, char *element_data) 
{
	trace(&internalize_socket_label_td);
	return (0);
}

static void
stacktrace_relabel_socket(struct ucred *cred, struct socket *so, struct label *so_label, struct label *newlabel) 
{
	trace(&relabel_socket_td);
}

static void
stacktrace_set_socket_peer_from_socket(struct socket *source, struct label *sourcelabel, struct socket *target, struct label *targetlabel) 
{
	trace(&set_socket_peer_from_socket_td);
}

static void
stacktrace_set_socket_peer_from_mbuf(struct mbuf *m, struct label *m_label, struct socket *so, struct label *so_label) 
{
	trace(&set_socket_peer_from_mbuf_td);
}

static void
stacktrace_create_port(struct label *it, struct label *st, struct label *portlabel) 
{
	trace(&create_port_td);
}

static void
stacktrace_create_kernel_port(struct label *portlabel, int isreply) 
{
	trace(&create_kernel_port_td);
}

static void
stacktrace_update_port_kobject(struct label *portlabel, int kotype) 
{
	trace(&update_port_kobject_td);
}

static void
stacktrace_create_posix_sem(struct ucred *cred, struct pseminfo *ps, struct label *semlabel, const char *name) 
{
	trace(&create_posix_sem_td);
}

static void
stacktrace_create_posix_shm(struct ucred *cred, struct pshminfo *ps, struct label *shmlabel, const char *name) 
{
	trace(&create_posix_shm_td);
}

static void
stacktrace_create_sysv_sem(struct ucred *cred, struct semid_kernel *semakptr, struct label *semalabel) 
{
	trace(&create_sysv_sem_td);
}

static void
stacktrace_create_sysv_shm(struct ucred *cred, struct shmid_kernel *shmsegptr, struct label *shmlabel) 
{
	trace(&create_sysv_shm_td);
}

static void
stacktrace_create_cred(struct ucred *parent_cred, struct ucred *child_cred) 
{
	trace(&create_cred_td);
}

static void
stacktrace_create_task(struct task *parent, struct task *child, struct label *parentlabel, struct label *childlabel, struct label *childportlabel) 
{
	trace(&create_task_td);
}

static void
stacktrace_create_kernel_task(struct task *kproc, struct label *tasklabel, struct label *portlabel) 
{
	trace(&create_kernel_task_td);
}

static void
stacktrace_execve_transition(struct ucred *old, struct ucred *new, struct vnode *vp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel) 
{
	trace(&execve_transition_td);
}

static int
stacktrace_execve_will_transition(struct ucred *old, struct vnode *vp, struct label *vnodelabel, struct label *scriptvnodelabel, struct label *execlabel, struct proc *proc) 
{
	trace(&execve_will_transition_td);
	return (0);
}

static void
stacktrace_create_proc0(struct ucred *cred) 
{
	trace(&create_proc0_td);
}

static void
stacktrace_create_proc1(struct ucred *cred) 
{
	trace(&create_proc1_td);
}

static void
stacktrace_relabel_cred(struct ucred *cred, struct label *newlabel) 
{
	trace(&relabel_cred_td);
}

static int
stacktrace_request_object_label(struct label *subj, struct label *obj, const char *serv, struct label *out) 
{
	trace(&request_object_label_td);
	return (0);
}

static void
stacktrace_proc_create_lctx(struct proc *p, struct lctx *l) 
{
	trace(&proc_create_lctx_td);
}

static void
stacktrace_proc_join_lctx(struct proc *p, struct lctx *l) 
{
	trace(&proc_join_lctx_td);
}

static void
stacktrace_proc_leave_lctx(struct proc *p, struct lctx *l) 
{
	trace(&proc_leave_lctx_td);
}

static void
stacktrace_relabel_lctx(struct lctx *l, struct label *newlabel) 
{
	trace(&relabel_lctx_td);
}

static int
stacktrace_check_service_access(struct label *subj, struct label *obj, const char *serv, const char *perm) 
{
	trace(&check_service_access_td);
	return (0);
}

static int
stacktrace_check_cred_relabel(struct ucred *cred, struct label *newlabel) 
{
	trace(&check_cred_relabel_td);
	return (0);
}

static int
stacktrace_check_lctx_relabel(struct lctx *l, struct label *newlabel) 
{
	trace(&check_lctx_relabel_td);
	return (0);
}

static int
stacktrace_check_port_relabel(struct label *task, struct label *oldlabel, struct label *newlabel) 
{
	trace(&check_port_relabel_td);
	return (0);
}

static int
stacktrace_check_port_send(struct label *task, struct label *port) 
{
	trace(&check_port_send_td);
	return (0);
}

static int
stacktrace_check_port_make_send(struct label *task, struct label *port) 
{
	trace(&check_port_make_send_td);
	return (0);
}

static int
stacktrace_check_port_copy_send(struct label *task, struct label *port) 
{
	trace(&check_port_copy_send_td);
	return (0);
}

static int
stacktrace_check_port_hold_send(struct label *task, struct label *port) 
{
	trace(&check_port_hold_send_td);
	return (0);
}

static int
stacktrace_check_port_hold_receive(struct label *task, struct label *port) 
{
	trace(&check_port_hold_receive_td);
	return (0);
}

static int
stacktrace_check_port_move_receive(struct label *task, struct label *port) 
{
	trace(&check_port_move_receive_td);
	return (0);
}

static int
stacktrace_check_cred_visible(struct ucred *u1, struct ucred *u2) 
{
	trace(&check_cred_visible_td);
	return (0);
}

static int
stacktrace_check_fcntl(struct ucred *cred, struct file *fd, int cmd, int arg) 
{
	trace(&check_fcntl_td);
	return (0);
}

static int
stacktrace_check_get_fd(struct ucred *cred, struct file *fd, char *elements, int len) 
{
	trace(&check_get_fd_td);
	return (0);
}

static int
stacktrace_check_ioctl(struct ucred *cred, struct file *fd, int com, void *data) 
{
	trace(&check_ioctl_td);
	return (0);
}

static int
stacktrace_check_ipc_method(struct label *task, struct label *port, int msgid) 
{
	trace(&check_ipc_method_td);
	return (0);
}

static int
stacktrace_check_posix_sem_create(struct ucred *cred, const char *name) 
{
	trace(&check_posix_sem_create_td);
	return (0);
}

static int
stacktrace_check_posix_sem_open(struct ucred *cred, struct pseminfo *ps, struct label *semlabel) 
{
	trace(&check_posix_sem_open_td);
	return (0);
}

static int
stacktrace_check_posix_sem_post(struct ucred *cred, struct pseminfo *ps, struct label *semlabel) 
{
	trace(&check_posix_sem_post_td);
	return (0);
}

static int
stacktrace_check_posix_sem_unlink(struct ucred *cred, struct pseminfo *ps, struct label *semlabel, const char *name) 
{
	trace(&check_posix_sem_unlink_td);
	return (0);
}

static int
stacktrace_check_posix_sem_wait(struct ucred *cred, struct pseminfo *ps, struct label *semlabel) 
{
	trace(&check_posix_sem_wait_td);
	return (0);
}

static int
stacktrace_check_posix_shm_create(struct ucred *cred, const char *name) 
{
	trace(&check_posix_shm_create_td);
	return (0);
}

static int
stacktrace_check_posix_shm_open(struct ucred *cred, struct pshminfo *ps, struct label *shmlabel) 
{
	trace(&check_posix_shm_open_td);
	return (0);
}

static int
stacktrace_check_posix_shm_mmap(struct ucred *cred, struct pshminfo *ps, struct label *shmlabel, int prot, int flags) 
{
	trace(&check_posix_shm_mmap_td);
	return (0);
}

static int
stacktrace_check_posix_shm_stat(struct ucred *cred, struct pshminfo *ps, struct label *shmlabel) 
{
	trace(&check_posix_shm_stat_td);
	return (0);
}

static int
stacktrace_check_posix_shm_truncate(struct ucred *cred, struct pshminfo *ps, struct label *shmlabel, size_t len) 
{
	trace(&check_posix_shm_truncate_td);
	return (0);
}

static int
stacktrace_check_posix_shm_unlink(struct ucred *cred, struct pshminfo *ps, struct label *shmlabel, const char *name) 
{
	trace(&check_posix_shm_unlink_td);
	return (0);
}

static int
stacktrace_check_sysv_semctl(struct ucred *cred, struct semid_kernel *semakptr, struct label *semaklabel, int cmd) 
{
	trace(&check_sysv_semctl_td);
	return (0);
}

static int
stacktrace_check_sysv_semget(struct ucred *cred, struct semid_kernel *semakptr, struct label *semaklabel) 
{
	trace(&check_sysv_semget_td);
	return (0);
}

static int
stacktrace_check_sysv_semop(struct ucred *cred, struct semid_kernel *semakptr, struct label *semaklabel, size_t accesstype) 
{
	trace(&check_sysv_semop_td);
	return (0);
}

static int
stacktrace_check_sysv_shmat(struct ucred *cred, struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg) 
{
	trace(&check_sysv_shmat_td);
	return (0);
}

static int
stacktrace_check_sysv_shmctl(struct ucred *cred, struct shmid_kernel *shmsegptr, struct label *shmseglabel, int cmd) 
{
	trace(&check_sysv_shmctl_td);
	return (0);
}

static int
stacktrace_check_sysv_shmdt(struct ucred *cred, struct shmid_kernel *shmsegptr, struct label *shmseglabel) 
{
	trace(&check_sysv_shmdt_td);
	return (0);
}

static int
stacktrace_check_sysv_shmget(struct ucred *cred, struct shmid_kernel *shmsegptr, struct label *shmseglabel, int shmflg) 
{
	trace(&check_sysv_shmget_td);
	return (0);
}

static int
stacktrace_check_mount_stat(struct ucred *cred, struct mount *mp, struct label *mntlabel) 
{
	trace(&check_mount_stat_td);
	return (0);
}

static int
stacktrace_check_proc_debug(struct ucred *cred, struct proc *proc) 
{
	trace(&check_proc_debug_td);
	return (0);
}

static int
stacktrace_check_proc_sched(struct ucred *cred, struct proc *proc) 
{
	trace(&check_proc_sched_td);
	return (0);
}

static int
stacktrace_check_proc_signal(struct ucred *cred, struct proc *proc, int signum) 
{
	trace(&check_proc_signal_td);
	return (0);
}

static int
stacktrace_check_proc_wait(struct ucred *cred, struct proc *proc) 
{
	trace(&check_proc_wait_td);
	return (0);
}

static int
stacktrace_check_set_fd(struct ucred *cred, struct file *fd, char *elements, int len) 
{
	trace(&check_set_fd_td);
	return (0);
}

static int
stacktrace_check_socket_accept(struct ucred *cred, struct socket *socket, struct label *socklabel, struct sockaddr *addr) 
{
	trace(&check_socket_accept_td);
	return (0);
}

static int
stacktrace_check_socket_bind(struct ucred *cred, struct socket *socket, struct label *socklabel, struct sockaddr *addr) 
{
	trace(&check_socket_bind_td);
	return (0);
}

static int
stacktrace_check_socket_connect(struct ucred *cred, struct socket *socket, struct label *socklabel, struct sockaddr *addr) 
{
	trace(&check_socket_connect_td);
	return (0);
}

static int
stacktrace_check_socket_deliver(struct socket *so, struct label *so_label, struct mbuf *m, struct label *m_label) 
{
	trace(&check_socket_deliver_td);
	return (0);
}

static int
stacktrace_check_socket_listen(struct ucred *cred, struct socket *socket, struct label *socklabel) 
{
	trace(&check_socket_listen_td);
	return (0);
}

static int
stacktrace_check_socket_poll(struct ucred *cred, struct socket *socket, struct label *socklabel) 
{
	trace(&check_socket_poll_td);
	return (0);
}

static int
stacktrace_check_socket_receive(struct ucred *cred, struct socket *socket, struct label *socklabel) 
{
	trace(&check_socket_receive_td);
	return (0);
}

static int
stacktrace_check_socket_relabel(struct ucred *cred, struct socket *so, struct label *so_label, struct label *newlabel) 
{
	trace(&check_socket_relabel_td);
	return (0);
}

static int
stacktrace_check_socket_select(struct ucred *cred, struct socket *so, struct label *socklabel) 
{
	trace(&check_socket_select_td);
	return (0);
}

static int
stacktrace_check_socket_send(struct ucred *cred, struct socket *so, struct label *socklabel) 
{
	trace(&check_socket_send_td);
	return (0);
}

static int
stacktrace_check_socket_stat(struct ucred *cred, struct socket *so, struct label *socklabel) 
{
	trace(&check_socket_stat_td);
	return (0);
}

static int
stacktrace_check_system_acct(struct ucred *cred, struct vnode *vp, struct label *vlabel) 
{
	trace(&check_system_acct_td);
	return (0);
}

static int
stacktrace_check_system_nfsd(struct ucred *cred) 
{
	trace(&check_system_nfsd_td);
	return (0);
}

static int
stacktrace_check_system_reboot(struct ucred *cred, int howto) 
{
	trace(&check_system_reboot_td);
	return (0);
}

static int
stacktrace_check_system_settime(struct ucred *cred) 
{
	trace(&check_system_settime_td);
	return (0);
}

static int
stacktrace_check_system_swapon(struct ucred *cred, struct vnode *vp, struct label *label) 
{
	trace(&check_system_swapon_td);
	return (0);
}

static int
stacktrace_check_system_swapoff(struct ucred *cred, struct vnode *vp, struct label *label) 
{
	trace(&check_system_swapoff_td);
	return (0);
}

static int
stacktrace_check_system_sysctl(struct ucred *cred, int *name, u_int namelen, void *old, size_t *oldlenp, int inkernel, void *new, size_t newlen) 
{
	trace(&check_system_sysctl_td);
	return (0);
}

static int
stacktrace_check_vnode_access(struct ucred *cred, struct vnode *vp, struct label *label, int acc_mode) 
{
	trace(&check_vnode_access_td);
	return (0);
}

static int
stacktrace_check_vnode_chdir(struct ucred *cred, struct vnode *dvp, struct label *dlabel) 
{
	trace(&check_vnode_chdir_td);
	return (0);
}

static int
stacktrace_check_vnode_chroot(struct ucred *cred, struct vnode *dvp, struct label *dlabel) 
{
	trace(&check_vnode_chroot_td);
	return (0);
}

static int
stacktrace_check_vnode_create(struct ucred *cred, struct vnode *dvp, struct label *dlabel, struct componentname *cnp, struct vattr *vap) 
{
	trace(&check_vnode_create_td);
	return (0);
}

static int
stacktrace_check_vnode_delete(struct ucred *cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp) 
{
	trace(&check_vnode_delete_td);
	return (0);
}

static int
stacktrace_check_vnode_deleteextattr(struct ucred *cred, struct vnode *vp, int attrnamespace, const char *name) 
{
	trace(&check_vnode_deleteextattr_td);
	return (0);
}

static int
stacktrace_check_vnode_exchangedata(struct ucred *cred, struct vnode *v1, struct label *vl1, struct vnode *v2, struct label *vl2) 
{
	trace(&check_vnode_exchangedata_td);
	return (0);
}

static int
stacktrace_check_vnode_exec(struct ucred *cred, struct vnode *vp, struct label *label, struct label *execlabel) 
{
	trace(&check_vnode_exec_td);
	return (0);
}

static int
stacktrace_check_vnode_getattrlist(struct ucred *cred, struct vnode *vp, struct label *vlabel, struct attrlist *alist, struct uio *attrblk) 
{
	trace(&check_vnode_getattrlist_td);
	return (0);
}

static int
stacktrace_check_vnode_getextattr(struct ucred *cred, struct vnode *vp, struct label *label, int attrnamespace, const char *name, struct uio *uio) 
{
	trace(&check_vnode_getextattr_td);
	return (0);
}

static int
stacktrace_check_vnode_link(struct ucred *cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp) 
{
	trace(&check_vnode_link_td);
	return (0);
}

static int
stacktrace_check_vnode_listextattr(struct ucred *cred, struct vnode *vp, int attrnamespace) 
{
	trace(&check_vnode_listextattr_td);
	return (0);
}

static int
stacktrace_check_vnode_lookup(struct ucred *cred, struct vnode *dvp, struct label *dlabel, struct componentname *cnp) 
{
	trace(&check_vnode_lookup_td);
	return (0);
}

static int
stacktrace_check_vnode_mmap(struct ucred *cred, struct vnode *vp, struct label *label, int prot, int flags, int *maxprot) 
{
	trace(&check_vnode_mmap_td);
	return (0);
}

static void
stacktrace_check_vnode_mmap_downgrade(struct ucred *cred, struct vnode *vp, struct label *label, int *prot) 
{
	trace(&check_vnode_mmap_downgrade_td);
}

static int
stacktrace_check_vnode_mprotect(struct ucred *cred, struct vnode *vp, struct label *label, int prot) 
{
	trace(&check_vnode_mprotect_td);
	return (0);
}

static int
stacktrace_check_vnode_open(struct ucred *cred, struct vnode *vp, struct label *label, int acc_mode) 
{
	trace(&check_vnode_open_td);
	return (0);
}

static int
stacktrace_check_vnode_poll(struct ucred *active_cred, struct ucred *file_cred, struct vnode *vp, struct label *label) 
{
	trace(&check_vnode_poll_td);
	return (0);
}

static int
stacktrace_check_vnode_read(struct ucred *active_cred, struct ucred *file_cred, struct vnode *vp, struct label *label) 
{
	trace(&check_vnode_read_td);
	return (0);
}

static int
stacktrace_check_vnode_readdir(struct ucred *cred, struct vnode *dvp, struct label *dlabel) 
{
	trace(&check_vnode_readdir_td);
	return (0);
}

static int
stacktrace_check_vnode_readlink(struct ucred *cred, struct vnode *vp, struct label *label) 
{
	trace(&check_vnode_readlink_td);
	return (0);
}

static int
stacktrace_check_vnode_relabel(struct ucred *cred, struct vnode *vp, struct label *vnodelabel, struct label *newlabel) 
{
	trace(&check_vnode_relabel_td);
	return (0);
}

static int
stacktrace_check_vnode_rename_from(struct ucred *cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, struct componentname *cnp) 
{
	trace(&check_vnode_rename_from_td);
	return (0);
}

static int
stacktrace_check_vnode_rename_to(struct ucred *cred, struct vnode *dvp, struct label *dlabel, struct vnode *vp, struct label *label, int samedir, struct componentname *cnp) 
{
	trace(&check_vnode_rename_to_td);
	return (0);
}

static int
stacktrace_check_vnode_revoke(struct ucred *cred, struct vnode *vp, struct label *label) 
{
	trace(&check_vnode_revoke_td);
	return (0);
}

static int
stacktrace_check_vnode_select(struct ucred *cred, struct vnode *vp, struct label *label) 
{
	trace(&check_vnode_select_td);
	return (0);
}

static int
stacktrace_check_vnode_setattrlist(struct ucred *cred, struct vnode *vp, struct label *vlabel, struct attrlist *alist, struct uio *attrblk) 
{
	trace(&check_vnode_setattrlist_td);
	return (0);
}

static int
stacktrace_check_vnode_setextattr(struct ucred *cred, struct vnode *vp, struct label *label, int attrnamespace, const char *name, struct uio *uio) 
{
	trace(&check_vnode_setextattr_td);
	return (0);
}

static int
stacktrace_check_vnode_setflags(struct ucred *cred, struct vnode *vp, struct label *label, u_long flags) 
{
	trace(&check_vnode_setflags_td);
	return (0);
}

static int
stacktrace_check_vnode_setmode(struct ucred *cred, struct vnode *vp, struct label *label, mode_t mode) 
{
	trace(&check_vnode_setmode_td);
	return (0);
}

static int
stacktrace_check_vnode_setowner(struct ucred *cred, struct vnode *vp, struct label *label, uid_t uid, gid_t gid) 
{
	trace(&check_vnode_setowner_td);
	return (0);
}

static int
stacktrace_check_vnode_setutimes(struct ucred *cred, struct vnode *vp, struct label *label, struct timespec atime, struct timespec mtime) 
{
	trace(&check_vnode_setutimes_td);
	return (0);
}

static int
stacktrace_check_vnode_stat(struct ucred *active_cred, struct ucred *file_cred, struct vnode *vp, struct label *label) 
{
	trace(&check_vnode_stat_td);
	return (0);
}

static int
stacktrace_check_vnode_write(struct ucred *active_cred, struct ucred *file_cred, struct vnode *vp, struct label *label) 
{
	trace(&check_vnode_write_td);
	return (0);
}

static int
stacktrace_check_system_audit(struct ucred *cred, void *record, int length) 
{
	trace(&check_system_audit_td);
	return (0);
}

static int
stacktrace_check_system_auditon(struct ucred *cred, int cmd) 
{
	trace(&check_system_auditon_td);
	return (0);
}

static int
stacktrace_check_system_auditctl(struct ucred *cred, struct vnode *vp, struct label *vl) 
{
	trace(&check_system_auditctl_td);
	return (0);
}

static int
stacktrace_check_proc_getauid(struct ucred *cred) 
{
	trace(&check_proc_getauid_td);
	return (0);
}

static int
stacktrace_check_proc_getlcid(struct proc *p0, struct proc *p, pid_t pid) 
{
	trace(&check_proc_getlcid_td);
	return (0);
}

static int
stacktrace_check_proc_setauid(struct ucred *cred, uid_t auid) 
{
	trace(&check_proc_setauid_td);
	return (0);
}

static int
stacktrace_check_proc_setlcid(struct proc *p0, struct proc *p, pid_t pid, pid_t lcid) 
{
	trace(&check_proc_setlcid_td);
	return (0);
}

static int
stacktrace_check_proc_getaudit(struct ucred *cred) 
{
	trace(&check_proc_getaudit_td);
	return (0);
}

static int
stacktrace_check_proc_setaudit(struct ucred *cred, struct auditinfo *ai) 
{
	trace(&check_proc_setaudit_td);
	return (0);
}

static int
stacktrace_audit_preselect(struct ucred *cred, unsigned short syscode, void *args) 
{
	trace(&audit_preselect_td);
	return (0);
}

static int
stacktrace_audit_postselect(struct ucred *cred, unsigned short syscode, void *args, int error, int retval) 
{
	trace(&audit_postselect_td);
	return (0);
}


static struct mac_policy_ops stacktrace_ops = {
	.mpo_destroy			= stacktrace_destroy,
	.mpo_init			= stacktrace_init,
	.mpo_init_bsd			= stacktrace_init_bsd,
	.mpo_syscall			= stacktrace_syscall,
	.mpo_init_cred_label		= stacktrace_init_cred_label,
	.mpo_init_lctx_label		= stacktrace_init_lctx_label,
	.mpo_init_devfsdirent_label	= stacktrace_init_devfsdirent_label,
	.mpo_init_mbuf_failed_label	= stacktrace_init_mbuf_failed_label,
	.mpo_init_mbuf_socket_label	= stacktrace_init_mbuf_socket_label,
	.mpo_init_mount_label		= stacktrace_init_mount_label,
	.mpo_init_mount_fs_label	= stacktrace_init_mount_fs_label,
	.mpo_init_port_label		= stacktrace_init_port_label,
	.mpo_init_posix_sem_label	= stacktrace_init_posix_sem_label,
	.mpo_init_posix_shm_label	= stacktrace_init_posix_shm_label,
	.mpo_init_proc_label		= stacktrace_init_proc_label,
	.mpo_init_socket_label		= stacktrace_init_socket_label,
	.mpo_init_socket_peer_label	= stacktrace_init_socket_peer_label,
	.mpo_init_sysv_sem_label	= stacktrace_init_sysv_sem_label,
	.mpo_init_sysv_shm_label	= stacktrace_init_sysv_shm_label,
	.mpo_init_task_label		= stacktrace_init_task_label,
	.mpo_init_tcp_label		= stacktrace_init_tcp_label,
	.mpo_init_mbuf_unknown_source_label= stacktrace_init_mbuf_unknown_source_label,
	.mpo_init_vnode_label		= stacktrace_init_vnode_label,
	.mpo_destroy_cred_label		= stacktrace_destroy_cred_label,
	.mpo_destroy_lctx_label		= stacktrace_destroy_lctx_label,
	.mpo_destroy_devfsdirent_label	= stacktrace_destroy_devfsdirent_label,
	.mpo_destroy_mbuf_socket_label	= stacktrace_destroy_mbuf_socket_label,
	.mpo_destroy_mount_label	= stacktrace_destroy_mount_label,
	.mpo_destroy_mount_fs_label	= stacktrace_destroy_mount_fs_label,
	.mpo_destroy_port_label		= stacktrace_destroy_port_label,
	.mpo_destroy_posix_sem_label	= stacktrace_destroy_posix_sem_label,
	.mpo_destroy_posix_shm_label	= stacktrace_destroy_posix_shm_label,
	.mpo_destroy_proc_label		= stacktrace_destroy_proc_label,
	.mpo_destroy_socket_label	= stacktrace_destroy_socket_label,
	.mpo_destroy_socket_peer_label	= stacktrace_destroy_socket_peer_label,
	.mpo_destroy_sysv_sem_label	= stacktrace_destroy_sysv_sem_label,
	.mpo_destroy_sysv_shm_label	= stacktrace_destroy_sysv_shm_label,
	.mpo_destroy_task_label		= stacktrace_destroy_task_label,
	.mpo_destroy_vnode_label	= stacktrace_destroy_vnode_label,
	.mpo_cleanup_sysv_sem_label	= stacktrace_cleanup_sysv_sem_label,
	.mpo_cleanup_sysv_shm_label	= stacktrace_cleanup_sysv_shm_label,
	.mpo_copy_cred_to_task		= stacktrace_copy_cred_to_task,
	.mpo_update_port_from_cred_label= stacktrace_update_port_from_cred_label,
	.mpo_copy_vnode_label		= stacktrace_copy_vnode_label,
	.mpo_copy_devfs_label		= stacktrace_copy_devfs_label,
	.mpo_copy_mbuf_socket_label	= stacktrace_copy_mbuf_socket_label,
	.mpo_copy_port_label		= stacktrace_copy_port_label,
	.mpo_externalize_cred_label	= stacktrace_externalize_cred_label,
	.mpo_externalize_cred_audit_label= stacktrace_externalize_cred_audit_label,
	.mpo_externalize_lctx_label	= stacktrace_externalize_lctx_label,
	.mpo_externalize_vnode_label	= stacktrace_externalize_vnode_label,
	.mpo_externalize_vnode_audit_label= stacktrace_externalize_vnode_audit_label,
	.mpo_internalize_cred_label	= stacktrace_internalize_cred_label,
	.mpo_internalize_lctx_label	= stacktrace_internalize_lctx_label,
	.mpo_internalize_vnode_label	= stacktrace_internalize_vnode_label,
	.mpo_associate_vnode_devfs	= stacktrace_associate_vnode_devfs,
	.mpo_associate_vnode_extattr	= stacktrace_associate_vnode_extattr,
	.mpo_associate_vnode_singlelabel= stacktrace_associate_vnode_singlelabel,
	.mpo_create_devfs_device	= stacktrace_create_devfs_device,
	.mpo_create_devfs_directory	= stacktrace_create_devfs_directory,
	.mpo_create_devfs_symlink	= stacktrace_create_devfs_symlink,
	.mpo_create_vnode_extattr	= stacktrace_create_vnode_extattr,
	.mpo_create_mount		= stacktrace_create_mount,
	.mpo_relabel_vnode		= stacktrace_relabel_vnode,
	.mpo_setlabel_vnode_extattr	= stacktrace_setlabel_vnode_extattr,
	.mpo_update_devfsdirent		= stacktrace_update_devfsdirent,
	.mpo_copy_socket_label		= stacktrace_copy_socket_label,
	.mpo_create_socket		= stacktrace_create_socket,
	.mpo_create_socket_from_socket	= stacktrace_create_socket_from_socket,
	.mpo_create_mbuf_from_socket	= stacktrace_create_mbuf_from_socket,
	.mpo_externalize_socket_label	= stacktrace_externalize_socket_label,
	.mpo_externalize_socket_peer_label= stacktrace_externalize_socket_peer_label,
	.mpo_internalize_socket_label	= stacktrace_internalize_socket_label,
	.mpo_relabel_socket		= stacktrace_relabel_socket,
	.mpo_set_socket_peer_from_socket= stacktrace_set_socket_peer_from_socket,
	.mpo_set_socket_peer_from_mbuf	= stacktrace_set_socket_peer_from_mbuf,
	.mpo_create_port		= stacktrace_create_port,
	.mpo_create_kernel_port		= stacktrace_create_kernel_port,
	.mpo_update_port_kobject	= stacktrace_update_port_kobject,
	.mpo_create_posix_sem		= stacktrace_create_posix_sem,
	.mpo_create_posix_shm		= stacktrace_create_posix_shm,
	.mpo_create_sysv_sem		= stacktrace_create_sysv_sem,
	.mpo_create_sysv_shm		= stacktrace_create_sysv_shm,
	.mpo_create_cred		= stacktrace_create_cred,
	.mpo_create_task		= stacktrace_create_task,
	.mpo_create_kernel_task		= stacktrace_create_kernel_task,
	.mpo_execve_transition		= stacktrace_execve_transition,
	.mpo_execve_will_transition	= stacktrace_execve_will_transition,
	.mpo_create_proc0		= stacktrace_create_proc0,
	.mpo_create_proc1		= stacktrace_create_proc1,
	.mpo_relabel_cred		= stacktrace_relabel_cred,
	.mpo_request_object_label	= stacktrace_request_object_label,
	.mpo_proc_create_lctx		= stacktrace_proc_create_lctx,
	.mpo_proc_join_lctx		= stacktrace_proc_join_lctx,
	.mpo_proc_leave_lctx		= stacktrace_proc_leave_lctx,
	.mpo_relabel_lctx		= stacktrace_relabel_lctx,
	.mpo_check_service_access	= stacktrace_check_service_access,
	.mpo_check_cred_relabel		= stacktrace_check_cred_relabel,
	.mpo_check_lctx_relabel		= stacktrace_check_lctx_relabel,
	.mpo_check_port_relabel		= stacktrace_check_port_relabel,
	.mpo_check_port_send		= stacktrace_check_port_send,
	.mpo_check_port_make_send	= stacktrace_check_port_make_send,
	.mpo_check_port_copy_send	= stacktrace_check_port_copy_send,
	.mpo_check_port_hold_send	= stacktrace_check_port_hold_send,
	.mpo_check_port_hold_receive	= stacktrace_check_port_hold_receive,
	.mpo_check_port_move_receive	= stacktrace_check_port_move_receive,
	.mpo_check_cred_visible		= stacktrace_check_cred_visible,
	.mpo_check_fcntl		= stacktrace_check_fcntl,
	.mpo_check_get_fd		= stacktrace_check_get_fd,
	.mpo_check_ioctl		= stacktrace_check_ioctl,
	.mpo_check_ipc_method		= stacktrace_check_ipc_method,
	.mpo_check_posix_sem_create	= stacktrace_check_posix_sem_create,
	.mpo_check_posix_sem_open	= stacktrace_check_posix_sem_open,
	.mpo_check_posix_sem_post	= stacktrace_check_posix_sem_post,
	.mpo_check_posix_sem_unlink	= stacktrace_check_posix_sem_unlink,
	.mpo_check_posix_sem_wait	= stacktrace_check_posix_sem_wait,
	.mpo_check_posix_shm_create	= stacktrace_check_posix_shm_create,
	.mpo_check_posix_shm_open	= stacktrace_check_posix_shm_open,
	.mpo_check_posix_shm_mmap	= stacktrace_check_posix_shm_mmap,
	.mpo_check_posix_shm_stat	= stacktrace_check_posix_shm_stat,
	.mpo_check_posix_shm_truncate	= stacktrace_check_posix_shm_truncate,
	.mpo_check_posix_shm_unlink	= stacktrace_check_posix_shm_unlink,
	.mpo_check_sysv_semctl		= stacktrace_check_sysv_semctl,
	.mpo_check_sysv_semget		= stacktrace_check_sysv_semget,
	.mpo_check_sysv_semop		= stacktrace_check_sysv_semop,
	.mpo_check_sysv_shmat		= stacktrace_check_sysv_shmat,
	.mpo_check_sysv_shmctl		= stacktrace_check_sysv_shmctl,
	.mpo_check_sysv_shmdt		= stacktrace_check_sysv_shmdt,
	.mpo_check_sysv_shmget		= stacktrace_check_sysv_shmget,
	.mpo_check_mount_stat		= stacktrace_check_mount_stat,
	.mpo_check_proc_debug		= stacktrace_check_proc_debug,
	.mpo_check_proc_sched		= stacktrace_check_proc_sched,
	.mpo_check_proc_signal		= stacktrace_check_proc_signal,
	.mpo_check_proc_wait		= stacktrace_check_proc_wait,
	.mpo_check_set_fd		= stacktrace_check_set_fd,
	.mpo_check_socket_accept	= stacktrace_check_socket_accept,
	.mpo_check_socket_bind		= stacktrace_check_socket_bind,
	.mpo_check_socket_connect	= stacktrace_check_socket_connect,
	.mpo_check_socket_deliver	= stacktrace_check_socket_deliver,
	.mpo_check_socket_listen	= stacktrace_check_socket_listen,
	.mpo_check_socket_poll		= stacktrace_check_socket_poll,
	.mpo_check_socket_receive	= stacktrace_check_socket_receive,
	.mpo_check_socket_relabel	= stacktrace_check_socket_relabel,
	.mpo_check_socket_select	= stacktrace_check_socket_select,
	.mpo_check_socket_send		= stacktrace_check_socket_send,
	.mpo_check_socket_stat		= stacktrace_check_socket_stat,
	.mpo_check_system_acct		= stacktrace_check_system_acct,
	.mpo_check_system_nfsd		= stacktrace_check_system_nfsd,
	.mpo_check_system_reboot	= stacktrace_check_system_reboot,
	.mpo_check_system_settime	= stacktrace_check_system_settime,
	.mpo_check_system_swapon	= stacktrace_check_system_swapon,
	.mpo_check_system_swapoff	= stacktrace_check_system_swapoff,
	.mpo_check_system_sysctl	= stacktrace_check_system_sysctl,
	.mpo_check_vnode_access		= stacktrace_check_vnode_access,
	.mpo_check_vnode_chdir		= stacktrace_check_vnode_chdir,
	.mpo_check_vnode_chroot		= stacktrace_check_vnode_chroot,
	.mpo_check_vnode_create		= stacktrace_check_vnode_create,
	.mpo_check_vnode_delete		= stacktrace_check_vnode_delete,
	.mpo_check_vnode_deleteextattr	= stacktrace_check_vnode_deleteextattr,
	.mpo_check_vnode_exchangedata	= stacktrace_check_vnode_exchangedata,
	.mpo_check_vnode_exec		= stacktrace_check_vnode_exec,
	.mpo_check_vnode_getattrlist	= stacktrace_check_vnode_getattrlist,
	.mpo_check_vnode_getextattr	= stacktrace_check_vnode_getextattr,
	.mpo_check_vnode_link		= stacktrace_check_vnode_link,
	.mpo_check_vnode_listextattr	= stacktrace_check_vnode_listextattr,
	.mpo_check_vnode_lookup		= stacktrace_check_vnode_lookup,
	.mpo_check_vnode_mmap		= stacktrace_check_vnode_mmap,
	.mpo_check_vnode_mmap_downgrade	= stacktrace_check_vnode_mmap_downgrade,
	.mpo_check_vnode_mprotect	= stacktrace_check_vnode_mprotect,
	.mpo_check_vnode_open		= stacktrace_check_vnode_open,
	.mpo_check_vnode_poll		= stacktrace_check_vnode_poll,
	.mpo_check_vnode_read		= stacktrace_check_vnode_read,
	.mpo_check_vnode_readdir	= stacktrace_check_vnode_readdir,
	.mpo_check_vnode_readlink	= stacktrace_check_vnode_readlink,
	.mpo_check_vnode_relabel	= stacktrace_check_vnode_relabel,
	.mpo_check_vnode_rename_from	= stacktrace_check_vnode_rename_from,
	.mpo_check_vnode_rename_to	= stacktrace_check_vnode_rename_to,
	.mpo_check_vnode_revoke		= stacktrace_check_vnode_revoke,
	.mpo_check_vnode_select		= stacktrace_check_vnode_select,
	.mpo_check_vnode_setattrlist	= stacktrace_check_vnode_setattrlist,
	.mpo_check_vnode_setextattr	= stacktrace_check_vnode_setextattr,
	.mpo_check_vnode_setflags	= stacktrace_check_vnode_setflags,
	.mpo_check_vnode_setmode	= stacktrace_check_vnode_setmode,
	.mpo_check_vnode_setowner	= stacktrace_check_vnode_setowner,
	.mpo_check_vnode_setutimes	= stacktrace_check_vnode_setutimes,
	.mpo_check_vnode_stat		= stacktrace_check_vnode_stat,
	.mpo_check_vnode_write		= stacktrace_check_vnode_write,
	.mpo_check_system_audit		= stacktrace_check_system_audit,
	.mpo_check_system_auditon	= stacktrace_check_system_auditon,
	.mpo_check_system_auditctl	= stacktrace_check_system_auditctl,
	.mpo_check_proc_getauid		= stacktrace_check_proc_getauid,
	.mpo_check_proc_getlcid		= stacktrace_check_proc_getlcid,
	.mpo_check_proc_setauid		= stacktrace_check_proc_setauid,
	.mpo_check_proc_setlcid		= stacktrace_check_proc_setlcid,
	.mpo_check_proc_getaudit	= stacktrace_check_proc_getaudit,
	.mpo_check_proc_setaudit	= stacktrace_check_proc_setaudit,
	.mpo_audit_preselect		= stacktrace_audit_preselect,
	.mpo_audit_postselect		= stacktrace_audit_postselect
};

#if 0
MAC_POLICY_SET(&mac_stacktrace_ops, mac_stacktrace, "MAC/Stacktrace",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
#endif

static char *labelnamespaces[MAC_STACKTRACE_LABEL_NAME_COUNT] =
	{ MAC_STACKTRACE_LABEL_NAME };

struct mac_policy_conf stacktrace_policy_conf = {
	.mpc_name		= MAC_STACKTRACE_LABEL_NAME,
							/* policy name */
	.mpc_fullname		= POLICY_DESC,		/* full name */
	.mpc_labelnames		= labelnamespaces,	/* label namespaces */
	.mpc_labelname_count	= MAC_STACKTRACE_LABEL_NAME_COUNT,
							/* namespace count */
	.mpc_ops		= &stacktrace_ops,	/* policy operations */
	.mpc_loadtime_flags	= 0,			/* loadtime flags*/
	.mpc_field_off		= &stack_slot,		/* security field */
	.mpc_runtime_flags	= 0			/* runtime flags */
};

static kern_return_t
kmod_start(kmod_info_t *ki, void *xd)
{

	return (mac_policy_register(&stacktrace_policy_conf));
}
static kern_return_t
kmod_stop(kmod_info_t *ki, void *data)
{

	return (mac_policy_unregister(&stacktrace_policy_conf));
}

extern kern_return_t	_start(kmod_info_t *ki, void *data);
extern kern_return_t	_stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(security.stacktrace, POLICY_VER, _start, _stop);
kmod_start_func_t	*_realmain = kmod_start;
kmod_stop_func_t	*_antimain = kmod_stop;
int			 _kext_apple_cc = __APPLE_CC__;
