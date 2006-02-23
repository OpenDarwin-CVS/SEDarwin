
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

#include <mach/mac.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/lock.h>
#include <vm/vm_kern.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/mac_policy.h>
#include <sys/vnode.h>

#include "ipctrace.h"

#define	SLOT(x)	(struct ipctrace_label *) (LABEL_TO_SLOT((x), ipctrace_slot).l_ptr)

static int	ipctrace_slot;

/* The same label structure is used for all object types implemented
   by the ipctrace policy. */

struct ipctrace_label
{
	char itask[IT_TASKLEN]; /* task that performed mach_port_allocate */
	char ttask[IT_TASKLEN]; /* task that gets the first right */
	int  portn;		/* number of this port (-1 for a task) */
	int  cport;		/* number for next port created in this task */
	int  kotype;		/* kind of kernel port (not used yet) */
};

/* Trace data buffer */

struct ipctrace_rec	tbuf[8192];
struct ipctrace_rec	*tbuf_end;
struct ipctrace_rec	*tbuf_cur;
mutex_t			*tbuf_lock;

static void
ipctrace_init(struct mac_policy_conf *mpc __unused)
{
	printf("ipctrace: init\n");
	tbuf_lock = mutex_alloc(ETAP_MISC_PRINTF);
	tbuf_cur = tbuf;
	tbuf_end = (struct ipctrace_rec *)((char *)tbuf + sizeof(tbuf));
}

static void
push_trace(const struct ipctrace_rec *tr)
{
	struct ipctrace_rec *p;

	mutex_lock(tbuf_lock);

	for (p = tbuf; p <= tbuf_cur; p++) {
		if (p->action == tr->action &&
		    p->portn == tr->portn &&
		    p->kotype == tr->kotype &&
		    !strcmp (p->task, tr->task) &&
		    !strcmp (p->ttask, tr->ttask)) {
			p->count++;
			mutex_unlock(tbuf_lock);
			return;
		}
	}

	if (tbuf_cur == tbuf_end) {

		/* current behavior - discard new events when buffer fills */
		mutex_unlock(tbuf_lock);
		return;
	}

	memcpy(tbuf_cur, tr, sizeof(struct ipctrace_rec));
	tbuf_cur->count = 1;
	tbuf_cur++;
	mutex_unlock(tbuf_lock);
}

/*
 * Copy the buffer into a newly-allocated buffer in the user task's
 * address space and reset the trace buffer.
 */
static int
getbuffer(task_t usertask, vm_offset_t *out, vm_size_t *outsize)
{
	kern_return_t error;
	vm_map_copy_t copy;
	vm_map_t map;

	map = get_task_map(usertask);		/* destination map */

	mutex_lock(tbuf_lock);
	*outsize = (tbuf_cur - tbuf) * sizeof(struct ipctrace_rec);
	if (*outsize == 0) {
		mutex_unlock(tbuf_lock);
		*out = 0;
		return (KERN_SUCCESS);
	}
	/* make a COW copy of the trace buffer and release the mutext */
	error = vm_map_copyin(kernel_map, (vm_offset_t)tbuf, *outsize,
	    FALSE, &copy);
	tbuf_cur = tbuf;
	mutex_unlock(tbuf_lock);
	if (error != KERN_SUCCESS)
		return (error);
	error = vm_map_copyout(map, out, copy);
	if (error != KERN_SUCCESS)
		vm_map_copy_discard(copy);
	return (error);
}

/*
 * This syscall is a temporary measure until per-policy mig calls are
 * added.  The mach way to do this would be to have the process send
 * a message instead of using a syscall, similar to how the vm_*
 * functions in libc are implemented (with mig).
 */
static int
ipctrace_syscall(struct proc *p, int call, void *arg, int *retval)
{
	struct ipctrace_call_get out;
	int error;

	switch (call) {
	case IT_CALL_GET:
		error = getbuffer(p->task, &out.buffer, &out.size);
		if (error)
			return (EINVAL);
		error = copyout(&out, arg, sizeof(struct ipctrace_call_get));
		return (error);

	default:
		return (EINVAL);
	}
}

/* Labelling operations */

static void
ipctrace_init_label(struct label *l)
{
	struct ipctrace_label *il;

	il = (struct ipctrace_label *)kalloc(sizeof (struct ipctrace_label));
	il->ttask[0] = '?';
	il->ttask[1] = 0;
	il->itask[0] = '?';
	il->itask[1] = 0;
	il->portn = -1;
	il->cport = 0;
	il->kotype = 0;
	SLOT(l) = il;
}

static void
ipctrace_copy_label(struct label *src, struct label *dst)
{
	struct ipctrace_label *srcl, *dstl;

	srcl = SLOT(src);
	dstl = SLOT(dst);
	memcpy(dstl, srcl, sizeof(struct ipctrace_label));
}

static void
ipctrace_destroy_label(struct label *l)
{

	kfree((vm_offset_t)SLOT(l), sizeof(struct ipctrace_label));
	SLOT(l) = NULL;
}

static int
ipctrace_externalize_label(struct label *l, char *element_name, struct sbuf *sb)
{
	struct ipctrace_label *ll;
	ll = SLOT(l);

	if (ll == NULL)
		return (EINVAL);

	if (ll->portn >= 0) {
		if (strcmp(ll->itask, ll->ttask))
			sbuf_printf(sb, "P:%s:%s:%d", ll->itask, ll->ttask, 
			    ll->portn);
		else
			sbuf_printf(sb, "P:%s:%d", ll->ttask, ll->portn);
	} else {
		sbuf_printf(sb, "T:%s", ll->ttask);
	}

	return (0);
}

/* Setup a port label by storing the task name of the 
 * issuer and creator, and assigning an increasing (per-task) serial
 * number to the port. Both task labels are locked during this function.
 */

static void
ipctrace_create_port(struct label *it, struct label *st,
	struct label *portlabel)
{
	struct ipctrace_label *itl, *stl, *portl;

	itl = SLOT(it);
	stl = SLOT(st);
	portl = SLOT(portlabel);

	strcpy (portl->itask, itl->ttask);
	strcpy (portl->ttask, stl->ttask);
	portl->portn = (++stl->cport);
}

static void
ipctrace_create_kernel_port(struct label *portlabel, int isreply)
{
	struct ipctrace_label *portl;

	portl = SLOT(portlabel);

	strcpy (portl->itask, "mach_kernel");
	strcpy (portl->ttask, "mach_kernel");
	portl->portn = isreply;
	portl->kotype = 99;
}

static void
ipctrace_update_port_kobject(struct label *portlabel, int kot)
{
	struct ipctrace_label *portl;

	portl = SLOT(portlabel);
	portl->kotype = kot;
}

static void
ipctrace_create_task(struct task *parent, struct task *child, 
	struct label *pl, struct label *cl, struct label *cportl)
{
	struct ipctrace_label *pli, *cli;

	pli = SLOT(pl);
	cli = SLOT(cl);

	strcpy(cli->ttask, pli->ttask);
}

extern int vn_getpath(struct vnode *vp, char *pathbuf, int *len);

static void
taskl_changettask (struct label *l, void *str)
{
	struct ipctrace_label *taskl;

	taskl = SLOT(l);
	strcpy(taskl->ttask, (char *)str);
}

static int
ipctrace_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *vnodelabel, struct label *interpvnodelabel,
    struct label *execlabel, struct proc *p)
{
	struct task *pt = (struct task *) p->task;
	char vpath[IT_TASKLEN];
	int len = IT_TASKLEN;

	vn_getpath(vp, vpath, &len);

	mac_modify_task_label(pt, vpath, &taskl_changettask);

	return (0);
}

static void
ipctrace_create_kernel_task(struct task *t,
	struct label *ktaskl, struct label *kportl)
{
	struct ipctrace_label *l;

	l = SLOT(ktaskl);
	strcpy(l->ttask, "mach_kernel");
	l = SLOT(kportl);
	strcpy(l->ttask, "mach_kernel");
	strcpy(l->itask, "mach_kernel");
}

static void
log1(int act, struct ipctrace_label *subl, struct ipctrace_label *objl)
{
	struct ipctrace_rec tr;

	strcpy(tr.task, subl->ttask);
	strcpy(tr.ttask, objl->ttask);
	tr.portn = objl->portn;
	tr.kotype = objl->kotype;
	tr.action = act;

	push_trace(&tr);
}

#define ipctrace_port_action(act)					\
static int								\
ipctrace_check_port_##act(struct label *task, struct label *port)	\
{									\
	if (SLOT(task) && SLOT(port))					\
		log1(ITA_##act, SLOT(task), SLOT(port));		\
									\
	return (0);							\
}

ipctrace_port_action(SEND)
ipctrace_port_action(COPY_SEND)
ipctrace_port_action(MAKE_SEND)
ipctrace_port_action(MOVE_RECV)

static struct mac_policy_ops ipctrace_ops =
{
	.mpo_init = ipctrace_init,
	.mpo_syscall = ipctrace_syscall,
	.mpo_init_cred_label = ipctrace_init_label,
	.mpo_init_task_label = ipctrace_init_label,
	.mpo_init_port_label = ipctrace_init_label,
	.mpo_destroy_cred_label = ipctrace_destroy_label,
	.mpo_destroy_task_label = ipctrace_destroy_label,
	.mpo_destroy_port_label = ipctrace_destroy_label,
	.mpo_copy_port_label = ipctrace_copy_label,
	.mpo_externalize_cred_label = ipctrace_externalize_label,

	/* Labeling event operations */

	.mpo_create_port = ipctrace_create_port,
	.mpo_create_kernel_port = ipctrace_create_kernel_port,
	.mpo_update_port_kobject = ipctrace_update_port_kobject,
	.mpo_create_task = ipctrace_create_task,
	.mpo_create_kernel_task = ipctrace_create_kernel_task,
	
	/* Access control checks */

	.mpo_check_port_send = ipctrace_check_port_SEND,
	.mpo_check_port_copy_send = ipctrace_check_port_COPY_SEND,
	.mpo_check_port_move_receive = ipctrace_check_port_MOVE_RECV,

	/*
	 * make_send can be logged, but it not very useful as your
	 * trace will get filled with lots of reply ports.
	 */
	/* .mpo_check_port_make_send = ipctrace_check_port_MAKE_SEND, */


	.mpo_execve_will_transition = ipctrace_execve_will_transition
};

static char *labelnamespaces[IPCTRACE_LABEL_NAME_COUNT] = {IPCTRACE_LABEL_NAME};
struct mac_policy_conf ipctrace_policy_conf = {
	"ipctrace",		/* policy name */
	"IPC Trace Module",	/* full name */
	labelnamespaces,	/* label namespace */
	IPCTRACE_LABEL_NAME_COUNT, /* namespace count */
	&ipctrace_ops,		/* policy operations */
	0,			/* loadtime flags*/
	&ipctrace_slot,		/* security field */
	0			/* runtime flags */
};
 
static kern_return_t
kmod_start(kmod_info_t *ki, void *xd)
{

	return (mac_policy_register(&ipctrace_policy_conf));
}

static kern_return_t
kmod_stop(kmod_info_t *ki, void *data)
{

	return (mac_policy_unregister(&ipctrace_policy_conf));
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(security.test, POLICY_VER, _start, _stop);
kmod_start_func_t *_realmain = kmod_start;
kmod_stop_func_t *_antimain = kmod_stop;
int _kext_apple_cc = __APPLE_CC__;
