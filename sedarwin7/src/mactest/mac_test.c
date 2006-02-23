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
 * $FreeBSD: src/sys/security/mac_test/mac_test.c,v 1.30 2003/08/21 17:28:45 rwatson Exp $
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/extattr.h>
#include <sys/kernel.h>
#include <sys/mac.h>
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
#include <kern/simple_lock.h>
#include <sys/mbuf.h>
#include <sys/mac_policy.h>
#include <kern/kalloc.h>

#define MAC_TEST_POLICY_NAME		"test"
#define MAC_TEST_LABEL_NAMESPACE	"test"
#define MAC_TEST_LABEL_NAMESPACE_COUNT	1

/* 
 * Defining DO_NOTHING disables all code that manipulates the
 * SLOT value of this module, replaces it with printf's 
 * describing which action is being performed.  So, the 
 * functions that "do something" will now contain only the 
 * sanity checks on the label as a whole (ex: NULL pointer) 
 * and printf's 
 */
	
//#define DO_NOTHING

/* 
 * Defining NOPORTS replaces the mac*port* functions with stubs.
 * To be removed at some point later.  
 */
	
//#define NOPORTS

#undef KASSERT
#define KASSERT(exp, msg) \
	if (!(exp)) \
		panic(msg);

/* operations on a label */
#define ALLOC 0   // ALLOC = "_init" in MAC terminology 
#define INIT 1    // INIT = "_create" (and several others) in MAC terminology
#define USE 2     // USE = everything that isn't one of the other ops
#define DESTROY 3

/* the good states in the lifecycle of a label */
#define ALLOCD 0
#define INITD 1
#define DESTROYEDMAGIC (void *) 0xfe8765af

/* Error states */
#define E1 104  	/* repeated init */
#define E2 105		/* use before initialization*/
#define E3 106		/* tried to ALLOC a label already in use*/
#define E4 107		/* tried to use a destroyed label */

/* types that get labelled by mac */
#define BPFDTYPE	0
#define CREDTYPE	1
#define DEVNODETYPE     2
#define IFNETTYPE       3
#define IPQTYPE		4
#define SOCKETTYPE      5
#define PIPETYPE	6
#define MBUFTYPE	7
#define MTAGTYPE	8
#define MOUNTTYPE       9
#define PROCTYPE	1       // this is intentional
#define VNODETYPE       11
#define VNODELABELTYPE  12  
#define PORTTYPE	1       // this is intentional
#define SYSVSEMATYPE    14
#define SYSVSHMTYPE     15
#define POSIXSEMTYPE    16
#define POSIXSHMTYPE    17
#define TASKTYPE	1       // this is intentional

#define	SLOT(x)	LABEL_TO_SLOT((x), test_slot).l_ptr

#define CHECKNULL(ptr, ptrname, fcnname) \
	if (ptr == NULL) \
		panic("%s: %s is NULL\n", fcnname, ptrname);

#define printf(args...) (debug_mode == 1 ? panic(args) : printf(args)) 
#define panic(args...) (debug_mode == 2 ? printf(args) : panic(args))

SYSCTL_DECL(_security_mac);

SYSCTL_NODE(_security_mac, OID_AUTO, test, CTLFLAG_RW, 0,
    "Darwin mac_test policy controls");

static int      mac_test_enabled = 1;
SYSCTL_INT(_security_mac_test, OID_AUTO, enabled, CTLFLAG_RW,
    &mac_test_enabled, 0, "Enforce test policy");

static int      test_slot;
SYSCTL_INT(_security_mac_test, OID_AUTO, slot, CTLFLAG_RD,
    &test_slot, 0, "Slot allocated by framework");

/* 
 * debug_mode determines which faults are considered warnings and which are errors 
 * 0: panic on fatal errors, such as NULL parameters that shouldn't be NULL, 
 *		printf warnings for faults involving everything else.
 * 1: super debug mode.  Panic on all faults.
 * 2: niceguy mode.  printf all faults, never panic delibrately (often this results
 *		in unintentional panics anyway, beware).
 */

static int      debug_mode = 0;
SYSCTL_INT(_security_mac_test, OID_AUTO, debug_mode, CTLFLAG_RW,
    &debug_mode, 0, "Debugging mode");

struct test_security_struct {
	int state;
	int type;
};

/* 
 * transition_table encodes the expected lifecycle of a label. 
 * Since error states aren't transitioned from, and the destroyed state
 * is handled differently, this is a 2x3 (state x operation) matrix.  This 
 * makes it easy to change mac_test's behavior.
 */

static int transition_table[2][3] = {
	{ E1, INITD, E2},       // in ALLOCD state
	{ E3, INITD, INITD}     // in INITD state
};

/* 
 * Generic lifecycle and sanity checking function.  It verifies
 * that the current operation makes sense given the current state of the
 * label, and that the types are consistent between the test_security_struct
 * and the specific mac policy call.  
 *
 * Note: There is currently no way to validate init operations because
 * init's clobber whatever is there.  The transitions and error states
 * based on an incoming init operation are placeholders for now.
 *
 * Note2: mac_test_check only sanitizes slot values, not the label itself.
 *
 * Parameters: 
 *	l - the label to check
 *	op - the operation being performed
 *	type - the data type the label is CREATEd with
 *
 * Return codes:
 * 	0 - all is well
 * 	1 - null SLOT value
 * 	2 - type mismatch
 * 	3 - new bad state
 *	4 - old bad state (it was in a bad state before the transition)
 *	5 - operation on a destroyed object
 */

static int 
mac_test_check(struct label *l, int op, int type) 
{
	struct test_security_struct *ts;

#ifdef DO_NOTHING
	printf("MAC_TEST:  mac_test_check()\n");
#else
	if (SLOT(l) == NULL) 
		return (1);
	if (SLOT(l) == DESTROYEDMAGIC)
		return (5);
	ts = SLOT(l);
	if (ts->type != type)
		return (2);	
	if (op == DESTROY) {
		kfree((vm_offset_t) ts, sizeof(struct test_security_struct));
		SLOT(l) = DESTROYEDMAGIC;
		return (0);
	}
	if (ts->state < E1)
		ts->state = transition_table[ts->state][op];
	else
		return (4);
	if (ts->state >= E1)
		return (3);
#endif  // DO_NOTHING
	return (0);
}

static void 
print_error(char *name, int e_state)  
{

	switch(e_state) {
	case E1:
		printf("%s: repeated _init operation\n", name);
		break;
	case E2:
		printf("%s: tried to use a label that wasn't created yet\n",
		    name);
		break;
	case E3:
		printf("%s: _init operation on an object in use\n", name);
		break;
	case E4:
		printf("%s: operation attempted on a destroyed label\n", name);
		break;
	default:
		printf("%s: unknown error state! print_error is out of sync\n",
		    name);
		break;
	}
}

static void
use_label(struct label *label, int type, char *fcnname)
{
	int check;
	struct test_security_struct *ts;
    
	if (label == NULL) 
		panic("%s (use_label): label is NULL!\n", fcnname);		
	if ((label->l_flags & MAC_FLAG_INITIALIZED) == 0) 
		panic("%s (use_label): label is uninitialized!\n", fcnname);
	
#ifdef DO_NOTHING
	printf("MAC_TEST:  %s -> use_label()\n", fcnname);
#else
	check = mac_test_check(label, USE, type); 
	ts = SLOT(label);
	switch (check) {
        case 0:
		return;
        case 1:
		printf("%s (use_label): Slot is NULL!\n", fcnname);
		break;
	case 2:
		printf("%s (use_label): Type mismatch! Label says type "
		    "is %d, function expects %d\n",
		    fcnname, ts->type, type);
		break;
	case 3:
		print_error(fcnname, ts->state);
		break;
	case 4:
		printf("label previously in an error state\n");
		print_error(fcnname, ts->state);
		break;
	case 5:
		print_error(fcnname, E4);
		break;
	default:
		printf("use_label: unhandled error code\n");
		break;
	}
#endif
}

static int
alloc_label_waitcheck(int type, struct label *label, char *fcnname, int waitok)
{ 
	struct test_security_struct *ts; 
	
	if (label == NULL) 
		panic("%s (alloc_label): label is NULL!\n", fcnname); 
	if ((label->l_flags & MAC_FLAG_INITIALIZED) == 0)  
		panic("%s (alloc_label): uninitialized label detected!\n", fcnname);
#ifdef DO_NOTHING    
	printf("%s -> alloc_label()\n", fcnname);
#else
	if (SLOT(label) == DESTROYEDMAGIC) 
		printf("%s: _init being performed on a previously destroyed label\n", fcnname);
	else if (SLOT(label) != NULL)
		panic("%s: attempted to _init a label probably in use already\n", fcnname);
	if (waitok == MAC_WAITOK)
		ts = (struct test_security_struct *) kalloc(
		    sizeof(struct test_security_struct)); 
	else
		ts = (struct test_security_struct *)kalloc_noblock(
 		    sizeof(struct test_security_struct));
	if (ts == NULL)
		return (ENOMEM);
	ts->state = ALLOCD; 
	ts->type = type; 
	SLOT(label) = ts;
	return (0);
#endif
}

/* 
 * By default, it's ok to wait for the allocator
 */
static int
alloc_label(int type, struct label *label, char *fcnname)
{ 

	return (alloc_label_waitcheck(type, label, fcnname, MAC_WAITOK));
}

static void
cleanup_label(struct label *label, int type, char *fcnname)
{
	struct test_security_struct *ts;

	if (label == NULL) 
		panic("%s (cleanup_label): label is NULL!\n", fcnname);
	if ((label->l_flags & MAC_FLAG_INITIALIZED) == 0) 
		panic("%s (cleanup_label): label is uninitialized!\n",fcnname);

	/*
	 * XXX/TBD: This isn't in the state diagram yet, but cleanup
	 * operations typically bzero the label structure, essentially
	 * reverting to the post-allocation state.  We will call
	 * use_label to make sure the label was allocated and
	 * initialized.
	 */
#ifdef DO_NOTHING
	printf("%s -> cleanup_label()\n", fcnname);
#else
	use_label(label, type, fcnname);
	ts = SLOT(label);
	ts->state = ALLOCD;
#endif
}

static void 
destroy_label(struct label *label, int type, char *fcnname) 
{ 
	int check;
	struct test_security_struct *ts;

	if (label == NULL) 
		panic("%s (destroy_label):  label is NULL!\n", fcnname);
	if ((label->l_flags & MAC_FLAG_INITIALIZED) == 0) 
		panic("%s (destroy_label):  label is uninitialized!\n", fcnname);
		
#ifdef DO_NOTHING	
    printf("MAC_TEST:   %s -> destroy_label()\n", fcnname);
#else
	check = mac_test_check(label, DESTROY, type);
	ts = SLOT(label);
	switch (check) {
        case 0:
		return;
        case 1:
		printf("%s (destroy_label): Slot is NULL!\n", fcnname);
		break;
	case 2:
		printf("%s (destroy_label): Type mismatch! Label says "
		    "type is %d, function expects %d\n",
		    fcnname, ts->type, type);
		break;
	case 3:
		print_error(fcnname, ts->state);
		break;
	case 4:
		printf("label previously in an error state\n");
		print_error(fcnname, ts->state);
		break;
	case 5:
		printf("%s (destroy_label): duplicate destroy operation\n",
		    fcnname);
		break;
	default:
		printf("destroy_label: unhandled error code\n");
		break;
	}
#endif  //DO_NOTHING
}

static void 
init_label(struct label *label, int type, char *fcnname) 
{ 
	int check;
	struct test_security_struct *ts;

	if (label == NULL) 
		panic("%s (init_label): label is NULL!\n", fcnname);
	if ((label->l_flags & MAC_FLAG_INITIALIZED) == 0) 
		panic("%s (init_label): label is uninitialized!\n", fcnname);
		
#ifdef DO_NOTHING
	printf("MAC_TEST:  %s -> init_label\n", fcnname);
#else
	check = mac_test_check(label, INIT, type); 
	ts = SLOT(label);
	switch (check) {
        case 0: 
		return;
        case 1:
		printf("%s (init_label): Slot is NULL!\n", fcnname);
		break;
	case 2:
		printf("%s (init_label): Type mismatch! Label says type "
		    "is %d, function expects %d\n",
		    fcnname, ts->type, type);
		break;
	case 3:
		print_error(fcnname, ts->state);
		break;
	case 4:
		printf("label previously in an error state\n");
		print_error(fcnname, ts->state);
		break;
	case 5:
		print_error(fcnname, E4);
		break;
	default:
		printf("init_label: unhandled error code\n");
		break;
	}
#endif
}

/* 
 * sanity_check doesn't validate a state or make a state transition,
 * it verifies that it's a valid label and slot value. 
 */
static void 
sanity_check(struct label *label, int type, char *fcnname) 
{ 
	struct test_security_struct *ts; 

	if (label == NULL) 
		panic("%s (sanity_check): label is NULL\n", fcnname);
	if ((label->l_flags & MAC_FLAG_INITIALIZED) == 0) 
		panic("%s (sanity_check): label is uninitialized!\n", fcnname);

#ifdef DO_NOTHING
	printf("MAC_TEST:  %s -> sanity_check()\n", fcnname);
#else
	if (SLOT(label) == NULL) 
		printf("%s (sanity_check): slot is NULL\n", fcnname); 
	else if (SLOT(label) == DESTROYEDMAGIC)
		printf("%s (sanity_check):  Warning!  This label was destroyed.\n", 
		    fcnname);
	ts = SLOT(label); 
	if (ts->type != type) 
		printf("%s (sanity_check): type mismatch\n", fcnname); 
#endif
}

/*
 * Copy operations are equivalent to initialization.  In the previous
 * version copy_label actually copied slot values labels.
 */
static void 
copy_label(struct label *src, struct label *dest, int desttype, 
    char *fcnname)
{	
	init_label(dest, desttype, fcnname);
}

static int
externalize_label(struct label *label, int type, char *fcnname) 
{
 
#ifdef DO_NOTHING
	printf("MAC_TEST:  %s -> externalize_label\n", fcnname);
#else
	use_label(label, type, fcnname);
#endif  
	return (0); 
}

static int 
internalize_label(struct label *label, int type, char *fcnname) 
{

#ifdef DO_NOTHING
	printf("%s -> internalize_label()\n", fcnname);
#else
	init_label(label, type, fcnname);
#endif
	return (0);
}

/*
 * Policy module operations.
 */
 
static void
mac_test_destroy(struct mac_policy_conf *conf)
{
}

static void
mac_test_init(struct mac_policy_conf *conf)
{

/* 
 * XXX: possible addition for later.  Add a lookup table associating
 * labeled objects with their security struct so that we can verify that
 * the slot value hasn't been clobbered by either another MAC policy or 
 * by the alloc_label operation in this policy.  As is, there's no way
 * to check the init operation unless a label's slot values are
 * initialized to something on creation. 
 */

#ifdef DO_NOTHING
    printf("MAC_TEST:   Init()!!!\n");
#endif
}

static void
mac_test_init_bsd(struct mac_policy_conf *conf)
{
	sysctl_register_oid(&sysctl__security_mac_test);
	sysctl_register_oid(&sysctl__security_mac_test_enabled);
	sysctl_register_oid(&sysctl__security_mac_test_slot);
	sysctl_register_oid(&sysctl__security_mac_test_debug_mode);
}

static int
mac_test_syscall(struct proc *p, int call, void *arg) 
{
	return (0);
}

/*
 * Init and destroy operations.
 */

static void
mac_test_init_cred_label(struct label *label)
{
	alloc_label(CREDTYPE, label, "mac_test_init_cred_label");
}

static void
mac_test_init_devfsdirent_label(struct label *label)
{	
	alloc_label(DEVNODETYPE, label, "mac_test_init_devfsdirent_label");
}

static void
mac_test_init_sysv_sem_label(struct label *label)
{
	alloc_label(SYSVSEMATYPE, label, "mac_test_init_sysv_sem_label");
}

static void
mac_test_init_sysv_shm_label(struct label *label)
{
	alloc_label(SYSVSHMTYPE, label, "mac_test_init_sysv_shm_label");
}

static void
mac_test_init_mount_label(struct label *label)
{
	alloc_label(MOUNTTYPE, label, "mac_test_init_mount_label");
}

static void
mac_test_init_mount_fs_label(struct label *label)
{	
	alloc_label(MOUNTTYPE, label, "mac_test_init_mount_fs_label");
}

static void
mac_test_init_proc_label(struct label *label)
{
	alloc_label(PROCTYPE, label, "mac_test_init_proc_label");
}

static void
mac_test_init_task_label(struct label *label)
{
	alloc_label(TASKTYPE, label, "mac_test_init_task_label");
}

static void
mac_test_init_port_label(struct label *label)
{
#ifndef NOPORTS
	alloc_label(PORTTYPE, label, "mac_test_init_port_label");
#endif
}

static void
mac_test_init_vnode_label(struct label *label)
{
	alloc_label(VNODETYPE, label, "mac_test_init_vnode_label");
}

static void
mac_test_destroy_cred_label(struct label *label)
{	
	destroy_label(label, CREDTYPE, "mac_test_destroy_cred_label");
}

static void
mac_test_destroy_devfsdirent_label(struct label *label)
{
	destroy_label(label, DEVNODETYPE, "mac_test_destroy_devfsdirent_label");
}

static void
mac_test_destroy_sysv_sem_label(struct label *label)
{
	destroy_label(label, SYSVSEMATYPE, "mac_test_destroy_sysv_sem_label");
}

static void
mac_test_destroy_sysv_shm_label(struct label *label)
{
	destroy_label(label, SYSVSHMTYPE, "mac_test_destroy_sysv_shm_label");
}

static void
mac_test_destroy_mount_label(struct label *label)
{
	destroy_label(label, MOUNTTYPE, "mac_test_destroy_mount_label");
}

static void
mac_test_destroy_mount_fs_label(struct label *label)
{
	destroy_label(label, MOUNTTYPE, "mac_test_destroy_mount_fs_label");
}

static void
mac_test_destroy_proc_label(struct label *label)
{
	destroy_label(label, PROCTYPE, "mac_test_destroy_proc_label");
}

static void
mac_test_destroy_task_label(struct label *label)
{
	destroy_label(label, TASKTYPE, "mac_test_destroy_proc_label");
}

/* 
 * XXX: mactest reports that this function is often passed a CRED/PROC/TASK
 * typed label.  Bug?
 */
static void
mac_test_destroy_port_label(struct label *label)
{
#ifndef NOPORTS
	destroy_label(label, PORTTYPE, "mac_test_destroy_port_label");
#endif
}

static void
mac_test_destroy_vnode_label(struct label *label)
{
	destroy_label(label, VNODETYPE, "mac_test_destroy_vnode_label");
}

static void
mac_test_copy_cred_to_task(struct label *cred, struct label *task) 
{
	use_label(cred, CREDTYPE, "mac_test_copy_cred_to_task");
	copy_label(cred, task, CREDTYPE, "mac_test_copy_cred_to_task");
}

static void
mac_test_update_port_from_cred_label(struct label *cred,
    struct label *port) 
{
#ifndef NOPORTS
	use_label(cred, CREDTYPE, "mac_test_update_port_from_cred_label");
	copy_label(cred, port, PORTTYPE, "mac_test_update_port_from_cred_label"); 
#endif
}

static void
mac_test_copy_vnode_label(struct label *src, struct label *dest) 
{
	use_label(src, VNODETYPE, "mac_test_copy_vnode_label");
	copy_label(src, dest, VNODETYPE, "mac_test_copy_vnode_label");
}

static void 
mac_test_copy_devfs_label(struct label *src, struct label *dest) 
{
	/* XXX: This line is causing an error, commenting it for now */
	/* 
	 * 5/9/05 - check whether this is still the case
	 * 5/11/05 - looks like it works now, need more comprehesive testing
	 */
	use_label(src, DEVNODETYPE, "mac_test_copy_devfs_label");
	copy_label(src, dest, DEVNODETYPE, "mac_test_copy_devfs_label");
}

static void
mac_test_copy_port_label(struct label *src, struct label *dest) 
{
#ifndef NOPORTS
	use_label(src, PORTTYPE, "mac_test_copy_port_label");
	copy_label(src, dest, PORTTYPE, "mac_test_copy_port_label");
#endif
}

static int
mac_test_externalize_cred_label(struct label *label, 
    char *element_name, struct sbuf *sb) 
{
	return externalize_label(label, CREDTYPE,
	    "mac_test_externalize_cred_label");
}

static int
mac_test_externalize_cred_audit_label(struct label *label, 
    char *element_name, struct sbuf *sb) 
{
	return externalize_label(label, CREDTYPE,
	    "mac_test_externalize_cred_audit_label");
}

static int 
mac_test_externalize_vnode_label(struct label *label,
    char *element_name, struct sbuf *sb) 
{
	return externalize_label(label, VNODETYPE, 
	    "mac_test_externalize_vnode_label");
}

static int 
mac_test_externalize_vnode_audit_label(struct label *label,
    char *element_name, struct sbuf *sb) 
{
	return externalize_label(label, VNODETYPE, 
	    "mac_test_externalize_vnode_audit_label");
}

static int 
mac_test_internalize_cred_label(struct label *label,
    char *element_name, char *element_data) 
{
	return internalize_label(label, CREDTYPE, 
	    "mac_test_internalize_cred_label");
}

static int 
mac_test_internalize_vnode_label(struct label *label,
    char *element_name, char *element_data) 
{
	return internalize_label(label, VNODETYPE, 
	    "mac_test_internalize_vnode_label");
}
	
/*
 * Labeling event operations: file system objects, and things that look
 * a lot like file system objects.
 */
 
/* mp can be NULL in this fcn */ 
static void
mac_test_associate_vnode_devfs(struct mount *mp, struct label *fslabel,
    struct devnode *de, struct label *delabel, struct vnode *vp,
    struct label *vlabel)
{
	CHECKNULL(de, "de", "mac_test_associate_vnode_devfs");
	CHECKNULL(vp, "vp", "mac_test_associate_vnode_devfs");

	init_label(vlabel, VNODETYPE, "mac_test_associate_vnode_devfs");
	if (mp != NULL)
		use_label(fslabel, MOUNTTYPE, 
		    "mac_test_associate_vnode_devfs (1)");
	use_label(delabel, DEVNODETYPE, "mac_test_associate_vnode_devfs (2)");
}

static int
mac_test_associate_vnode_extattr(struct mount *mp, struct label *fslabel,
    struct vnode *vp, struct label *vlabel)
{
	CHECKNULL(mp, "mp", "mac_test_associate_vnode_extattr");
	CHECKNULL(vp, "vp", "mac_test_associate_vnode_extattr");

	init_label(vlabel, VNODETYPE, "mac_test_associate_vnode_extattr");
	use_label(fslabel, MOUNTTYPE, "mac_test_associate_vnode_extattr");
	return (0);
}

static void
mac_test_associate_vnode_singlelabel(struct mount *mp,
    struct label *fslabel, struct vnode *vp, struct label *vlabel)
{
	CHECKNULL(mp, "mp", "mac_test_associate_vnode_singlelabel");
	CHECKNULL(vp, "vp", "mac_test_associate_vnode_singlelabel");

	init_label(vlabel, VNODETYPE, 
	    "mac_test_associate_vnode_singlelabel(1)");
	use_label(fslabel, MOUNTTYPE, 
	    "mac_test_associate_vnode_singlelabel(2)");
}


/*  The ucred and mount parameters can be NULL for this fcn */
static void
mac_test_create_devfs_device(struct ucred *cr, struct mount *mp, 
    dev_t dev, struct devnode *de, struct label *label,
    const char *fullpath)
{
	CHECKNULL(de, "de", "mac_test_create_devfs_device");

	init_label(label, DEVNODETYPE, "mac_test_create_devfs_device");
	if (cr != NULL)
		sanity_check(cr->cr_label, CREDTYPE, 
		    "mac_test_create_devfs_device");
}

static void
mac_test_create_devfs_directory(struct mount *mp, char *dirname,
	int dirnamelen, struct devnode *de,
	struct label *label, const char *fullpath)
{
	/*
	 * MP should be NULL for devfs
	 * CHECKNULL(mp, "mp", "mac_test_create_devfs_directory");
	 */
	 
	CHECKNULL(de, "de", "mac_test_create_devfs_directory");

	init_label(label, DEVNODETYPE, 
	    "mac_test_create_devfs_directory");
}

static void
mac_test_create_devfs_symlink(struct ucred *cred,
    struct mount *mp, struct devnode *dd,
    struct label *ddlabel, struct devnode *de,
    struct label *delabel, const char *fullpath)
{
	CHECKNULL(cred, "cred", "mac_test_create_devfs_symlink");
	CHECKNULL(dd, "dd", "mac_test_create_devfs_symlink");
	CHECKNULL(mp, "mp", "mac_test_create_devfs_symlink");
	CHECKNULL(de, "de", "mac_test_create_devfs_symlink");

	init_label(delabel, DEVNODETYPE, 
	    "mac_test_create_devfs_symlink");
	use_label(cred->cr_label, CREDTYPE, 
	    "mac_test_create_devfs_symlink (1)");
	use_label(ddlabel, DEVNODETYPE, 
	    "mac_test_create_devfs_symlink (2)");
}

static int
mac_test_create_vnode_extattr(struct ucred *cred, struct mount *mp,
    struct label *fslabel, struct vnode *dvp, struct label *dlabel,
    struct vnode *vp, struct label *vlabel, struct componentname *cnp)
{
	CHECKNULL(cred, "cred", "mac_test_create_vnode_extattr");
	CHECKNULL(mp, "mp", "mac_test_create_vnode_extattr");
	CHECKNULL(dvp, "dvp", "mac_test_create_vnode_extattr");
	CHECKNULL(vp, "vp", "mac_test_create_vnode_extattr");

	init_label(vlabel, VNODETYPE, 
	    "mac_test_create_vnode_extattr");
	use_label(dlabel, VNODETYPE, 
	    "mac_test_create_vnode_extattr (1)");
	use_label(fslabel, MOUNTTYPE, 
	    "mac_test_create_vnode_extattr (2)");
	use_label(cred->cr_label, CREDTYPE, 
	    "mac_test_create_vnode_extattr (3)");
	return (0);
}


static void
mac_test_create_mount(struct ucred *cred, struct mount *mp,
    struct label *mntlabel, struct label *fslabel)
{
	CHECKNULL(cred, "cred", "mac_test_create_mount");
	CHECKNULL(mp, "mp", "mac_test_create_mount");	

	init_label(fslabel, MOUNTTYPE, "mac_test_create_mount (1)"); 
	use_label(cred->cr_label, CREDTYPE, "mac_test_create_mount (2)");
	init_label(mntlabel, MOUNTTYPE, "mac_test_create_mount (3)");
}

static void
mac_test_relabel_vnode(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, struct label *label)
{
	CHECKNULL(cred, "cred", "mac_test_relabel_vnode");
	CHECKNULL(vp, "vp", "mac_test_relabel_vnode");		

	use_label(cred->cr_label, CREDTYPE, "mac_test_relabel_vnode (1)");
	use_label(label, VNODETYPE, "mac_test_relabel_vnode (2)");
	copy_label(label, vnodelabel, VNODETYPE, "mac_test_relabel_vnode");	
}

static int
mac_test_setlabel_vnode_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vlabel, struct label *intlabel)
{
	CHECKNULL(cred, "cred", "mac_test_setlabel_vnode_extattr");
	CHECKNULL(vp, "vp", "mac_test_setlabel_vnode_extattr");

	use_label(cred->cr_label, CREDTYPE, 
	    "mac_test_setlabel_vnode_extattr (1)");
	use_label(intlabel, VNODETYPE, "mac_test_setlabel_vnode_extattr (2)");
	copy_label(intlabel, vlabel, VNODETYPE, 
	    "mac_test_setlabel_vnode_extattr");
	return (0);
}

static void
mac_test_update_devfsdirent(struct mount *mp,
    struct devnode *devfs_dirent, struct label *direntlabel,
    struct vnode *vp, struct label *vnodelabel)
{
	CHECKNULL(mp, "mp", "mac_test_update_devfsdirent");
	CHECKNULL(devfs_dirent, "devfs_dirent", "mac_test_update_devfsdirent");
	CHECKNULL(vp, "vp", "mac_test_update_devfsdirent");
	
	use_label(vnodelabel, VNODETYPE, "mac_test_update_devfsdirent (1)");
	init_label(direntlabel, DEVNODETYPE, "mac_test_update_devfsdirent (2)");
}

/*  XXX: What type should "it" and "st" be?  */
static void
mac_test_create_port(struct label *it, struct label *st,
    struct label *portlabel) 
{
#ifndef NOPORTS	
	init_label(portlabel, PORTTYPE, "mac_test_create_port");
#endif
}

/*
 * Labeling event operations: processes.
 */
static void
mac_test_create_cred(struct ucred *cred_parent, struct ucred *cred_child)
{
	CHECKNULL(cred_parent, "cred_parent", "mac_test_create_cred");
	CHECKNULL(cred_child, "cred_child", "mac_test_create_cred");

	use_label(cred_parent->cr_label, CREDTYPE, "mac_test_create_cred");
	copy_label(cred_parent->cr_label, cred_child->cr_label, CREDTYPE, 
	    "mac_test_create_cred");
}

static void
mac_test_create_task(struct task *parent, struct task *child, 
    struct label *pl, struct label *cl, struct label *childportlabel) 
{
	CHECKNULL(parent, "parent", "mac_test_create_task");
	CHECKNULL(child, "child", "mac_test_create_task");
	
	use_label(pl, CREDTYPE, "mac_test_create_task");
	copy_label(pl, cl, CREDTYPE, "mac_test_create_task");
}

static void
mac_test_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *filelabel,
    struct label *interpvnodelabel, struct label *execlabel)
{
	CHECKNULL(old, "old", "mac_test_execve_transition");
	CHECKNULL(new, "new", "mac_test_execve_transition");
	CHECKNULL(vp, "vp", "mac_test_execve_transition");

	use_label(old->cr_label, CREDTYPE, "mac_test_execve_transition (1)");
	use_label(filelabel, VNODETYPE, "mac_test_execve_transition (2)");
	if (interpvnodelabel != NULL)
	    use_label(interpvnodelabel, VNODETYPE, "mac_test_execve_transition (3)");
	if (execlabel != NULL)
	    use_label(execlabel, VNODETYPE, "mac_test_execve_transition (4)");
	init_label(new->cr_label, CREDTYPE, "mac_test_execve_transition");
}

static int
mac_test_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *filelabel, struct label *interpvnodelabel,
    struct label *execlabel, struct proc *proc)
{
	CHECKNULL(old, "old", "mac_test_execve_will_transition");
	CHECKNULL(vp, "vp", "mac_test_execve_will_transition");
	
	use_label(filelabel, VNODETYPE, "mac_test_execve_will_transition (1)");
	if (interpvnodelabel != NULL)
		use_label(interpvnodelabel, VNODETYPE, 
		    "mac_test_execve_will_transition (2)");
	if (execlabel != NULL)
		use_label(execlabel, VNODETYPE, 
		    "mac_test_execve_will_transition (3)");

	return (0);
}

static void
mac_test_create_proc0(struct ucred *cred)
{
	CHECKNULL(cred, "cred", "mac_test_create_proc0");
	init_label(cred->cr_label, CREDTYPE, "mac_test_create_proc0");
}

static void
mac_test_create_proc1(struct ucred *cred)
{
	CHECKNULL(cred, "cred", "mac_test_create_proc1");
	init_label(cred->cr_label, CREDTYPE, "mac_test_create_proc1");
}

static void
mac_test_relabel_cred(struct ucred *cred, struct label *newlabel)
{
	CHECKNULL(cred, "cred", "mac_test_relabel_cred");

	use_label(newlabel, CREDTYPE, "mac_test_relabel_cred");
	copy_label(newlabel, cred->cr_label, CREDTYPE, 
	    "mac_test_relabel_cred");
}

/*
 * Access control checks.
 */

static int
mac_test_check_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_cred_relabel");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_cred_relabel (1)");
	use_label(newlabel, CREDTYPE, "mac_test_check_cred_relabel (2)");
	return (0);
}

static int
mac_test_check_cred_visible(struct ucred *u1, struct ucred *u2)
{
	CHECKNULL(u1, "u1", "mac_test_check_cred_visible");
	CHECKNULL(u2, "u2", "mac_test_check_cred_visible");

	use_label(u1->cr_label, CREDTYPE, "mac_test_check_cred_visible (1)");
	use_label(u2->cr_label, CREDTYPE, "mac_test_check_cred_visible (2)");
	return (0);
}

static int
mac_test_check_fcntl(struct ucred *cred, struct file *fd, int cmd, int arg)
{
	CHECKNULL(cred, "cred", "mac_test_check_fcntl");
	CHECKNULL(fd, "fd", "mac_test_check_fcntl");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_fcntl");
	return (0);
}

static int
mac_test_check_get_fd(struct ucred *cred, struct file *fd, char *elements, 
	    int len)
{
	CHECKNULL(cred, "cred", "mac_test_check_get_fd");
	CHECKNULL(fd, "fd", "mac_test_check_get_fd");
	CHECKNULL(elements, "elements", "mac_test_check_get_fd");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_get_fd");
	return (0);
}

static int
mac_test_check_ioctl(struct ucred *cred, struct file *fd, int com, void *data)
{
	CHECKNULL(cred, "cred", "mac_test_check_ioctl");
	CHECKNULL(fd, "fd", "mac_test_check_ioctl");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_ioctl");
	return (0);
}

static int
mac_test_check_mount_stat(struct ucred *cred, struct mount *mp,
    struct label *mntlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_mount_stat");
	CHECKNULL(mp, "mp", "mac_test_check_mount_stat");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_mount_stat (1)");
	use_label(mntlabel, MOUNTTYPE, "mac_test_check_mount_stat (2)");
	return (0);
}

static int
mac_test_check_port_relabel(struct label *task, struct label *old,
	struct label *newlabel) 
{
#ifndef NOPORTS
	use_label(task, CREDTYPE, "mac_test_check_port_relabel (1)");
	use_label(old, PORTTYPE, "mac_test_check_port_relabel (2)");
	use_label(newlabel, PORTTYPE, "mac_test_check_port_relabel (3)");
#endif
	return (0);
}

static int
mac_test_check_port_send(struct label *task, struct label *port) 
{
#ifndef NOPORTS
	use_label(task, CREDTYPE, "mac_test_check_port_send (1)");
	use_label(port, PORTTYPE, "mac_test_check_port_send (2)");
#endif
	return (0);
}

static int
mac_test_check_port_make_send(struct label *task, struct label *port) 
{
#ifndef NOPORTS
	use_label(task, CREDTYPE, "mac_test_check_port_make_send (1)");
	use_label(port, PORTTYPE, "mac_test_check_port_make_send (2)");
#endif
	return (0);
}

static int
mac_test_check_port_copy_send(struct label *task, struct label *port) 
{
#ifndef NOPORTS
	use_label(task, CREDTYPE, "mac_test_check_port_copy_send (1)");
	use_label(port, PORTTYPE, "mac_test_check_port_copy_send (2)");
#endif
	return (0);
}

static int
mac_test_check_port_move_receive(struct label *task, struct label *port) 
{
#ifndef NOPORTS
	use_label(task, CREDTYPE, "mac_test_check_port_move_receive (1)");
	use_label(port, PORTTYPE, "mac_test_check_port_move_receive (2)");
#endif
	return (0);
}

static int
mac_test_check_proc_debug(struct ucred *cred, struct proc *proc)
{
	CHECKNULL(cred, "cred", "mac_test_check_proc_debug");
	CHECKNULL(proc, "proc", "mac_test_check_proc_debug");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_proc_debug (1)");
	use_label(proc->p_ucred->cr_label, CREDTYPE, 
	    "mac_test_check_proc_debug (2)");
	return (0);
}

static int
mac_test_check_proc_sched(struct ucred *cred, struct proc *proc)
{
	CHECKNULL(cred, "cred", "mac_test_check_proc_sched");
	CHECKNULL(proc, "proc", "mac_test_check_proc_sched");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_proc_sched (1)");
	use_label(proc->p_ucred->cr_label, CREDTYPE, 
	    "mac_test_check_proc_sched (2)");
	return (0);
}

static int
mac_test_check_proc_signal(struct ucred *cred, struct proc *proc, int signum)
{
	CHECKNULL(cred, "cred", "mac_test_check_proc_signal");
	CHECKNULL(proc, "proc", "mac_test_check_proc_signal");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_proc_signal (1)");
	use_label(proc->p_ucred->cr_label, CREDTYPE, 
	    "mac_test_check_proc_signal (2)");
	return (0);
}

static int
mac_test_check_proc_wait(struct ucred *cred, struct proc *proc)
{

	CHECKNULL(cred, "cred", "mac_test_check_proc_wait");
	CHECKNULL(proc, "proc", "mac_test_check_proc_wait");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_proc_wait (1)");
	use_label(proc->p_ucred->cr_label, CREDTYPE, 
	    "mac_test_check_proc_wait (2)");
	return (0);
}

static int
mac_test_check_service_access(struct label *subj, struct label *obj, 
    const char *serv, const char *perm)
{

	use_label(subj, CREDTYPE, "mac_test_check_service_access (1)");
	use_label(obj, CREDTYPE, "mac_test_check_service_access (2)");
	return (0);
}

static int
mac_test_check_set_fd(struct ucred *cred, struct file *fd, char *elements,
	    int len)
{
	CHECKNULL(cred, "cred", "mac_test_check_set_fd");
	CHECKNULL(fd, "fd", "mac_test_check_set_fd");
	CHECKNULL(elements, "elements", "mac_test_check_set_fd");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_set_fd");
	return (0);
}

static int
mac_test_check_system_acct(struct ucred *cred, struct vnode *vp,
    struct label *label)
{
	CHECKNULL(cred, "cred", "mac_test_check_sysarch_acct");
	CHECKNULL(vp, "vp", "mac_test_check_sysarch_acct");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_acct (1)");
	use_label(label, VNODETYPE, "mac_test_check_system_acct (2)");
	return (0);
}

static int 
mac_test_check_system_nfsd(struct ucred *cred) 
{
	CHECKNULL(cred, "cred", "mac_test_check_system_nfsd");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_nfsd");
	return (0);
}

static int
mac_test_check_system_reboot(struct ucred *cred, int how)
{
	CHECKNULL(cred, "cred", "mac_test_check_system_reboot");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_reboot");
	return (0);
}

static int
mac_test_check_system_settime(struct ucred *cred)
{
	CHECKNULL(cred, "cred", "mac_test_check_system_settime");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_settime");
	return (0);
}

static int
mac_test_check_system_swapon(struct ucred *cred, struct vnode *vp,
    struct label *label)
{
	CHECKNULL(cred, "cred", "mac_test_check_system_swapon");
	CHECKNULL(vp, "vp", "mac_test_check_system_swapon");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_swapon (1)");
	use_label(label, VNODETYPE, "mac_test_check_system_swapon (2)");
	return (0);
}

static int
mac_test_check_system_swapoff(struct ucred *cred, struct vnode *vp,
    struct label *label)
{
	CHECKNULL(cred, "cred", "mac_test_check_system_swapoff");
	CHECKNULL(vp, "vp", "mac_test_check_system_swapoff");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_swapon (1)");
	use_label(label, VNODETYPE, "mac_test_check_system_swapon (2)");
	return (0);
}

static int
mac_test_check_system_sysctl(struct ucred *cred, int *name, u_int namelen,
    void *old, size_t *oldlenp, int inkernel, void *new, size_t newlen)
{
	CHECKNULL(cred, "cred", "mac_test_check_system_sysctl");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_sysctl");
	return (0);
}

static int
mac_test_check_vnode_access(struct ucred *cred, struct vnode *vp,
    struct label *label, int acc_mode)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_access");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_access");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_access (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_access (2)");
	return (0);
}

static int
mac_test_check_vnode_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_chdir");
	CHECKNULL(dvp, "dvp", "mac_test_check_vnode_chdir");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_chdir (1)");
	use_label(dlabel, VNODETYPE, "mac_test_check_vnode_chdir (2)");
	return (0);
}

static int
mac_test_check_vnode_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_chroot");
	CHECKNULL(dvp, "dvp", "mac_test_check_vnode_chroot");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_chroot (1)");
	use_label(dlabel, VNODETYPE, "mac_test_check_vnode_chroot (2)");
	return (0);
}

static int
mac_test_check_vnode_create(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp, struct vattr *vap)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_create");
	CHECKNULL(dvp, "dvp", "mac_test_check_vnode_create");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_create (1)");
	use_label(dlabel, VNODETYPE, "mac_test_check_vnode_create (2)");
	return (0);
}

static int
mac_test_check_vnode_delete(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_delete");
	CHECKNULL(dvp, "dvp", "mac_test_check_vnode_delete");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_delete");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_delete (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_delete (2)");
	use_label(dlabel, VNODETYPE, "mac_test_check_vnode_delete (3)");
	return (0);
}

/* 
 * XXX: This function doesn't take a label parameter for the vnode.  
 * Intentional?  
 */
static int
mac_test_check_vnode_deleteextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_deleteextattr");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_deleteextattr");

	use_label(cred->cr_label, CREDTYPE, 
	    "mac_test_check_vnode_deleteextattr");
	use_label(vp->v_label, VNODETYPE, "mac_test_check_vnode_deleteextattr");
	return (0);
}

static int
mac_test_check_vnode_exec(struct ucred *cred, struct vnode *vp,
    struct label *label, struct label *execlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_exec");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_exec");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_exec (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_exec (2)");
	if (execlabel != NULL)
	    use_label(execlabel, CREDTYPE, "mac_test_check_vnode_exec (3)");
	return (0);
}

static int
mac_test_check_vnode_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *label, int attrnamespace, const char *name, struct uio *uio)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_getextattr");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_getextattr");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_getextattr (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_getextattr (2)");
	return (0);
}

static int
mac_test_check_vnode_link(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_link");
	CHECKNULL(dvp, "dvp", "mac_test_check_vnode_link");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_link");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_link (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_link (2)");
	use_label(dlabel, VNODETYPE, "mac_test_check_vnode_link (3)");
	return (0);
}

static int
mac_test_check_vnode_listextattr(struct ucred *cred, struct vnode *vp,
	int attrnamespace)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_listextattr");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_listextattr");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_listextattr");
	use_label(vp->v_label, VNODETYPE, "mac_test_check_vnode_listextattr");
	return (0);
}

static int
mac_test_check_vnode_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_lookup");
	CHECKNULL(dvp, "dvp", "mac_test_check_vnode_lookup");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_lookup (1)");
	use_label(dlabel, VNODETYPE, "mac_test_check_vnode_lookup (2)");
	return (0);
}

static int
mac_test_check_vnode_mmap(struct ucred *cred, struct vnode *vp,
    struct label *label, int prot, int flags, int *maxprot)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_mmap");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_mmap");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_mmap (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_mmap (2)");
	return (0);
}

/* XXX: This check doesn't return an error code? */
static void
mac_test_check_vnode_mmap_downgrade(struct ucred *cred, struct vnode *vp,
    struct label *label, int *prot)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_mmap_downgrade");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_mmap_downgrade");

	use_label(cred->cr_label, CREDTYPE, 
	    "mac_test_check_vnode_mmap_downgrade (1)");
	use_label(label, VNODETYPE, 
	    "mac_test_check_vnode_mmap_downgrade (2)");
}

static int
mac_test_check_vnode_mprotect(struct ucred *cred, struct vnode *vp,
    struct label *label, int prot)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_mprotect");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_mprotect");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_mprotect (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_mprotect (2)");
	return (0);
}

static int
mac_test_check_vnode_open(struct ucred *cred, struct vnode *vp,
    struct label *filelabel, int acc_mode)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_open");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_open");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_open (1)");
	use_label(filelabel, VNODETYPE, "mac_test_check_vnode_open (2)");
	return (0);
}

static int
mac_test_check_vnode_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *label)
{
	CHECKNULL(active_cred, "active_cred", "mac_test_check_vnode_poll");
	CHECKNULL(file_cred, "file_cred", "mac_test_check_vnode_poll");

	use_label(active_cred->cr_label, CREDTYPE, "mac_test_check_vnode_poll (1)");
	use_label(file_cred->cr_label, CREDTYPE, "mac_test_check_vnode_poll (2)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_poll (3)");
	return (0);
}

static int
mac_test_check_vnode_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *label)
{
	CHECKNULL(active_cred, "active_cred", "mac_test_check_vnode_poll");
	CHECKNULL(file_cred, "file_cred", "mac_test_check_vnode_poll");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_poll");

	use_label(active_cred->cr_label, CREDTYPE, "mac_test_check_vnode_read (1)");
	use_label(file_cred->cr_label, CREDTYPE, "mac_test_check_vnode_read (2)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_read (3)");
	return (0);
}

static int
mac_test_check_vnode_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_readdir");
	CHECKNULL(dvp, "dvp", "mac_test_check_vnode_readdir");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_readdir (1)");
	use_label(dlabel, VNODETYPE, "mac_test_check_vnode_readdir (2)");
	return (0);
}

static int
mac_test_check_vnode_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_readlink");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_readlink");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_readlink (1)");
	use_label(vnodelabel, VNODETYPE, "mac_test_check_vnode_readlink (2)");
	return (0);
}

static int
mac_test_check_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, struct label *newlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_relabel");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_relabel");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_relabel (1)");
	use_label(vnodelabel, VNODETYPE, "mac_test_check_vnode_relabel (2)");	
	use_label(newlabel, VNODETYPE, "mac_test_check_vnode_relabel (3)");
	return (0);
}

static int
mac_test_check_vnode_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_rename_from");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_rename_from");
	CHECKNULL(dvp, "dvp", "mac_test_check_vnode_rename_from");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_rename_from (1)");
	use_label(dlabel, VNODETYPE, "mac_test_check_vnode_rename_from (2)");	
	use_label(label, VNODETYPE, "mac_test_check_vnode_rename_from (3)");
	return (0);
}

static int
mac_test_check_vnode_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label, int samedir,
    struct componentname *cnp)
{
	/* vp can be NULL on this call */

	CHECKNULL(cred, "cred", "mac_test_check_vnode_rename_to");
	//CHECKNULL(vp, "vp", "mac_test_check_vnode_rename_to");
	CHECKNULL(dvp, "dvp", "mac_test_check_vnode_rename_to");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_rename_to (1)");
	use_label(dlabel, VNODETYPE, "mac_test_check_vnode_rename_to (2)");	
	if (vp != NULL)
		use_label(label, VNODETYPE, "mac_test_check_vnode_rename_to (3)");
	return (0);
}

static int
mac_test_check_vnode_revoke(struct ucred *cred, struct vnode *vp,
    struct label *label)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_revoke");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_revoke");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_revoke (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_revoke (2)");
	return (0);
}

static int
mac_test_check_vnode_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *label, int attrnamespace, const char *name, struct uio *uio)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_setextattr");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_setextattr");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_setextattr (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_setextattr (2)");
	return (0);
}

static int
mac_test_check_vnode_setflags(struct ucred *cred, struct vnode *vp,
    struct label *label, u_long flags)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_setflags");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_setflags");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_setflags (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_setflags (2)");
	return (0);
}

static int
mac_test_check_vnode_setmode(struct ucred *cred, struct vnode *vp,
    struct label *label, mode_t mode)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_setmode");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_setmode");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_setmode (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_setmode (2)");
	return (0);
}

static int
mac_test_check_vnode_setowner(struct ucred *cred, struct vnode *vp,
    struct label *label, uid_t uid, gid_t gid)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_setowner");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_setowner");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_setowner (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_setowner (2)");
	return (0);
}

static int
mac_test_check_vnode_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *label, struct timespec atime, struct timespec mtime)
{
	CHECKNULL(cred, "cred", "mac_test_check_vnode_setutimes");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_setutimes");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_vnode_setutimes (1)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_setutimes (2)");
	return (0);
}

/** file_cred can be NULL here **/
static int
mac_test_check_vnode_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *label)
{
	CHECKNULL(active_cred, "active_cred", "mac_test_check_vnode_stat");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_stat");

	use_label(active_cred->cr_label, CREDTYPE, "mac_test_check_vnode_stat (1)");
	if (file_cred != NULL)
		use_label(file_cred->cr_label, CREDTYPE, "mac_test_check_vnode_stat (2)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_stat (3)");
	return (0);
}

static int
mac_test_check_vnode_write(struct ucred *active_cred,
    struct ucred *file_cred, struct vnode *vp, struct label *label)
{
	// file_cred can be NULL (see kern_ktrace.c:ktrwrite())

	CHECKNULL(active_cred, "active_cred", "mac_test_check_vnode_write");
	//CHECKNULL(file_cred, "file_cred", "mac_test_check_vnode_write");
	CHECKNULL(vp, "vp", "mac_test_check_vnode_write");

	use_label(active_cred->cr_label, CREDTYPE, "mac_test_check_vnode_write (1)");
	if (file_cred != NULL)
		use_label(file_cred->cr_label, CREDTYPE, 
		    "mac_test_check_vnode_write (2)");
	use_label(label, VNODETYPE, "mac_test_check_vnode_write (3)");
	return (0);
}

/*
 * Audit related entry points.
 */

static int
mac_test_audit_preselect(struct ucred *cred, unsigned short syscode, 
	void *args)
{
	return (MAC_AUDIT_DEFAULT);
}

static int
mac_test_audit_postselect(struct ucred *cred, unsigned short syscode,
	void *args, int error, int retval)
{
	return (MAC_AUDIT_DEFAULT);
}

static int
mac_test_check_system_audit(struct ucred *cred, void *record, int length)
{
	CHECKNULL(cred, "cred", "mac_test_check_system_audit");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_audit");
	return (0);
}

static int 
mac_test_check_system_auditon(struct ucred *cred, int cmd)
{
	CHECKNULL(cred, "cred", "mac_test_check_system_auditon");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_auditon");
	return (0);
}

static int
mac_test_check_system_auditctl(struct ucred *cred, struct vnode *vp, 
    struct label *vlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_system_auditctl");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_system_auditctl");
	return (0);
}

static int 
mac_test_check_proc_getaudit(struct ucred *cred)
{
	CHECKNULL(cred, "cred", "mac_test_check_proc_getaudit");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_proc_getaudit");
	return (0);
}

static int 
mac_test_check_proc_setaudit(struct ucred *cred, struct auditinfo *ai)
{
	CHECKNULL(cred, "cred", "mac_test_check_proc_setaudit");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_proc_setaudit");
	return (0);
}

static int
mac_test_check_proc_getauid(struct ucred *cred)
{
	CHECKNULL(cred, "cred", "mac_test_check_proc_getauid");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_proc_getauid");
	return (0);
}

static int
mac_test_check_proc_setauid(struct ucred *cred, uid_t auid)
{
	CHECKNULL(cred, "cred", "mac_test_check_proc_setauid");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_proc_setauid");
	return (0);
}

/*
 * Socket-related entry points.
 */
 
static int
mac_test_init_socket_label(struct label *label, int waitok) 
{
	int error;

	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_init_socket_label: not holding the network funnel!");
	    
	error = alloc_label_waitcheck(SOCKETTYPE, label,
	    "mac_test_init_socket_label", waitok);

	return (error);
}

static int
mac_test_init_socket_peer_label(struct label *label, int waitok) 
{
	int error;
	
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_init_socket_peer_label: not holding the network funnel!");
	
	error = alloc_label_waitcheck(SOCKETTYPE, label, 
	    "mac_test_init_socket_peer_label", waitok);
	if (error)
		return (error);
	init_label(label, SOCKETTYPE, "mac_test_init_socket_peer_label");
	return (0);
}

static void
mac_test_destroy_socket_label(struct label *label)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_destroy_socket_label: not holding the network funnel!");

	destroy_label(label, SOCKETTYPE, "mac_test_destroy_socket_label");
}


static void
mac_test_destroy_socket_peer_label(struct label *label) 
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_destroy_socket_peer_label: not holding the network funnel!");
	
	destroy_label(label, SOCKETTYPE, "mac_test_destroy_socket_peer_label");
}


static void
mac_test_create_socket(struct ucred *cred, struct socket *so,
	struct label *solabel)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_create_socket: not holding the network funnel!");	
	
	CHECKNULL(cred, "cred", "mac_test_create_socket"); 
	CHECKNULL(so, "socket", "mac_test_create_socket");
	
	init_label(solabel, SOCKETTYPE, "mac_test_create_socket (1)");
	use_label(cred->cr_label, CREDTYPE, "mac_test_create_socket (1)");
}


static void 
mac_test_create_socket_from_socket(struct socket *oldsock,
	struct label *oldlabel, struct socket *newsock,
	struct label *newlabel) 
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_create_socket_from_socket: not holding the network funnel!");	
	
	CHECKNULL(oldsock, "oldsock", "mac_test_create_socket_from_socket");
	CHECKNULL(newsock, "newsock", "mac_test_create_socket_from_socket");

	use_label(oldlabel, SOCKETTYPE, "mac_test_create_socket_from_socket (1)");
	copy_label(oldlabel, newlabel, SOCKETTYPE, "mac_test_create_socket_from_socket (2)");
}



static int
mac_test_externalize_socket_label(struct label *label,
	char *element_name, struct sbuf *sb)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_externalize_socket_label: not holding the network funnel!");
		
	// this probably doesn't work.  
	if (sbuf_cat(sb, "socket") < 0) 
		return (ENOMEM);
	return externalize_label(label, SOCKETTYPE, 
	    "mac_test_externalize_socket_label");
}

static int 
mac_test_externalize_socket_peer_label(struct label *label,
	char *element_name, struct sbuf *sb) 
{
	//this probably doesn't work.
	if (sbuf_cat(sb, "socketpeer") < 0)
		return ENOMEM;
	return externalize_label(label, SOCKETTYPE, 
	    "mac_test_externalize_socket_peer_label");
}

static int 
mac_test_internalize_socket_label(struct label *label,
	char *element_name, char *element_data) 
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_internalize_socket_label: not holding the network funnel!");

	return internalize_label(label, SOCKETTYPE, 
	    "mac_test_internalize_socket_label");
}

static void
mac_test_relabel_socket(struct ucred *cred, struct socket *so,
	struct label *oldlabel, struct label *newlabel) 
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_relabel_socket: not holding the network funnel!");
	    
	CHECKNULL(cred, "cred", "mac_test_relabel_socket");
	CHECKNULL(so, "so", "mac_test_relabel_socket");

	use_label(oldlabel, SOCKETTYPE, "mac_test_relabel_socket (1)");
	copy_label(oldlabel, newlabel, SOCKETTYPE, "mac_test_relabel_socket");
	use_label(cred->cr_label, CREDTYPE, 
	    "mac_test_relabel_socket (2)");
}

static void
mac_test_set_socket_peer_from_socket(struct socket *oldsocket,
    struct label *oldsocketlabel, struct socket *newsocket,
    struct label *newsocketpeerlabel)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_set_socket_peer_from_socket: not holding the network funnel!");

	CHECKNULL(oldsocket, "oldsocket", "mac_test_set_socket_peer_from_socket");
	CHECKNULL(newsocket, "newsocket", "mac_test_set_socket_peer_from_socket");	

	use_label(oldsocketlabel, SOCKETTYPE,
	    "mac_test_set_socket_peer_from_socket (1)");
	copy_label(oldsocketlabel, newsocketpeerlabel, SOCKETTYPE,
	    "mac_test_set_socket_peer_from_socket (2)");
}


static void
mac_test_copy_socket_label(struct label *src, struct label *dest) 
{

	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_copy_socket_label: not holding the network funnel!");

	use_label(src, SOCKETTYPE, "mac_test_copy_socket_label (1)");
	copy_label(src, dest, SOCKETTYPE, "mac_test_copy_socket_label (2)");
}

static int
mac_test_check_socket_accept(struct ucred *cred, struct socket *so,
    struct label *so_label, struct sockaddr *sockaddr)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_accept: not holding the network funnel!");

	CHECKNULL(cred, "cred", "mac_test_check_socket_accept");
	CHECKNULL(so, "socket", "mac_test_check_socket_accept");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_accept (1)");
	use_label(so_label, SOCKETTYPE, "mac_test_check_socket_accept (2)");
	return (0);
}

static int
mac_test_check_socket_bind(struct ucred *cred, struct socket *socket,
    struct label *socketlabel, struct sockaddr *sockaddr)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_bind: not holding the network funnel!");

	CHECKNULL(cred, "cred", "mac_test_check_socket_bind");
	CHECKNULL(socket, "socket", "mac_test_check_socket_bind");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_bind (1)");
	use_label(socketlabel, SOCKETTYPE, "mac_test_check_socket_bind (2)");
	return (0);
}

static int
mac_test_check_socket_connect(struct ucred *cred, struct socket *socket,
    struct label *socketlabel, struct sockaddr *sockaddr)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_connect: not holding the network funnel!");

	CHECKNULL(cred, "cred", "mac_test_check_socket_connect");
	CHECKNULL(socket, "socket", "mac_test_check_socket_connect");
	CHECKNULL(sockaddr, "sockaddr", "mac_test_check_socket_connect");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_connect (1)");
	use_label(socketlabel, SOCKETTYPE, "mac_test_check_socket_connect (2)");
	return (0);
}

static int
mac_test_check_socket_listen(struct ucred *cred, struct socket *socket,
    struct label *socketlabel)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_listen: not holding the network funnel!");

	CHECKNULL(cred, "cred", "mac_test_check_socket_listen");
	CHECKNULL(socket, "socket", "mac_test_check_socket_listen");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_listen (1)");
	use_label(socketlabel, SOCKETTYPE, "mac_test_check_socket_listen (2)");
	return (0);
}

static int
mac_test_check_socket_poll(struct ucred *cred, struct socket *socket,
    struct label *socketlabel)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_poll: not holding the network funnel!");

	CHECKNULL(cred, "cred", "mac_test_check_socket_poll");
	CHECKNULL(socket, "socket", "mac_test_check_socket_poll");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_poll (1)");
	use_label(socketlabel, SOCKETTYPE, "mac_test_check_socket_poll (2)");
	return (0);
}

static int
mac_test_check_socket_receive(struct ucred *cred, struct socket *so, 
	struct label *socketlabel) 
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_receive: not holding the network funnel!");	

	CHECKNULL(cred, "cred", "mac_test_check_socket_receive");
	CHECKNULL(so, "so", "mac_test_check_socket_receive");	

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_receive (1)");
	use_label(socketlabel, SOCKETTYPE, "mac_test_check_socket_receive (2)");
	return (0);
}


static int
mac_test_check_socket_relabel(struct ucred *cred, struct socket *socket,
	struct label *oldlabel, struct label *newlabel)
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_relabel: not holding the network funnel!");

	CHECKNULL(cred, "cred", "mac_test_check_socket_relabel");
	CHECKNULL(socket, "socket", "mac_test_check_socket_relabel");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_relabel (1)");
	use_label(oldlabel, SOCKETTYPE, "mac_test_check_socket_relabel (2)");
	use_label(newlabel, SOCKETTYPE, "mac_test_check_socket_relabel (3)");
	return (0);
}

static int
mac_test_check_socket_select(struct ucred *cred, struct socket *so, 
	struct label *socketlabel) 
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_select: not holding the network funnel!");

	CHECKNULL(cred, "cred", "mac_test_check_socket_select");
	CHECKNULL(so, "so", "mac_test_check_socket_select");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_select (1)");
	use_label(socketlabel, SOCKETTYPE, "mac_test_check_socket_select (2)");
	return (0);
}

static int
mac_test_check_socket_send(struct ucred *cred, struct socket *so, 
	struct label *socketlabel) 
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_send: not holding the network funnel!");

	CHECKNULL(cred, "cred", "mac_test_check_socket_send");
	CHECKNULL(so, "so", "mac_test_check_socket_send");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_send (1)");
	use_label(socketlabel, SOCKETTYPE, "mac_test_check_socket_send (2)");
	return (0);
}

static int
mac_test_check_socket_stat(struct ucred *cred, struct socket *so, struct label *solabel) 
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_check_socket_stat: not holding the network funnel!");

	CHECKNULL(cred, "cred", "mac_test_check_socket_stat");
	CHECKNULL(so, "so", "mac_test_check_socket_stat");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_socket_stat (1)");
	use_label(solabel, SOCKETTYPE, "mac_test_check_socket_stat (2)");
	return (0);
}
 
/*
 * Mbuf traffic labeling entry points.
 */

static void
mac_test_init_mbuf_unknown_source_label(struct label *l)
{
	CHECKNULL(l, "l", "mac_test_init_mbuf_unknown_source_label");
	
	alloc_label(SOCKETTYPE, l, "mac_init_mbuf_unknown_source_label(1)");
	init_label(l, SOCKETTYPE, "mac_init_mbuf_unknown_source_label(2)");
}

static void
mac_test_init_tcp_label(struct label *l)
{
	CHECKNULL(l, "l", "mac_test_init_tcp_label");
	
	alloc_label(SOCKETTYPE, l, "mac_test_init_tcp_label");
	init_label(l, SOCKETTYPE, "mac_test_init_tcp_label");
}
 
static int
mac_test_init_mbuf_socket_label(struct label *so_label, int waitok)
{
	return(alloc_label_waitcheck(SOCKETTYPE, so_label, 
	    "mac_test_init_mbuf_socket_label", waitok));
}

static int
mac_test_check_socket_deliver(struct socket *so, struct label *so_label,
    struct mbuf *m, struct label *m_label)
{
	struct test_security_struct *ts;

	KASSERT(thread_funnel_get() == network_flock,
	   "mac_test_check_socket_deliver: not holding the network funnel!");

	CHECKNULL(so, "so", "mac_test_check_socket_deliver");
	CHECKNULL(m, "m", "mac_test_check_socket_deliver");
	
	if ((m->m_flags & M_PKTHDR) == 0)
		panic("WARNING! mac_test_check_socket_deliver: not a pkthdr!\n");
	use_label(so_label, SOCKETTYPE, "mac_test_check_socket_deliver(so_label)");
	use_label(m_label, SOCKETTYPE, "mac_test_check_socket_deliver(m_label)");
	return (0);
}

static void
mac_test_copy_mbuf_socket_label(struct label *from, struct label *to)
{
	/*
	 * There shouldn't be more than one instance of the unknown_source
	 * label.  Make sure we're not copying it.
	 */
	if (from == mac_get_mbuf_unknown_source())
		panic("mac_test_copy_mbuf_socket_label: from = unknown_label");
	if (from == mac_get_tcp_label())
		panic("mac_test_copy_mbuf_socket_label: from = tcp_label!");
	use_label(from, SOCKETTYPE, "mac_test_copy_mbuf_socket_label (1)");
	copy_label(from, to, SOCKETTYPE, "mac_test_copy_mbuf_socket_label (2)");
}

static void
mac_test_set_socket_peer_from_mbuf(struct mbuf *mbuf, struct label *mbuflabel,
    struct socket *socket, struct label *socketpeerlabel)
{
	CHECKNULL(mbuf, "mbuf", "mac_test_set_socket_peer_from_mbuf");
	CHECKNULL(socket, "socket", "mac_test_set_socket_peer_from_mbuf");

	if ((mbuf->m_flags & M_PKTHDR) == 0)
		panic("mac_test_set_socket_peer_from_mbuf: from mbuf isn't a pkthdr!");
	use_label(mbuflabel, SOCKETTYPE, "mac_test_set_socket_peer_from_mbuf");
	copy_label(mbuflabel, socketpeerlabel, SOCKETTYPE,
	    "mac_test_set_socket_peer_from_mbuf");
}

static void
mac_test_destroy_mbuf_socket_label(struct label *l)
{
	destroy_label(l, SOCKETTYPE, "mac_test_destroy_mbuf_socket_label");
}

static void
mac_test_create_mbuf_from_socket(struct socket *so, struct label *so_label,
    struct mbuf *m, struct label *m_label) 
{
	KASSERT(thread_funnel_get() == network_flock,
	    "mac_test_create_mbuf_from_socket: not holding the network funnel!");

	use_label(so_label, SOCKETTYPE, "mac_test_create_mbuf_from_socket (1)");
	copy_label(so_label, m_label, SOCKETTYPE, 
	    "mac_test_create_mbuf_from_socket (2)");
}

/*
 * Sys V IPC entry points.
 */
 
static void
mac_test_cleanup_sysv_sem_label(struct label *label)
{
	cleanup_label(label, SYSVSEMATYPE, "mac_test_cleanup_sysv_sem_label");
}

static void
mac_test_cleanup_sysv_shm_label(struct label *label)
{
	cleanup_label(label, SYSVSHMTYPE, "mac_test_cleanup_sysv_shm_label");
}

static void
mac_test_create_sysv_sem(struct ucred *cred, struct semid_kernel *semakptr,
   struct label *semalabel)
{
	CHECKNULL(cred, "cred", "mac_test_create_sysv_sem");
	CHECKNULL(semakptr, "semakptr", "mac_test_create_sysv_sem");
	use_label(cred->cr_label, CREDTYPE, "mac_test_create_sysv_sem");
	init_label(semalabel, SYSVSEMATYPE, "mac_test_create_sysv_sem");
}

static void
mac_test_create_sysv_shm(struct ucred *cred, struct shmid_kernel *shmsegptr,
   struct label *shmlabel)
{
	CHECKNULL(cred, "cred", "mac_test_create_sysv_shm");
	CHECKNULL(shmsegptr, "shmsegptr", "mac_test_create_sysv_shm");
	use_label(cred->cr_label, CREDTYPE, "mac_test_create_sysv_shm");
	init_label(shmlabel, SYSVSHMTYPE, "mac_test_create_sysv_shm");
}

static int
mac_test_check_sysv_semctl(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel, int cmd)
{
	CHECKNULL(cred, "cred", "mac_test_check_sysv_semctl");
	CHECKNULL(semakptr, "semakptr", "mac_test_check_sysv_semctl");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_sysv_semctl");
	use_label(semaklabel, SYSVSEMATYPE, "mac_test_check_sysv_semctl");
	return (0);
}

static int
mac_test_check_sysv_semget(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_sysv_semget");
	CHECKNULL(semakptr, "semakptr", "mac_test_check_sysv_semget");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_sysv_semget");
	use_label(semaklabel, SYSVSEMATYPE, "mac_test_check_sysv_semget");
	return (0);
}

static int
mac_test_check_sysv_semop(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semaklabel, size_t accesstype)
{
	CHECKNULL(cred, "cred", "mac_test_check_sysv_semop");
	CHECKNULL(semakptr, "semakptr", "mac_test_check_sysv_semop");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_sysv_semop");
	use_label(semaklabel, SYSVSEMATYPE, "mac_test_check_sysv_semop");
	return (0);
}

static int
mac_test_check_sysv_shmat(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int shmflg)
{
	CHECKNULL(cred, "cred", "mac_test_check_sysv_shmat");
	CHECKNULL(shmsegptr, "shmsegptr", "mac_test_check_sysv_shmat");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_sysv_shmat");
	use_label(shmseglabel, SYSVSHMTYPE, "mac_test_check_sysv_shmat");
	return (0);
}

static int
mac_test_check_sysv_shmctl(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int cmd)
{
	CHECKNULL(cred, "cred", "mac_test_check_sysv_shmctl");
	CHECKNULL(shmsegptr, "shmsegptr", "mac_test_check_sysv_shmctl");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_sysv_shmctl");
	use_label(shmseglabel, SYSVSHMTYPE, "mac_test_check_sysv_shmctl");
	return (0);
}

static int
mac_test_check_sysv_shmdt(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_sysv_shmdt");
	CHECKNULL(shmsegptr, "shmsegptr", "mac_test_check_sysv_shmdt");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_sysv_shmdt");
	use_label(shmseglabel, SYSVSHMTYPE, "mac_test_check_sysv_shmdt");
	return (0);
}

static int
mac_test_check_sysv_shmget(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmseglabel, int shmflg)
{
	CHECKNULL(cred, "cred", "mac_test_check_sysv_shmget");
	CHECKNULL(shmsegptr, "shmsegptr", "mac_test_check_sysv_shmget");
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_sysv_shmget");
	use_label(shmseglabel, SYSVSHMTYPE, "mac_test_check_sysv_shmget");
	return (0);
}

/*
 * POSIX IPC entry points
 */

static void
mac_test_init_posix_sem_label(struct label *l) 
{
	alloc_label(POSIXSEMTYPE, l, "mac_test_init_posix_sem_label"); 
}

static void
mac_test_init_posix_shm_label(struct label *l) 
{
	alloc_label(POSIXSHMTYPE, l, "mac_test_init_posix_shm_label");
}

static void
mac_test_destroy_posix_sem_label(struct label *l) 
{
	destroy_label(l, POSIXSEMTYPE, "mac_test_destroy_posix_sem_label");
}

static void
mac_test_destroy_posix_shm_label(struct label *l) 
{
	destroy_label(l, POSIXSHMTYPE, "mac_test_destroy_posix_shm_label");
}

static void
mac_test_create_posix_sem(struct ucred *cred, struct pseminfo *ps,
    struct label *semlabel, const char *name)
{
	CHECKNULL(cred, "cred", "mac_test_create_posix_sem");
	CHECKNULL(ps, "ps", "mac_test_create_posix_sem");
	CHECKNULL(name, "name", "mac_test_create_posix_sem");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_create_posix_sem");
	init_label(semlabel, POSIXSEMTYPE, "mac_test_create_posix_sem");
}

static void
mac_test_create_posix_shm(struct ucred *cred, struct pshminfo *ps,
    struct label *shmlabel, const char *name)
{
	CHECKNULL(cred, "cred", "mac_test_create_posix_shm");
	CHECKNULL(ps, "ps", "mac_test_create_posix_shm");
	CHECKNULL(name, "name", "mac_test_create_posix_shm");

	use_label(cred->cr_label, CREDTYPE, "mac_test_create_posix_shm");
	init_label(shmlabel, POSIXSHMTYPE, "mac_test_create_posix_shm");
}

static int
mac_test_check_posix_sem_create(struct ucred *cred, const char *name)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_sem_create");
	CHECKNULL(name, "name", "mac_test_check_posix_sem_create");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_sem_create");
	return (0);
}

static int
mac_test_check_posix_sem_open(struct ucred *cred, struct pseminfo *ps,
    struct label *semlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_sem_open");
	CHECKNULL(ps, "ps", "mac_test_check_posix_sem_open");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_sem_open");
	use_label(semlabel, POSIXSEMTYPE, "mac_test_check_posix_sem_open");
	return (0);
}

static int
mac_test_check_posix_sem_post(struct ucred *cred, struct pseminfo *ps,
    struct label *semlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_sem_post");
	CHECKNULL(ps, "ps", "mac_test_check_posix_sem_post");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_sem_post");
	use_label(semlabel, POSIXSEMTYPE, "mac_test_check_posix_sem_post");
	return (0);
}

static int
mac_test_check_posix_sem_unlink(struct ucred *cred, struct pseminfo *ps,
    struct label *semlabel, const char *name)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_sem_unlink");
	CHECKNULL(ps, "ps", "mac_test_check_posix_sem_unlink");
	CHECKNULL(name, "name", "mac_test_check_posix_sem_unlink");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_sem_unlink");
	use_label(semlabel, POSIXSEMTYPE, "mac_test_check_posix_sem_unlink");
	return (0);
}

static int
mac_test_check_posix_sem_wait(struct ucred *cred, struct pseminfo *ps,
    struct label *semlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_sem_wait");
	CHECKNULL(ps, "ps", "mac_test_check_posix_sem_wait");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_sem_wait");
	use_label(semlabel, POSIXSEMTYPE, "mac_test_check_posix_sem_wait");
	return (0);
}

static int
mac_test_check_posix_shm_create(struct ucred *cred, const char *name)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_shm_create");
	CHECKNULL(name, "name", "mac_test_check_posix_shm_create");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_shm_create");
	return (0);
}

static int
mac_test_check_posix_shm_mmap(struct ucred *cred, struct pshminfo *ps,
    struct label *shmlabel, int prot, int flags)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_shm_mmap");
	CHECKNULL(ps, "ps", "mac_test_check_posix_shm_mmap");
	
	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_shm_mmap");
	use_label(shmlabel, POSIXSHMTYPE, "mac_test_check_posix_shm_mmap");
	return (0);
}

static int
mac_test_check_posix_shm_open(struct ucred *cred, struct pshminfo *ps,
    struct label *shmlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_shm_open");
	CHECKNULL(ps, "ps", "mac_test_check_posix_shm_open");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_shm_open");
	use_label(shmlabel, POSIXSHMTYPE, "mac_test_check_posix_shm_open");
	return (0);
}

static int
mac_test_check_posix_shm_stat(struct ucred *cred, struct pshminfo *ps,
    struct label *shmlabel)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_shm_stat");
	CHECKNULL(ps, "ps", "mac_test_check_posix_shm_stat");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_shm_stat");
	use_label(shmlabel, POSIXSHMTYPE, "mac_test_check_posix_shm_stat");
	return (0);
}

static int
mac_test_check_posix_shm_truncate(struct ucred *cred, struct pshminfo *ps,
    struct label *shmlabel, size_t len)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_shm_truncate");
	CHECKNULL(ps, "ps", "mac_test_check_posix_shm_truncate");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_shm_truncate");
	use_label(shmlabel, POSIXSHMTYPE, "mac_test_check_posix_shm_truncate");
	return (0);
}

static int
mac_test_check_posix_shm_unlink(struct ucred *cred, struct pshminfo *ps,
    struct label *shmlabel, const char *name)
{
	CHECKNULL(cred, "cred", "mac_test_check_posix_shm_unlink");
	CHECKNULL(ps, "ps", "mac_test_check_posix_shm_unlink");

	use_label(cred->cr_label, CREDTYPE, "mac_test_check_posix_shm_unlink");
	use_label(shmlabel, POSIXSHMTYPE, "mac_test_check_posix_shm_unlink");
	return (0);
}

/*
 * Mach IPC entry points
 */

static void
mac_test_create_kernel_port(struct label *portlabel, int isreply)
{
	init_label(portlabel, PORTTYPE, "mac_test_create_kernel_port");
}

static void
mac_test_update_port_kobject(struct label *portlabel, int kotype)
{
	use_label(portlabel, PORTTYPE, "mac_test_update_port_kobject");
}

static void
mac_test_create_kernel_task(struct task *kproc, struct label *tasklabel,
    struct label *portlabel)
{
	CHECKNULL(kproc, "kproc", "mac_test_create_kernel_task");
	
	init_label(tasklabel, TASKTYPE, "mac_test_create_kernel_task");
	use_label(portlabel, PORTTYPE, "mac_test_create_kernel_task");
}

static int
mac_test_check_port_hold_send(struct label *task, struct label *port)
{
	use_label(task, TASKTYPE, "mac_test_check_port_hold_send");
	use_label(port, PORTTYPE, "mac_test_check_port_hold_send");
	return (0);
}

static int
mac_test_check_port_hold_receive(struct label *task, struct label *port)
{
	use_label(task, TASKTYPE, "mac_test_check_port_hold_receive");
	use_label(port, PORTTYPE, "mac_test_check_port_hold_receive");
	return (0);
}

static struct mac_policy_ops mac_test_ops =
{

	/*
	 * Policy module operations
	 */
	.mpo_destroy			= mac_test_destroy,
	.mpo_init			= mac_test_init,
	.mpo_init_bsd			= mac_test_init_bsd,
	.mpo_syscall			= mac_test_syscall,

	/* 
	 * Label operations
	 */
	.mpo_init_cred_label		= mac_test_init_cred_label,
	.mpo_init_devfsdirent_label     = mac_test_init_devfsdirent_label,
	.mpo_init_mbuf_socket_label     = mac_test_init_mbuf_socket_label,
	.mpo_init_mbuf_unknown_source_label = mac_test_init_mbuf_unknown_source_label,
	.mpo_init_mount_label		= mac_test_init_mount_label,
	.mpo_init_mount_fs_label	= mac_test_init_mount_fs_label,
	.mpo_init_port_label		= mac_test_init_port_label,
	.mpo_init_posix_sem_label	= mac_test_init_posix_sem_label,
	.mpo_init_posix_shm_label	= mac_test_init_posix_shm_label,
	.mpo_init_proc_label		= mac_test_init_proc_label,
	.mpo_init_socket_label		= mac_test_init_socket_label,
	.mpo_init_socket_peer_label	= mac_test_init_socket_peer_label,
	.mpo_init_sysv_sem_label	= mac_test_init_sysv_sem_label,
	.mpo_init_sysv_shm_label	= mac_test_init_sysv_shm_label,
	.mpo_init_task_label		= mac_test_init_task_label,
	.mpo_init_tcp_label		= mac_test_init_tcp_label,
	.mpo_init_vnode_label		= mac_test_init_vnode_label,
	.mpo_destroy_cred_label		= mac_test_destroy_cred_label,
	.mpo_destroy_devfsdirent_label	= mac_test_destroy_devfsdirent_label,
	.mpo_destroy_mbuf_socket_label	= mac_test_destroy_mbuf_socket_label,
	.mpo_destroy_mount_label	= mac_test_destroy_mount_label,
	.mpo_destroy_mount_fs_label	= mac_test_destroy_mount_fs_label,
	.mpo_destroy_port_label		= mac_test_destroy_port_label,
	.mpo_destroy_posix_sem_label	= mac_test_destroy_posix_sem_label,
	.mpo_destroy_posix_shm_label	= mac_test_destroy_posix_shm_label,
	.mpo_destroy_proc_label		= mac_test_destroy_proc_label,
	.mpo_destroy_socket_label	= mac_test_destroy_socket_label,
	.mpo_destroy_socket_peer_label	= mac_test_destroy_socket_peer_label,
	.mpo_destroy_sysv_sem_label	= mac_test_destroy_sysv_sem_label,
	.mpo_destroy_sysv_shm_label	= mac_test_destroy_sysv_shm_label,
	.mpo_destroy_task_label		= mac_test_destroy_task_label,
	.mpo_destroy_vnode_label	= mac_test_destroy_vnode_label,
	.mpo_cleanup_sysv_sem_label	= mac_test_cleanup_sysv_sem_label,
	.mpo_cleanup_sysv_shm_label	= mac_test_cleanup_sysv_shm_label,
	.mpo_copy_cred_to_task		= mac_test_copy_cred_to_task,
	.mpo_update_port_from_cred_label= mac_test_update_port_from_cred_label,
	.mpo_copy_vnode_label		= mac_test_copy_vnode_label,
	.mpo_copy_devfs_label		= mac_test_copy_devfs_label,
	.mpo_copy_mbuf_socket_label	= mac_test_copy_mbuf_socket_label,
	.mpo_copy_port_label		= mac_test_copy_port_label,
 	.mpo_copy_socket_label		= mac_test_copy_socket_label,
	.mpo_externalize_cred_label	= mac_test_externalize_cred_label,
	.mpo_externalize_cred_audit_label = 
					mac_test_externalize_cred_audit_label,
	.mpo_externalize_socket_label	= mac_test_externalize_socket_label,
	.mpo_externalize_socket_peer_label =
					mac_test_externalize_socket_peer_label,
	.mpo_externalize_vnode_label	= mac_test_externalize_vnode_label,
	.mpo_externalize_vnode_audit_label = 
					mac_test_externalize_vnode_audit_label,
	.mpo_internalize_cred_label	= mac_test_internalize_cred_label,
	.mpo_internalize_socket_label	= mac_test_internalize_socket_label,
	.mpo_internalize_vnode_label	= mac_test_internalize_vnode_label,

	/*
	 * Labeling event operations: file system objects; and things that
	 * look a lot like file system objects.
	 */

	.mpo_associate_vnode_devfs	= mac_test_associate_vnode_devfs,
	.mpo_associate_vnode_extattr	= mac_test_associate_vnode_extattr,
	.mpo_associate_vnode_singlelabel= mac_test_associate_vnode_singlelabel,
	.mpo_create_devfs_device	= mac_test_create_devfs_device,
	.mpo_create_devfs_directory	= mac_test_create_devfs_directory,
	.mpo_create_devfs_symlink	= mac_test_create_devfs_symlink,
	.mpo_create_vnode_extattr	= mac_test_create_vnode_extattr,
	.mpo_create_mount		= mac_test_create_mount,
	.mpo_relabel_vnode		= mac_test_relabel_vnode,
	.mpo_setlabel_vnode_extattr	= mac_test_setlabel_vnode_extattr,
	.mpo_update_devfsdirent		= mac_test_update_devfsdirent,

	/* 
	 * Labeling event operations: network objects.  
	 */
	.mpo_create_socket		= mac_test_create_socket,
	.mpo_create_socket_from_socket	= mac_test_create_socket_from_socket,
	.mpo_create_mbuf_from_socket	= mac_test_create_mbuf_from_socket,
	.mpo_relabel_socket		= mac_test_relabel_socket,
	.mpo_set_socket_peer_from_socket= mac_test_set_socket_peer_from_socket,
	.mpo_set_socket_peer_from_mbuf  = mac_test_set_socket_peer_from_mbuf,

	/*
	 * Labeling event operations: Mach IPC objects.
	 */
	.mpo_create_port		= mac_test_create_port,
	.mpo_create_kernel_port		= mac_test_create_kernel_port,
	.mpo_update_port_kobject	= mac_test_update_port_kobject,

	/*
	 * Labeling event operations: Posix IPC primitives.
	 */
	.mpo_create_posix_sem		= mac_test_create_posix_sem,
	.mpo_create_posix_shm		= mac_test_create_posix_shm,

	/*
	 * Labeling event operations: System V IPC primitives.
	 */
	.mpo_create_sysv_sem		= mac_test_create_sysv_sem,
	.mpo_create_sysv_shm		= mac_test_create_sysv_shm,

	/*
	 * Labeling event operations: processes.
	 */
	.mpo_create_cred		= mac_test_create_cred,
	.mpo_create_task		= mac_test_create_task,
	.mpo_create_kernel_task		= mac_test_create_kernel_task,
	.mpo_execve_transition		= mac_test_execve_transition,
	.mpo_execve_will_transition	= mac_test_execve_will_transition,
	.mpo_create_proc0		= mac_test_create_proc0,
	.mpo_create_proc1		= mac_test_create_proc1,
	.mpo_relabel_cred		= mac_test_relabel_cred,

	/*
	 * Access control checks.
	 */
	.mpo_check_cred_relabel		= mac_test_check_cred_relabel,
	.mpo_check_cred_visible		= mac_test_check_cred_visible,
	.mpo_check_fcntl		= mac_test_check_fcntl,
	.mpo_check_get_fd		= mac_test_check_get_fd,
	.mpo_check_ioctl		= mac_test_check_ioctl,
	.mpo_check_mount_stat		= mac_test_check_mount_stat,
	.mpo_check_port_relabel		= mac_test_check_port_relabel,
	.mpo_check_port_send		= mac_test_check_port_send,
	.mpo_check_port_make_send	= mac_test_check_port_make_send,
	.mpo_check_port_copy_send	= mac_test_check_port_copy_send,
	.mpo_check_port_move_receive	= mac_test_check_port_move_receive,
	.mpo_check_port_hold_send	= mac_test_check_port_hold_send,
	.mpo_check_port_hold_receive	= mac_test_check_port_hold_receive,
	.mpo_check_posix_sem_create	= mac_test_check_posix_sem_create,
	.mpo_check_posix_sem_open	= mac_test_check_posix_sem_open,
	.mpo_check_posix_sem_post	= mac_test_check_posix_sem_post,
	.mpo_check_posix_sem_unlink	= mac_test_check_posix_sem_unlink,
	.mpo_check_posix_sem_wait	= mac_test_check_posix_sem_wait,
	.mpo_check_posix_shm_create	= mac_test_check_posix_shm_create,
	.mpo_check_posix_shm_open	= mac_test_check_posix_shm_open,
	.mpo_check_posix_shm_mmap	= mac_test_check_posix_shm_mmap,
	.mpo_check_posix_shm_stat	= mac_test_check_posix_shm_stat,
	.mpo_check_posix_shm_truncate	= mac_test_check_posix_shm_truncate,
	.mpo_check_posix_shm_unlink	= mac_test_check_posix_shm_unlink,
	.mpo_check_proc_debug		= mac_test_check_proc_debug,
	.mpo_check_proc_getaudit	= mac_test_check_proc_getaudit,
	.mpo_check_proc_getauid		= mac_test_check_proc_getauid,	
	.mpo_check_proc_sched		= mac_test_check_proc_sched,
	.mpo_check_proc_setaudit	= mac_test_check_proc_setaudit,
	.mpo_check_proc_setauid		= mac_test_check_proc_setauid,
	.mpo_check_proc_signal		= mac_test_check_proc_signal,
	.mpo_check_proc_wait		= mac_test_check_proc_wait,
	.mpo_check_service_access	= mac_test_check_service_access,
	.mpo_check_set_fd		= mac_test_check_set_fd,
	.mpo_check_socket_bind		= mac_test_check_socket_bind,
	.mpo_check_socket_connect	= mac_test_check_socket_connect,
	.mpo_check_socket_deliver	= mac_test_check_socket_deliver,
	.mpo_check_socket_listen	= mac_test_check_socket_listen,
	.mpo_check_socket_receive	= mac_test_check_socket_receive,
	.mpo_check_socket_relabel	= mac_test_check_socket_relabel,
	.mpo_check_socket_send		= mac_test_check_socket_send,
	.mpo_check_socket_stat		= mac_test_check_socket_stat,
	.mpo_check_system_acct		= mac_test_check_system_acct,
	.mpo_check_system_audit		= mac_test_check_system_audit,
	.mpo_check_system_auditon	= mac_test_check_system_auditon,
	.mpo_check_system_auditctl	= mac_test_check_system_auditctl,
	.mpo_check_system_nfsd		= mac_test_check_system_nfsd,
	.mpo_check_system_reboot	= mac_test_check_system_reboot,
	.mpo_check_system_settime	= mac_test_check_system_settime,
	.mpo_check_system_swapon	= mac_test_check_system_swapon,
	.mpo_check_system_swapoff	= mac_test_check_system_swapoff,
	.mpo_check_system_sysctl	= mac_test_check_system_sysctl,
	.mpo_check_sysv_semctl		= mac_test_check_sysv_semctl,
	.mpo_check_sysv_semget		= mac_test_check_sysv_semget,
	.mpo_check_sysv_semop		= mac_test_check_sysv_semop,
	.mpo_check_sysv_shmat		= mac_test_check_sysv_shmat,
	.mpo_check_sysv_shmctl		= mac_test_check_sysv_shmctl,
	.mpo_check_sysv_shmdt		= mac_test_check_sysv_shmdt,
	.mpo_check_sysv_shmget		= mac_test_check_sysv_shmget,	
	.mpo_check_vnode_access		= mac_test_check_vnode_access,
	.mpo_check_vnode_chdir		= mac_test_check_vnode_chdir,
	.mpo_check_vnode_chroot		= mac_test_check_vnode_chroot,
	.mpo_check_vnode_create		= mac_test_check_vnode_create,
	.mpo_check_vnode_delete		= mac_test_check_vnode_delete,
	.mpo_check_vnode_deleteextattr	= mac_test_check_vnode_deleteextattr,
	.mpo_check_vnode_exec		= mac_test_check_vnode_exec,
	.mpo_check_vnode_getextattr	= mac_test_check_vnode_getextattr,
	.mpo_check_vnode_link		= mac_test_check_vnode_link,
	.mpo_check_vnode_listextattr	= mac_test_check_vnode_listextattr,
	.mpo_check_vnode_lookup		= mac_test_check_vnode_lookup,
	.mpo_check_vnode_mmap		= mac_test_check_vnode_mmap,
	.mpo_check_vnode_mmap_downgrade = mac_test_check_vnode_mmap_downgrade,
	.mpo_check_vnode_mprotect	= mac_test_check_vnode_mprotect,
	.mpo_check_vnode_open		= mac_test_check_vnode_open,
	.mpo_check_vnode_poll		= mac_test_check_vnode_poll,
	.mpo_check_vnode_read		= mac_test_check_vnode_read,
	.mpo_check_vnode_readdir	= mac_test_check_vnode_readdir,
	.mpo_check_vnode_readlink	= mac_test_check_vnode_readlink,
	.mpo_check_vnode_relabel	= mac_test_check_vnode_relabel,
	.mpo_check_vnode_rename_from	= mac_test_check_vnode_rename_from,
	.mpo_check_vnode_rename_to	= mac_test_check_vnode_rename_to,
	.mpo_check_vnode_revoke		= mac_test_check_vnode_revoke,
	.mpo_check_vnode_setextattr	= mac_test_check_vnode_setextattr,
	.mpo_check_vnode_setflags	= mac_test_check_vnode_setflags,
	.mpo_check_vnode_setmode	= mac_test_check_vnode_setmode,
	.mpo_check_vnode_setowner	= mac_test_check_vnode_setowner,
	.mpo_check_vnode_setutimes	= mac_test_check_vnode_setutimes,
	.mpo_check_vnode_stat		= mac_test_check_vnode_stat,
	.mpo_check_vnode_write		= mac_test_check_vnode_write,

	/*
	 * Audit selection functions.  
	 */
	.mpo_audit_preselect		= mac_test_audit_preselect,
	.mpo_audit_postselect		= mac_test_audit_postselect
};

static char *labelnamespaces[MAC_TEST_LABEL_NAMESPACE_COUNT] = 
    {MAC_TEST_LABEL_NAMESPACE};

struct mac_policy_conf test_mac_policy_conf = {
	MAC_TEST_POLICY_NAME,	/* policy name */
	"MAC Test Module",	/* full name */
	labelnamespaces,	/* label namespace */
	MAC_TEST_LABEL_NAMESPACE_COUNT, /* namespace count */
	&mac_test_ops,		/* policy operations */
	0,			/* loadtime flags*/
	&test_slot,		/* security field */
	0			/* runtime flags */
};
 
 
static kern_return_t 
kmod_start(kmod_info_t *ki, void *xd) 
{
    
    return mac_policy_register(&test_mac_policy_conf);
}

static kern_return_t 
kmod_stop(kmod_info_t *ki, void *data) 
{
    
    return mac_policy_unregister(&test_mac_policy_conf);
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(security.test, "1.0", _start, _stop);
kmod_start_func_t *_realmain = kmod_start;
kmod_stop_func_t *_antimain = kmod_stop;
int _kext_apple_cc = __APPLE_CC__;
