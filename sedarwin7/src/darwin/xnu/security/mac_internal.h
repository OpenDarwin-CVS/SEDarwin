
/*-
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001, 2002, 2003, 2004 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
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
 */

#ifndef _security_mac_internal_h_
#define _security_mac_internal_h_

#include <string.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/mac.h>
#include <sys/mac_policy.h>
#include <sys/sysctl.h>
#include <kern/wait_queue.h>
#include <kern/lock.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/condvar.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

/*
 * MAC Framework sysctl namespace.
 */

SYSCTL_DECL(_security);
SYSCTL_DECL(_security_mac);

#ifdef MAC_DEBUG
SYSCTL_DECL(_security_mac_debug);
SYSCTL_DECL(_security_mac_debug_counters);

#define	MAC_DEBUG_COUNTER_INC(x)	atomic_add_int(x, 1);
#define	MAC_DEBUG_COUNTER_DEC(x)	atomic_subtract_int(x, 1);

#else

#define	MAC_DEBUG_COUNTER_INC(x)
#define	MAC_DEBUG_COUNTER_DEC(x)

#endif /* MAC_DEBUG */

/* Enables the TCP loopback traffic labeling code */
#define MAC_NETWORK

/* Enables socket labeling and the related checks on socket ops */
#define MAC_SOCKET

LIST_HEAD(mac_policy_list_t, mac_policy_conf);


/*
 * Darwin functions not properly exported
 */
extern void kmod_load_early();	/* defined in libsa/kext.cpp */

/* 
 * Type of list used to manage label namespace names.
 */   
struct mac_label_element {
	char				mle_name[MAC_MAX_LABEL_ELEMENT_NAME];
	LIST_ENTRY(mac_label_element)	mle_list;
};

LIST_HEAD(mac_label_element_list_t, mac_label_element);

/*
 * MAC Framework global variables.
 */

extern struct mac_policy_list_t mac_policy_list;
extern struct mac_policy_list_t mac_static_policy_list;
extern struct mac_label_element_list_t mac_label_element_list;
extern struct mac_label_element_list_t mac_static_label_element_list;

extern int mac_enforce_fs;
extern int mac_enforce_process;
extern int mac_enforce_system;
extern int mac_enforce_fs;
extern int mac_enforce_vm;


/*
 * MAC Framework infrastructure functions.
 */

int mac_error_select(int error1, int error2);

void  mac_policy_list_busy(void);
int   mac_policy_list_conditional_busy(void);
int   mac_policy_list_conditional_busy_noblock(void);
void  mac_policy_list_unbusy(void);

void           mac_labelzone_init(void);
struct label  *mac_labelzone_alloc(int flags);
void           mac_labelzone_free(struct label *label);

void  mac_init_label(struct label *label);
void  mac_destroy_label(struct label *label);
int   mac_check_structmac_consistent(struct mac *mac);
	
int mac_externalize_cred_label(struct label *, char *e, char *out, size_t olen, int flags);
int mac_externalize_lctx_label(struct label *, char *e, char *out, size_t olen);
int mac_externalize_task_label(struct label *, char *e, char *out, size_t olen, int flags);
int mac_externalize_port_label(struct label *, char *e, char *out, size_t olen, int flags);
int mac_externalize_socket_label(struct label *, char *e, char *out, size_t olen, int flags);
int mac_externalize_vnode_label(struct label *, char *e, char *out, size_t olen, int flags);

int mac_internalize_cred_label(struct label *label, char *string);
int mac_internalize_lctx_label(struct label *label, char *string);
int mac_internalize_port_label(struct label *label, char *string);
int mac_internalize_socket_label(struct label *label, char *string);
int mac_internalize_vnode_label(struct label *label, char *string);

/* internal socket label manipulation functions */
struct  label *mac_socket_label_alloc(int flags);
void    mac_socket_label_free(struct label *l);
int     mac_socket_label_set(struct ucred *cred, struct socket *so, struct label *l);

/*
 * MAC_CHECK performs the designated check by walking the policy
 * module list and checking with each as to how it feels about the
 * request.  Note that it returns its value via 'error' in the scope
 * of the caller.
 */
#define	MAC_CHECK(check, args...) do {					\
	struct mac_policy_conf *mpc;					\
	int entrycount;							\
									\
	error = 0;							\
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {		\
		if (mpc->mpc_ops->mpo_ ## check != NULL)		\
			error = mac_error_select(      			\
			    mpc->mpc_ops->mpo_ ## check (args),		\
			    error);					\
	}								\
	if ((entrycount = mac_policy_list_conditional_busy()) != 0) {	\
		LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {		\
			if (mpc->mpc_ops->mpo_ ## check != NULL)	\
				error = mac_error_select(      		\
				    mpc->mpc_ops->mpo_ ## check (args),	\
				    error);				\
		}							\
		mac_policy_list_unbusy();				\
	}								\
} while (0)

/*
 * MAC_CHECK_NOBLOCK has the same semantics as MAC_CHECK,
 * except that it will not block for the policy lock.  It sets check_failed to
 * 1 if it could not get the lock.  This function should only be called
 * on policy entry points that support the waitok flag, or which are 
 * guaranteed not to block.
 */
#define	MAC_CHECK_NOBLOCK(check, args...) do {					\
	struct mac_policy_conf *mpc;					\
	int entrycount;							\
									\
	error = 0;							\
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {		\
		if (mpc->mpc_ops->mpo_ ## check != NULL)		\
			error = mac_error_select(      			\
			    mpc->mpc_ops->mpo_ ## check (args),		\
			    error);					\
	}								\
	if ((entrycount = mac_policy_list_conditional_busy_noblock()) > 0) { \
		LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {		\
			if (mpc->mpc_ops->mpo_ ## check != NULL)	\
				error = mac_error_select(      		\
				    mpc->mpc_ops->mpo_ ## check (args),	\
				    error);				\
		}							\
		mac_policy_list_unbusy();				\
	}								\
	else if (entrycount < 0)					\
		check_failed = 1;					\
} while (0)

/*
 * MAC_BOOLEAN performs the designated boolean composition by walking
 * the module list, invoking each instance of the operation, and
 * combining the results using the passed C operator.  Note that it
 * returns its value via 'result' in the scope of the caller, which
 * should be initialized by the caller in a meaningful way to get
 * a meaningful result.
 */
#define	MAC_BOOLEAN(operation, composition, args...) do {		\
	struct mac_policy_conf *mpc;					\
	int entrycount;							\
									\
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {		\
		if (mpc->mpc_ops->mpo_ ## operation != NULL)		\
			result = result composition			\
			    mpc->mpc_ops->mpo_ ## operation (args);	\
	}								\
	if ((entrycount = mac_policy_list_conditional_busy()) != 0) {	\
		LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {		\
			if (mpc->mpc_ops->mpo_ ## operation != NULL)	\
				result = result composition		\
				    mpc->mpc_ops->mpo_ ## operation	\
				    (args);				\
		}							\
		mac_policy_list_unbusy();				\
	}								\
} while (0)

/*
 * Get the external forms of labels from all policies, for a single 
 * label namespace.
 */
#define	MAC_EXTERNALIZE(type, label, element, sb, count)		\
do {									\
									\
	struct mac_policy_conf *ME_mpc;					\
	struct mac_policy_list_t *list;					\
	int i;								\
	int busy = FALSE;						\
	int idx;							\
									\
	count = 0;							\
	list = &mac_static_policy_list;					\
	for (i = 0; i < 2; i++) {					\
	    LIST_FOREACH(ME_mpc, list, mpc_list) {			\
		if (ME_mpc->mpc_ops->mpo_externalize_## type ##_label == NULL)\
			continue;					\
									\
		if (ME_mpc->mpc_labelnames == NULL)			\
			continue;					\
									\
		for (idx = 0; idx < ME_mpc->mpc_labelname_count; idx++) { \
			if (strcmp(ME_mpc->mpc_labelnames[idx], element) != 0)\
				continue;				\
			if (count == 0) {				\
				error = sbuf_printf(&sb, "%s/",	element);\
				if (error)				\
					break;				\
			} else {					\
				error = sbuf_printf(&sb, ",");		\
				if (error)				\
					break;				\
			}						\
			error = ME_mpc->mpc_ops->mpo_externalize_## type ##_label\
				    (label, element, &sb);		\
			if (error)					\
				break;					\
			count++;					\
		}							\
		if (error)						\
			break;						\
	    }								\
	    if (mac_policy_list_conditional_busy() == 0)		\
		break;							\
	    list = &mac_policy_list;					\
	    busy = TRUE;						\
	}								\
	if (busy)							\
	    mac_policy_list_unbusy();					\
} while (0)

/* 
 * Get the external forms of labels from all policies, for all label
 * namespaces contained in a list.
 */
#define	MAC_EXTERNALIZE_LIST(type, label, elementlist, outbuf, outbuflen)\
do {									\
	int ignorenotfound;						\
	char *element, *sptr;						\
	struct sbuf sb;							\
	unsigned int count, total_count;				\
									\
	error = 0;							\
	total_count = 0;						\
	sbuf_new(&sb, outbuf, outbuflen, SBUF_FIXEDLEN);		\
	sptr = elementlist;						\
	while ((element = strsep(&sptr, ",")) != NULL) {		\
		if (element[0] == '?') {				\
			element++;					\
			ignorenotfound = 1;				\
		 } else							\
			ignorenotfound = 0;				\
		MAC_EXTERNALIZE(type, label, element, sb, count);	\
		if (error)						\
			break;						\
		if (count > 0) {					\
			total_count += count;				\
			error = sbuf_printf(&sb, ":");			\
			if (error)					\
				break;					\
		} else if (!ignorenotfound) {				\
			error = ENOENT; /* XXX: ENOLABEL? */		\
			break;						\
		}							\
	}								\
	/* Remove the last ':' if there was at least one match */	\
	if (total_count != 0) {						\
		count = sbuf_len(&sb) - 1;				\
		sbuf_setpos(&sb, count);				\
	}								\
	sbuf_finish(&sb);						\
} while (0)

/* 
 * Get the external forms of MAC labels (normal or audit) from all 
 * policies, for all label namespaces contained in the master list of
 * registered namespaces.
 * This macro uses the mac_policy_list locking mechanisms to protect the
 * non-static label element list.
 */
#define MAC_EXTERNALIZE_REGISTERED_LABELS(type, label, outbuf, outbuflen, count) \
do { 									\
									\
	struct mac_label_element *MERL_mle;				\
	struct mac_label_element_list_t *list;				\
	struct sbuf sb;							\
	int busy = FALSE;						\
	int i;								\
									\
	sbuf_new(&sb, outbuf, outbuflen, SBUF_FIXEDLEN);		\
									\
	list = &mac_static_label_element_list;				\
	for (i = 0; i < 2; i++) {					\
	    LIST_FOREACH(MERL_mle, list, mle_list) {			\
		MAC_EXTERNALIZE(type, label, MERL_mle->mle_name, sb, count);\
		if (error)						\
			break;						\
									\
		if (LIST_NEXT(MERL_mle, mle_list) != NULL) {		\
			error = sbuf_printf(&sb, ":");			\
			if (error)					\
				break;					\
		}							\
	    }								\
	    if (mac_policy_list_conditional_busy() == 0)		\
		break;							\
	    list = &mac_label_element_list;				\
	    busy = TRUE;						\
	}								\
	if (busy)							\
	    mac_policy_list_unbusy();					\
									\
	sbuf_finish(&sb);						\
									\
} while (0)

/*
 * Have all policies set the internal form of a label, for a single 
 * label namespace.
 */
#define	MAC_INTERNALIZE(type, label, element, element_data, count)	\
do {									\
									\
	struct mac_policy_conf *MI_mpc;					\
	struct mac_policy_list_t *list;					\
	int i;								\
	int busy = FALSE;						\
	int idx;							\
									\
	count = 0;							\
	list = &mac_static_policy_list;					\
	for (i = 0; i < 2; i++) {					\
	    LIST_FOREACH(MI_mpc, list, mpc_list) {			\
		if (MI_mpc->mpc_ops->mpo_internalize_## type ##_label == NULL)\
			continue;					\
									\
		if (MI_mpc->mpc_labelnames == NULL)			\
			continue;					\
									\
		for (idx = 0; idx < MI_mpc->mpc_labelname_count; idx++) { \
			if (strcmp(MI_mpc->mpc_labelnames[idx], element) != 0) \
				continue;				\
			error = MI_mpc->mpc_ops->mpo_internalize_## type ##_label\
				    (label, element, element_data);	\
			if (error)					\
				break;					\
			count++;					\
		}							\
		if (error)						\
			break;						\
	    }								\
	    if (mac_policy_list_conditional_busy() == 0)		\
		break;							\
	    list = &mac_policy_list;					\
	    busy = TRUE;						\
	}								\
	if (busy)							\
	    mac_policy_list_unbusy();					\
} while (0)

#define	MAC_INTERNALIZE_LIST(type, label, instring) do {		\
	char *sptr, *element, *element_data;				\
	int count;							\
									\
	error = 0;							\
	sptr = instring;						\
	while ((element = strsep(&sptr, ",")) != NULL) {		\
		element_data = element;					\
		element = strsep(&element_data, "/");			\
		if (element_data == NULL) {				\
			error = EINVAL;					\
			break;						\
		}							\
		MAC_INTERNALIZE(type, label, element, element_data,	\
		    count);						\
		if (error)						\
			break;						\
		if (count == 0) {					\
			error = EINVAL;					\
			break;						\
		}							\
	}								\
} while (0)

/*
 * MAC_PERFORM performs the designated operation by walking the policy
 * module list and invoking that operation for each policy.
 */
#define	MAC_PERFORM(operation, args...) do {				\
	struct mac_policy_conf *mpc;					\
	int entrycount;							\
									\
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {		\
		if (mpc->mpc_ops->mpo_ ## operation != NULL)		\
			mpc->mpc_ops->mpo_ ## operation (args);		\
	}								\
	if ((entrycount = mac_policy_list_conditional_busy()) != 0) {	\
		LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {		\
			if (mpc->mpc_ops->mpo_ ## operation != NULL)	\
				mpc->mpc_ops->mpo_ ## operation (args);	\
		}							\
		mac_policy_list_unbusy();				\
	}								\
} while (0)

/*
 * MAC_PERFORM_NOBLOCK differs from MAC_PERFORM in that it will not block.
 * If it cannot grab the policy mutex, it will set error to -1.  Otherwise, it
 * it is the same.
 */
#define MAC_PERFORM_NOBLOCK(operation, args...) do {			\
	struct mac_policy_conf *mpc;					\
	int entrycount;							\
									\
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {		\
		if (mpc->mpc_ops->mpo_ ## operation != NULL)		\
			mpc->mpc_ops->mpo_ ## operation (args);		\
	}								\
	if ((entrycount = mac_policy_list_conditional_busy_noblock()) > 0) { \
		LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {		\
			if (mpc->mpc_ops->mpo_ ## operation != NULL)	\
				mpc->mpc_ops->mpo_ ## operation (args);	\
		}							\
		mac_policy_list_unbusy();				\
	}								\
	else if (entrycount < 0)					\
		error = -1;						\
} while (0)

/* Darwin */

#define	TUNABLE_INT(x, y)
#define	WITNESS_WARN(x, y, z, ...)
#define	mtx_assert(x, y)
#define	MA_OWNED
#define	PROC_LOCK_ASSERT(x, y)
#define M_ASSERTPKTHDR(x)

#define PROC_LOCK(p)
#define PROC_UNLOCK(p)

#define ASSERT_VOP_LOCKED(vp,msg) 

#define atomic_add_int(P, V)         (*(u_int*)(P) += (V))
#define atomic_subtract_int(P, V)    (*(u_int*)(P) -= (V))

#endif
