
/*-
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001, 2002, 2003, 2004 Networks Associates Technology, Inc.
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

#define MAC /* XXX */

/*-
 * Framework for extensible kernel access control.  This file contains
 * Kernel and userland interface to the framework, policy registration
 * and composition.  Per-object interfaces, controls, and labeling may be
 * found in src/sys/mac/.  Sample policies may be found in src/sys/mac*.
 */

#include <string.h>
#include <security/mac_internal.h>
#include <sys/mac.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <bsd/bsm/audit_kernel.h>
#include <sys/file.h>
#include <sys/filedesc.h>

#ifdef MAC

/*
 * Declare that the kernel provides MAC support, version 1.  This permits
 * modules to refuse to be loaded if the necessary support isn't present,
 * even if it's pre-boot.
 */
#if 0
MODULE_VERSION(kernel_mac_support, 1);
#endif

struct sysctl_oid_list sysctl__security_children;
SYSCTL_NODE(, OID_AUTO, security, CTLFLAG_RW, 0, 
    "Security Controls");

struct sysctl_oid_list sysctl__security_mac_children;
SYSCTL_NODE(_security, OID_AUTO, mac, CTLFLAG_RW, 0,
    "TrustedBSD MAC policy controls");

#if MAC_MAX_SLOTS > 32
#error "MAC_MAX_SLOTS too large"
#endif

static unsigned int mac_max_slots = MAC_MAX_SLOTS;
static unsigned int mac_slot_offsets_free = (1 << MAC_MAX_SLOTS) - 1;
SYSCTL_UINT(_security_mac, OID_AUTO, max_slots, CTLFLAG_RD,
    &mac_max_slots, 0, "");

/*
 * Has the kernel started generating labeled objects yet?  All read/write
 * access to this variable is serialized during the boot process.  Following
 * the end of serialization, we don't update this flag; no locking.
 */
static int	mac_late = 0;

/*
 * Flag to indicate whether or not we should allocate label storage for
 * new mbufs.  Since most dynamic policies we currently work with don't
 * rely on mbuf labeling, try to avoid paying the cost of mtag allocation
 * unless specifically notified of interest.  One result of this is
 * that if a dynamically loaded policy requests mbuf labels, it must
 * be able to deal with a NULL label being returned on any mbufs that
 * were already in flight when the policy was loaded.  Since the policy
 * already has to deal with uninitialized labels, this probably won't
 * be a problem.  Note: currently no locking.  Will this be a problem?
 */
#ifndef MAC_ALWAYS_LABEL_MBUF
static int	mac_labelmbufs = 0;
#endif

int	mac_enforce_fs = 1;
SYSCTL_INT(_security_mac, OID_AUTO, enforce_fs, CTLFLAG_RW,
    &mac_enforce_fs, 0, "Enforce MAC policy on file system objects");
TUNABLE_INT("security.mac.enforce_fs", &mac_enforce_fs);

int	mac_enforce_process = 1;
SYSCTL_INT(_security_mac, OID_AUTO, enforce_process, CTLFLAG_RW,
    &mac_enforce_process, 0, "Enforce MAC policy on inter-process operations");
TUNABLE_INT("security.mac.enforce_process", &mac_enforce_process);

int mac_enforce_socket = 1;
SYSCTL_INT(_security_mac, OID_AUTO, enforce_socket, CTLFLAG_RW,
	&mac_enforce_socket, 1, "Enforce MAC policy on sockets");
TUNABLE_INT("security.mac.enforce_socket", &mac_enforce_socket);

int	mac_enforce_system = 1;
SYSCTL_INT(_security_mac, OID_AUTO, enforce_system, CTLFLAG_RW,
    &mac_enforce_system, 0, "Enforce MAC policy on system operations");
TUNABLE_INT("security.mac.enforce_system", &mac_enforce_system);

int	mac_enforce_vm = 1;
SYSCTL_INT(_security_mac, OID_AUTO, enforce_vm, CTLFLAG_RW,
    &mac_enforce_vm, 0, "Enforce MAC policy on vm operations");
TUNABLE_INT("security.mac.enforce_vm", &mac_enforce_vm);

int	mac_mmap_revocation = 1;
SYSCTL_INT(_security_mac, OID_AUTO, mmap_revocation, CTLFLAG_RW,
    &mac_mmap_revocation, 0, "Revoke mmap access to files on subject "
    "relabel");
int	mac_mmap_revocation_via_cow = 1;
SYSCTL_INT(_security_mac, OID_AUTO, mmap_revocation_via_cow, CTLFLAG_RW,
    &mac_mmap_revocation_via_cow, 0, "Revoke mmap access to files via "
    "copy-on-write semantics, or by removing all write access");

#ifdef MAC_DEBUG
struct sysctl_oid_list sysctl__security_mac_debug_children;
SYSCTL_NODE(_security_mac, OID_AUTO, debug, CTLFLAG_RW, 0,
    "TrustedBSD MAC debug info");

static int	mac_debug_label_fallback = 0;
SYSCTL_INT(_security_mac_debug, OID_AUTO, label_fallback, CTLFLAG_RW,
    &mac_debug_label_fallback, 0, "Filesystems should fall back to fs label"
    "when label is corrupted.");
TUNABLE_INT("security.mac.debug_label_fallback",
    &mac_debug_label_fallback);

struct sysctl_oid_list sysctl__security_mac_debug_counters_children;
SYSCTL_NODE(_security_mac_debug, OID_AUTO, counters, CTLFLAG_RW, 0,
    "TrustedBSD MAC object counters");

static u_int nmaccreds=0, nmacmounts=0, nmactemp=0, nmacvnodes=0,
    nmacdevfsdirents=0, nmacprocs=0;

SYSCTL_UINT(_security_mac_debug_counters, OID_AUTO, creds, CTLFLAG_RD,
    &nmaccreds, 0, "number of ucreds in use");
SYSCTL_UINT(_security_mac_debug_counters, OID_AUTO, procs, CTLFLAG_RD,
    &nmacprocs, 0, "number of procs in use");
SYSCTL_UINT(_security_mac_debug_counters, OID_AUTO, mounts, CTLFLAG_RD,
    &nmacmounts, 0, "number of mounts in use");
SYSCTL_UINT(_security_mac_debug_counters, OID_AUTO, temp, CTLFLAG_RD,
    &nmactemp, 0, "number of temporary labels in use");
SYSCTL_UINT(_security_mac_debug_counters, OID_AUTO, vnodes, CTLFLAG_RD,
    &nmacvnodes, 0, "number of vnodes in use");
SYSCTL_UINT(_security_mac_debug_counters, OID_AUTO, devfsdirents, CTLFLAG_RD,
    &nmacdevfsdirents, 0, "number of devfs dirents inuse");
#endif

/*
 * mac_static_policy_list holds a list of policy modules that are not
 * loaded while the system is "live", and cannot be unloaded.  These
 * policies can be invoked without holding the busy count.
 *
 * mac_policy_list stores the list of dynamic policies.  A busy count is
 * maintained for the list, stored in mac_policy_count.  The busy count
 * is protected by mac_policy_mtx; the list may be modified only
 * while the busy count is 0, requiring that the lock be held to
 * prevent new references to the list from being acquired.  For almost
 * all operations, incrementing the busy count is sufficient to
 * guarantee consistency, as the list cannot be modified while the
 * busy count is elevated.  For a few special operations involving a
 * change to the list of active policies, the mtx itself must be held.
 * A condition variable, mac_policy_cv, is used to signal potential
 * exclusive consumers that they should try to acquire the lock if a
 * first attempt at exclusive access fails.
 */
static mutex_t *mac_policy_mtx;
static struct cv mac_policy_cv;
static int mac_policy_count;
struct mac_policy_list_t mac_policy_list;
struct mac_policy_list_t mac_static_policy_list;

/*
 * mac_label_element_list holds the master list of label namespaces for
 * all the policies. When a policy is loaded, each of it's label namespace
 * elements is added to the master list if not already present. When a
 * policy is unloaded, the namespace elements are removed if no other 
 * policy is interested in that namespace element.
 */
struct mac_label_element_list_t mac_label_element_list;
struct mac_label_element_list_t mac_static_label_element_list;

static __inline void
mac_policy_grab_exclusive(void)
{
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
 	    "mac_policy_grab_exclusive() at %s:%d", __FILE__, __LINE__);
	mutex_lock(mac_policy_mtx);
	while (mac_policy_count != 0)
		cv_wait(&mac_policy_cv, mac_policy_mtx);
}

static __inline void
mac_policy_assert_exclusive(void)
{
	mtx_assert(&mac_policy_mtx, MA_OWNED);
	KASSERT(mac_policy_count == 0,
	    ("mac_policy_assert_exclusive(): not exclusive"));
}

static __inline void
mac_policy_release_exclusive(void)
{

	KASSERT(mac_policy_count == 0,
	    ("mac_policy_release_exclusive(): not exclusive"));
	mutex_unlock(mac_policy_mtx);
	cv_signal(&mac_policy_cv);
}

void
mac_policy_list_busy(void)
{
        mutex_lock(mac_policy_mtx);
	mac_policy_count++;
	mutex_unlock(mac_policy_mtx);
}

int
mac_policy_list_conditional_busy_noblock(void)
{
	int ret;

	if (!mutex_try(mac_policy_mtx))
		return (-1);
	if (!LIST_EMPTY(&mac_policy_list)) {
		mac_policy_count++;
		ret = 1;
	} else
		ret = 0;
	mutex_unlock(mac_policy_mtx);
	return (ret);
}

int
mac_policy_list_conditional_busy(void)
{
	int ret;

	mutex_lock(mac_policy_mtx);
	if (!LIST_EMPTY(&mac_policy_list)) {
		mac_policy_count++;
		ret = 1;
	} else
		ret = 0;
	mutex_unlock(mac_policy_mtx);
	return (ret);
}

void
mac_policy_list_unbusy(void)
{
	mutex_lock(mac_policy_mtx);
	mac_policy_count--;
	KASSERT(mac_policy_count >= 0, ("MAC_POLICY_LIST_LOCK"));
	if (mac_policy_count == 0)
		cv_signal(&mac_policy_cv);
	mutex_unlock(mac_policy_mtx);
}

/*
 * Initialize the MAC subsystem, including appropriate SMP locks.
 */
void
mac_init_mach ()
{
	LIST_INIT(&mac_static_policy_list);
	LIST_INIT(&mac_policy_list);
	LIST_INIT(&mac_label_element_list);
	LIST_INIT(&mac_static_label_element_list);

	mac_policy_mtx = mutex_alloc(ETAP_NO_TRACE);
	mac_labelzone_init();

	/*
	 * For the purposes of modules that want to know if they were
	 * loaded "early", set the mac_late flag once we've processed
	 * modules either linked into the kernel, or loaded before the
	 * kernel startup.
	 */
	kmod_load_early();
	mac_late = 1;
}

void
mac_init_bsd(void)
{
	cv_init(&mac_policy_cv, "mac_policy_cv");

	sysctl_register_oid(&sysctl__security);
	sysctl_register_oid(&sysctl__security_mac);
	sysctl_register_oid(&sysctl__security_mac_max_slots);
	sysctl_register_oid(&sysctl__security_mac_enforce_fs);
	sysctl_register_oid(&sysctl__security_mac_enforce_process);
	sysctl_register_oid(&sysctl__security_mac_enforce_system);
	sysctl_register_oid(&sysctl__security_mac_enforce_socket);	
	sysctl_register_oid(&sysctl__security_mac_enforce_vm);
	sysctl_register_oid(&sysctl__security_mac_mmap_revocation);
	sysctl_register_oid(&sysctl__security_mac_mmap_revocation_via_cow);
#ifdef MAC_DEBUG
	sysctl_register_oid(&sysctl__security_mac_debug);
	sysctl_register_oid(&sysctl__security_mac_debug_label_fallback);
	sysctl_register_oid(&sysctl__security_mac_debug_counters);
	sysctl_register_oid(&sysctl__security_mac_debug_counters_creds);
	sysctl_register_oid(&sysctl__security_mac_debug_counters_procs);
	sysctl_register_oid(&sysctl__security_mac_debug_counters_mounts);
	sysctl_register_oid(&sysctl__security_mac_debug_counters_temp);
	sysctl_register_oid(&sysctl__security_mac_debug_counters_vnodes);
	sysctl_register_oid(&sysctl__security_mac_debug_counters_devfsdirents);
#endif
	printf("MAC Framework successfully initialized\n");

	/* Call bsd init functions of already loaded policies */

	/* Using the exclusive lock means no other framework entry
	   points can proceed while initializations are running. This
	   may not be necessary. */

	mac_policy_grab_exclusive();
	struct mac_policy_conf *mpc;

	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {
		if (mpc->mpc_ops->mpo_init_bsd != NULL)
		        (*(mpc->mpc_ops->mpo_init_bsd))(mpc);
	}
	LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {
		if (mpc->mpc_ops->mpo_init_bsd != NULL)
		        (*(mpc->mpc_ops->mpo_init_bsd))(mpc);
	}

	mac_policy_release_exclusive();
}

/*
 * After a policy has been loaded, add the label namespaces managed by the
 * policy to either the static or non-static label namespace list.  
 * A namespace is added to the the list only if it is not already on one of 
 * the lists.
 */
void
mac_policy_addto_labellist(struct mac_policy_conf *mpc, int static_entry)
{
	struct mac_label_element *mle;
	struct mac_label_element_list_t *list;
	char *name;
	int found;
	int idx;
	int midx;

	if (mpc->mpc_labelnames == NULL)
		return;

	if (mpc->mpc_labelname_count == 0)
		return;

	if (static_entry)
		list = &mac_static_label_element_list;
	else
		list = &mac_label_element_list;
	{
		/* Before we grab the policy list lock, allocate enough memory
		 * to contain the potential new elements so we don't have to 
		 * give up the lock, or allocate with the lock held.
		 */
		struct mac_label_element *new_mles[mpc->mpc_labelname_count];

		for (idx = 0; idx < mpc->mpc_labelname_count; idx++)
			MALLOC(new_mles[idx], struct mac_label_element *, 
			    sizeof(struct mac_label_element),
			    M_MACTEMP, M_WAITOK);
		midx = 0;

		if (mac_late)
			mac_policy_grab_exclusive();
		for (idx = 0; idx < mpc->mpc_labelname_count; idx++) {

			name = mpc->mpc_labelnames[idx];

			/* Check both label element lists and add to the 
			 * appropriate list only if not already on a list
			 */
			found = FALSE;
			LIST_FOREACH(mle, &mac_static_label_element_list, 
			    mle_list) {
				if (strcmp(name, mle->mle_name) == 0) {
					found = TRUE;
					break;
				}
			}
			if (!found)
				LIST_FOREACH(mle, 
				    &mac_label_element_list, mle_list) {
					if (strcmp(name, mle->mle_name) == 0) {
						found = TRUE;
						break;
					}
				}
			if (!found) {
				strcpy(new_mles[midx]->mle_name, name);
				LIST_INSERT_HEAD(list, new_mles[midx], 
				    mle_list);
				midx++;
			}
		}
		if (mac_late)
			mac_policy_release_exclusive();

		/* Free up any unused label elements */
		for (idx = midx; idx < mpc->mpc_labelname_count; idx++)
			FREE(new_mles[idx], M_MACTEMP);
	}
}

/*
 * After a policy has been unloaded, remove the label namespaces that the
 * the policy manages from the non-static list of namespaces.
 * The removal only takes place when no other policy is interested in the
 * namespace.
 */
void
mac_policy_removefrom_labellist(struct mac_policy_conf *mpc)
{
	struct mac_label_element *mle;
	struct mac_policy_conf *lmpc;
	char *name, *name2;
	int idx, idx2;
	int found;

	if (mpc->mpc_labelnames == NULL)
		return;

	if (mpc->mpc_labelname_count == 0)
		return;

	/* Check each label namespace managed by the policy and remove
	 * it from the non-static list only if no other policy is interested
	 * in that label namespace.
	 */
	if (mac_late)
		mac_policy_grab_exclusive();
	for (idx = 0; idx < mpc->mpc_labelname_count; idx++) {
		name = mpc->mpc_labelnames[idx];
		found = FALSE;
		LIST_FOREACH(lmpc, &mac_static_policy_list, mpc_list)
			for (idx2 = 0; idx2 < lmpc->mpc_labelname_count; 
			    idx2++) {
				name2 = lmpc->mpc_labelnames[idx2];
				if (strcmp(name, name2) == 0) {
					found = TRUE;
					break;
				}
			}
		if (!found)	/* No 'static' policy manages the namespace */
			LIST_FOREACH(lmpc, &mac_policy_list, mpc_list)
				for (idx2 = 0; idx2 < lmpc->mpc_labelname_count;
				    idx2++) {
					name2 = lmpc->mpc_labelnames[idx2];
					if (strcmp(name, name2) == 0) {
						found = TRUE;
						break;
					}
				}

		if (!found) 	/* No policy manages this namespace */
			LIST_FOREACH(mle, &mac_label_element_list, mle_list)
				if (strcmp(name, mle->mle_name) == 0) {
					LIST_REMOVE(mle, mle_list);
					FREE(mle, M_MACTEMP);
				}
	}
	if (mac_late)
		mac_policy_release_exclusive();
}

/*
 * After the policy list has changed, walk the list to update any global
 * flags.
 */
static void
mac_policy_updateflags(void)
{
#ifndef MAC_ALWAYS_LABEL_MBUF
	struct mac_policy_conf *tmpc;
	int labelmbufs;

	mac_policy_assert_exclusive();

	labelmbufs = 0;

	LIST_FOREACH(tmpc, &mac_static_policy_list, mpc_list) {
		if (tmpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_LABELMBUFS)
			labelmbufs++;
	}
	LIST_FOREACH(tmpc, &mac_policy_list, mpc_list) {
		if (tmpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_LABELMBUFS)
			labelmbufs++;
	}
	mac_labelmbufs = (labelmbufs != 0);
#endif
}

int
mac_policy_register(struct mac_policy_conf *mpc)
{
	struct mac_policy_conf *tmpc;
	int error, slot, static_entry;

	/*
	 * Some preliminary checks to make sure the policy's conf structure
	 * contains the required fields.
	 */
	if (mpc->mpc_name == NULL)
		panic("policy's name is not set\n");

	if (mpc->mpc_fullname == NULL)
		panic("policy's full name is not set\n");

	if (mpc->mpc_labelname_count > MAC_MAX_MANAGED_NAMESPACES)
		panic("policy's managed label namespaces exceeds maximum\n");

	if (mpc->mpc_ops == NULL)
		panic("policy's OPs field is NULL\n");

	error = 0;

	/*
	 * We don't technically need exclusive access while !mac_late,
	 * but hold it for assertion consistency.
	 */
	if (mac_late)
		mac_policy_grab_exclusive();

	/*
	 * If the module can potentially be unloaded, or we're loading
	 * late, we have to stick it in the non-static list and pay
	 * an extra performance overhead.  Otherwise, we can pay a
	 * light locking cost and stick it in the static list.
	 */
	static_entry = (!mac_late &&
	    !(mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_UNLOADOK));

	if (static_entry) {
		LIST_FOREACH(tmpc, &mac_static_policy_list, mpc_list) {
			if (strcmp(tmpc->mpc_name, mpc->mpc_name) == 0) {
				error = EEXIST;
				goto out;
			}
		}
	} else {
		LIST_FOREACH(tmpc, &mac_policy_list, mpc_list) {
			if (strcmp(tmpc->mpc_name, mpc->mpc_name) == 0) {
				error = EEXIST;
				goto out;
			}
		}
	}
	if (mpc->mpc_field_off != NULL) {
		slot = ffs(mac_slot_offsets_free);
		if (slot == 0) {
			error = ENOMEM;
			goto out;
		}
		slot--;
		mac_slot_offsets_free &= ~(1 << slot);
		*mpc->mpc_field_off = slot;
	}
	mpc->mpc_runtime_flags |= MPC_RUNTIME_FLAG_REGISTERED;

	/*
	 * If we're loading a MAC module after the framework has
	 * initialized, it has to go into the dynamic list.  If
	 * we're loading it before we've finished initializing,
	 * it can go into the static list with weaker locking
	 * requirements.
	 */
	if (static_entry)
		LIST_INSERT_HEAD(&mac_static_policy_list, mpc, mpc_list);
	else
		LIST_INSERT_HEAD(&mac_policy_list, mpc, mpc_list);

	/* Per-policy initialization. */
	printf ("calling mpo_init for %s\n", mpc->mpc_name);
	if (mpc->mpc_ops->mpo_init != NULL)
		(*(mpc->mpc_ops->mpo_init))(mpc);

	mac_policy_updateflags();

	if (mac_late)
		mac_policy_release_exclusive();

	mac_policy_addto_labellist(mpc, static_entry);

	printf("Security policy loaded: %s (%s)\n", mpc->mpc_fullname,
	    mpc->mpc_name);

	return (0);

out:
	if (mac_late)
		mac_policy_release_exclusive();

	return (error);
}

int
mac_policy_unregister(struct mac_policy_conf *mpc)
{

	/*
	 * If we fail the load, we may get a request to unload.  Check
	 * to see if we did the run-time registration, and if not,
	 * silently succeed.
	 */
	mac_policy_grab_exclusive();
	if ((mpc->mpc_runtime_flags & MPC_RUNTIME_FLAG_REGISTERED) == 0) {
		mac_policy_release_exclusive();
		return (0);
	}
#if 0
	/*
	 * Don't allow unloading modules with private data.
	 */
	if (mpc->mpc_field_off != NULL) {
		MAC_POLICY_LIST_UNLOCK();
		return (EBUSY);
	}
#endif
	/*
	 * Only allow the unload to proceed if the module is unloadable
	 * by its own definition.
	 */
	if ((mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_UNLOADOK) == 0) {
		mac_policy_release_exclusive();
		return (EBUSY);
	}
	if (mpc->mpc_ops->mpo_destroy != NULL)
		(*(mpc->mpc_ops->mpo_destroy))(mpc);

	LIST_REMOVE(mpc, mpc_list);
	mpc->mpc_runtime_flags &= ~MPC_RUNTIME_FLAG_REGISTERED;
	mac_policy_updateflags();

	mac_policy_release_exclusive();

	mac_policy_removefrom_labellist(mpc);

	printf("Security policy unload: %s (%s)\n", mpc->mpc_fullname,
	    mpc->mpc_name);

	return (0);
}

/*
 * Define an error value precedence, and given two arguments, selects the
 * value with the higher precedence.
 */
int
mac_error_select(int error1, int error2)
{

	/* Certain decision-making errors take top priority. */
	if (error1 == EDEADLK || error2 == EDEADLK)
		return (EDEADLK);

	/* Invalid arguments should be reported where possible. */
	if (error1 == EINVAL || error2 == EINVAL)
		return (EINVAL);

	/* Precedence goes to "visibility", with both process and file. */
	if (error1 == ESRCH || error2 == ESRCH)
		return (ESRCH);

	if (error1 == ENOENT || error2 == ENOENT)
		return (ENOENT);

	/* Precedence goes to DAC/MAC protections. */
	if (error1 == EACCES || error2 == EACCES)
		return (EACCES);

	/* Precedence goes to privilege. */
	if (error1 == EPERM || error2 == EPERM)
		return (EPERM);

	/* Precedence goes to error over success; otherwise, arbitrary. */
	if (error1 != 0)
		return (error1);
	return (error2);
}

void
mac_init_label(struct label *label)
{

	bzero(label, sizeof(*label));
	label->l_flags = MAC_FLAG_INITIALIZED;
}

void
mac_destroy_label(struct label *label)
{

	KASSERT(label->l_flags & MAC_FLAG_INITIALIZED,
	    ("destroying uninitialized label"));

	bzero(label, sizeof(*label));
	/* implicit: label->l_flags &= ~MAC_FLAG_INITIALIZED; */
}

int
mac_check_service_access (struct label *subj, struct label *obj,
			  const char *s, const char *p)
{
  int error;

  MAC_CHECK (check_service_access, subj, obj, s, p);
  return (error);
}

int
mac_request_object_label(struct label *subj, struct label *obj,
    const char *s, struct label *out)
{
  int error;

  MAC_CHECK (request_object_label, subj, obj, s, out);
  return error;
}

int
mac_check_structmac_consistent(struct mac *mac)
{

	if (mac->m_buflen > MAC_MAX_LABEL_BUF_LEN)
		return (EINVAL);

	return (0);
}

/* system calls */

struct __mac_get_pid_args {
	pid_t       pid;
	struct mac *mac_p;
};

int
__mac_get_pid(struct proc *p, struct __mac_get_pid_args *uap, register_t *ret)
{
	char *elements, *buffer;
	struct mac mac;
	struct proc *tproc;
	struct ucred *tcred;
	int error;
	size_t ulen;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	tproc = pfind(uap->pid);
	if (tproc == NULL)
		return (ESRCH);

	tcred = NULL;				/* Satisfy gcc. */
	error = 0;/*p_cansee(p, tproc);*/
	if (error == 0) {
		tcred = tproc->p_ucred;
		crhold(tcred);
	}
	PROC_UNLOCK(tproc);
	if (error)
		return (error);

	MALLOC(elements, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, elements, mac.m_buflen, &ulen);
	if (error) {
		FREE(elements, M_MACTEMP);
		crfree(tcred);
		return (error);
	}

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
	error = mac_externalize_cred_label(tcred->cr_label, elements,
	    buffer, mac.m_buflen, M_WAITOK);
	if (error == 0)
		error = copyout(buffer, mac.m_string, strlen(buffer)+1);

	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);
	crfree(tcred);
	return (error);
}

struct __mac_get_proc_args {
	struct mac *mac_p;
};

int
__mac_get_proc(struct proc *p, struct __mac_get_proc_args *uap, register_t *ret)
{
	char *elements, *buffer;
	struct mac mac;
	struct ucred *cr;
	int error;
	size_t ulen;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	MALLOC(elements, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, elements, mac.m_buflen, &ulen);
	if (error) {
		FREE(elements, M_MACTEMP);
		return (error);
	}

	PROC_LOCK(p);
	cr = p->p_ucred;
	crhold(cr);
	PROC_UNLOCK(p);

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
	error = mac_externalize_cred_label(cr->cr_label,
	    elements, buffer, mac.m_buflen, M_WAITOK);
	if (error == 0)
		error = copyout(buffer, mac.m_string, strlen(buffer)+1);

	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);
	crfree (cr);
	return (error);
}

/*
 * MPSAFE
 */
struct __mac_set_proc_args {
	struct mac *mac_p;
};

int
__mac_set_proc(struct proc *p, struct __mac_set_proc_args *uap, register_t *ret)
{
	struct ucred *newcred, *oldcred;
	struct label *intlabel;
	struct mac mac;
	char *buffer;
	int error;
	size_t dummy;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, buffer, mac.m_buflen, &dummy);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}

	intlabel = mac_cred_label_alloc();
	error = mac_internalize_cred_label(intlabel, buffer);
	FREE(buffer, M_MACTEMP);
	if (error)
		goto out;

	PROC_LOCK(p);
	oldcred = p->p_ucred;

	error = mac_check_cred_relabel(oldcred, intlabel);
	if (error) {
		PROC_UNLOCK(p);
		goto out;
	}

	/*setsugid(p);*/
	newcred = crdup(oldcred);
	mac_relabel_cred(newcred, intlabel);
	p->p_ucred = newcred;
	mac_update_task_from_cred (newcred, p->task);

	/*
	 * Grab additional reference for use while revoking mmaps, prior
	 * to releasing the proc lock and sharing the cred.
	 */
	crhold(newcred);
	PROC_UNLOCK(p);

#if 0
	if (mac_enforce_vm) {
		mutex_lock(Giant);					/* XXX FUNNEL? */
		mac_cred_mmapped_drop_perms(p, newcred);
		mutex_unlock(Giant);					/* XXX FUNNEL? */
	}
#endif

	crfree(newcred);	/* Free revocation reference. */
	crfree(oldcred);

out:
	mac_cred_label_free(intlabel);
	return (error);
}

struct __mac_get_lcid_args {
	pid_t lcid;
	struct mac *mac_p;
};

int
__mac_get_lcid(struct proc *p, struct __mac_get_lcid_args *uap, register_t *ret)
{
	char *elements, *buffer;
	struct mac mac;
	struct lctx *l;
	int error;
	size_t ulen;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	l = lcfind(uap->lcid);
	if (l == NULL)
		return (ESRCH);

	MALLOC(elements, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, elements, mac.m_buflen, &ulen);
	if (error) {
		LCTX_UNLOCK(l);
		FREE(elements, M_MACTEMP);
		return (error);
	}
	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = mac_externalize_lctx_label(l->lc_label, elements,
					   buffer, mac.m_buflen);
	if (error == 0)
		error = copyout(buffer, mac.m_string, strlen(buffer)+1);

	LCTX_UNLOCK(l);
	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);
	return (error);
}

struct __mac_get_lctx_args {
	struct mac *mac_p;
};

int
__mac_get_lctx(struct proc *p, struct __mac_get_lctx_args *uap, register_t *ret)
{
	char *elements, *buffer;
	struct mac mac;
	int error;
	size_t ulen;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	MALLOC(elements, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, elements, mac.m_buflen, &ulen);
	if (error) {
		FREE(elements, M_MACTEMP);
		return (error);
	}
	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);

	PROC_LOCK(p);
	if (p->p_lctx == NULL) {
		PROC_UNLOCK(p);
		error = ENOENT;
		goto out;
	}

	error = mac_externalize_lctx_label(p->p_lctx->lc_label,
					   elements, buffer, mac.m_buflen);
	PROC_UNLOCK(p);
	if (error == 0)
		error = copyout(buffer, mac.m_string, strlen(buffer)+1);

out:
	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);
	return (error);
}

struct __mac_set_lctx_args {
	struct mac *mac_p;
};

int
__mac_set_lctx(struct proc *p, struct __mac_set_lctx_args *uap, register_t *ret)
{
	struct mac mac;
	struct label *intlabel;
	char *buffer;
	int error;
	size_t ulen;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, buffer, mac.m_buflen, &ulen);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}

	intlabel = mac_lctx_label_alloc();
	error = mac_internalize_lctx_label(intlabel, buffer);
	FREE(buffer, M_MACTEMP);
	if (error)
		goto out;

	PROC_LOCK(p);
	if (p->p_lctx == NULL) {
		PROC_UNLOCK(p);
		error = ENOENT;
		goto out;
	}

	error = mac_check_lctx_relabel(p->p_lctx, intlabel);
	if (error) {
		PROC_UNLOCK(p);
		goto out;
	}
	mac_relabel_lctx(p->p_lctx, intlabel);
	PROC_UNLOCK(p);
out:
	mac_lctx_label_free(intlabel);
	return (error);
}

struct __mac_get_fd_args {
	int         fd;
	struct mac *mac_p;
};

int
__mac_get_fd(struct proc *p, struct __mac_get_fd_args *uap, register_t *ret)
{

	struct file *fp;
	struct mac m;
	char *elements, *buffer;
	int error, count;
#ifdef MAC_NETWORK
	struct socket *so;
	struct label *intlabel;
#endif

	AUDIT_ARG(fd, uap->fd);

	error = copyin(uap->mac_p, &m, sizeof(m));
	if (error) 
		return (error);

	error = mac_check_structmac_consistent(&m);
	if (error)
		return (error);
			
	MALLOC(elements, char *, m.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(m.m_string, elements, m.m_buflen, (size_t *) &count);
	if (error) {
		FREE(elements, M_MACTEMP);
		return (error);
	}

	MALLOC(buffer, char *, m.m_buflen, M_MACTEMP, M_WAITOK);
	error = fdgetf(p, uap->fd, &fp);
	if (error) {
		FREE(buffer, M_MACTEMP);
		FREE(elements, M_MACTEMP);
		return (error);
	}
	
	error = mac_check_get_fd(p->p_ucred, fp, elements, m.m_buflen);
	if (error) {
		FREE(buffer, M_MACTEMP);
		FREE(elements, M_MACTEMP);
		return (error);
	}
	
	switch (fp->f_type) {
		case DTYPE_SOCKET:
#ifdef MAC_SOCKET
			so = (struct socket *) fp->f_data;
			thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
			intlabel = mac_socket_label_alloc(MAC_WAITOK);
			mac_copy_socket_label(so->so_label, intlabel);
			error = mac_externalize_socket_label(intlabel, elements, buffer,
				m.m_buflen, M_WAITOK);
			mac_socket_label_free(intlabel);
			thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
			break;
#endif
		default:
			error = ENOSYS;   // only sockets are handled so far
	}
	
	if (error == 0)
		error = copyout(buffer, m.m_string, strlen(buffer) + 1);
		
	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);
	return (error);
}

struct __mac_get_file_args {
	char       *path_p;
	struct mac *mac_p;
};

int
__mac_get_file(struct proc *p, struct __mac_get_file_args *uap, register_t *ret)
{
	char *elements, *buffer;
	struct nameidata nd;
	struct label *intlabel;
	struct mac mac;
	int error;
	size_t ulen;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	MALLOC(elements, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, elements, mac.m_buflen, &ulen);
	if (error) {
		FREE(elements, M_MACTEMP);
		return (error);
	}

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
#if 0
	mutex_lock(&Giant);				/* VFS */ /* XXX FUNNEL? */
#endif
	NDINIT(&nd, LOOKUP, LOCKLEAF | FOLLOW | AUDITVNPATH1, UIO_USERSPACE, uap->path_p,
	    p);
	error = namei(&nd);
	if (error)
		goto out;

	intlabel = mac_vnode_label_alloc();
	mac_copy_vnode_label(nd.ni_vp->v_label, intlabel);
	error = mac_externalize_vnode_label(intlabel, elements, buffer,
	    mac.m_buflen, M_WAITOK);

	vput (nd.ni_vp);
	mac_vnode_label_free(intlabel);

	if (error == 0)
		error = copyout(buffer, mac.m_string, strlen(buffer)+1);

out:
#if 0
	mutex_unlock(&Giant);				/* VFS */ /* XXX FUNNEL? */
#endif

	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);

	return (error);
}

/*
 * MPSAFE
 */
struct __mac_get_link_args {
	char       *path_p;
	struct mac *mac_p;
};

int
__mac_get_link(struct proc *p, struct __mac_get_link_args *uap)
{
	char *elements, *buffer;
	struct nameidata nd;
	struct label *intlabel;
	struct mac mac;
	int error;
	size_t ulen;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	MALLOC(elements, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, elements, mac.m_buflen, &ulen);
	if (error) {
		FREE(elements, M_MACTEMP);
		return (error);
	}

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
#if 0
	mutex_lock(&Giant);				/* VFS */ /* XXX FUNNEL? */
#endif
	NDINIT(&nd, LOOKUP, LOCKLEAF | NOFOLLOW | AUDITVNPATH1, UIO_USERSPACE, uap->path_p,
	    p);
	error = namei(&nd);
	if (error)
		goto out;

	intlabel = mac_vnode_label_alloc();
	mac_copy_vnode_label(nd.ni_vp->v_label, intlabel);
	error = mac_externalize_vnode_label(intlabel, elements, buffer,
	    mac.m_buflen, M_WAITOK);

	vput (nd.ni_vp);
	mac_vnode_label_free(intlabel);

	if (error == 0)
		error = copyout(buffer, mac.m_string, strlen(buffer)+1);

out:
#if 0
	mutex_unlock(&Giant);				/* VFS */ /* XXX FUNNEL? */
#endif

	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);

	return (error);
}

struct __mac_set_fd_args {
	int         fd;
	struct mac *mac_p;
};

int
__mac_set_fd(struct proc *p, struct __mac_set_fd_args *uap, register_t *ret)
{

	struct file *fp;
	struct mac mac;
	int error, count;
	char *buffer;
#ifdef MAC_NETWORK
	struct label *intlabel;
	struct socket *so;
#endif

	AUDIT_ARG(fd, uap->fd);

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error) 
		return (error);
		
	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);
	
	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, buffer, mac.m_buflen, (size_t *) &count);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}
	
	error = fdgetf(p, uap->fd, &fp);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}
	
	error = mac_check_set_fd(p->p_ucred, fp, buffer, mac.m_buflen);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}
	
	switch (fp->f_type) {
		case DTYPE_SOCKET:
#ifdef MAC_SOCKET
			thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
			intlabel = mac_socket_label_alloc(MAC_WAITOK);
			error = mac_internalize_socket_label(intlabel, buffer);
			if (error == 0) {
				so = (struct socket *) fp->f_data;
				error = mac_socket_label_set(p->p_ucred, so, intlabel);
			}
			mac_socket_label_free(intlabel);
			thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
			break;
#endif
		default:
			error = ENOSYS;  // only sockets are handled at this point
	}
	
	FREE(buffer, M_MACTEMP);
	return (error);
}
	

struct __mac_set_file_args {
	char       *path_p;
	struct mac *mac_p;
};

int
__mac_set_file(struct proc *p, struct __mac_set_file_args *uap, register_t *ret)
{
	struct label *intlabel;
	struct nameidata nd;
	struct mac mac;
	char *buffer;
	int error;
	size_t dummy;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error) {
		printf("mac_set_file: failed structure consistency check\n");
		return (error);
	}

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, buffer, mac.m_buflen, &dummy);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}

	intlabel = mac_vnode_label_alloc();
	error = mac_internalize_vnode_label(intlabel, buffer);
	FREE(buffer, M_MACTEMP);
	if (error) {
		mac_vnode_label_free(intlabel);
		return (error);
	}

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, UIO_USERSPACE, uap->path_p, p);
	error = namei(&nd);
	if (error == 0)
	  {
	    struct vnode *vp = nd.ni_vp;

	    VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	    vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	    error = vn_setlabel (vp, intlabel, p->p_ucred, p);

	    vput (nd.ni_vp);
	}

	mac_vnode_label_free(intlabel);
	return (error);
}

/*
 * MPSAFE
 */
int
__mac_set_link(struct proc *p, struct __mac_set_file_args *uap)
{
	struct label *intlabel;
	struct nameidata nd;
	struct mac mac;
	char *buffer;
	int error;
	size_t dummy;

	error = copyin(uap->mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

	MALLOC(buffer, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, buffer, mac.m_buflen, &dummy);
	if (error) {
		FREE(buffer, M_MACTEMP);
		return (error);
	}

	intlabel = mac_vnode_label_alloc();
	error = mac_internalize_vnode_label(intlabel, buffer);
	FREE(buffer, M_MACTEMP);
	if (error) {
		mac_vnode_label_free(intlabel);
		return (error);
	}

	NDINIT(&nd, LOOKUP, NOFOLLOW | AUDITVNPATH1, UIO_USERSPACE, uap->path_p, p);

	error = namei(&nd);
	if (error == 0)
	  {
	    struct vnode *vp = nd.ni_vp;

	    VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	    vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	    error = vn_setlabel (vp, intlabel, p->p_ucred, p);

	    vput (nd.ni_vp);
	}

	mac_vnode_label_free(intlabel);
	return (error);
}

/*
 * MPSAFE
 */
struct __mac_syscall_args {
	char *policy;
	int   call;
	void *arg;
};

int
__mac_syscall(struct proc *p, struct __mac_syscall_args *uap, register_t *retv)
{
	struct mac_policy_conf *mpc;
	char target[MAC_MAX_POLICY_NAME];
	int entrycount, error;
	size_t dummy;

	error = copyinstr(uap->policy, target, sizeof(target), &dummy);
	if (error)
		return (error);

	error = ENOSYS;
	LIST_FOREACH(mpc, &mac_static_policy_list, mpc_list) {
		if (strcmp(mpc->mpc_name, target) == 0 &&
		    mpc->mpc_ops->mpo_syscall != NULL) {
			error = mpc->mpc_ops->mpo_syscall(p,
			    uap->call, uap->arg, retv);
			goto out;
		}
	}

	if ((entrycount = mac_policy_list_conditional_busy()) != 0) {
		LIST_FOREACH(mpc, &mac_policy_list, mpc_list) {
			if (strcmp(mpc->mpc_name, target) == 0 &&
			    mpc->mpc_ops->mpo_syscall != NULL) {
				error = mpc->mpc_ops->mpo_syscall(p,
				    uap->call, uap->arg, retv);
				break;
			}
		}
		mac_policy_list_unbusy();
	}
out:
	return (error);
}


#else /* MAC */
int
__mac_get_pid(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_get_proc(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_set_proc(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_get_lcid(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_get_lctx(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_set_lctx(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_get_file(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_get_link(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_set_file(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_set_link(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_get_fd(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_set_fd(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

int
__mac_syscall(struct proc *p, void *uap, register_t *ret)
{

	return (ENOSYS);
}

#endif /* !MAC */
