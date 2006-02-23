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
 * $FreeBSD: src/sys/sys/mac_policy.h,v 1.39 2003/04/18 19:57:37 rwatson Exp $
 */

/**
  @file mac_policy.h
  @brief Kernel Interfaces for MAC policy modules

   This header defines the list of operations that are defined by the
   TrustedBSD MAC Framwork on Darwin.  MAC Policy modules register
   with the framework to declare interest in a specific set of
   operations.  If interest in an entry point is not declared, then
   the policy will be ignored when the Framework evaluates that entry
   point.
*/

#ifndef _SYS_MAC_POLICY_H
#define _SYS_MAC_POLICY_H

struct auditinfo;
struct attrlist;
struct bpf_d;
struct ifnet;
struct ipq;
struct label;
struct lctx;
struct mac_policy_conf;
struct mbuf;
struct mount;
struct sbuf;
struct semid_kernel;
struct shmid_kernel;
struct socket;
struct ucred;
struct vnode;
struct devnode;
struct task;
/** @struct dummy */

/*-
 * Operations are sorted first by general class of operation, then
 * alphabetically.
 */

/**
  @name Entry Points for Module Operations
*/
/*@{*/
/**
  @brief Policy unload event
  @param mpc MAC policy configuration

  This is the MAC Framework policy unload event.  This entry point will
  only be called if the module's policy configuration allows unload (if
  the MPC_LOADTIME_FLAG_UNLOADOK is set).  Most security policies won't
  want to be unloaded; they should set their flags to prevent this
  entry point from being called.

  @warning During this call, the mac policy list mutex is held, so
  sleep operations cannot be performed, and calls out to other kernel
  subsystems must be made with caution.

  @see MPC_LOADTIME_FLAG_UNLOADOK
*/
typedef void mpo_destroy_t(
	struct mac_policy_conf *mpc
);

/**
  @brief Policy initialization event
  @param mpc MAC policy configuration
  @see mac_policy_register
  @see mpo_init_bsd_t

  This is the MAC Framework policy initialization event.  This entry
  point is called during mac_policy_register, when the policy module
  is first registered with the MAC Framework.  This is often done very
  early in the boot process, after the kernel Mach subsystem has been
  initialized, but prior to the BSD subsystem being initialized.
  Since the kernel BSD services are not yet available, it is possible
  that some initialization must occur later, possibly in the
  mpo_init_bsd_t policy entry point, such as registering BSD system
  controls (sysctls).  Policy modules loaded at boot time will be
  registered and initialized before labeled Mach objects are created.

  @warning During this call, the mac policy list mutex is held, so
  sleep operations cannot be performed, and calls out to other kernel
  subsystems must be made with caution.
*/
typedef void mpo_init_t(
	struct mac_policy_conf *mpc
);

/**
  @brief Policy BSD initialization event
  @param mpc MAC policy configuration
  @see mpo_init_t

  This entry point is called after the kernel BSD subsystem has been
  initialized.  By this point, the module should already be loaded,
  registered, and initialized.  Since policy modules are initialized
  before kernel BSD services are available, this second initialization
  phase is necessary.  At this point, BSD services (memory management,
  synchronization primitives, vfs, etc.) are available, but the first
  process has not yet been created.  Mach-related objects and tasks
  will already be fully initialized and may be in use--policies
  requiring ubiquitous labeling may also want to implement mpo_init_t.

  @warning During this call, the mac policy list mutex is held, so
  sleep operations cannot be performed, and calls out to other kernel
  subsystems must be made with caution.
*/
typedef void mpo_init_bsd_t(
	struct mac_policy_conf *mpc
);

/**
  @brief Policy extension service
  @param p Calling process
  @param call Policy-specific syscall number
  @param arg Pointer to syscall arguments
  @param retval Pointer to store actual return value in

  This entry point provides a policy-multiplexed system call so that
  policies may provide additional services to user processes without
  registering specific system calls. The policy name provided during
  registration is used to demux calls from userland, and the arguments
  will be forwarded to this entry point.  When implementing new
  services, security modules should be sure to invoke appropriate
  access control checks from the MAC framework as needed.  For
  example, if a policy implements an augmented signal functionality,
  it should call the necessary signal access control checks to invoke
  the MAC framework and other registered policies.

  @warning Since the format and contents of the policy-specific
  arguments are unknown to the MAC Framework, modules must perform the
  required copyin() of the syscall data on their own.  No policy
  mediation is performed, so policies must perform any necessary
  access control checks themselves.  If multiple policies are loaded,
  they will currently be unable to mediate calls to other policies.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_syscall_t(
	struct proc *p,
	int call,
	void *arg,
	int *retval
);
/*@}*/

/**
  @name Entry Points for Label Management

  These are the entry points corresponding to the life cycle events for
  kernel objects, such as initialization, creation, and destruction.

  Most policies (that use labels) will initialize labels by allocating
  space for policy-specific data.  In most cases, it is permitted to
  sleep during label initialization operations; it will be noted when
  it is not permitted.

  Initialization usually will not require doing more than allocating a
  generic label for the given object.  What follows initialization is
  creation, where a label is made specific to the object it is associated 
  with.  Destruction occurs when the label is no longer needed, such as
  when the corresponding object is destroyed.  All necessary cleanup should
  be performed in label destroy operations.

  Where possible, the label entry points have identical parameters.  If
  the policy module does not require structure-specific label
  information, the same function may be registered in the policy
  operation vector.  Many policies will implement two such generic
  allocation calls: one to handle sleepable requests, and one to handle
  potentially non-sleepable requests.
*/
/*@{*/
/**
  @brief Initialize user credential label
  @param label New label to initialize

  Initialize the label for a newly instantiated user credential.
  Sleeping is permitted.
*/
typedef void mpo_init_cred_label_t(
	struct label *label
);

/**
  @brief Initialize Login Context label
  @param label New label to initialize
*/
typedef void mpo_init_lctx_label_t(
	struct label *label
);

/**
  @brief Initialize devfs label
  @param label New label to initialize

  Initialize the label for a newly instantiated devfs entry.  Sleeping
  is permitted.
*/
typedef void mpo_init_devfsdirent_label_t(
	struct label *label
);

/**
  @brief Initialize a special label denoting failed label establishment
  @param label New label to initialize

  Every mbuf has a label describing the source of the data, however, due to
  some locking restrictions, it is not always possible to allocate space
  for a new label at the moment data arrives.  When that happens, the data is 
  given a special label, the "failed label", indicating failure to create a 
  label.  This function initializes that label.
  
  The only function that will have to deal with the failed label is
  mpo_check_socket_deliver().  Modules can take any action in response
  to receiving data with the failed label.  If the packet is dropped, it will
  eventually be resent by the remote TCP with the correct label.
  
  This function is called only once during system initialization.  The
  failed label should not be modified after initialization or destroyed
  at any point as it is global and persistent.
*/
typedef void mpo_init_mbuf_failed_label_t(
	struct label *label
);

/**
  @brief Initialize the label on an mbuf.
  @param label New label to initialize
  @param waitok Malloc flags

  Initialize the socket label stored within an mbuf.  The waitok field
  may be one of M_WAITOK and M_NOWAIT, and should be employed to avoid
  performing a sleeping malloc(9) during this initialization call.  It
  is not always safe to sleep during this entry point.

  @warning Since it is possible for the waitok flags to be set to
  M_NOWAIT, the malloc operation may fail.

  @return On success, 0, otherwise, an appropriate errno return value.
*/
typedef int mpo_init_mbuf_socket_label_t(
	struct label *label,
	int waitok
);

/**
  @brief Initialize mount label
  @param label New label to initialize
  @see mpo_init_mount_fs_label_t

  Initialize the label for a newly instantiated mount structure.  This
  is the label for the mount point itself.  Sleeping is permitted.
*/
typedef void mpo_init_mount_label_t(
	struct label *label
);

/**
  @brief Initialize mount point file system label
  @param label New label to initialize
  @see mpo_init_mount_label_t

  Initialize the file system label for a newly instantiated mount
  structure.  This label is typically used to store a file system
  default label in the case that the file system has been mounted
  singlelabel.  Since some file systems do not support persistent
  labels (extended attributes) or are read-only (such as CD-ROMs), it
  is often necessary to store a default label separately from the
  label of the mount point itself.  Sleeping is permitted.

  @warning This is not the label for the mount point itself.
*/
typedef void mpo_init_mount_fs_label_t(
	struct label *label
);

/**
  @brief Initialize Mach port label
  @param label New label to initialize

  Initialize the label for a newly instantiated Mach port.  Sleeping
  is permitted.
*/
typedef void mpo_init_port_label_t(
	struct label *label
);

/**
  @brief Initialize POSIX semaphore label
  @param label New label to initialize

  Initialize the label for a newly instantiated POSIX semaphore. Sleeping 
  is permitted.
*/
typedef void mpo_init_posix_sem_label_t(
	struct label *label
);

/**
  @brief Initialize POSIX Shared Memory region label
  @param label New label to initialize

  Initialize the label for newly a instantiated POSIX Shared Memory 
  region. Sleeping is permitted.
*/
typedef void mpo_init_posix_shm_label_t(
	struct label *label
);

/**
  @brief Initialize process label
  @param label New label to initialize
  @see mpo_init_cred_label_t

  Initialize the label for a newly instantiated BSD process structure.
  Normally, security policies will store the process label in the user
  credential rather than here in the process structure.  However,
  there are some floating label policies that may need to temporarily
  store a label in the process structure until it is safe to update
  the user credential label.  Sleeping is permitted.
*/
typedef void mpo_init_proc_label_t(
	struct label *label
);

/**
  @brief Initialize socket label
  @param label New label to initialize
  @param waitok Malloc flags

  Initialize the label of a newly instantiated socket.  The waitok
  field may be one of M_WAITOK and M_NOWAIT, and should be employed to
  avoid performing a sleeping malloc(9) during this initialization
  call.  It it not always safe to sleep during this entry point.

  @warning Since it is possible for the waitok flags to be set to
  M_NOWAIT, the malloc operation may fail.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_init_socket_label_t(
	struct label *label,
	int waitok
);

/**
  @brief Initialize socket peer label
  @param label New label to initialize
  @param waitok Malloc flags

  Initialize the peer label of a newly instantiated socket.  The
  waitok field may be one of M_WAITOK and M_NOWAIT, and should be
  employed to avoid performing a sleeping malloc(9) during this
  initialization call.  It it not always safe to sleep during this
  entry point.

  @warning Since it is possible for the waitok flags to be set to
  M_NOWAIT, the malloc operation may fail.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_init_socket_peer_label_t(
	struct label *label,
	int waitok
);

/**
  @brief Initialize System V semaphore label
  @param label New label to initialize

  Initialize the label for a newly instantiated System V semaphore.  Sleeping
  is permitted.
*/
typedef void mpo_init_sysv_sem_label_t(
	struct label *label
);

/**
  @brief Initialize System V Shared Memory region label
  @param label New label to initialize

  Initialize the label for a newly instantiated System V Shared Memory
  region.  Sleeping is permitted.
*/
typedef void mpo_init_sysv_shm_label_t(
	struct label *label
);

/**
  @brief Initialize Mach task label
  @param label New label to initialize

  Initialize the label for a newly instantiated Mach task.  Sleeping
  is permitted.
*/
typedef void mpo_init_task_label_t(
	struct label *label
);

/**
  @brief Initialize the label denoting the TCP stack itself.
  @param label New label to initialize

  Every mbuf through the TCP has a label that describes the sender.  Some 
  packets originate from the TCP stack itself.  This function initializes the 
  global, persistent label denoting the TCP stack.
  
  This function is called once when the system is initialized.  The TCP label
  should not be altered after initialization or destroyed at any point.
*/
typedef void mpo_init_tcp_label_t(
	struct label *label
);

/**
  @brief Initialize a special label denoting an unknown source
  @param label New label to initialize

  Every mbuf has a label describing the source of the data, however,
  currently only TCP segments received on the loopback interface will have a 
  label that denotes the real sender.  All others will have a label denoting 
  that the source of the data is unknown.  This function initializes that label.
  
  This function is called only once during system initialization.  The
  unknown source label should not be modified after initialization or
  destroyed at any point, as it is global and persistent.
  
 */
typedef void mpo_init_mbuf_unknown_source_label_t(
	struct label *label
);

/**
  @brief Initialize vnode label
  @param label New label to initialize

  Initialize label storage for use with a newly instantiated vnode, or
  for temporary storage associated with the copying in or out of a
  vnode label.  While it is necessary to allocate space for a
  kernel-resident vnode label, it is not yet necessary to link this vnode
  with persistent label storage facilities, such as extended attributes.
  Sleeping is permitted.
*/
typedef void mpo_init_vnode_label_t(
	struct label *label
);

/**
  @brief Destroy credential label
  @param label The label to be destroyed

  Destroy a user credential label.  Since the user credential
  is going out of scope, policy modules should free any internal
  storage associated with the label so that it may be destroyed.
*/
typedef void mpo_destroy_cred_label_t(
	struct label *label
);

/**
 @brief Destroy Login Context label
 @param label The label to be destroyed
*/
typedef void mpo_destroy_lctx_label_t(
	struct label *label
);

/**
  @brief Destroy devfs label
  @param label The label to be destroyed

  Destroy a devfs entry label.  Since the object is going out
  of scope, policy modules should free any internal storage associated
  with the label so that it may be destroyed.
*/
typedef void mpo_destroy_devfsdirent_label_t(
	struct label *label
);

/**
  @brief Destroy mbuf label
  @param label The label to be destroyed

  Destroy an mbuf header label.  Since the object is going out of 
  scope, policy modules should free any internal storage associated with 
  the label so that it may be destroyed.
  
  @warning: this function can never block.
*/
typedef void mpo_destroy_mbuf_socket_label_t(
	struct label *label
);

/**
  @brief Destroy mount label
  @param label The label to be destroyed

  Destroy a file system mount label.  Since the
  object is going out of scope, policy modules should free any
  internal storage associated with the label so that it may be
  destroyed.
*/
typedef void mpo_destroy_mount_label_t(
	struct label *label
);

/**
  @brief Destroy file system label
  @param label The label to be destroyed

  Destroy the file system label associated with a mount point.
  Since the object is going out of scope, policy modules should free
  any internal storage associated with the label so that it may be
  destroyed.
*/
typedef void mpo_destroy_mount_fs_label_t(
	struct label *label
);

/**
  @brief Destroy Mach port label
  @param label The label to be destroyed

  Destroy a Mach port label.  Since the object is going out of
  scope, policy modules should free any internal storage associated
  with the label so that it may be destroyed.
*/
typedef void mpo_destroy_port_label_t(
	struct label *label
);

/**
  @brief Destroy POSIX semaphore label
  @param label The label to be destroyed

  Destroy a POSIX semaphore label.  Since the object is
  going out of scope, policy modules should free any internal storage
  associated with the label so that it may be destroyed.
*/
typedef void mpo_destroy_posix_sem_label_t(
	struct label *label
);

/**
  @brief Destroy POSIX shared memory label
  @param label The label to be destroyed

  Destroy a POSIX shared memory region label.  Since the
  object is going out of scope, policy modules should free any
  internal storage associated with the label so that it may be
  destroyed.
*/
typedef void mpo_destroy_posix_shm_label_t(
	struct label *label
);

/**
  @brief Destroy process label
  @param label The label to be destroyed

  Destroy a process label.  Since the object is going
  out of scope, policy modules should free any internal storage
  associated with the label so that it may be destroyed.
*/
typedef void mpo_destroy_proc_label_t(
	struct label *label
);

/**
  @brief Destroy socket label
  @param label The label to be destroyed

  Destroy a socket label.  Since the object is going out of
  scope, policy modules should free any internal storage associated
  with the label so that it may be destroyed.
*/
typedef void mpo_destroy_socket_label_t(
	struct label *label
);

/**
  @brief Destroy socket peer label
  @param label The peer label to be destroyed

  Destroy a socket peer label.  Since the object is going out of
  scope, policy modules should free any internal storage associated
  with the label so that it may be destroyed.
*/
typedef void mpo_destroy_socket_peer_label_t(
	struct label *label
);

/**
  @brief Destroy System V semaphore label
  @param label The label to be destroyed

  Destroy a System V semaphore label.  Since the object is
  going out of scope, policy modules should free any internal storage
  associated with the label so that it may be destroyed.
*/
typedef void mpo_destroy_sysv_sem_label_t(
	struct label *label
);

/**
  @brief Destroy System V shared memory label
  @param label The label to be destroyed

  Destroy a System V shared memory region label.  Since the
  object is going out of scope, policy modules should free any
  internal storage associated with the label so that it may be
  destroyed.
*/
typedef void mpo_destroy_sysv_shm_label_t(
	struct label *label
);

/**
  @brief Destroy Mach task label
  @param label The label to be destroyed

  Destroy a Mach task label.  Since the object is going out of
  scope, policy modules should free any internal storage associated
  with the label so that it may be destroyed.
*/
typedef void mpo_destroy_task_label_t(
	struct label *label
);

/**
  @brief Destroy vnode label
  @param label The label to be destroyed

  Destroy a vnode label.  Since the object is going out of scope,
  policy modules should free any internal storage associated with the
  label so that it may be destroyed.
*/
typedef void mpo_destroy_vnode_label_t(
	struct label *label
);

/**
  @brief Clean up a System V semaphore label
  @param label The label to be destroyed

  Clean up a System V semaphore label.  Darwin pre-allocates
  semaphores at system boot time and re-uses them rather than
  allocating new ones.  Before semaphores are returned to the "free
  pool", policies can cleanup or overwrite any information present in
  the label.
*/
typedef void mpo_cleanup_sysv_sem_label_t(
	struct label *label
);

/**
  @brief Clean up a System V Share Memory Region label
  @param shmlabel The label to be destroyed

  Clean up a System V Shared Memory Region label.  Darwin
  pre-allocates these objects at system boot time and re-uses them
  rather than allocating new ones.  Before the memory regions are
  returned to the "free pool", policies can cleanup or overwrite any
  information present in the label.
*/
typedef void mpo_cleanup_sysv_shm_label_t(
	struct label *shmlabel
);

/**
  @brief Update a Mach task label
  @param cred User credential label to be used as the source
  @param task Mach task label to be used as the destination
  @see mpo_relabel_cred_t
  @see mpo_execve_transition_t

  Update the label on a Mach task, using the supplied user credential
  label. When a mac_execve_transition or a mac_relabel_cred operation
  causes the label on a user credential to change, the Mach task label
  also needs to be updated to reflect the change.  Both labels are
  already valid (initialized and created).

  @warning XXX We may change the name of this entry point in a future
  version of the MAC framework.
*/
typedef void mpo_copy_cred_to_task_t(
	struct label *cred,
	struct label *task
);

/**
  @brief Update a Mach task port label
  @param cred User credential label to be used as the source
  @param task Mach port label to be used as the destination
  @see mpo_relabel_cred_t
  @see mpo_execve_transition_t

  Update the label on a Mach task port, using the supplied user
  credential label. When a mac_execve_transition or a mac_relabel_cred
  operation causes the label on a user credential to change, the Mach
  task port label also needs to be updated to reflect the change.
  Both labels are already valid (initialized and created).
*/
typedef void mpo_update_port_from_cred_label_t(
	struct label *cred,
	struct label *task
);

/**
  @brief Copy a vnode label
  @param src Source vnode label
  @param dest Destination vnode label

  Copy the vnode label information from src to dest.  On Darwin, this
  is currently only necessary when executing interpreted scripts, but
  will later be used if vnode label externalization cannot be an
  atomic operation.
*/
typedef void mpo_copy_vnode_label_t(
	struct label *src,
	struct label *dest
);

/** 
  @brief Copy a devfs label
  @param src Source devfs label
  @param dest Destination devfs label

  Copy the label information from src to dest.  The devfs file system
  often duplicates (splits) existing device nodes rather than creating
  new ones.
*/
typedef void mpo_copy_devfs_label_t(
	struct label *src,
	struct label *dest
);

/** 
  @brief Copy a mbuf socket label
  @param src Source label
  @param dest Destination label

  Copy the mbuf socket label information in src into dest.
*/
typedef void mpo_copy_mbuf_socket_label_t(
	struct label *src,
	struct label *dest
);

/** 
  @brief Copy a Mach port label
  @param src Source port label
  @param dest Destination port label

  Copy the Mach port label information from src to dest.  This is used
  to copy user-suplied labels into an existing port.
*/
typedef void mpo_copy_port_label_t(
	struct label *src,
	struct label *dest
);

/**
  @brief Externalize a user credential label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be 
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a user
  credential.  An externalized label consists of a text representation
  of the label contents that can be used with user applications.
  Policy-agnostic user space tools will display this externalized
  version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data. 

*/
typedef int mpo_externalize_cred_label_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);

/**
  @brief Externalize a user credential label for auditing
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be 
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a user credential for
  inclusion in an audit record.  An externalized label consists of a text 
  representation of the label contents that will be added to the audit record
  as part of a text token.  Policy-agnostic user space tools will display 
  this externalized version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data. 

*/
typedef int mpo_externalize_cred_audit_label_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);

/**
  @brief Externalize a Login Context label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be 
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a Login Context.
  An externalized label consists of a text representation
  of the label contents that can be used with user applications.
  Policy-agnostic user space tools will display this externalized
  version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data. 

*/
typedef int mpo_externalize_lctx_label_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);

/**
  @brief Externalize a vnode label
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be 
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a vnode.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will display this externalized version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data. 

*/
typedef int mpo_externalize_vnode_label_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);

/**
  @brief Externalize a vnode label for auditing
  @param label Label to be externalized
  @param element_name Name of the label namespace for which labels should be 
  externalized
  @param sb String buffer to be filled with a text representation of the label

  Produce an external representation of the label on a vnode suitable for
  inclusion in an audit record.  An externalized label consists of a text 
  representation of the label contents that will be added to the audit record
  as part of a text token.  Policy-agnostic user space tools will display 
  this externalized version.

  @return 0 on success, return non-zero if an error occurs while
  externalizing the label data. 

*/
typedef int mpo_externalize_vnode_audit_label_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);

/**
  @brief Internalize a user credential label
  @param label Label to be internalized
  @param element_name Name of the label namespace for which the label should
  be internalized
  @param element_data Text data to be internalized

  Produce a user credential label from an external representation.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will forward text version to the kernel for
  processing by individual policy modules.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, Otherwise, return non-zero if an error occurs
  while internalizing the label data. 

*/
typedef int mpo_internalize_cred_label_t(
	struct label *label,
	char *element_name,
	char *element_data
);

/**
  @brief Internalize a Login Context label
  @param label Label to be internalized
  @param element_name Name of the label namespace for which the label should
  be internalized
  @param element_data Text data to be internalized

  Produce a Login Context label from an external representation.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will forward text version to the kernel for
  processing by individual policy modules.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, Otherwise, return non-zero if an error occurs
  while internalizing the label data. 

*/
typedef int mpo_internalize_lctx_label_t(
	struct label *label,
	char *element_name,
	char *element_data
);

/**
  @brief Internalize a vnode label
  @param label Label to be internalized
  @param element_name Name of the label namespace for which the label should
  be internalized
  @param element_data Text data to be internalized

  Produce a vnode label from an external representation.  An
  externalized label consists of a text representation of the label
  contents that can be used with user applications.  Policy-agnostic
  user space tools will forward text version to the kernel for
  processing by individual policy modules.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return 0 on success, Otherwise, return non-zero if an error occurs
  while internalizing the label data. 
*/
typedef int mpo_internalize_vnode_label_t(
	struct label *label,
	char *element_name,
	char *element_data
);
/*@}*/

/* ================================================================ */
/**
  @name Entry Points for Labeling Event Operations

  The following group of entry points are used to manage labels.
*/
/*@{*/
/**
  @brief Associate a vnode with a devfs entry
  @param mp Devfs mount point
  @param fslabel Devfs file system label
  @param de Devfs directory entry
  @param delabel Label associated with de
  @param vp vnode associated with de
  @param vlabel Label associated with vp

  Fill in the label (vlabel) for a newly created devfs vnode.  The
  label is typically derived from the label on the devfs directory
  entry or the label on the filesystem, supplied as parameters.
*/
typedef void mpo_associate_vnode_devfs_t(
	struct mount *mp,
	struct label *fslabel,
	struct devnode *de,
	struct label *delabel,
	struct vnode *vp,
	struct label *vlabel
);

/**
  @brief Associate a label with a vnode
  @param mp File system mount point
  @param fslabel File system label
  @param vp Vnode to label
  @param vlabel Label associated with vp

  Attempt to retrieve label information for the vnode, vp, from the
  file system extended attribute store.  The label should be stored in
  the supplied vlabel parameter.  If a policy cannot retrieve an
  extended attribute, sometimes it is acceptible to fallback to using
  the fslabel.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_associate_vnode_extattr_t(
	struct mount *mp,
	struct label *fslabel,
	struct vnode *vp,
	struct label *vlabel
);

/**
  @brief Associate a label with a vnode
  @param mp File system mount point
  @param fslabel File system label
  @param vp Vnode to label
  @param vlabel Label associated with vp

  On non-multilabel file systems, set the label for a vnode.  The
  label will most likely be based on the file system label.
*/
typedef void mpo_associate_vnode_singlelabel_t(
	struct mount *mp,
	struct label *fslabel,
	struct vnode *vp,
	struct label *vlabel
);

/**
  @brief Create a new devfs device
  @param cred Process credential, if created on behalf of a user process
  @param mp Devfs mount point (currently unused in Darwin)
  @param dev Major and minor numbers of special file 
  @param de "inode" of new device file
  @param label Destination label
  @param fullpath Path relative to mount (e.g. /dev) of new device file

  This entry point labels a new devfs device. The label will likely be based
  on the path to the device, or the major and minor numbers. If the device was
  created on behalf of a user process (for example, /dev/pts/1), then
  'cred' contains the credentials of that process.
  Otherwise, 'cred' is null. The policy should store an appropriate
  label into 'label'.
*/
typedef void mpo_create_devfs_device_t(
	struct ucred *cred,
	struct mount *mp,
	dev_t dev,
	struct devnode *de,
	struct label *label,
	const char *fullpath
);

/**
  @brief Create a new devfs directory
  @param mp Not used in Darwin
  @param dirname Name of new directory
  @param dirnamelen Length of 'dirname'
  @param de "inode" of new directory
  @param label Destination label
  @param fullpath Path relative to mount (e.g. /dev) of new directory

  This entry point labels a new devfs directory. The label will likely be
  based on the path of the new directory. The policy should store an appropriate
  label into 'label'. The devfs root directory is labelled in this way.
*/
typedef void mpo_create_devfs_directory_t(
	struct mount *mp,
	char *dirname,
	int dirnamelen,
	struct devnode *de,
	struct label *label,
	const char *fullpath
);

/**
  @brief Create a new devfs symlink

  @warning XXX Currently not supported in Darwin.
*/
typedef void mpo_create_devfs_symlink_t(
	struct ucred *cred,
	struct mount *mp,
	struct devnode *dd,
	struct label *ddlabel,
	struct devnode *de,
	struct label *delabel,
	const char *fullpath
);

/**
  @brief Create a new vnode, backed by extended attributes
  @param cred User credential for the creating process
  @param mp File system mount point
  @param fslabel File system label
  @param dvp Parent directory vnode
  @param dlabel Parent directory vnode label
  @param vp Newly created vnode
  @param vlabel Label to associate with the new vnode
  @param cnp Component name for vp

  Write out the label for the newly created vnode, most likely storing
  the results in a file system extended attribute.  Most policies will
  derive the new vnode label using information from a combination
  of the subject (user) credential, the file system label, the parent
  directory label, and potentially the path name component.

  @return If the operation succeeds, store the new label in vlabel and
  return 0.  Otherwise, return an appropriate errno value.
*/
typedef int mpo_create_vnode_extattr_t(
	struct ucred *cred,
	struct mount *mp,
	struct label *fslabel,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *vlabel,
	struct componentname *cnp
);

/**
  @brief Create mount labels
  @param cred Subject credential
  @param mp Mount point of file system being mounted
  @param mntlabel Label to associate with the new mount point
  @param fslabel Label for the file system default
  @see mpo_init_mount_label_t
  @see mpo_init_mount_fs_label_t

  Fill out the labels on the mount point being created by the supplied
  user credential.  This call is made when file systems are first mounted.
*/
typedef void mpo_create_mount_t(
	struct ucred *cred,
	struct mount *mp,
	struct label *mntlabel,
	struct label *fslabel
);

/**
  @brief Update a vnode label
  @param cred Subject credential
  @param vp The vnode to relabel
  @param vnodelabel Existing vnode label
  @param label New label to replace existing label
  @see mpo_check_vnode_relabel_t

  The subject identified by the credential has previously requested 
  and was authorized to relabel the vnode; this entry point allows 
  policies to perform the actual relabel operation.  Policies should 
  update vnodelabel using the label stored in the label parameter.
*/
typedef void mpo_relabel_vnode_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *vnodelabel,
	struct label *label
);

/**
  @brief Write a label to a extended attribute
  @param cred Subject credential
  @param vp The vnode for which the label is being stored
  @param vlabel Label associated with vp
  @param intlabel The new label to store

  Store a new label in the extended attribute corresponding to the
  supplied vnode.  The policy has already authorized the operation;
  this call must be implemented in order to perform the actual
  operation.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.

  @warning XXX After examining the extended attribute implementation on
  Apple's future release, this entry point may be changed.
*/
typedef int mpo_setlabel_vnode_extattr_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *vlabel,
	struct label *intlabel
);

/**
  @brief Update a devfs label after relabelling its vnode 
  @param mp Devfs mount point
  @param de Affected devfs directory entry
  @param delabel Label of devfs directory entry
  @param vp Vnode associated with de
  @param vnodelabel New label of vnode

  Update a devfs label when its vnode is manually relabelled,
  for example with setfmac(1). Typically, this will simply copy
  the vnode label into the devfs label.
*/
typedef void mpo_update_devfsdirent_t(
	struct mount *mp,
	struct devnode *de,
	struct label *delabel,
	struct vnode *vp,
	struct label *vnodelabel
);

/* 
 * Labeling event operations: network objects.  
 */

/**
  @brief Copy a socket label
  @param src Source label
  @param dest Destination label

  Copy the socket label information in src into dest.
*/
typedef void mpo_copy_socket_label_t(
	struct label *src,
	struct label *dest
);

/**
  @brief Assign a label to a new socket 
  @param cred Credential of the owning process
  @param so The socket being labeled
  @param solabel The label
  @warning cred can be NULL

  Set the label on a newly created socket from the passed subject
  credential.  This call is made when a socket is created.  The
  credentials may be null if the socket is being created by the
  kernel.
*/
typedef void mpo_create_socket_t(
	struct ucred *cred,
	struct socket *so,
	struct label *solabel
);

/**
  @brief Label a socket
  @param oldsock Listening socket 
  @param oldlabel Policy label associated with oldsock
  @param newsock New socket 
  @param newlabel Policy label associated with newsock

  A new socket is created when a connection is accept(2)ed.  This
  function labels the new socket based on the existing listen(2)ing
  socket.
*/
typedef void mpo_create_socket_from_socket_t(
	struct socket *oldsock,
	struct label *oldlabel,
	struct socket *newsock,
	struct label *newlabel
);

/**
  @brief Assign a label to a new mbuf 
  @param so Socket to label 
  @param so_label Policy label for so
  @param m Object; mbuf
  @param m_label Policy label to fill in for m 

  An mbuf structure is used to store network traffic in transit.  
  When an application sends data to a socket or a pipe, it is wrapped 
  in an mbuf first.  This function sets the label on a newly created mbuf header 
  based on the socket sending the data.  The contents of the label should be 
  suitable for performing an access check on the receiving side of the 
  communication.
*/
typedef void mpo_create_mbuf_from_socket_t(
	struct socket *so,
	struct label *so_label,
	struct mbuf *m,
	struct label *m_label
);

/**
  @brief Externalize a socket label 
  @param label Label to be externalized 
  @param element_name Name of the label namespace for which labels should be 
  externalized
  @param sb String buffer to be filled with a text representation of label

  Produce an externalized socket label based on the label structure passed. 
  An externalized label consists of a text representation of the label 
  contents that can be used with userland applications and read by the 
  user.  If element_name does not match a namespace managed by the policy, 
  simply return 0. Only return nonzero if an error occurs while externalizing 
  the label data.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_externalize_socket_label_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);

/**
  @brief Externalize a socket peer label 
  @param label Label to be externalized 
  @param element_name Name of the label namespace for which labels should be 
  externalized
  @param sb String buffer to be filled with a text representation of label

  Produce an externalized socket peer label based on the label structure 
  passed. An externalized label consists of a text representation of the 
  label contents that can be used with userland applications and read by the 
  user.  If element_name does not match a namespace managed by the policy,
  simply return 0. Only return nonzero if an error occurs while externalizing 
  the label data.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_externalize_socket_peer_label_t(
	struct label *label,
	char *element_name,
	struct sbuf *sb
);

/**
  @brief Internalize a socket label 
  @param label Label to be filled in 
  @param element_name Name of the label namespace for which the label should 
  be internalized 
  @param element_data Text data to be internalized

  Produce an internal socket label structure based on externalized label 
  data in text format.

  The policy's internalize entry points will be called only if the
  policy has registered interest in the label namespace.

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_internalize_socket_label_t(
	struct label *label,
	char *element_name,
	char *element_data
);

/**
  @brief Relabel socket
  @param cred Subject credential
  @param so Object; socket
  @param so_label Current label of the socket
  @param newlabel The label to be assigned to so

  The subject identified by the credential has previously requested
  and was authorized to relabel the socket; this entry point allows
  policies to perform the actual label update operation.

  @warning XXX This entry point will likely change in future versions.
*/
typedef void mpo_relabel_socket_t(
	struct ucred *cred,
	struct socket *so,
	struct label *so_label,
	struct label *newlabel
);

/**
  @brief Set the peer label on a socket from socket
  @param source Local socket
  @param sourcelabel Policy label for source 
  @param target Peer socket
  @param targetlabel Policy label to fill in for target

  Set the peer label on a stream UNIX domain socket from the passed 
  remote socket endpoint. This call will be made when the socket pair 
  is connected, and will be made for both endpoints.
  
  Note that this call is only made on connection; it is currently not updated
  during communication.
*/
typedef void mpo_set_socket_peer_from_socket_t(
	struct socket *source,
	struct label *sourcelabel,
	struct socket *target,
	struct label *targetlabel
);

/**
  @brief Set the peer label on a socket from mbuf
  @param m Mbuf chain received on socket so
  @param m_label Label for m 
  @param so Current label for the socket
  @param so_label Policy label to be filled out for the socket

  Set the peer label of a socket based on the label of the sender of the 
  mbuf.  
  
  This is called for every TCP/IP packet received.  The first call for a given
  socket operates on a newly initialized label, and subsequent calls operate
  on existing label data.
  
  @warning Because this can affect performance significantly, it has
  different sematics than other 'set' operations.  Typically, 'set' operations
  operate on newly initialzed labels and policies do not need to worry about
  clobbering existing values.  In this case, it is too inefficient to 
  initialize and destroy a label every time data is received for the socket.
  Instead, it is up to the policies to determine how to replace the label data. 
  Most policies should be able to replace the data inline.
*/
typedef void mpo_set_socket_peer_from_mbuf_t(
	struct mbuf *m,
	struct label *m_label,
	struct socket *so,
	struct label *so_label
);

/**
  @brief Assign a label to a new Mach port
  @param it Task label of issuer
  @param st Task label of target
  @param portlabel Label for the new port

  Assign a label to a new port. The policy can base this label on 
  the label of the calling task, as well as the label of the target task.
  The target task is the one which recieves the first right for this port.
  Both task labels and the port are locked.
*/
typedef void mpo_create_port_t(
	struct label *it,
	struct label *st,
	struct label *portlabel
);

/**
  @brief Assign a label to a new Mach port created by the kernel
  @param portlabel Label for the new port
  @param isreply True if the port is for a reply message from the kernel

  Assign a label to a new port created by the kernel. If the port is being 
  used to reply to a message, isreply is 1 (0 otherwise). The port is locked.
*/
typedef void mpo_create_kernel_port_t(
	struct label *portlabel,
	int isreply
);

/**
  @brief Assign a label to a Mach port connected to a kernel object
  @param portlabel Label for the port
  @param kotype Type of kernel object

  Label a kernel port based on the type of object behind it. The
  kotype parameter is one of the IKOT constants in
  <kern/ipc_kobject.h>. The port already has a valid label from either
  mpo_create_kernel_port, or because it is a task port and has a label
  derived from the process and task labels. The port is locked.
*/
typedef void mpo_update_port_kobject_t(
	struct label *portlabel,
	int kotype
);

/**
  @brief Create a POSIX semaphore label
  @param cred Subject credential
  @param ps Pointer to semaphore information structure 
  @param semlabel Label to associate with the new semaphore
  @param name String name of the semaphore 
  
  Label a new POSIX semaphore.  The label was previously
  initialized and associated with the semaphore.  At this time, an
  appropriate initial label value should be assigned to the object and
  stored in semalabel.
*/
typedef void mpo_create_posix_sem_t(
	struct ucred *cred,
	struct pseminfo *ps,
	struct label *semlabel,
	const char *name);

/**
  @brief Create a POSIX shared memory region label
  @param cred Subject credential
  @param ps Pointer to shared memory information structure 
  @param shmlabel Label to associate with the new shared memory region
  @param name String name of the shared memory region 
  
  Label a new POSIX shared memory region.  The label was previously
  initialized and associated with the shared memory region.  At this
  time, an appropriate initial label value should be assigned to the
  object and stored in shmlabel.
*/
typedef void mpo_create_posix_shm_t(
	struct ucred *cred,
	struct pshminfo *ps,
	struct label *shmlabel,
	const char *name
);

/**
  @brief Create a System V semaphore label
  @param cred Subject credential
  @param semakptr The semaphore being created
  @param semalabel Label to associate with the new semaphore
  
  Label a new System V semaphore.  The label was previously
  initialized and associated with the semaphore.  At this time, an
  appropriate initial label value should be assigned to the object and
  stored in semalabel.
*/
typedef void mpo_create_sysv_sem_t(
	struct ucred *cred,
	struct semid_kernel *semakptr,
	struct label *semalabel
);

/**
  @brief Create a System V shared memory region label
  @param cred Subject credential
  @param shmsegptr The shared memory region being created
  @param shmlabel Label to associate with the new shared memory region
  
  Label a new System V shared memory region.  The label was previously
  initialized and associated with the shared memory region.  At this
  time, an appropriate initial label value should be assigned to the
  object and stored in shmlabel.
*/
typedef void mpo_create_sysv_shm_t(
	struct ucred *cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmlabel
);

/**
  @brief Create a credential label
  @param parent_cred Parent credential
  @param child_cred Child credential

  Set the label of a newly created credential, most likely using the
  information in the supplied parent credential.

  @warning This call is made when crcopy or crdup is invoked on a
  newly created struct ucred, and should not be confused with a
  process fork or creation event.
*/
typedef void mpo_create_cred_t(
	struct ucred *parent_cred,
	struct ucred *child_cred
);

/**
  @brief Assign a label to a new (userspace) Mach task
  @param parent Parent task
  @param child New (child) task
  @param parentlabel Label of parent task
  @param childlabel Label for new task
  @param childportlabel Label for new task's task port

  Assign labels to a new task and its task port. Both the task and
  task port labels should be specified. Both new labels are initialized.
  If the task will have an associated BSD process, that information will be
  made available by the copy_cred_to_task and copy_cred_to_port entry points.
*/
typedef void mpo_create_task_t(
	struct task *parent,
	struct task *child,
	struct label *parentlabel,
	struct label *childlabel,
	struct label *childportlabel
);

/**
  @brief Assign a label to a new kernelspace Mach task
  @param kproc New task
  @param tasklabel Label for new task
  @param portlabel Label for new task port
  @see mpo_create_proc0_t

  Assign labels to a new kernel task and its task port. Both the task and
  task port labels should be specified. Both new labels are initialized.
  If there is an associated BSD process structure, it will be labelled
  with calls to mpo_create_proc0.
*/
typedef void mpo_create_kernel_task_t(
	struct task *kproc,
	struct label *tasklabel,
	struct label *portlabel
);

/**
  @brief Update credential at exec time
  @param old Existing subject credential
  @param new New subject credential to be labeled
  @param vp File being executed
  @param vnodelabel Label corresponding to vp
  @param scriptvnodelabel Script vnode label
  @param execlabel Userspace provided execution label
  @see mac_execve
  @see mpo_execve_will_transition_t
  @see mpo_check_vnode_exec_t
  
  Update the label of a newly created credential (new) from the
  existing subject credential (old).  This call occurs when a process
  executes the passed vnode and one of the loaded policy modules has
  returned success from the mpo_execve_will_transition entry point.
  Access has already been checked via the mpo_check_vnode_exec entry
  point, this entry point is only used to update any policy state.

  The supplied vnode and vnodelabel correspond with the file actually
  being executed; in the case that the file is interpreted (for
  example, a script), the label of the original exec-time vnode has
  been preserved in scriptvnodelabel.

  The final label, execlabel, corresponds to a label supplied by a
  user space application through the use of the mac_execve system call.

  The vnode lock is held during this operation.  No changes should be
  made to the old credential structure.
*/
typedef void mpo_execve_transition_t(
	struct ucred *old,
	struct ucred *new,
	struct vnode *vp,
	struct label *vnodelabel,
	struct label *scriptvnodelabel,
	struct label *execlabel
);

/**
  @brief Indicate desire to change the process label at exec time
  @param old Existing subject credential
  @param vp File being executed
  @param vnodelabel Label corresponding to vp
  @param scriptvnodelabel Script vnode label
  @param execlabel Userspace provided execution label
  @param proc Object process
  @see mac_execve
  @see mpo_execve_transition_t
  @see mpo_check_vnode_exec_t
  
  Indicate whether this policy intends to update the label of a newly
  created credential from the existing subject credential (old).  This
  call occurs when a process executes the passed vnode.  If a policy
  returns success from this entry point, the mpo_execve_transition
  entry point will later be called with the same parameters.  Access
  has already been checked via the mpo_check_vnode_exec entry point,
  this entry point is necessary to preserve kernel locking constraints
  during program execution.

  The supplied vnode and vnodelabel correspond with the file actually
  being executed; in the case that the file is interpreted (for
  example, a script), the label of the original exec-time vnode has
  been preserved in scriptvnodelabel.

  The final label, execlabel, corresponds to a label supplied by a
  user space application through the use of the mac_execve system call.

  The vnode lock is held during this operation.  No changes should be
  made to the old credential structure.

  @warning Even if a policy returns 0, it should behave correctly in
  the presence of an invocation of mpo_execve_transition, as that call
  may happen as a result of another policy requesting a transition.

  @return Non-zero if a transition is required, 0 otherwise.
*/
typedef int mpo_execve_will_transition_t(
	struct ucred *old,
	struct vnode *vp,
	struct label *vnodelabel,
	struct label *scriptvnodelabel,
	struct label *execlabel,
	struct proc *proc
);

/**
  @brief Create the first process
  @param cred Subject credential to be labeled

  Create the subject credential of process 0, the parent of all BSD
  kernel processes.  Policies should update the label in the
  previously initialized credential structure.
*/
typedef void mpo_create_proc0_t(
	struct ucred *cred
);

/**
  @brief Create the first process
  @param cred Subject credential to be labeled

  Create the subject credential of process 1, the parent of all BSD
  user processes.  Policies should update the label in the previously
  initialized credential structure.  This is the 'init' process.
*/
typedef void mpo_create_proc1_t(
	struct ucred *cred
);

/**
  @brief Update a credential label
  @param cred The existing credential
  @param newlabel A new label to apply to the credential
  @see mpo_check_cred_relabel_t
  @see mac_set_proc

  Update the label on a user credential, using the supplied new label.
  This is called as a result of a process relabel operation.  Access
  control was already confirmed by mpo_check_cred_relabel.
*/
typedef void mpo_relabel_cred_t(
	struct ucred *cred,
	struct label *newlabel
);

/**
  @brief Request label for new (userspace) object
  @param subj Subject label
  @param obj Parent or existing object label
  @param serv Name of service
  @param out Computed label

  Ask the loaded policies to compute a label based on the two input labels
  and the service name. There is currently no standard for the service name,
  or even what the input labels represent (Subject and parent object are only
  a suggestion). If successful, the computed label is stored in out. All labels
  must be port (or task) labels. The userspace interfaces to this entry point
  allow label handles (ports) to be provided.

  @return 0 on success, or an errno value for failure.
*/

typedef int mpo_request_object_label_t(
	struct label *subj,
	struct label *obj,
	const char *serv,
	struct label *out
);
/*@}*/

/**
  @brief A process has created a login context
  @param p Subject
  @param l Login Context
*/
typedef void mpo_proc_create_lctx_t(
	struct proc *p,
	struct lctx *l
);

/**
  @brief A process has joined a login context
  @param p Subject
  @param l Login Context
*/
typedef void mpo_proc_join_lctx_t(
	struct proc *p,
	struct lctx *l
);

/**
  @brief A process has left a login context
  @param p Subject
  @param l Login Context
*/
typedef void mpo_proc_leave_lctx_t(
	struct proc *p,
	struct lctx *l
);

/**
  @brief Update a Login Context label
  @param l
  @param newlabel A new label to apply to the Login Context
  @see mpo_check_lctx_relabel_t
  @see mac_set_lcid
  @see mac_set_lctx
*/
typedef void mpo_relabel_lctx_t(
	struct lctx *l,
	struct label *newlabel
);
/*@}*/

/**
  @name Entry Points for Access Control
*/
/*@{*/

/**
  @brief Generic access control check
  @param subj Caller-provided subject label
  @param obj Caller-provided object label
  @param serv Service or object class name
  @param perm Permission, or method, within the specified service

  This function provides a general way for a user process to query
  an arbitrary access control decision from the system's security policies.
  Currently, there are no standards for the format of the service and
  permission names. Labels may be either cred or port labels; the policy
  must accept either. The userspace interfaces to this entry point allow
  label strings or label handles (ports) to be provided.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_service_access_t(
	struct label *subj,
	struct label *obj,
	const char *serv,
	const char *perm
);

/**
  @brief Access control check for relabelling processes 
  @param cred Subject credential
  @param newlabel New label to apply to the user credential
  @see mpo_relabel_cred_t
  @see mac_set_proc

  Determine whether the subject identified by the credential can relabel 
  itself to the supplied new label (newlabel).  This access control check 
  is called when the mac_set_proc system call is invoked.  A user space
  application will supply a new value, the value will be internalized
  and provided in newlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_cred_relabel_t(
	struct ucred *cred,
	struct label *newlabel
);

/**
  @brief Access control check for relabelling Login Context
  @param l Subject credential
  @param newlabel New label to apply to the Login Context
  @see mpo_relabel_lctx_t
  @see mac_set_lcid
  @see mac_set_lctx

  Determine whether the subject identified by the credential can relabel 
  itself to the supplied new label (newlabel).  This access control check 
  is called when the mac_set_lctx/lcid system call is invoked.  A user space
  application will supply a new value, the value will be internalized
  and provided in newlabel.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_lctx_relabel_t(
	struct lctx *l,
	struct label *newlabel
);

/**
  @brief Access control check for relabelling ports
  @param task Subject's task label
  @param oldlabel Original label of port
  @param newlabel New label for port

  Access control check for relabelling ports. The policy should 
  indicate whether the subject is permitted to change the label
  of a port from oldlabel to newlabel. The port is locked, but
  the subject's task label is not locked.

  @warning XXX In future releases, the task label lock will likely
  also be held.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_port_relabel_t(
	struct label *task,
	struct label *oldlabel,
	struct label *newlabel
);

/**
  @brief Access control check for sending Mach messsages
  @param task Label of the sender task
  @param port Label of the destination port

  Access control check for sending messages. The task label and the
  port are locked. 

  @warning This entry point can be invoked from many places inside the
  kernel, with arbitrary other locks held. The implementation of this
  entry point must not cause page faults, as those are handled by mach
  messages.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_port_send_t(
	struct label *task,
	struct label *port
);

/**
  @brief Access control check for producing a send right from a receive right
  @param task Label of the sender task
  @param port Label of the affected port

  Access control check for obtaining send rights from receive rights. The new
  send right may be destined for the calling task, or a different task. 
  In either case the mpo_check_port_hold_send entry point
  handles the receiving task. check_port_make_send may be called as part of 
  a group of policy invocations when messages with port rights are sent.
  All access control checks made for a particular message must be successful
  for the message to be sent.

  The task label and the port are locked. Sleeping is permitted.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_port_make_send_t(
	struct label *task,
	struct label *port
);

/**
  @brief Access control check for copying a send right to another task
  @param task Label of the sender task
  @param port Label of the affected port

  Access control check for copying send rights to the port from the
  specified task. A complementary entry point, mpo_check_port_hold_send,
  handles the receiving task. check_port_copy_send is called as part of 
  a group of policy invocations when messages with port rights are sent.
  All access control checks made for a particular message must be successful
  for the message to be sent.

  The task label and the port are locked. Sleeping is permitted.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_port_copy_send_t(
	struct label *task,
	struct label *port
);

/**
  @brief Access control check for transferring a send right
  @param task Label of the sender task
  @param port Label of the affected port

  Access control check for transferring a send right from one task to the
  task listening to the specified port. A complementary entry point,
  mpo_check_port_hold_send, handles the receiving task.
  check_port_move_send is called as part of a group of policy invocations
  when messages with port rights are sent.  All access control checks made
  for a particular message must be successful for the message to be sent.

  The task label and the port are locked. Sleeping is permitted.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_port_move_send_t(
	struct label *task,
	struct label *port
);

/**
  @brief Access control check for obtaining a send right
  @param task Label of the receiving task
  @param port Label of the affected port

  Access control check for a task obtaining send rights to a port. Usually,
  these are port rights that were part of a message sent by another userspace
  task. check_port_hold_send is called as part of a group of policy
  invocations when messages with port rights are received. All of these access
  control checks must succeed in order to receive the message.

  The task label and the port are locked. Sleeping is permitted.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_port_hold_send_t(
	struct label *task,
	struct label *port
);

/**
  @brief Access control check for receiving Mach messsages
  @param task Label of the receiving task
  @param sender Label of the sending task

  Access control check for receiving messages. The two labels are locked. 

  @warning This entry point can be invoked from many places inside the
  kernel, with arbitrary other locks held. The implementation of this
  entry point must not cause page faults, as those are handled by mach
  messages.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_port_receive_t(
	struct label *task,
	struct label *sender
);

/**
  @brief Access control check for obtaining a receive right
  @param task Label of the receiving task
  @param port Label of the affected port

  Access control check for a task obtaining receive rights to a
  port. Usually, these are port rights that were obtained with a call
  to mach_port_allocate.  This entry point is called as part of a
  group of policy invocations when messages with port rights are
  received.  All of these access control checks must succeed in order
  to receive the message.

  The task label and the port are locked. Sleeping is permitted.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_port_hold_receive_t(
	struct label *task,
	struct label *port
);

/**
  @brief Access control check for transferring a receive right
  @param task Label of the sender task
  @param port Label of the affected port

  Access control check for transferring the receive right to a port out
  of the specified task. A complementary entry point,
  mpo_check_port_hold_receive, handles the receiving task.
  check_port_move_receive is called as part of 
  a group of policy invocations when messages with port rights are sent.
  All access control checks made for a particular message must be successful
  for the message to be sent.

  The task label and the port are locked. Sleeping is permitted.

  @return Return 0 if access is granted, non-zero otherwise.
*/
typedef int mpo_check_port_move_receive_t(
	struct label *task,
	struct label *port
);


/**
  @brief Access control check for visibility of other subjects 
  @param u1 Subject credential
  @param u2 Object credential

  Determine whether the subject identified by the credential u1 can 
  "see" other subjects with the passed subject credential u2. This call 
  may be made in a number of situations, including inter-process status 
  sysctls used by ps, and in procfs lookups.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch, 
  EPERM for lack of privilege, or ESRCH to hide visibility. 
*/
typedef int mpo_check_cred_visible_t(
	struct ucred *u1,
	struct ucred *u2
);

/**
  @brief Access control check for fcntl 
  @param cred Subject credential
  @param fd File descriptor 
  @param cmd Control operation to be performed; see fcntl(2)
  @param arg fcnt arguments; see fcntl(2)

  Determine whether the subject identified by the credential can perform 
  the file control operation indicated by cmd.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_fcntl_t(
	struct ucred *cred,
	struct file *fd,
	int cmd,
	int arg
);

/**
  @brief Access control check for mac_get_fd 
  @param cred Subject credential
  @param fd File descriptor 
  @param elements Element buffer 
  @param len Length of buffer 

  Determine whether the subject identified by the credential should be allowed
  to get an externalized version of the label on the object indicated by fd.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_get_fd_t(
	struct ucred *cred,
	struct file *fd,
	char *elements,
	int len
);

/**
  @brief Access control check for ioctl 
  @param cred Subject credential
  @param fd File descriptor 
  @param com Device-dependent request code; see ioctl(2)
  @param data Request-specific information; see ioctl(2) 

  Determine whether the subject identified by the credential can perform 
  the ioctl operation indicated by com.  
  
  This entry point currently isn't used, as ioctl() is a far-reaching, 
  monolithic function.  This check would also have to be far-reaching and
  monolithic, and that is not good from a security perspective.  Sometime in
  the future we plan to break this function into several similar entry points 
  based on object type.

  @warning Since ioctl data is opaque from the standpoint of the MAC
  framework, and since ioctls can affect many aspects of system
  operation, policies must exercise extreme care when implementing
  access control checks.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_ioctl_t(
	struct ucred *cred,
	struct file *fd,
	int com,
	void *data
);

/**
  @brief Compute access control check for a Mach message-based service
  @param task Sender's task label
  @param port Destination port label
  @param msgid Message id 

  Access control computation for message-based services. This entry point
  computes permission to the service requested by the specified port and message
  id, for example a single MiG server routine, and is unrelated to the access
  check for sending messages to ports (but that check must succeed for the
  message to be sent to the destination). The result of this access computation
  is stored in the message trailer field msgh_ad (only if requested by the
  recipient); it does not actually inhibit the message from being sent or
  received.

  @return 0 for access granted, nonzero for access denied.
*/

typedef int mpo_check_ipc_method_t(
	struct label *task,
	struct label *port,
	int msgid
);

/**
  @brief Access control check for POSIX semaphore create 
  @param cred Subject credential
  @param name String name of the semaphore 

  Determine whether the subject identified by the credential can create 
  a POSIX semaphore specified by name. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_sem_create_t(
	struct ucred *cred,
	const char *name
);

/**
  @brief Access control check for POSIX semaphore open 
  @param cred Subject credential
  @param ps Pointer to semaphore information structure 
  @param semlabel Label associated with the semaphore

  Determine whether the subject identified by the credential can open 
  the named POSIX semaphore with label semlabel. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_sem_open_t(
	struct ucred *cred,
	struct pseminfo *ps,
	struct label *semlabel
);

/**
  @brief Access control check for POSIX semaphore post 
  @param cred Subject credential
  @param ps Pointer to semaphore information structure 
  @param semlabel Label associated with the semaphore

  Determine whether the subject identified by the credential can unlock 
  the named POSIX semaphore with label semlabel. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_sem_post_t(
	struct ucred *cred,
	struct pseminfo *ps,
	struct label *semlabel
);

/**
  @brief Access control check for POSIX semaphore unlink 
  @param cred Subject credential
  @param ps Pointer to semaphore information structure 
  @param semlabel Label associated with the semaphore
  @param name String name of the semaphore 

  Determine whether the subject identified by the credential can remove 
  the named POSIX semaphore with label semlabel. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_sem_unlink_t(
	struct ucred *cred,
	struct pseminfo *ps,
	struct label *semlabel,
	const char *name
);

/**
  @brief Access control check for POSIX semaphore wait 
  @param cred Subject credential
  @param ps Pointer to semaphore information structure 
  @param semlabel Label associated with the semaphore

  Determine whether the subject identified by the credential can lock 
  the named POSIX semaphore with label semlabel. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_sem_wait_t(
	struct ucred *cred, 
	struct pseminfo *ps,
	struct label *semlabel
);

/**
  @brief Access control check for POSIX shared memory region create 
  @param cred Subject credential
  @param name String name of the shared memory region  

  Determine whether the subject identified by the credential can create 
  the POSIX shared memory region referenced by name. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_shm_create_t(
	struct ucred *cred,
	const char *name
);

/**
  @brief Access control check for POSIX shared memory region open 
  @param cred Subject credential
  @param ps Pointer to shared memory information structure 
  @param shmlabel Label associated with the shared memory region

  Determine whether the subject identified by the credential can open 
  the POSIX shared memory region. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_shm_open_t(
	struct ucred *cred,
	struct pshminfo *ps,
	struct label *shmlabel
);

/**
  @brief Access control check for mapping POSIX shared memory 
  @param cred Subject credential
  @param ps Pointer to shared memory information structure 
  @param shmlabel Label associated with the shared memory region
  @param prot mmap protections; see mmap(2)
  @param flags shmat flags; see shmat(2) 

  Determine whether the subject identified by the credential can map 
  the POSIX shared memory segment associated with shmlabel. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_shm_mmap_t(
	struct ucred *cred,
	struct pshminfo *ps,
	struct label *shmlabel,
	int prot, 
	int flags
);

/**
  @brief Access control check for POSIX shared memory stat
  @param cred Subject credential
  @param ps Pointer to shared memory information structure 
  @param shmlabel Label associated with the shared memory region

  Determine whether the subject identified by the credential can obtain 
  status for the POSIX shared memory segment associated with shmlabel. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_shm_stat_t(
	struct ucred *cred,
	struct pshminfo *ps,
	struct label *shmlabel
);

/**
  @brief Access control check for POSIX shared memory truncate
  @param cred Subject credential
  @param ps Pointer to shared memory information structure 
  @param shmlabel Label associated with the shared memory region
  @param len Length to truncate or extend shared memory segment 

  Determine whether the subject identified by the credential can truncate
  or extend (to len) the POSIX shared memory segment associated with shmlabel. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_shm_truncate_t(
	struct ucred *cred,
	struct pshminfo *ps,
	struct label *shmlabel,
	size_t len
);

/**
  @brief Access control check for POSIX shared memory unlink
  @param cred Subject credential
  @param ps Pointer to shared memory information structure 
  @param shmlabel Label associated with the shared memory region
  @param name String name of the shared memory region  

  Determine whether the subject identified by the credential can delete
  the POSIX shared memory segment associated with shmlabel. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_posix_shm_unlink_t(
	struct ucred *cred,
	struct pshminfo *ps,
	struct label *shmlabel,
	const char *name
);

/**
  @brief Access control check for System V semaphore control operation
  @param cred Subject credential
  @param semakptr Pointer to semaphore identifier
  @param semaklabel Label associated with semaphore 
  @param cmd Control operation to be performed; see semctl(2)

  Determine whether the subject identified by the credential can perform 
  the operation indicated by cmd on the System V semaphore semakptr. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_sysv_semctl_t(
	struct ucred *cred,
	struct semid_kernel *semakptr,
	struct label *semaklabel,
	int cmd
);

/**
  @brief Access control check for obtaining a System V semaphore
  @param cred Subject credential
  @param semakptr Pointer to semaphore identifier
  @param semaklabel Label to associate with the semaphore 

  Determine whether the subject identified by the credential can 
  obtain a System V semaphore.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_sysv_semget_t(
	struct ucred *cred,
	struct semid_kernel *semakptr,
	struct label *semaklabel
);

/**
  @brief Access control check for System V semaphore operations
  @param cred Subject credential
  @param semakptr Pointer to semaphore identifier
  @param semaklabel Label associated with the semaphore 
  @param accesstype Flags to indicate access (read and/or write)

  Determine whether the subject identified by the credential can
  perform the operations on the System V semaphore indicated by
  semakptr.  The accesstype flags hold the maximum set of permissions
  from the sem_op array passed to the semop system call.  It may
  contain SEM_R for read-only operations or SEM_A for read/write
  operations.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_sysv_semop_t(
	struct ucred *cred,
	struct semid_kernel *semakptr,
	struct label *semaklabel,
	size_t accesstype
);

/**
  @brief Access control check for mapping System V shared memory 
  @param cred Subject credential
  @param shmsegptr Pointer to shared memory segment identifier
  @param shmseglabel Label associated with the shared memory segment 
  @param shmflg shmat flags; see shmat(2) 

  Determine whether the subject identified by the credential can map 
  the System V shared memory segment associated with shmsegptr. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_sysv_shmat_t(
	struct ucred *cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmseglabel,
	int shmflg
);

/**
  @brief Access control check for System V shared memory control operation
  @param cred Subject credential
  @param shmsegptr Pointer to shared memory segment identifier
  @param shmseglabel Label associated with the shared memory segment 
  @param cmd Control operation to be performed; see shmctl(2)

  Determine whether the subject identified by the credential can perform 
  the operation indicated by cmd on the System V shared memory segment 
  shmsegptr. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_sysv_shmctl_t(
	struct ucred *cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmseglabel,
	int cmd
);

/**
  @brief Access control check for unmapping System V shared memory 
  @param cred Subject credential
  @param shmsegptr Pointer to shared memory segment identifier
  @param shmseglabel Label associated with the shared memory segment 

  Determine whether the subject identified by the credential can unmap 
  the System V shared memory segment associated with shmsegptr. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_sysv_shmdt_t(
	struct ucred *cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmseglabel
);

/**
  @brief Access control check obtaining System V shared memory identifier
  @param cred Subject credential
  @param shmsegptr Pointer to shared memory segment identifier
  @param shmseglabel Label associated with the shared memory segment 
  @param shmflg shmget flags; see shmget(2) 

  Determine whether the subject identified by the credential can get 
  the System V shared memory segment address. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_sysv_shmget_t(
	struct ucred *cred,
	struct shmid_kernel *shmsegptr,
	struct label *shmseglabel,
	int shmflg
);

/**
  @brief Access control check for file system statistics 
  @param cred Subject credential
  @param mp Object file system mount
  @param mntlabel Policy label for mp

  Determine whether the subject identified by the credential can see 
  the results of a statfs performed on the file system. This call may 
  be made in a number of situations, including during invocations of 
  statfs(2) and related calls, as well as to determine what file systems 
  to exclude from listings of file systems, such as when getfsstat(2) 
  is invoked.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch 
  or EPERM for lack of privilege. 
*/
typedef int mpo_check_mount_stat_t(
	struct ucred *cred,
	struct mount *mp,
	struct label *mntlabel
);

/**
  @brief Access control check for debugging process 
  @param cred Subject credential
  @param proc Object process

  Determine whether the subject identified by the credential can debug 
  the passed process. This call may be made in a number of situations, 
  including use of the ptrace(2) and ktrace(2) APIs, as well as for some 
  types of procfs operations.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to hide visibility of the target. 
*/
typedef int mpo_check_proc_debug_t(
	struct ucred *cred,
	struct proc *proc
);

/**
  @brief Access control check for changing scheduling parameters 
  @param cred Subject credential
  @param proc Object process

  Determine whether the subject identified by the credential can change 
  the scheduling parameters of the passed process. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to limit visibility.
*/
typedef int mpo_check_proc_sched_t(
	struct ucred *cred,
	struct proc *proc
);

/**
  @brief Access control check for delivering signal 
  @param cred Subject credential
  @param proc Object process
  @param signum Signal number; see kill(2)

  Determine whether the subject identified by the credential can deliver 
  the passed signal to the passed process. 

  @warning Programs typically expect to be able to send and receive
  signals as part or their normal process lifecycle; caution should be
  exercised when implementing access controls over signal events.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch,
  EPERM for lack of privilege, or ESRCH to limit visibility.
*/
typedef int mpo_check_proc_signal_t(
	struct ucred *cred,
	struct proc *proc,
	int signum
);

/**
  @brief Access control check for wait 
  @param cred Subject credential
  @param proc Object process

  Determine whether the subject identified by the credential can wait 
  for process termination. 

  @warning Caution should be exercised when implementing access
  controls for wait, since programs often wait for child processes to
  exit.  Failure to be notified of a child process terminating may
  cause the parent process to hang, or may produce zombie processes.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_proc_wait_t(
	struct ucred *cred,
	struct proc *proc
);

/**
  @brief Access control check for mac_set_fd 
  @param cred Subject credential
  @param fd File descriptor 
  @param elements Elements buffer
  @param len Length of elements buffer

  Determine whether the subject identified by the credential can
  perform the mac_set_fd operation.  The mac_set_fd operation is used
  to associate a MAC label with a file.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_set_fd_t(
	struct ucred *cred,
	struct file *fd,
	char *elements,
	int len
);

/**
  @brief Access control check for socket accept
  @param cred Subject credential
  @param socket Object socket
  @param socklabel Policy label for socket
  @param addr assigned to the socket

  Determine whether the subject identified by the credential can accept()
  a new connection on the socket from the host specified by addr.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_accept_t(
	struct ucred *cred,
	struct socket *socket,
	struct label *socklabel, 
	struct sockaddr *addr
);

/**
  @brief Access control check for socket bind
  @param cred Subject credential
  @param socket Object socket
  @param socklabel Policy label for socket
  @param addr Name to assign to the socket

  Determine whether the subject identified by the credential can bind()
  the name (addr) to the socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_bind_t(
	struct ucred *cred,
	struct socket *socket,
	struct label *socklabel, 
	struct sockaddr *addr
);

/**
  @brief Access control check for socket connect
  @param cred Subject credential
  @param socket Object socket
  @param socklabel Policy label for socket
  @param addr Name to assign to the socket

  Determine whether the subject identified by the credential can
  connect() the passed socket to the remote host specified by addr.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_connect_t(
	struct ucred *cred,
	struct socket *socket,
	struct label *socklabel,
	struct sockaddr *addr
);

/**
  @brief Access control check for delivering data to a user's receieve queue
  @param so The socket data is being delivered to
  @param so_label The label of so
  @param m The mbuf whose data will be deposited into the receive queue
  @param m_label The label of the sender of the data.

  A socket has a queue for receiving incoming data.  When a packet arrives
  on the wire, it eventually gets deposited into this queue, which the
  owner of the socket drains when they read from the socket's file descriptor.
  
  This function determines whether the socket can receive data from 
  the sender specified by m_label.

  @warning There is an outstanding design issue surrounding the placement
  of this function.  The check must be placed either before or after the
  TCP sequence and ACK counters are updated.  Placing the check before
  the counters are updated causes the incoming packet to be resent by
  the remote if the check rejects it.  Placing the check after the counters 
  are updated results in a completely silent drop.  As far as each TCP stack
  is concerned the packet was received, however, the data will not be in the 
  socket's receive queue.  Another consideration is that the current design
  requires using the "failed label" occasionally.  In that case, on rejection, 
  we want the remote TCP to resend the data.  Because of this, we chose to 
  place this check before the counters are updated, so rejected packets will be 
  resent by the remote host.  
  
  If a policy keeps rejecting the same packet, eventually the connection will
  be dropped.  Policies have several options if this design causes problems.
  For example, one options is to sanitize the mbuf such that it is acceptable,
  then accept it.  That may require negotiation between policies as the 
  Framework will not know to re-check the packet.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_deliver_t(
	struct socket *so,
	struct label *so_label,
	struct mbuf *m,
	struct label *m_label
);

/**
  @brief Access control check for socket listen
  @param cred Subject credential
  @param socket Object socket
  @param socklabel Policy label for socket

  Determine whether the subject identified by the credential can
  listen() on the passed socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_listen_t(
	struct ucred *cred,
	struct socket *socket,
	struct label *socklabel
);

/**
  @brief Access control check for socket poll
  @param cred Subject credential
  @param socket Object socket
  @param socklabel Policy label for socket

  Determine whether the subject identified by the credential can use the 
  socket in a call to poll().

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_poll_t(
	struct ucred *cred,
	struct socket *socket,
	struct label *socklabel
);

/**
  @brief Access control check for socket receive
  @param cred Subject credential
  @param socket Object socket
  @param socklabel Policy label for socket

  Determine whether the subject identified by the credential can
  receive data from the socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_receive_t(
	struct ucred *cred,
	struct socket *socket,
	struct label *socklabel
);

/**
  @brief Access control check for socket relabel
  @param cred Subject credential
  @param so Object socket
  @param so_label The current label of so
  @param newlabel The label to be assigned to so

  Determine whether the subject identified by the credential can
  change the label on the socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_relabel_t(
	struct ucred *cred,
	struct socket *so,
	struct label *so_label,
	struct label *newlabel
);

/**
  @brief Access control check for socket select
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket

  Determine whether the subject identified by the credential can use the
  socket in a call to select().

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_select_t(
	struct ucred *cred,
	struct socket *so,
	struct label *socklabel
);

/**
  @brief Access control check for socket send
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for socket

  Determine whether the subject identified by the credential can send
  data to the socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_send_t(
	struct ucred *cred,
	struct socket *so,
	struct label *socklabel
);

/**
  @brief Access control check for retrieving socket status
  @param cred Subject credential
  @param so Object socket
  @param socklabel Policy label for so

  Determine whether the subject identified by the credential can
  execute the stat() system call on the given socket.

  @return Return 0 if access if granted, otherwise an appropriate
  value for errno should be returned.
*/
typedef int mpo_check_socket_stat_t(
	struct ucred *cred,
	struct socket *so,
	struct label *socklabel
);

/**
  @brief Access control check for enabling accounting 
  @param cred Subject credential
  @param vp Accounting file
  @param vlabel Label associated with vp

  Determine whether the subject should be allowed to enable accounting, 
  based on its label and the label of the accounting log file.  See
  acct(5) for more information.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_system_acct_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *vlabel
);

/**
  @brief Access control check for calling NFS services 
  @param cred Subject credential

  Determine whether the subject identified by the credential should be 
  allowed to call nfssrv(2).

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_system_nfsd_t(
	struct ucred *cred
);

/**
  @brief Access control check for reboot 
  @param cred Subject credential
  @param howto howto parameter from reboot(2)

  Determine whether the subject identified by the credential should be 
  allowed to reboot the system in the specified manner.  

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_system_reboot_t(
	struct ucred *cred,
	int howto
);

/**
  @brief Access control check for setting system clock 
  @param cred Subject credential

  Determine whether the subject identified by the credential should be 
  allowed to set the system clock. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_system_settime_t(
	struct ucred *cred
);

/**
  @brief Access control check for adding swap devices 
  @param cred Subject credential
  @param vp Swap device 
  @param label Label associated with vp

  Determine whether the subject identified by the credential should be 
  allowed to add vp as a swap device. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_system_swapon_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label
);

/**
  @brief Access control check for removing swap devices 
  @param cred Subject credential
  @param vp Swap device 
  @param label Label associated with vp

  Determine whether the subject identified by the credential should be 
  allowed to remove vp as a swap device. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_system_swapoff_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label
);

/**
  @brief Access control check for sysctl 
  @param cred Subject credential
  @param name Integer name; see sysctl(3)
  @param namelen Length of name array of integers; see sysctl(3)
  @param old 0 or address where to store old value; see sysctl(3)
  @param oldlenp Pointer to length of old buffer; see sysctl(3)
  @param inkernel Boolean; 1 if called from kernel
  @param new 0 or address of new value; see sysctl(3)
  @param newlen Length of new buffer; see sysctl(3)

  Determine whether the subject identified by the credential should be 
  allowed to make the specified sysctl(3) transaction. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_system_sysctl_t(
	struct ucred *cred,
	int *name,
	u_int namelen,
	void *old,
	size_t *oldlenp,
	int inkernel,
	void *new,
	size_t newlen
);

/**
  @brief Check vnode access
  @param cred Subject credential
  @param vp Object vnode
  @param label Label for vp
  @param acc_mode access(2) flags

  Determine how invocations of access(2) and related calls by the 
  subject identified by the credential should return when performed 
  on the passed vnode using the passed access flags. This should 
  generally be implemented using the same semantics used in 
  mpo_check_vnode_open. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_access_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	int acc_mode
);

/**
  @brief Access control check for changing working directory
  @param cred Subject credential
  @param dvp Object; vnode to chdir(2) into
  @param dlabel Policy label for dvp

  Determine whether the subject identified by the credential can change 
  the process working directory to the passed vnode. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_chdir_t(
	struct ucred *cred,
	struct vnode *dvp,
	struct label *dlabel
);

/**
  @brief Access control check for changing root directory
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label associated with dvp

  Determine whether the subject identified by the credential should be 
  allowed to chroot(2) into the specified directory (dvp). 

  @return In the event of an error, an appropriate value for errno
  should be returned, otherwise return 0 upon success.
*/
typedef int mpo_check_vnode_chroot_t(
	struct ucred *cred,
	struct vnode *dvp,
	struct label *dlabel
);

/**
  @brief Access control check for creating vnode
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label for dvp
  @param cnp Component name for dvp
  @param vap vnode attributes for vap

  Determine whether the subject identified by the credential can create 
  a vnode with the passed parent directory, passed name information, 
  and passed attribute information. This call may be made in a number of 
  situations, including as a result of calls to open(2) with O_CREAT, 
  mknod(2), mkfifo(2), and others.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_create_t(
	struct ucred *cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct componentname *cnp,
	struct vattr *vap
);

/** 
  @brief Access control check for deleting vnode
  @param cred Subject credential
  @param dvp Parent directory vnode
  @param dlabel Policy label for dvp
  @param vp Object vnode to delete
  @param label Policy label for vp
  @param cnp Component name for vp
  @see mpo_check_rename_to_t

  Determine whether the subject identified by the credential can delete 
  a vnode from the passed parent directory and passed name information. 
  This call may be made in a number of situations, including as a 
  results of calls to unlink(2) and rmdir(2). Policies implementing 
  this entry point should also implement mpo_check_rename_to to 
  authorize deletion of objects as a result of being the target of a rename.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_delete_t(
	struct ucred *cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *label,
	struct componentname *cnp
);

/**
  @brief Access control check for deleting extended attribute
  @param cred Subject credential
  @param vp Object vnode
  @param attrnamespace Extended attribute namespace
  @param name Extended attribute name 

  Determine whether the subject identified by the credential can delete 
  the extended attribute from the passed vnode. 

  @warning XXX The current extattr implementation does not support the
  deleteextattr operation, but future versions may.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_deleteextattr_t(
	struct ucred *cred,
	struct vnode *vp,
	int attrnamespace,
	const char *name
);


/**
  @brief Access control check for exchanging file data
  @param cred Subject credential
  @param v1 vnode 1 to swap
  @param vl1 Policy label for v1
  @param v2 vnode 2 to swap
  @param vl2 Policy label for v2

  Determine whether the subject identified by the credential can swap the data
  in the two supplied vnodes.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_exchangedata_t(
	struct ucred *cred,
	struct vnode *v1,
	struct label *vl1,
	struct vnode *v2,
	struct label *vl2
);

/**
  @brief Access control check for executing the vnode 
  @param cred Subject credential
  @param vp Object vnode to execute
  @param execlabel Policy label for vp

  Determine whether the subject identified by the credential can execute 
  the passed vnode. Determination of execute privilege is made separately 
  from decisions about any process label transitioning event.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_exec_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	struct label *execlabel
);

/**
  @brief Access control check for retrieving file attributes
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param attrlist List of attributes to retrieve
  @param attrblk I/O structure for returning attribute data (not useful)

  Determine whether the subject identified by the credential can read
  various attributes of the specified vnode, or the filesystem or volume on
  which that vnode resides. See <sys/attr.h> for definitions of the
  attributes.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. Access control covers all attributes requested
  with this call; the security policy is not permitted to change the set of 
  attributes requested.
*/
typedef int mpo_check_vnode_getattrlist_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *vlabel,
	struct attrlist *alist,
	struct uio *attrblk
);

/**
  @brief Access control check for retrieving an extended attribute
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param attrnamespace Extended attribute namespace
  @param name Extended attribute name 
  @param uio I/O structure pointer 

  Determine whether the subject identified by the credential can retrieve 
  the extended attribute from the passed vnode. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_getextattr_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	int attrnamespace,
	const char *name,
	struct uio *uio
);

/**
  @brief Access control check for creating link 
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label associated with dvp
  @param vp Link destination vnode
  @param label Policy label associated with vp
  @param cnp Component name for the link being created

  Determine whether the subject identified by the credential should be 
  allowed to create a link to the vnode vp with the name specified by cnp. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_vnode_link_t(
	struct ucred *cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *label,
	struct componentname *cnp
);


/**
  @brief Access control check for listing extended attributes
  @param cred Subject credential
  @param vp Object vnode
  @param attrnamespace Extended attribute namespace

  Determine whether the subject identified by the credential can retrieve 
  a list of named extended attributes from a vnode. 

  @warning XXX The current extattr implementation does not support the
  listextattr operation, but future versions may.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_vnode_listextattr_t(
	struct ucred *cred,
	struct vnode *vp,
	int attrnamespace
);

/**
  @brief Access control check for lookup 
  @param cred Subject credential
  @param dvp Object vnode
  @param dlabel Policy label for dvp
  @param cnp Component name being looked up 

  Determine whether the subject identified by the credential can perform 
  a lookup in the passed directory vnode for the passed name (cnp).

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_lookup_t(
	struct ucred *cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct componentname *cnp
);

/**
  @brief Access control check for mapping the vnode 
  @param cred Subject credential
  @param vp vnode to map
  @param label Policy label associated with vp
  @param prot mmap protections; see mmap(2)
  @param flags Type of mapped object; see mmap(2) 
  @param maxprot Maximum rights

  Determine whether the subject identified by the credential should be 
  allowed to map the vnode vp with the protections specified in prot. 
  The maxprot field holds the maximum permissions on the new mapping,
  a combination of VM_PROT_READ, VM_PROT_WRITE, and VM_PROT_EXECUTE.
  To avoid overriding prior access control checks, a policy should only
  remove flags from maxprot.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_mmap_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	int prot,
	int flags,
	int *maxprot
);

/**
  @brief Downgrade the mmap protections
  @param cred Subject credential
  @param vp vnode to map
  @param label Policy label associated with vp
  @param prot mmap protections to be downgraded

  Downgrade the mmap protections based on the subject and object labels.
*/
typedef void mpo_check_vnode_mmap_downgrade_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	int *prot
);

/**
  @brief Access control check for setting memory protections
  @param cred Subject credential
  @param vp Mapped vnode
  @param label Policy label associated with vp
  @param prot Memory protections, see mmap(2)

  Determine whether the subject identified by the credential should 
  be allowed to set the specified memory protections on memory mapped 
  from the vnode vp.
 
  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_vnode_mprotect_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	int prot
);

/**
  @brief Access control check for open 
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label associated with vp
  @param acc_mode open(2) access mode

  Determine whether the subject identified by the credential can perform 
  an open operation on the passed vnode with the passed access mode. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_open_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	int acc_mode
);

/**
  @brief Access control check for polling 
  @param active_cred Subject credential
  @param file_cred Credential associated with the struct file
  @param vp Polled vnode
  @param label Policy label associated with vp

  Determine whether the subject identified by the credential should be
  allowed the poll the vnode vp.  The active_cred hold the credentials
  of the subject performing the operation, and file_cred holds the
  credentials of the subject that originally opened the file.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_vnode_poll_t(
	struct ucred *active_cred,
	struct ucred *file_cred,
	struct vnode *vp,
	struct label *label
);

/**
  @brief Access control check for read 
  @param active_cred Subject credential
  @param file_cred Credential associated with the struct file
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can perform 
  a read operation on the passed vnode.  The active_cred hold the credentials
  of the subject performing the operation, and file_cred holds the
  credentials of the subject that originally opened the file.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_read_t(
	struct ucred *active_cred,
	struct ucred *file_cred,
	struct vnode *vp,
	struct label *label
);

/**
  @brief Access control check for read directory
  @param cred Subject credential
  @param dvp Object directory vnode
  @param dlabel Policy label for dvp

  Determine whether the subject identified by the credential can
  perform a readdir operation on the passed directory vnode.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_readdir_t(
	struct ucred *cred,
	struct vnode *dvp,
	struct label *dlabel
);

/**
  @brief Access control check for read link
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can perform 
  a readlink operation on the passed symlink vnode.  This call can be made 
  in a number of situations, including an explicit readlink call by the 
  user process, or as a result of an implicit readlink during a name 
  lookup by the process.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege.
*/
typedef int mpo_check_vnode_readlink_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label
);

/**
  @brief Access control check for relabel
  @param cred Subject credential
  @param vp Object vnode
  @param vnodelabel Existing policy label for vp
  @param newlabel Policy label update to later be applied to vp
  @see mpo_relable_vnode_t
  
  Determine whether the subject identified by the credential can relabel 
  the passed vnode to the passed label update.  If all policies permit
  the label change, the actual relabel entry point (mpo_relabel_vnode)
  will follow.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_vnode_relabel_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *vnodelabel,
	struct label *newlabel
);

/**
  @brief Access control check for rename from
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label associated with dvp
  @param vp vnode to be renamed
  @param dlabel Policy label associated with vp
  @param cnp Component name for vp
  @see mpo_check_vnode_rename_to_t

  Determine whether the subject identified by the credential should be 
  allowed to rename the vnode vp to something else.  

  Due to VFS locking constraints (to make sure proper vnode locks are
  held during this entry point), the vnode relabel checks had to be
  split into two parts: relabel_from and relabel to.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_vnode_rename_from_t(
	struct ucred *cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *label,
	struct componentname *cnp
);

/**
  @brief Access control check for rename to
  @param cred Subject credential
  @param dvp Directory vnode
  @param dlabel Policy label associated with dvp
  @param vp Overwritten vnode 
  @param label Policy label associated with vp
  @param samedir Boolean; 1 if the source and destination directories are the same
  @param cnp Destination component name
  @see mpo_check_vnode_rename_from_t

  Determine whether the subject identified by the credential should be 
  allowed to rename to the vnode vp, into the directory dvp, or to the 
  name represented by cnp. If there is no existing file to overwrite, 
  vp and label will be NULL.

  Due to VFS locking constraints (to make sure proper vnode locks are
  held during this entry point), the vnode relabel checks had to be
  split into two parts: relabel_from and relabel to.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_vnode_rename_to_t(
	struct ucred *cred,
	struct vnode *dvp,
	struct label *dlabel,
	struct vnode *vp,
	struct label *label,
	int samedir,
	struct componentname *cnp
);

/**
  @brief Access control check for revoke 
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can revoke 
  access to the passed vnode.  

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. 
*/
typedef int mpo_check_vnode_revoke_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label
);

/**
  @brief Access control check for select
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can select 
  the vnode.  

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_vnode_select_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label
);

/**
  @brief Access control check for setting file attributes
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param attrlist List of attributes to set
  @param attrblk I/O structure containing attribute data to set

  Determine whether the subject identified by the credential can set
  various attributes of the specified vnode, or the filesystem or volume on
  which that vnode resides. See <sys/attr.h> for definitions of the
  attributes. A security policy can use the UIO structure attrblk to access
  the values of attributes to be set, but the format is complex. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. Access control covers all attributes requested
  with this call.
*/
typedef int mpo_check_vnode_setattrlist_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *vlabel,
	struct attrlist *alist,
	struct uio *attrblk
);

/**
  @brief Access control check for setting extended attribute
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param attrnamespace Extended attribute namespace
  @param name Extended attribute name 
  @param uio I/O structure pointer 

  Determine whether the subject identified by the credential can set the 
  extended attribute of passed name and passed namespace on the passed 
  vnode. Policies implementing security labels backed into extended 
  attributes may want to provide additional protections for those 
  attributes. Additionally, policies should avoid making decisions based 
  on the data referenced from uio, as there is a potential race condition 
  between this check and the actual operation. The uio may also be NULL 
  if a delete operation is being performed. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. 
*/
typedef int mpo_check_vnode_setextattr_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	int attrnamespace,
	const char *name,
	struct uio *uio
);

/**
  @brief Access control check for setting flags 
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param flags File flags; see chflags(2)

  Determine whether the subject identified by the credential can set 
  the passed flags on the passed vnode. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. 
*/
typedef int mpo_check_vnode_setflags_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	u_long flags
);

/**
  @brief Access control check for setting mode 
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param mode File mode; see chmod(2)

  Determine whether the subject identified by the credential can set 
  the passed mode on the passed vnode. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. 
*/
typedef int mpo_check_vnode_setmode_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	mode_t mode
);

/**
  @brief Access control check for setting uid and gid 
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param uid User ID
  @param gid Group ID

  Determine whether the subject identified by the credential can set 
  the passed uid and passed gid as file uid and file gid on the passed 
  vnode. The IDs may be set to (-1) to request no update. 

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. 
*/
typedef int mpo_check_vnode_setowner_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	uid_t uid,
	gid_t gid
);

/**
  @brief Access control check for setting timestamps 
  @param cred Subject credential
  @param vp Object vnode
  @param label Policy label for vp
  @param atime Access time; see utimes(2)
  @param mtime Modification time; see utimes(2)

  Determine whether the subject identified by the credential can set 
  the passed access timestamps on the passed vnode.  

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. 
*/
typedef int mpo_check_vnode_setutimes_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *label,
	struct timespec atime,
	struct timespec mtime
);

/**
  @brief Access control check for stat 
  @param active_cred Subject credential
  @param file_cred Credential associated with the struct file
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can stat
  the passed vnode. See stat(2) for more information.  The active_cred
  hold the credentials of the subject performing the operation, and
  file_cred holds the credentials of the subject that originally
  opened the file.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. 
*/
typedef int mpo_check_vnode_stat_t(
	struct ucred *active_cred,
	struct ucred *file_cred,
	struct vnode *vp,
	struct label *label
);

/**
  @brief Access control check for write 
  @param active_cred Subject credential
  @param file_cred Credential associated with the struct file
  @param vp Object vnode
  @param label Policy label for vp

  Determine whether the subject identified by the credential can
  perform a write operation on the passed vnode.  The active_cred hold
  the credentials of the subject performing the operation, and
  file_cred holds the credentials of the subject that originally
  opened the file.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. Suggested failure: EACCES for label mismatch or 
  EPERM for lack of privilege. 
*/
typedef int mpo_check_vnode_write_t(
	struct ucred *active_cred,
	struct ucred *file_cred,
	struct vnode *vp,
	struct label *label
);
/*@}*/

/**
  @name Entry Points for Audit
*/
/*@{*/
/**
  @brief Access control check for audit
  @param cred Subject credential
  @param record Audit record
  @param length Audit record length

  Determine whether the subject identified by the credential can submit 
  an audit record for inclusion in the audit log via the audit() system call.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned. 
*/
typedef int mpo_check_system_audit_t(
	struct ucred *cred,
	void *record,
	int length
);

/**
  @brief Access control check for manipulating auditing 
  @param cred Subject credential
  @param cmd Audit control command

  Determine whether the subject identified by the credential can perform 
  the audit subsystem control operation cmd via the auditon() system call.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_system_auditon_t(
	struct ucred *cred,
	int cmd
);

/**
  @brief Access control check for controlling audit 
  @param cred Subject credential
  @param vp Audit file
  @param vl Label associated with vp

  Determine whether the subject should be allowed to enable auditing using
  the auditctl() system call, based on its label and the label of the proposed 
  audit file.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_system_auditctl_t(
	struct ucred *cred,
	struct vnode *vp,
	struct label *vl
);

/**
  @brief Access control check for retrieving audit user ID 
  @param cred Subject credential

  Determine whether the subject identified by the credential can get 
  the user identity being used by the auditing system, using the getauid()
  system call.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_proc_getauid_t(
	struct ucred *cred
);

/**
  @brief Access control check for retrieving Login Context ID
  @param p0
  @param p
  @param pid
*/
typedef int mpo_check_proc_getlcid_t(
	struct proc *p0,
	struct proc *p,
	pid_t pid
);

/**
  @brief Access control check for setting audit user ID 
  @param cred Subject credential
  @param auid Audit user ID 

  Determine whether the subject identified by the credential can set 
  the user identity used by the auditing system, using the setauid()
  system call.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_proc_setauid_t(
	struct ucred *cred,
	uid_t auid
);

/**
  @brief Access control check for setting the Login Context
  @param p0
  @param p
  @param pid
  @param lcid
*/
typedef int mpo_check_proc_setlcid_t(
	struct proc *p0,
	struct proc *p,
	pid_t pid,
	pid_t lcid
);

/**
  @brief Access control check for retrieving audit information 
  @param cred Subject credential

  Determine whether the subject identified by the credential can get 
  audit information such as the audit user ID, the preselection mask, 
  the terminal ID and the audit session ID, using the getaudit() system call.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_proc_getaudit_t(
	struct ucred *cred
);

/**
  @brief Access control check for setting audit information 
  @param cred Subject credential
  @param ai Audit information

  Determine whether the subject identified by the credential can set
  audit information such as the the preselection mask, the terminal ID
  and the audit session ID, using the setaudit() system call.

  @return Return 0 if access is granted, otherwise an appropriate value for 
  errno should be returned.
*/
typedef int mpo_check_proc_setaudit_t(
	struct ucred *cred,
	struct auditinfo *ai
);

/**
  @brief Audit event preselection
  @param cred Subject credential
  @param syscode Syscall number
  @param args Syscall arguments

  This is the MAC Framework audit preselect, which is called before a 
  syscall is entered to determine if an audit event should be created. 
  If the MAC policy forces the syscall to be audited, MAC_AUDIT_YES should be
  returned. A return value of MAC_AUDIT_NO causes the audit record to 
  be suppressed. Returning MAC_POLICY_DEFAULT indicates that the policy wants
  to defer to the system's existing preselection mechanism.  
  
  When policies return different preferences, the Framework decides what action
  to take based on the following policy.  If any policy returns MAC_AUDIT_YES,
  then create an audit record, else if any policy returns MAC_AUDIT_NO, then
  suppress the creations of an audit record, else defer to the system's
  existing preselection mechanism.

  @warning The audit implementation in Apple's current version is 
  incomplete, so the MAC policies have priority over the system's existing 
  mechanisms. This will probably change in the future version where 
  the audit implementation is more complete.

  @return Return MAC_AUDIT_YES to force auditing of the syscall, 
  MAC_AUDIT_NO to force no auditing of the syscall, MAC_AUDIT_DEFAULT
  to allow auditing mechanisms to determine if the syscall is audited.

*/
typedef int mpo_audit_preselect_t(
	struct ucred *cred,
	unsigned short syscode,
	void *args
);

/**
  @brief Audit event postselection
  @param cred Subject credential
  @param syscode Syscall number
  @param args Syscall arguments
  @param error Syscall errno
  @param retval Syscall return value

  This is the MAC Framework audit postselect, which is called before 
  exiting a syscall to determine if an audit event should be committed. 
  A return value of MAC_AUDIT_NO forces the audit record to be suppressed. 
  Any other return value results in the audit record being committed.

  @warning The suppression behavior will probably go away in Apple's 
  future version of the audit implementation.

  @return Return MAC_AUDIT_NO to force suppression of the audit record. 
  Any other value results in the audit record being committed.

*/
typedef int mpo_audit_postselect_t(
	struct ucred *cred,
	unsigned short syscode,
	void *args,
	int error,
	int retval
);
/*@}*/

/*!
  \struct mac_policy_ops
*/
struct mac_policy_ops {

	/*
	 * Policy module operations
	 */
	mpo_destroy_t				*mpo_destroy;
	mpo_init_t				*mpo_init;
	mpo_init_bsd_t				*mpo_init_bsd;
	mpo_syscall_t				*mpo_syscall;

	/*
	 * Audit operations
	 */
	mpo_audit_preselect_t			*mpo_audit_preselect;
	mpo_audit_postselect_t			*mpo_audit_postselect;

	/* 
	 * Label operations
	 */
	mpo_init_cred_label_t			*mpo_init_cred_label;
	mpo_init_devfsdirent_label_t		*mpo_init_devfsdirent_label;
	mpo_init_lctx_label_t			*mpo_init_lctx_label;
	mpo_init_mbuf_failed_label_t		*mpo_init_mbuf_failed_label;
	mpo_init_mbuf_socket_label_t		*mpo_init_mbuf_socket_label;
	mpo_init_mbuf_unknown_source_label_t	*mpo_init_mbuf_unknown_source_label;
	mpo_init_mount_label_t			*mpo_init_mount_label;
	mpo_init_mount_fs_label_t		*mpo_init_mount_fs_label;
	mpo_init_port_label_t			*mpo_init_port_label;
	mpo_init_posix_sem_label_t		*mpo_init_posix_sem_label;
	mpo_init_posix_shm_label_t		*mpo_init_posix_shm_label;
	mpo_init_proc_label_t			*mpo_init_proc_label;
	mpo_init_socket_label_t			*mpo_init_socket_label;
	mpo_init_socket_peer_label_t		*mpo_init_socket_peer_label;
	mpo_init_sysv_sem_label_t		*mpo_init_sysv_sem_label;
	mpo_init_sysv_shm_label_t		*mpo_init_sysv_shm_label;
	mpo_init_task_label_t			*mpo_init_task_label;
	mpo_init_tcp_label_t			*mpo_init_tcp_label;
	mpo_init_vnode_label_t			*mpo_init_vnode_label;
	mpo_destroy_cred_label_t		*mpo_destroy_cred_label;
	mpo_destroy_devfsdirent_label_t		*mpo_destroy_devfsdirent_label;
	mpo_destroy_lctx_label_t		*mpo_destroy_lctx_label;
	mpo_destroy_mbuf_socket_label_t		*mpo_destroy_mbuf_socket_label;
	mpo_destroy_mount_label_t		*mpo_destroy_mount_label;
	mpo_destroy_mount_fs_label_t		*mpo_destroy_mount_fs_label;
	mpo_destroy_port_label_t		*mpo_destroy_port_label;
	mpo_destroy_posix_sem_label_t		*mpo_destroy_posix_sem_label;
	mpo_destroy_posix_shm_label_t		*mpo_destroy_posix_shm_label;
	mpo_destroy_proc_label_t		*mpo_destroy_proc_label;
	mpo_destroy_socket_label_t		*mpo_destroy_socket_label;
	mpo_destroy_socket_peer_label_t		*mpo_destroy_socket_peer_label;
	mpo_destroy_sysv_sem_label_t		*mpo_destroy_sysv_sem_label;
	mpo_destroy_sysv_shm_label_t		*mpo_destroy_sysv_shm_label;
	mpo_destroy_task_label_t		*mpo_destroy_task_label;
	mpo_destroy_vnode_label_t		*mpo_destroy_vnode_label;
	mpo_cleanup_sysv_sem_label_t		*mpo_cleanup_sysv_sem_label;
	mpo_cleanup_sysv_shm_label_t		*mpo_cleanup_sysv_shm_label;
	mpo_copy_cred_to_task_t			*mpo_copy_cred_to_task;
	mpo_update_port_from_cred_label_t	*mpo_update_port_from_cred_label;
	mpo_copy_vnode_label_t			*mpo_copy_vnode_label;
	mpo_copy_devfs_label_t			*mpo_copy_devfs_label;
	mpo_copy_mbuf_socket_label_t		*mpo_copy_mbuf_socket_label;
	mpo_copy_port_label_t			*mpo_copy_port_label;
 	mpo_copy_socket_label_t			*mpo_copy_socket_label;
	mpo_externalize_cred_label_t		*mpo_externalize_cred_label;
	mpo_externalize_cred_audit_label_t	*mpo_externalize_cred_audit_label;
	mpo_externalize_lctx_label_t		*mpo_externalize_lctx_label;
	mpo_externalize_socket_label_t		*mpo_externalize_socket_label;
	mpo_externalize_socket_peer_label_t	*mpo_externalize_socket_peer_label;
	mpo_externalize_vnode_label_t		*mpo_externalize_vnode_label;
	mpo_externalize_vnode_audit_label_t	*mpo_externalize_vnode_audit_label;
	mpo_internalize_cred_label_t		*mpo_internalize_cred_label;
	mpo_internalize_lctx_label_t		*mpo_internalize_lctx_label;
	mpo_internalize_socket_label_t		*mpo_internalize_socket_label;
	mpo_internalize_vnode_label_t		*mpo_internalize_vnode_label;

	/*
	 * Labeling event operations: file system objects; and things that
	 * look a lot like file system objects.
	 */

	mpo_associate_vnode_devfs_t		*mpo_associate_vnode_devfs;
	mpo_associate_vnode_extattr_t		*mpo_associate_vnode_extattr;
	mpo_associate_vnode_singlelabel_t	*mpo_associate_vnode_singlelabel;
	mpo_create_devfs_device_t		*mpo_create_devfs_device;
	mpo_create_devfs_directory_t		*mpo_create_devfs_directory;
	mpo_create_devfs_symlink_t		*mpo_create_devfs_symlink;
	mpo_create_vnode_extattr_t		*mpo_create_vnode_extattr;
	mpo_create_mount_t			*mpo_create_mount;
	mpo_relabel_vnode_t			*mpo_relabel_vnode;
	mpo_setlabel_vnode_extattr_t		*mpo_setlabel_vnode_extattr;
	mpo_update_devfsdirent_t		*mpo_update_devfsdirent;

	/* 
	 * Labeling event operations: network objects.  
	 */
	mpo_create_socket_t			*mpo_create_socket;
	mpo_create_socket_from_socket_t		*mpo_create_socket_from_socket;
	mpo_create_mbuf_from_socket_t		*mpo_create_mbuf_from_socket;
	mpo_relabel_socket_t			*mpo_relabel_socket;
	mpo_set_socket_peer_from_socket_t	*mpo_set_socket_peer_from_socket;
	mpo_set_socket_peer_from_mbuf_t		*mpo_set_socket_peer_from_mbuf;

	/*
	 * Labeling event operations: Mach IPC objects.
	 */
	mpo_create_port_t			*mpo_create_port;
	mpo_create_kernel_port_t		*mpo_create_kernel_port;
	mpo_update_port_kobject_t		*mpo_update_port_kobject;

	/*
	 * Labeling event operations: Posix IPC primitives.
	 */
	mpo_create_posix_sem_t			*mpo_create_posix_sem;
	mpo_create_posix_shm_t			*mpo_create_posix_shm;

	/*
	 * Labeling event operations: System V IPC primitives.
	 */
	mpo_create_sysv_sem_t			*mpo_create_sysv_sem;
	mpo_create_sysv_shm_t			*mpo_create_sysv_shm;

	/*
	 * Labeling event operations: processes.
	 */
	mpo_create_cred_t			*mpo_create_cred;
	mpo_create_task_t			*mpo_create_task;
	mpo_create_kernel_task_t		*mpo_create_kernel_task;
	mpo_execve_transition_t			*mpo_execve_transition;
	mpo_execve_will_transition_t		*mpo_execve_will_transition;
	mpo_create_proc0_t			*mpo_create_proc0;
	mpo_create_proc1_t			*mpo_create_proc1;
	mpo_relabel_cred_t			*mpo_relabel_cred;

	mpo_request_object_label_t		*mpo_request_object_label;

	/*
	 * Labeling event operations: login context
	 */
	mpo_proc_create_lctx_t			*mpo_proc_create_lctx;
	mpo_proc_join_lctx_t			*mpo_proc_join_lctx;
	mpo_proc_leave_lctx_t			*mpo_proc_leave_lctx;
	mpo_relabel_lctx_t			*mpo_relabel_lctx;

	/*
	 * Access control checks.
	 */
	mpo_check_service_access_t		*mpo_check_service_access;
	mpo_check_cred_relabel_t		*mpo_check_cred_relabel;
	mpo_check_lctx_relabel_t		*mpo_check_lctx_relabel;
	mpo_check_port_relabel_t		*mpo_check_port_relabel;
	mpo_check_port_send_t			*mpo_check_port_send;
	mpo_check_port_make_send_t		*mpo_check_port_make_send;
	mpo_check_port_make_send_t		*mpo_check_port_make_send_once;
	mpo_check_port_copy_send_t		*mpo_check_port_copy_send;
	mpo_check_port_move_send_t		*mpo_check_port_move_send;
	mpo_check_port_move_send_t		*mpo_check_port_move_send_once;
	mpo_check_port_receive_t		*mpo_check_port_receive;
	mpo_check_port_move_receive_t		*mpo_check_port_move_receive;
	mpo_check_port_hold_send_t		*mpo_check_port_hold_send;
	mpo_check_port_hold_send_t		*mpo_check_port_hold_send_once;
	mpo_check_port_hold_receive_t		*mpo_check_port_hold_receive;
	mpo_check_cred_visible_t		*mpo_check_cred_visible;
	mpo_check_fcntl_t			*mpo_check_fcntl;
	mpo_check_get_fd_t			*mpo_check_get_fd;
	mpo_check_ioctl_t			*mpo_check_ioctl;
	mpo_check_ipc_method_t			*mpo_check_ipc_method;
	mpo_check_posix_sem_create_t		*mpo_check_posix_sem_create;
	mpo_check_posix_sem_open_t		*mpo_check_posix_sem_open;
	mpo_check_posix_sem_post_t		*mpo_check_posix_sem_post;
	mpo_check_posix_sem_unlink_t		*mpo_check_posix_sem_unlink;
	mpo_check_posix_sem_wait_t		*mpo_check_posix_sem_wait;
	mpo_check_posix_shm_create_t		*mpo_check_posix_shm_create;
	mpo_check_posix_shm_open_t		*mpo_check_posix_shm_open;
	mpo_check_posix_shm_mmap_t		*mpo_check_posix_shm_mmap;
	mpo_check_posix_shm_stat_t		*mpo_check_posix_shm_stat;
	mpo_check_posix_shm_truncate_t		*mpo_check_posix_shm_truncate;
	mpo_check_posix_shm_unlink_t		*mpo_check_posix_shm_unlink;
	mpo_check_sysv_semctl_t			*mpo_check_sysv_semctl;
	mpo_check_sysv_semget_t			*mpo_check_sysv_semget;
	mpo_check_sysv_semop_t			*mpo_check_sysv_semop;
	mpo_check_sysv_shmat_t			*mpo_check_sysv_shmat;
	mpo_check_sysv_shmctl_t			*mpo_check_sysv_shmctl;
	mpo_check_sysv_shmdt_t			*mpo_check_sysv_shmdt;
	mpo_check_sysv_shmget_t			*mpo_check_sysv_shmget;
	mpo_check_mount_stat_t			*mpo_check_mount_stat;
	mpo_check_proc_debug_t			*mpo_check_proc_debug;
	mpo_check_proc_getaudit_t		*mpo_check_proc_getaudit;
	mpo_check_proc_getauid_t		*mpo_check_proc_getauid;
	mpo_check_proc_getlcid_t		*mpo_check_proc_getlcid;
	mpo_check_proc_sched_t			*mpo_check_proc_sched;
	mpo_check_proc_setaudit_t		*mpo_check_proc_setaudit;
	mpo_check_proc_setauid_t		*mpo_check_proc_setauid;
	mpo_check_proc_setlcid_t		*mpo_check_proc_setlcid;
	mpo_check_proc_signal_t			*mpo_check_proc_signal;
	mpo_check_proc_wait_t			*mpo_check_proc_wait;
	mpo_check_set_fd_t			*mpo_check_set_fd;
	mpo_check_socket_accept_t		*mpo_check_socket_accept;
	mpo_check_socket_bind_t			*mpo_check_socket_bind;
	mpo_check_socket_connect_t		*mpo_check_socket_connect;
	mpo_check_socket_deliver_t		*mpo_check_socket_deliver;
	mpo_check_socket_listen_t		*mpo_check_socket_listen;
	mpo_check_socket_poll_t			*mpo_check_socket_poll;
	mpo_check_socket_receive_t		*mpo_check_socket_receive;
	mpo_check_socket_relabel_t		*mpo_check_socket_relabel;
	mpo_check_socket_select_t		*mpo_check_socket_select;
	mpo_check_socket_send_t			*mpo_check_socket_send;
	mpo_check_socket_stat_t			*mpo_check_socket_stat;
	mpo_check_system_acct_t			*mpo_check_system_acct;
	mpo_check_system_audit_t		*mpo_check_system_audit;
	mpo_check_system_auditctl_t		*mpo_check_system_auditctl;
	mpo_check_system_auditon_t		*mpo_check_system_auditon;
	mpo_check_system_nfsd_t			*mpo_check_system_nfsd;
	mpo_check_system_reboot_t		*mpo_check_system_reboot;
	mpo_check_system_settime_t		*mpo_check_system_settime;
	mpo_check_system_swapon_t		*mpo_check_system_swapon;
	mpo_check_system_swapoff_t		*mpo_check_system_swapoff;
	mpo_check_system_sysctl_t		*mpo_check_system_sysctl;
	mpo_check_vnode_access_t		*mpo_check_vnode_access;
	mpo_check_vnode_chdir_t			*mpo_check_vnode_chdir;
	mpo_check_vnode_chroot_t		*mpo_check_vnode_chroot;
	mpo_check_vnode_create_t		*mpo_check_vnode_create;
	mpo_check_vnode_delete_t		*mpo_check_vnode_delete;
	mpo_check_vnode_deleteextattr_t		*mpo_check_vnode_deleteextattr;
	mpo_check_vnode_exchangedata_t		*mpo_check_vnode_exchangedata;
	mpo_check_vnode_exec_t			*mpo_check_vnode_exec;
	mpo_check_vnode_getattrlist_t		*mpo_check_vnode_getattrlist;
	mpo_check_vnode_getextattr_t		*mpo_check_vnode_getextattr;
	mpo_check_vnode_link_t			*mpo_check_vnode_link;
	mpo_check_vnode_listextattr_t		*mpo_check_vnode_listextattr;
	mpo_check_vnode_lookup_t		*mpo_check_vnode_lookup;
	mpo_check_vnode_mmap_t			*mpo_check_vnode_mmap;
	mpo_check_vnode_mmap_downgrade_t	*mpo_check_vnode_mmap_downgrade;
	mpo_check_vnode_mprotect_t		*mpo_check_vnode_mprotect;
	mpo_check_vnode_open_t			*mpo_check_vnode_open;
	mpo_check_vnode_poll_t			*mpo_check_vnode_poll;
	mpo_check_vnode_read_t			*mpo_check_vnode_read;
	mpo_check_vnode_readdir_t		*mpo_check_vnode_readdir;
	mpo_check_vnode_readlink_t		*mpo_check_vnode_readlink;
	mpo_check_vnode_relabel_t		*mpo_check_vnode_relabel;
	mpo_check_vnode_rename_from_t		*mpo_check_vnode_rename_from;
	mpo_check_vnode_rename_to_t		*mpo_check_vnode_rename_to;
	mpo_check_vnode_revoke_t		*mpo_check_vnode_revoke;
	mpo_check_vnode_select_t		*mpo_check_vnode_select;
	mpo_check_vnode_setattrlist_t		*mpo_check_vnode_setattrlist;
	mpo_check_vnode_setextattr_t		*mpo_check_vnode_setextattr;
	mpo_check_vnode_setflags_t		*mpo_check_vnode_setflags;
	mpo_check_vnode_setmode_t		*mpo_check_vnode_setmode;
	mpo_check_vnode_setowner_t		*mpo_check_vnode_setowner;
	mpo_check_vnode_setutimes_t		*mpo_check_vnode_setutimes;
	mpo_check_vnode_stat_t			*mpo_check_vnode_stat;
	mpo_check_vnode_write_t			*mpo_check_vnode_write;
};

#define mpc_t	LIST_ENTRY(mac_policy_conf)

/**
  @brief Mac policy configuration

  This structure specifies the configuration information for a
  TrustedBSD MAC policy module.  A policy module developer must supply
  a short unique policy name, a more descriptive full name, a list of label
  namespaces and count, a pointer to the registered enty point operations, 
  any load time flags, and optionally, a pointer to a label slot identifier.

  The Framework will update the runtime flags (mpc_runtime_flags) to
  indicate that the module has been registered.

  If the label slot identifier (mpc_field_off) is NULL, the Framework
  will not provide label storage for the policy.  Otherwise, the
  Framework will store the label location (slot) in this field.

  The mpc_list field is used by the Framework and should not be
  modified by policies.
*/
struct mac_policy_conf {
	char			*mpc_name;		/** policy name */
	char			*mpc_fullname;		/** full name */
	char			**mpc_labelnames;	/** managed label namespaces */
	unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
	struct mac_policy_ops	*mpc_ops;		/** operation vector */
	int			 mpc_loadtime_flags;	/** load time flags */
	int			*mpc_field_off;		/** label slot */
	int			 mpc_runtime_flags;	/** run time flags */
	mpc_t			 mpc_list;		/** List reference */
};

/**
   @brief MAC policy module registration routine

   This function is called to register a policy with the TrustedBSD
   MAC framework.  A policy module will typically call this from the
   Darwin KEXT registration routine.
 */
int	mac_policy_register(struct mac_policy_conf *mpc);

/**
   @brief MAC policy module de-registration routine

   This function is called to de-register a policy with the TrustedBSD
   MAC framework.  A policy module will typically call this from the
   Darwin KEXT de-registration routine.
 */
int	mac_policy_unregister(struct mac_policy_conf *mpc);

/*
 * Framework entry points for the policies to add audit data.
 */
int	mac_audit_text(char *text, struct mac_policy_conf *mpc);

/* 
 * Arbitrary limit on how much data will be logged by the audit
 * entry points above.
 */
#define	MAC_AUDIT_DATA_LIMIT	1024

/* 
 * Values returned by mac_audit_{pre,post}select. To combine the responses
 * of the security policies into a single decision,
 * mac_audit_{pre,post}select() choose the greatest value returned.
 */
#define	MAC_AUDIT_DEFAULT	0	/* use system behavior */
#define	MAC_AUDIT_NO		1	/* force not auditing this event */
#define	MAC_AUDIT_YES		2	/* force auditing this event */

//  \defgroup mpc_loadtime_flags Flags for the mpc_loadtime_flags field

/**
  @name Flags for the mpc_loadtime_flags field
  @see mac_policy_conf

  This is the complete list of flags that are supported by the
  mpc_loadtime_flags field of the mac_policy_conf structure.  These
  flags specify the load time behavior of MAC Framework policy
  modules.
*/
/*@{*/

/**
  @brief Flag to indicate registration preference

  This flag indicates that the policy module must be loaded and
  initialized early in the boot process. If the flag is specified,
  attempts to register the module following boot will be rejected. The
  flag may be used by policies that require pervasive labeling of all
  system objects, and cannot handle objects that have not been
  properly initialized by the policy.
 */
#define	MPC_LOADTIME_FLAG_NOTLATE	0x00000001

/**
  @brief Flag to indicate unload preference

  This flag indicates that the policy module may be unloaded. If this
  flag is not set, then the policy framework will reject requests to
  unload the module. This flag might be used by modules that allocate
  label state and are unable to free that state at runtime, or for
  modules that simply do not want to permit unload operations.
*/
#define	MPC_LOADTIME_FLAG_UNLOADOK	0x00000002

/** 
  @brief Unsupported

  XXX This flag is not yet supported.
*/
#define	MPC_LOADTIME_FLAG_LABELMBUFS	0x00000004
/*@}*/

/**
  @brief Policy registration flag
  @see mac_policy_conf

  This flag indicates that the policy module has been successfully
  registered with the TrustedBSD MAC Framework.  The Framework will
  set this flag in the mpc_runtime_flags field of the policy's
  mac_policy_conf structure after registering the policy.
 */   
#define	MPC_RUNTIME_FLAG_REGISTERED	0x00000001

#if 0
#define	MAC_POLICY_SET(mpops, mpname, mpfullname, mpflags, privdata_wanted) \
	static struct mac_policy_conf mpname##_mac_policy_conf = {	\
		#mpname,						\
		mpfullname,						\
		mpops,							\
		mpflags,						\
		privdata_wanted,					\
		0,							\
	};								\
	static moduledata_t mpname##_mod = {				\
		#mpname,						\
		mac_policy_modevent,					\
		&mpname##_mac_policy_conf				\
	};								\
	MODULE_DEPEND(mpname, kernel_mac_support, 1, 1, 1);		\
	DECLARE_MODULE(mpname, mpname##_mod, SI_SUB_MAC_POLICY,		\
	    SI_ORDER_MIDDLE)

int	mac_policy_modevent(module_t mod, int type, void *data);
#endif

#define	LABEL_TO_SLOT(l, s)	(l)->l_perpolicy[s]

/**
  @name Flags for MAC allocator interfaces

  These flags are passed to the Darwin kernel allocator routines to
  indicate whether the allocation is permitted to block or not.
  Caution should be taken; some operations are not permitted to sleep,
  and some types of locks cannot be held when sleeping.
 */
/*@{*/

/** 
    @brief Allocation operations may block

    If memory is not immediately available, the allocation routine
    will block (typically sleeping) until memory is available.

    @warning Inappropriate use of this flag may cause kernel panics.
 */
#define MAC_WAITOK  0

/** 
    @brief Allocation operations may not block

    Rather than blocking, the allocator may return an error if memory
    is not immediately available.  This type of allocation will not
    sleep, preserving locking semantics.
 */
#define MAC_NOWAIT  1
/*@}*/

#endif /* !_SYS_MAC_POLICY_H */
