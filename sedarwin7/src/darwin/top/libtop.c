/*
 * Copyright (c) 2002 Apple Computer, Inc.  All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <mach/bootstrap.h>
#include <mach/host_priv.h>
#include <mach/mach_error.h>
#include <mach/mach_host.h>
#include <mach/mach_port.h>
#include <mach/mach_types.h>
#include <mach/message.h>
#include <mach/processor_set.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <mach/vm_prot.h>
#include <mach/shared_memory_server.h>

#define IOKIT 1 /* For io_name_t in device/device_types.h. */
#include <device/device_types.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDriver.h>

#include <fcntl.h>
#include <kvm.h>
#include <nlist.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <pwd.h>

#include <sys/resource.h>

#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>

#define LIBTOP_DBG
#ifndef LIBTOP_DBG
/* Disable assertions. */
#ifndef NDEBUG
#define NDEBUG
#endif
#endif
#include <assert.h>

#include "libtop.h"
#include "qr.h"
#include "ql.h"
#include "rb.h"
#include "ch.h"
#include "dch.h"

/*
 * Process info.
 */
typedef struct libtop_pinfo_s libtop_pinfo_t;
struct libtop_pinfo_s {
	/* Sample data that are exposed to the library user. */
	libtop_psamp_t		psamp;

	/* Linkage for pid-ordered tree. */
	rb_node(libtop_pinfo_t)	pnode;

	/* Linkage for sorted tree. */
	rb_node(libtop_pinfo_t)	snode;

	int			flag; /* Set, but not used. */

	/* Manual override for memory region reporting. */
	libtop_preg_t		preg;

	/* TRUE if the globally shared text and data segments are mapped in. */
	boolean_t		split;
};

/* Memory object info. */
typedef struct libtop_oinfo_s libtop_oinfo_t;
struct libtop_oinfo_s {
	/* Hash table linkage. */
	libtop_chi_t	chi;

	/* List linkage. */
	ql_elm(libtop_oinfo_t) link;

	/*
	 * pinfo structure that was most recently used to access this
	 * structure.
	 */
	libtop_pinfo_t	*pinfo;

	/* Memory object ID. */
	int		obj_id;

	/* Memory object size, in pages. */
	int		size;

	/* SM_PRIVATE, SM_SHARED, SM_PRIVATE_ALIASED, SM_COW, ... */
	int		share_type;

	/* Number of pages resident in memory. */
	int		resident_page_count;

	/* Number of references to memory object. */
	int		ref_count;

	/* Number of references to memory object that pinfo holds. */
	int		proc_ref_count;

	/*
	 * Rollback fields.  These are used to store old values that need to be
	 * rolled back to their previous values if an object is referenced more
	 * than once by a process.
	 *
	 * The reason rolling back is necessary has to do with the fact that
	 * memory usage statistics are tallied on the fly, but this can only be
	 * accurately done for each memory region a process refers to once all
	 * of the references have been encountered.  Since the code
	 * optimistically updates the statistics, changes have to be backed out
	 * when another reference to the same memory region is encountered.
	 */
	int			rb_share_type; /* SM_EMPTY == "no rollback" */
	vm_size_t		rb_aliased;
	vm_size_t		rb_vprvt;
	vm_size_t		rb_rshrd;
};

/*
 * Cache entry for uid-->username translations.
 */
typedef struct libtop_user_s libtop_user_t;
struct libtop_user_s {
	libtop_chi_t	chi;

	uid_t	uid;
	char	username[9];
};

/* Sample data that are exposed to the library user. */
static libtop_tsamp_t tsamp;

/* Function pointer that points to an abstract printing function. */
static libtop_print_t *libtop_print;
static void *libtop_user_data;

/* Temporary storage for sorting function and opaque data pointer. */
static libtop_sort_t *libtop_sort;
static void *libtop_sort_data;

/* Mach port, used for various Mach calls. */
static mach_port_t libtop_port;

/* Buffer that is large enough to hold the entire argument area of a process. */
static char *libtop_arg;
static int libtop_argmax;

static kvm_t *libtop_kvmd;
static struct nlist libtop_nlist_net[2];
static mach_port_t libtop_master_port;

/*
 * Memory object hash table and list.  For each sample, a hash table of memory
 * objects is created, and it is used to determine various per-process memory
 * statistics, as well as the total number of memory objects.  Rather than
 * allocating and freeing oinfo structures for every sample, previously
 * allocated structures are linked into a list, and objects in the list are used
 * in preference to allocation.
 */
static libtop_dch_t libtop_oinfo_hash;
static ql_head(libtop_oinfo_t) libtop_oinfo_list;
static unsigned libtop_oinfo_nspares;

/* Tree of all pinfo's, always ordered by -pid. */
static rb_tree(libtop_pinfo_t) libtop_ptree;
/*
 * Transient tree of all pinfo's, created for each sample according to a
 * sorting function.
 */
static rb_tree(libtop_pinfo_t) libtop_stree;

/* TRUE if the most recent sample is sorted. */
static boolean_t libtop_sorted;

/* Pointer to the most recently seen pinfo structure in libtop_piterate(). */
static libtop_pinfo_t *libtop_piter;

/* Cache of uid->username translations. */
static libtop_dch_t libtop_uhash;

#define	TIME_VALUE_TO_TIMEVAL(a, r) do {				\
	(r)->tv_sec = (a)->seconds;					\
	(r)->tv_usec = (a)->microseconds;				\
} while (0)

/* Function prototypes. */
static boolean_t
libtop_p_print(void *a_user_data, const char *a_format, ...);
static int
libtop_p_mach_state_order(int a_state, long a_sleep_time);
static boolean_t
libtop_p_kread(u_long a_addr, void *r_buf, size_t a_nbytes);
static boolean_t
libtop_p_load_get(host_cpu_load_info_t r_load);
static boolean_t
libtop_p_loadavg_update(void);
static void
libtop_p_fw_sample(boolean_t a_fw);
static boolean_t
libtop_p_vm_sample(void);
static void
libtop_p_networks_sample(void);
static boolean_t
libtop_p_disks_sample(void);
static boolean_t
libtop_p_proc_table_read(boolean_t a_reg);
static boolean_t
libtop_p_task_update(task_t a_task, boolean_t a_reg);
static boolean_t
libtop_p_proc_command(libtop_pinfo_t *a_pinfo, struct kinfo_proc *a_kinfo);
static void
libtop_p_pinsert(libtop_pinfo_t *a_pinfo);
static void
libtop_p_premove(libtop_pinfo_t *a_pinfo);
static libtop_pinfo_t *
libtop_p_psearch(pid_t a_pid);
static int
libtop_p_pinfo_pid_comp(libtop_pinfo_t *a_a, libtop_pinfo_t *a_b);
static int
libtop_p_pinfo_comp(libtop_pinfo_t *a_a, libtop_pinfo_t *a_b);
static libtop_user_t *
libtop_p_usearch(uid_t a_uid);
static void
libtop_p_oinfo_init(void);
static void
libtop_p_oinfo_fini(void);
static libtop_oinfo_t *
libtop_p_oinfo_insert(int a_obj_id, int a_share_type, int a_resident_page_count,
    int a_ref_count, int a_size, libtop_pinfo_t *a_pinfo);
static void
libtop_p_oinfo_reset(void);


boolean_t
libtop_init(libtop_print_t *a_print, void *a_user_data)
{
	boolean_t	retval;
	char		errbuf[_POSIX2_LINE_MAX];

	if (a_print != NULL) {
		libtop_print = a_print;
		libtop_user_data = a_user_data;
	} else {
		/* Use a noop printing function. */
		libtop_print = libtop_p_print;
		libtop_user_data = NULL;
	}

	tsamp.seq = 0;
	libtop_port = mach_host_self();
	host_page_size(libtop_port, &tsamp.pagesize);

	/* Initialize the pinfo tree. */
	rb_tree_new(&libtop_ptree, pnode);

	/* Initialized the user hash. */
	dch_new(&libtop_uhash, 32, 24, 0, ch_direct_hash, ch_direct_key_comp);

	/* Initialize the memory object hash table and spares ring. */
	libtop_p_oinfo_init();

	/*
	 * Allocate a buffer that is large enough to hold the maximum arguments
	 * to execve().  This is used when getting the arguments to programs.
	 */
	{
		int	mib[2];
		size_t	size;

		mib[0] = CTL_KERN;
		mib[1] = KERN_ARGMAX;

		size = sizeof(libtop_argmax);
		if (sysctl(mib, 2, &libtop_argmax, &size, NULL, 0) == -1) {
			libtop_print(libtop_user_data,
			    "%s(): Error in sysctl(): %s",
			    __FUNCTION__, strerror(errno));
			retval = TRUE;
			goto RETURN;
		}

		libtop_arg = (char *)malloc(libtop_argmax);
		if (libtop_arg == NULL) {
			retval = TRUE;
			goto RETURN;
		}
	}

	/*
	 * Initialize the kvm descriptor and get the location of _ifnet in
	 * preparation for gathering network statistics.
	 */
	libtop_kvmd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);
	if (libtop_kvmd == NULL) {
		libtop_print(libtop_user_data,
		    "Error in kvm_openfiles(): %s", errbuf);
		retval = TRUE;
		goto RETURN;
	}
	libtop_nlist_net[0].n_name = "_ifnet";
	libtop_nlist_net[1].n_name = NULL;
	if (kvm_nlist(libtop_kvmd, libtop_nlist_net) < 0) {
		libtop_print(libtop_user_data,
		    "Error in kvm_nlist(): %s", kvm_geterr(libtop_kvmd));
		retval = TRUE;
		goto RETURN;
	}
	if (libtop_nlist_net[0].n_type == N_UNDF) {
		libtop_print(libtop_user_data, "No nlist for _ifnet");
		retval = TRUE;
		goto RETURN;
	}

	/*
	 * Get ports and services for drive statistics.
	 */

	if (IOMasterPort(bootstrap_port, &libtop_master_port)) {
		libtop_print(libtop_user_data, "Error in IOMasterPort()");
		retval = TRUE;
		goto RETURN;
	}

	/* Initialize the load statistics. */
	if (libtop_p_load_get(&tsamp.b_cpu)) {
		retval = TRUE;
		goto RETURN;
	}
	tsamp.p_cpu = tsamp.b_cpu;
	tsamp.cpu = tsamp.b_cpu;

	/* Initialize the time. */
	gettimeofday(&tsamp.b_time, NULL);
	tsamp.p_time = tsamp.b_time;
	tsamp.time = tsamp.b_time;

	retval = FALSE;
	RETURN:
	return retval;
}

void
libtop_fini(void)
{
	libtop_pinfo_t *pinfo, *ppinfo;
	libtop_user_t *user;

	/* Deallocate the arg string. */
	free(libtop_arg);

	/* Clean up the oinfo structures. */
	libtop_p_oinfo_fini();

	/* Clean up the pinfo structures. */
	rb_first(&libtop_ptree, pnode, pinfo);
	for (;
	     pinfo != rb_tree_nil(&libtop_ptree);
	     pinfo = ppinfo) {
		rb_next(&libtop_ptree, pinfo, libtop_pinfo_t, pnode, ppinfo);

		libtop_p_premove(pinfo);
		if (pinfo->psamp.command != NULL) {
			free(pinfo->psamp.command);
		}
		free(pinfo);
	}

	/* Clean up the uid->username translation cache. */
	for (; dch_remove_iterate(&libtop_uhash, NULL, (void **)&user, NULL)
	    == FALSE;) {
		free(user);
	}
	dch_delete(&libtop_uhash);
}

/* Take a sample. */
boolean_t
libtop_sample(boolean_t a_reg, boolean_t a_fw)
{
	boolean_t		retval;

	/* Increment the sample sequence number. */
	tsamp.seq++;

	/*
	 * Make a note that the results haven't been sorted (reset by
	 * libtop_psort()).
	 */
	libtop_sorted = FALSE;
	libtop_piter = NULL;

	/* Clear state breakdown. */
	memset(tsamp.state_breakdown, 0, sizeof(tsamp.state_breakdown));

	/* Get time. */
	if (tsamp.seq != 1) {
		tsamp.p_time = tsamp.time;
		gettimeofday(&tsamp.time, NULL);
	}

	/*
	 * Read process information.
	 * Get load averages.
	 */
	if (libtop_p_proc_table_read(a_reg)
	    || libtop_p_loadavg_update()) {
		retval = TRUE;
		goto RETURN;
	}

	/* Get CPU usage counters. */
	tsamp.p_cpu = tsamp.cpu;
	if (libtop_p_load_get(&tsamp.cpu)) {
		retval = TRUE;
		goto RETURN;
	}

	/*
	 * Get shared library (framework) information.
	 */
	libtop_p_fw_sample(a_fw);

	/*
	 * Get system-wide memory usage.
	 */
	if (libtop_p_vm_sample()) {
		retval = TRUE;
		goto RETURN;
	}

	/*
	 * Get network statistics.
	 */
	libtop_p_networks_sample();

	/*
	 * Get disk statistics.
	 */
	if (libtop_p_disks_sample()) {
		retval = TRUE;
		goto RETURN;
	}

	retval = FALSE;
	RETURN:
	return retval;
}

/* Return a pointer to the structure that contains libtop-wide data. */
const libtop_tsamp_t *
libtop_tsamp(void)
{
	return &tsamp;
}

/*
 * Given a tree of pinfo structures, create another tree that is sorted
 * according to a_sort().
 */
void
libtop_psort(libtop_sort_t *a_sort, void *a_data)
{
	libtop_pinfo_t	*pinfo, *ppinfo;

	assert(tsamp.seq != 0);

	/* Reset the iteration pointer. */
	libtop_piter = NULL;

	/* Initialize the sorted tree. */
	rb_tree_new(&libtop_stree, snode);

	/* Note that the results are sorted. */
	libtop_sorted = TRUE;

	/*
	 * Set the sorting function and opaque data in preparation for building
	 * the sorted tree.
	 */
	libtop_sort = a_sort;
	libtop_sort_data = a_data;

	/*
	 * Iterate through ptree and insert the pinfo's into a sorted tree.
	 * At the same time, prune pinfo's that were associated with processes
	 * that were not found during the most recent sample.
	 */
	tsamp.nprocs = 0;
	rb_first(&libtop_ptree, pnode, pinfo);
	for (;
	     pinfo != rb_tree_nil(&libtop_ptree);
	     pinfo = ppinfo) {
		/*
		 * Get the next pinfo before potentially removing this one from
		 * the tree.
		 */
		rb_next(&libtop_ptree, pinfo, libtop_pinfo_t, pnode, ppinfo);

		if (pinfo->psamp.seq == tsamp.seq) {
			/* Insert the pinfo into the sorted tree. */
			rb_node_new(&libtop_stree, pinfo, snode);
			rb_insert(&libtop_stree, pinfo, libtop_p_pinfo_comp,
			    libtop_pinfo_t, snode);

			tsamp.nprocs++;
		} else {
			/* The associated process has gone away. */
			libtop_p_premove(pinfo);
			if (pinfo->psamp.command != NULL) {
				free(pinfo->psamp.command);
			}
			free(pinfo);
		}
	}
}

/*
 * Iteratively return a pointer to each process that was in the most recent
 * sample.  The order depends on if/how libtop_psort() was called.
 */
const libtop_psamp_t *
libtop_piterate(void)
{
	assert(tsamp.seq != 0);

	if (libtop_sorted) {
		/* Use the order set by libtop_psort(). */
		if (libtop_piter == NULL) {
			rb_first(&libtop_stree, snode, libtop_piter);
		} else {
			rb_next(&libtop_stree, libtop_piter, libtop_pinfo_t,
			    snode, libtop_piter);
		}
		if (libtop_piter == rb_tree_nil(&libtop_stree)) {
			libtop_piter = NULL;
		}
	} else {
		boolean_t	dead;

		/*
		 * Return results in ascending pid order.  Since dead processes
		 * weren't cleaned out by libtop_psamp(), take care to do so
		 * here on the fly.
		 */
		if (libtop_piter == NULL) {
			rb_first(&libtop_ptree, pnode, libtop_piter);
		} else {
			rb_next(&libtop_ptree, libtop_piter, libtop_pinfo_t,
			    pnode, libtop_piter);
		}

		do {
			dead = FALSE;

			if (libtop_piter == rb_tree_nil(&libtop_ptree)) {
				/* No more tree nodes. */
				libtop_piter = NULL;
				break;
			}
			if (libtop_piter->psamp.seq != tsamp.seq) {
				libtop_pinfo_t	*pinfo;

				/*
				 * Dead process.  Get the next pinfo tree node
				 * before removing this one.
				 */
				pinfo = libtop_piter;
				rb_next(&libtop_ptree, libtop_piter,
				    libtop_pinfo_t, pnode, libtop_piter);

				libtop_p_premove(pinfo);
				if (pinfo->psamp.command != NULL) {
					free(pinfo->psamp.command);
				}
				free(pinfo);

				dead = TRUE;
			}
		} while (dead);
	}

	return &libtop_piter->psamp;
}

/*
 * Set whether to collect memory region information for the process with pid
 * a_pid.
 */
boolean_t
libtop_preg(pid_t a_pid, libtop_preg_t a_preg)
{
	boolean_t	retval;
	libtop_pinfo_t	*pinfo;

	pinfo = libtop_p_psearch(a_pid);
	if (pinfo == NULL) {
		retval = TRUE;
		goto RETURN;
	}
	pinfo->preg = a_preg;

	retval = FALSE;
	RETURN:
	return retval;
}

/* Return a pointer to the username string associated with a_uid. */
const char *
libtop_username(uid_t a_uid)
{
	const char	*retval;
	libtop_user_t	*user;

	user = libtop_p_usearch(a_uid);
	if (user == NULL) {
		retval = NULL;
		goto RETURN;
	}
	retval = user->username;

	RETURN:
	return retval;
}

/* Return a pointer to a string representation of a process state. */
const char *
libtop_state_str(unsigned a_state)
{
	const char *strings[] = {
		"zombie",
#define LIBTOP_STATE_ZOMBIE	0
		"running",
#define LIBTOP_STATE_RUN	1
		"stuck",
#define LIBTOP_STATE_STUCK	2
		"sleeping",
#define LIBTOP_STATE_SLEEP	3
		"idle",
#define LIBTOP_STATE_IDLE	4
		"stopped",
#define LIBTOP_STATE_STOP	5
		"halted",
#define LIBTOP_STATE_HALT	6
		"unknown"
#define LIBTOP_STATE_UNKNOWN	7
	};

	assert(LIBTOP_NSTATES == sizeof(strings) / sizeof(char *));
	assert(a_state <= LIBTOP_STATE_MAX);

	return strings[a_state];
}

/*
 * Noop printing function, used when the user doesn't supply a printing
 * function.
 */
static boolean_t
libtop_p_print(void *a_user_data, const char *a_format, ...)
{
	/* Do nothing. */
	return FALSE;
}

/* Translate a mach state to a state in the state breakdown array. */
static int
libtop_p_mach_state_order(int a_state, long a_sleep_time)
{
	int	retval;

	switch (a_state) {
	case TH_STATE_RUNNING:
		retval = LIBTOP_STATE_RUN;
		break;
	case TH_STATE_UNINTERRUPTIBLE:
		retval = LIBTOP_STATE_STUCK;
		break;
	case TH_STATE_WAITING:
		if (a_sleep_time > 0) {
			retval = LIBTOP_STATE_IDLE;
		} else {
			retval = LIBTOP_STATE_SLEEP;
		}
		break;
	case TH_STATE_STOPPED:
		retval = LIBTOP_STATE_STOP;
		break;
	case TH_STATE_HALTED:
		retval = LIBTOP_STATE_HALT;
		break;
	default:
		retval = LIBTOP_STATE_UNKNOWN;
		break;
	}

	return retval;
}

/* Read data from kernel memory. */
static boolean_t
libtop_p_kread(u_long a_addr, void *r_buf, size_t a_nbytes)
{
	boolean_t	retval;

	assert(r_buf != NULL);

	if (kvm_read(libtop_kvmd, a_addr, r_buf, a_nbytes) != a_nbytes) {
		libtop_print(libtop_user_data, "Error in kvm_read(): %s",
		    kvm_geterr(libtop_kvmd));
		retval = TRUE;
		goto RETURN;
	}

	retval = FALSE;
	RETURN:
	return retval;
}

/* Get CPU load. */
static boolean_t
libtop_p_load_get(host_cpu_load_info_t r_load)
{
	boolean_t		retval;
	kern_return_t		error;
	mach_msg_type_number_t	count;

	count = HOST_CPU_LOAD_INFO_COUNT;
	error = host_statistics(libtop_port, HOST_CPU_LOAD_INFO,
	    (host_info_t)r_load, &count);
	if (error != KERN_SUCCESS) {
		libtop_print(libtop_user_data, "Error in host_statistics(): %s",
		    mach_error_string(error));
		retval = TRUE;
		goto RETURN;
	}

	retval = FALSE;
	RETURN:
	return retval;
}

/* Update load averages. */
static boolean_t
libtop_p_loadavg_update(void)
{
	boolean_t	retval;
	int		mib[2];
	size_t		size;
	struct loadavg	loadavg;

	mib[0] = CTL_VM;
	mib[1] = VM_LOADAVG;

	size = sizeof(loadavg);
	if (sysctl(mib, 2, &loadavg, &size, NULL, 0) == -1) {
		libtop_print(libtop_user_data,
		    "%s(): Error in sysctl(): %s",
		    __FUNCTION__, strerror(errno));
		retval = TRUE;
		goto RETURN;
	}

	/* Convert fixed point loads to floats. */
	tsamp.loadavg[0] = (float)loadavg.ldavg[0] / (float)loadavg.fscale;
	tsamp.loadavg[1] = (float)loadavg.ldavg[1] / (float)loadavg.fscale;
	tsamp.loadavg[2] = (float)loadavg.ldavg[2] / (float)loadavg.fscale;

	retval = FALSE;
	RETURN:
	return retval;
}

/* Sample framework memory statistics (if a_fw is TRUE). */
static void
libtop_p_fw_sample(boolean_t a_fw)
{
	boolean_t			fw_seen;
	vm_region_submap_info_data_64_t	sinfo;
	mach_msg_type_number_t		count;
	vm_size_t			size;
	int				depth;
	vm_address_t			addr;

	tsamp.fw_count = 0;
	tsamp.fw_code = 0;
	tsamp.fw_data = 0;
	tsamp.fw_linkedit = 0;
	if (a_fw) {
		for (fw_seen = FALSE, addr = GLOBAL_SHARED_TEXT_SEGMENT;
		     addr < (GLOBAL_SHARED_DATA_SEGMENT
		     + SHARED_DATA_REGION_SIZE);
		     addr += size
		     ) {
			/*
			 * Get the next submap in the globally shared segment.
			 */
			depth = 1;
			count = VM_REGION_SUBMAP_INFO_COUNT_64;
			if (vm_region_recurse_64(mach_task_self(), &addr, &size,
			    &depth, (vm_region_info_t)&sinfo, &count)
			    != KERN_SUCCESS) {
				break;
			}
			if (addr >= (GLOBAL_SHARED_DATA_SEGMENT
				+ SHARED_DATA_REGION_SIZE)) {
				break;
			}

			/* Update framework code/data/linkedit sizes. */
			if (addr < GLOBAL_SHARED_DATA_SEGMENT) {
				if (sinfo.share_mode == SM_SHARED
				    || sinfo.share_mode == SM_COW) {
					if (sinfo.max_protection
					    & VM_PROT_EXECUTE) {
						/* Code. */
						tsamp.fw_code
						    += sinfo.pages_resident
						    * tsamp.pagesize;
						if (fw_seen == FALSE) {
							tsamp.fw_count++;
							fw_seen = TRUE;
						}
					} else {
						/* Linkedit. */
						tsamp.fw_linkedit
						    += sinfo.pages_resident
						    * tsamp.pagesize;
						fw_seen = FALSE;
					}
				}
			} else {
				if (sinfo.share_mode == SM_SHARED
				    || sinfo.share_mode == SM_COW
				    || sinfo.share_mode == SM_TRUESHARED) {
					/* Data. */
					tsamp.fw_data += sinfo.pages_resident
					    * tsamp.pagesize;
				}
			}

			/* Update framework vsize. */
			tsamp.fw_vsize += size;
		}
	}
}

/* Sample general VM statistics. */
static boolean_t
libtop_p_vm_sample(void)
{
	boolean_t		retval;
	mach_msg_type_number_t	count;
	kern_return_t		error;
	unsigned		i, ocount;
	libtop_oinfo_t		*oinfo;

	/* Get VM statistics. */
	tsamp.p_vm_stat = tsamp.vm_stat;
	count = sizeof(tsamp.vm_stat) / sizeof(integer_t);
	error = host_statistics(libtop_port, HOST_VM_INFO,
	    (host_info_t)&tsamp.vm_stat, &count);
	if (error != KERN_SUCCESS) {
		libtop_print(libtop_user_data, "Error in host_statistics(): %s",
		    mach_error_string(error));
		retval = TRUE;
		goto RETURN;
	}
	if (tsamp.seq == 1) {
		tsamp.p_vm_stat = tsamp.vm_stat;
		tsamp.b_vm_stat = tsamp.vm_stat;
	}

	/*
	 * Iterate through the oinfo hash table and add up the collective size
	 * of the shared objects.
	 */
	tsamp.rshrd = 0;
	for (i = 0, ocount = dch_count(&libtop_oinfo_hash);
	     i < ocount;
	     i++) {
		dch_get_iterate(&libtop_oinfo_hash, NULL, (void **)&oinfo);
		if (oinfo->share_type == SM_SHARED
		    || oinfo->share_type == SM_COW) {
			tsamp.rshrd += oinfo->resident_page_count;
		}
	}
	tsamp.rshrd *= tsamp.pagesize;

	retval = FALSE;
	RETURN:
	return retval;
}

/*
 * Sample network usage.
 *
 * The algorithm used does not deal with the following conditions, which can
 * cause the statistics to be invalid:
 *
 * 1) Interface counters are 32 bit counters.  Given the speed of current
 *    interfaces, the counters can overflow (wrap) in a matter of seconds.  No
 *    effort is made to detect or correct counter overflow.
 *
 * 2) Interfaces are dynamic -- they can appear and disappear at any time.
 *    There is no way to get statistics on an interface that has disappeared, so
 *    it isn't possible to determine the amount of data transfer between the
 *    previous sample and when the interface went away.
 *
 *    Due to this problem, if an interface disappears, it is possible for the
 *    current sample values to be lower than those of the beginning or previous
 *    samples.
 */
static void
libtop_p_networks_sample(void)
{
	struct ifnet		ifnet;
	struct ifnethead	ifnethead;
	u_long			off;
	char			tname[16];

	tsamp.p_net_ipackets = tsamp.net_ipackets;
	tsamp.p_net_opackets = tsamp.net_opackets;
	tsamp.p_net_ibytes = tsamp.net_ibytes;
	tsamp.p_net_obytes = tsamp.net_obytes;

	tsamp.net_ipackets = 0;
	tsamp.net_opackets = 0;
	tsamp.net_ibytes = 0;
	tsamp.net_obytes = 0;
	if (libtop_nlist_net[0].n_value != 0
	    && libtop_p_kread(libtop_nlist_net[0].n_value, &ifnethead,
	    sizeof(ifnethead)) == FALSE) {
		for (off = (u_long)ifnethead.tqh_first;
		     off != 0;
		     off = (u_long)ifnet.if_link.tqe_next) {
			if (libtop_p_kread(off, &ifnet, sizeof(ifnet))) {
				break;
			}
			if (libtop_p_kread((u_long)ifnet.if_name, tname,
			    sizeof(tname))) {
				break;
			}
			if (strncmp(tname, "lo", 2)) {
				/* Not a loopback device. */
				tsamp.net_ipackets += ifnet.if_ipackets;
				tsamp.net_opackets += ifnet.if_opackets;

				tsamp.net_ibytes += ifnet.if_ibytes;
				tsamp.net_obytes += ifnet.if_obytes;
			}
		}
	}
	if (tsamp.seq == 1) {
		tsamp.b_net_ipackets = tsamp.net_ipackets;
		tsamp.p_net_ipackets = tsamp.net_ipackets;

		tsamp.b_net_opackets = tsamp.net_opackets;
		tsamp.p_net_opackets = tsamp.net_opackets;

		tsamp.b_net_ibytes = tsamp.net_ibytes;
		tsamp.p_net_ibytes = tsamp.net_ibytes;

		tsamp.b_net_obytes = tsamp.net_obytes;
		tsamp.p_net_obytes = tsamp.net_obytes;
	}
}

/*
 * Sample disk usage.  The algorithm used has the same limitations as that used
 * for libtop_p_networks_sample().
 */
static boolean_t
libtop_p_disks_sample(void)
{
	boolean_t		retval;
	io_registry_entry_t	drive;
	io_iterator_t		drive_list;
	CFNumberRef		number;
	CFDictionaryRef		properties, statistics;
	UInt64			value;

	/* Get the list of all drive objects. */
	if (IOServiceGetMatchingServices(libtop_master_port,
	    IOServiceMatching("IOBlockStorageDriver"), &drive_list)) {
		libtop_print(libtop_user_data,
		    "Error in IOServiceGetMatchingServices()");
		retval = TRUE;
		goto ERROR_NOLIST;
	}

	tsamp.p_disk_rops = tsamp.disk_rops;
	tsamp.p_disk_wops = tsamp.disk_wops;
	tsamp.p_disk_rbytes = tsamp.disk_rbytes;
	tsamp.p_disk_wbytes = tsamp.disk_wbytes;

	tsamp.disk_rops = 0;
	tsamp.disk_wops = 0;
	tsamp.disk_rbytes = 0;
	tsamp.disk_wbytes = 0;
	while ((drive = IOIteratorNext(drive_list)) != 0) {
		number = 0;
		properties = 0;
		statistics = 0;
		value = 0;

		/* Obtain the properties for this drive object. */
		if (IORegistryEntryCreateCFProperties(drive,
		    (CFMutableDictionaryRef *)&properties, kCFAllocatorDefault,
		    kNilOptions)) {
			libtop_print(libtop_user_data,
			    "Error in IORegistryEntryCreateCFProperties()");
			retval = TRUE;
			goto RETURN;
		}

		if (properties != 0) {
			/* Obtain the statistics from the drive properties. */
			statistics
			    = (CFDictionaryRef)CFDictionaryGetValue(properties,
			    CFSTR(kIOBlockStorageDriverStatisticsKey));

			if (statistics != 0) {
				/* Get number of reads. */
				number =
				    (CFNumberRef)CFDictionaryGetValue(statistics,
				    CFSTR(kIOBlockStorageDriverStatisticsReadsKey));
				if (number != 0) {
					CFNumberGetValue(number,
					    kCFNumberSInt64Type, &value);
					tsamp.disk_rops += value;
				}

				/* Get bytes read. */
				number =
				    (CFNumberRef)CFDictionaryGetValue(statistics,
				    CFSTR(kIOBlockStorageDriverStatisticsBytesReadKey));
				if (number != 0) {
					CFNumberGetValue(number,
					    kCFNumberSInt64Type, &value);
					tsamp.disk_rbytes += value;
				}

				/* Get number of writes. */
				number =
				    (CFNumberRef)CFDictionaryGetValue(statistics,
				    CFSTR(kIOBlockStorageDriverStatisticsWritesKey));
				if (number != 0) {
					CFNumberGetValue(number,
					    kCFNumberSInt64Type, &value);
					tsamp.disk_wops += value;
				}

				/* Get bytes written. */
				number =
				    (CFNumberRef)CFDictionaryGetValue(statistics,
				    CFSTR(kIOBlockStorageDriverStatisticsBytesWrittenKey));
				if (number != 0) {
					CFNumberGetValue(number,
					    kCFNumberSInt64Type, &value);
					tsamp.disk_wbytes += value;
				}
			}

			/* Release. */
			CFRelease(properties);
		}

		/* Release. */
		IOObjectRelease(drive);
	}
	IOIteratorReset(drive_list);
	if (tsamp.seq == 1) {
		tsamp.b_disk_rops = tsamp.disk_rops;
		tsamp.p_disk_rops = tsamp.disk_rops;

		tsamp.b_disk_wops = tsamp.disk_wops;
		tsamp.p_disk_wops = tsamp.disk_wops;

		tsamp.b_disk_rbytes = tsamp.disk_rbytes;
		tsamp.p_disk_rbytes = tsamp.disk_rbytes;

		tsamp.b_disk_wbytes = tsamp.disk_wbytes;
		tsamp.p_disk_wbytes = tsamp.disk_wbytes;
	}

	retval = FALSE;
	RETURN:
	/* Release. */
	IOObjectRelease(drive_list);
	ERROR_NOLIST:
	return retval;
}

/* Iterate through all processes and update their statistics. */
static boolean_t
libtop_p_proc_table_read(boolean_t a_reg)
{
	boolean_t	retval;
	kern_return_t	error;
	processor_set_t	*psets, pset;
	task_t		*tasks;
	unsigned	i, j, pcnt, tcnt;

	error = host_processor_sets(libtop_port, &psets, &pcnt);
	if (error != KERN_SUCCESS) {
		libtop_print(libtop_user_data,
		    "Error in host_processor_sets(): %s",
		    mach_error_string(error));
		retval = TRUE;
		goto RETURN;
	}

	for (i = 0; i < pcnt; i++) {
		error = host_processor_set_priv(libtop_port, psets[i], &pset);
		if (error != KERN_SUCCESS) {
			libtop_print(libtop_user_data, 
			    "Error in host_processor_set_priv(): %s",
			    mach_error_string(error));
			retval = TRUE;
			goto RETURN;
		}

		error = processor_set_tasks(pset, &tasks, &tcnt);
		if (error != KERN_SUCCESS) {
			libtop_print(libtop_user_data,
			    "Error in processor_set_tasks(): %s",
			    mach_error_string(error));
			retval = TRUE;
			goto RETURN;
		}

		tsamp.reg = 0;
		tsamp.fw_private = 0;
		tsamp.fw_vsize = 0;
		tsamp.rprvt = 0;
		tsamp.vsize = 0;
		tsamp.threads = 0;
		libtop_p_oinfo_reset();
		for (j = 0; j < tcnt; j++) {
			if (libtop_p_task_update(tasks[j], a_reg)) {
				retval = TRUE;
				goto RETURN;
			}

			/* Delete task port if it isn't our own. */
			if (tasks[j] != mach_task_self()) {
				mach_port_deallocate(mach_task_self(),
				    tasks[j]);
			}
		}

		error = vm_deallocate((vm_map_t)mach_task_self(),
		    (vm_address_t)tasks, tcnt * sizeof(task_t));
		if (error != KERN_SUCCESS) {
			libtop_print(libtop_user_data,
			    "Error in vm_deallocate(): %s",
			    mach_error_string(error));
			retval = TRUE;
			goto RETURN;
		}
		if ((error = mach_port_deallocate(mach_task_self(),
			 pset)) != KERN_SUCCESS
		    || (error = mach_port_deallocate(mach_task_self(),
			psets[i])) != KERN_SUCCESS) {
			libtop_print(libtop_user_data,
			    "Error in mach_port_deallocate(): %s",
			    mach_error_string(error));
			retval = TRUE;
			goto RETURN;
		}
	}

	error = vm_deallocate((vm_map_t)mach_task_self(),
	    (vm_address_t)psets, pcnt * sizeof(processor_set_t));
	if (error != KERN_SUCCESS) {
		libtop_print(libtop_user_data,
		    "Error in vm_deallocate(): %s",
		    mach_error_string(error));
		retval = TRUE;
		goto RETURN;
	}

	retval = FALSE;
	RETURN:
	return retval;
}

/* Update statistics for task a_task. */
static boolean_t
libtop_p_task_update(task_t a_task, boolean_t a_reg)
{
	boolean_t		retval;
	kern_return_t		error;
	struct kinfo_proc	kinfo;
	size_t			kinfosize;
	int			pid, mib[4];
	mach_msg_type_number_t	count;
	vm_size_t		aliased;
	libtop_pinfo_t		*pinfo;
	libtop_oinfo_t		*oinfo;
	task_basic_info_data_t	ti;
	struct timeval		tv;
	vm_address_t		address;
	mach_port_t		object_name;
	vm_region_top_info_data_t info;
	vm_size_t		size;
	int			state, tstate;
	thread_array_t		thread_table;
	unsigned int		table_size;
	thread_basic_info_t	thi;
	thread_basic_info_data_t thi_data;
	unsigned		i;
	mach_port_array_t	names, types;
	unsigned		ncnt, tcnt;

	state = LIBTOP_STATE_ZOMBIE;

	/* Get pid for this task. */
	error = pid_for_task(a_task, &pid);
	if (error != KERN_SUCCESS) {
		/* Not a process, or the process is gone. */
		retval = FALSE;
		goto GONE;
	}

	/* Get kinfo structure for this task. */
	kinfosize = sizeof(struct kinfo_proc);
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;

	if (sysctl(mib, 4, &kinfo, &kinfosize, NULL, 0) == -1) {
		libtop_print(libtop_user_data,
		    "%s(): Error in sysctl(): %s", __FUNCTION__,
		    strerror(errno));
		retval = TRUE;
		goto RETURN;
	}

	if (kinfo.kp_proc.p_stat == 0) {
		/* Zombie process. */
		retval = FALSE;
		goto RETURN;
	}

	/*
	 * Search for the process.  If we haven't seen it before, allocate and
	 * insert a new pinfo structure.
	 */
	pinfo = libtop_p_psearch((pid_t)pid);
	if (pinfo == NULL) {
		pinfo = (libtop_pinfo_t *)calloc(1, sizeof(libtop_pinfo_t));
		if (pinfo == NULL) {
			retval = TRUE;
			goto RETURN;
		}
		pinfo->psamp.pid = (pid_t)pid;
		libtop_p_pinsert(pinfo);
	}

	/* Get command name/args. */
	if (libtop_p_proc_command(pinfo, &kinfo)) {
		retval = TRUE;
		goto RETURN;
	}

	pinfo->psamp.uid = kinfo.kp_eproc.e_ucred.cr_uid;
	pinfo->psamp.ppid = kinfo.kp_eproc.e_ppid;
	pinfo->psamp.pgrp = kinfo.kp_eproc.e_pgid;
	pinfo->flag = kinfo.kp_proc.p_flag;

	pinfo->psamp.p_seq = pinfo->psamp.seq;
	pinfo->psamp.seq = tsamp.seq;

	/*
	 * Get task_info, which is used for memory usage and CPU usage
	 * statistics.
	 */
	count = TASK_BASIC_INFO_COUNT;
	error = task_info(a_task, TASK_BASIC_INFO, (task_info_t)&ti, &count);
	if (error != KERN_SUCCESS) {
		state = LIBTOP_STATE_ZOMBIE;
		retval = FALSE;
		goto GONE;
	}

	/*
	 * Get memory usage statistics.
	 */

	/* Make copies of previous sample values. */
	pinfo->psamp.p_rsize = pinfo->psamp.rsize;
	pinfo->psamp.p_vsize = pinfo->psamp.vsize;
	pinfo->psamp.p_rprvt = pinfo->psamp.rprvt;
	pinfo->psamp.p_vprvt = pinfo->psamp.vprvt;
	pinfo->psamp.p_rshrd = pinfo->psamp.rshrd;

	/* Clear sizes in preparation for determining their current values. */
	aliased = 0;
	pinfo->psamp.rprvt = 0;
	pinfo->psamp.vprvt = 0;
	pinfo->psamp.rshrd = 0;
	pinfo->psamp.reg = 0;

	/*
	 * Set rsize and vsize; they require no calculation.  (Well, actually,
	 * we adjust vsize if traversing memory objects to not include the
	 * globally shared text and data regions).
	 */
	pinfo->psamp.rsize = ti.resident_size;
	pinfo->psamp.vsize = ti.virtual_size;

	/*
	 * Do memory object traversaal if any of the following is true:
	 *
	 * 1) Region reporting is enabled for this sample, and it isn't
	 *    explicitly disabled for this process.
	 *
	 * 2) Region reporting is explicitly enabled for this process.
	 *
	 * 3) This is the first sample for this process.
	 *
	 * 4) A previous sample detected that the globally shared text and data
	 *    segments were mapped in, but if we were to subtract them out,
	 *    the process's calculated vsize would be less than 0.
	 */
	if ((a_reg && pinfo->preg != LIBTOP_PREG_off)
	    || pinfo->preg == LIBTOP_PREG_on
	    || pinfo->psamp.p_seq == 0
	    || (pinfo->split && pinfo->psamp.vsize
	    < (SHARED_TEXT_REGION_SIZE + SHARED_DATA_REGION_SIZE))
	    ) {
		/*
		 * Iterate through the VM regions of the process and determine
		 * the amount of memory of various types it has mapped.
		 */
		for (address = 0, pinfo->split = FALSE;
		     ;
		     address += size) {
			/* Get memory region. */
			count = VM_REGION_TOP_INFO_COUNT;
			if (vm_region(a_task, &address, &size,
			    VM_REGION_TOP_INFO, (vm_region_info_t)&info, &count,
			    &object_name) != KERN_SUCCESS) {
				/* No more memory regions. */
				break;
			}

			if (address >= GLOBAL_SHARED_TEXT_SEGMENT
			    && address < (GLOBAL_SHARED_DATA_SEGMENT
			    + SHARED_DATA_REGION_SIZE)) {
				/* This region is private shared. */

				tsamp.fw_private += info.private_pages_resident
				    * tsamp.pagesize;

				/*
				 * Check if this process has the globally shared
				 * text and data regions mapped in.  If so, set
				 * pinfo->split to TRUE and avoid checking
				 * again.
				 */
				if (pinfo->split == FALSE && info.share_mode
				    == SM_EMPTY) {
					vm_region_basic_info_data_64_t	b_info;

					count = VM_REGION_BASIC_INFO_COUNT_64;
					if (vm_region_64(a_task, &address,
					    &size, VM_REGION_BASIC_INFO,
					    (vm_region_info_t)&b_info, &count,
					    &object_name) != KERN_SUCCESS) {
						break;
					}

					if (b_info.reserved) {
						pinfo->split = TRUE;
					}
				}

				/*
				 * Short circuit the loop if this isn't a shared
				 * private region, since that's the only region
				 * type we care about within the current address
				 * range.
				 */
				if (info.share_mode != SM_PRIVATE) {
					continue;
				}
			}

			pinfo->psamp.reg++;

			/*
			 * Update counters according to the region type.
			 */
			switch (info.share_mode) {
			case SM_COW: {
				if (info.ref_count == 1) {
					/* Treat as SM_PRIVATE. */
					pinfo->psamp.vprvt += size;
					pinfo->psamp.rprvt
					    += info.shared_pages_resident
					    * tsamp.pagesize;
				} else {
					/*
					 * Insert a record into the oinfo hash
					 * table.
					 */
					if (pinfo->psamp.pid == 0) {
						/*
						 * Treat kernel_task specially.
						 */
						pinfo->psamp.rprvt
						    += info.private_pages_resident
						    * tsamp.pagesize;
						pinfo->psamp.vprvt
						    += info.private_pages_resident
						    * tsamp.pagesize;
						break;
					}

					oinfo
					    = libtop_p_oinfo_insert(info.obj_id,
					    SM_COW, info.shared_pages_resident,
					    info.ref_count, size, pinfo);
					if (oinfo == NULL) {
						retval = TRUE;
						goto RETURN;
					}

					/* Roll back, if necessary. */
					if (oinfo->proc_ref_count > 1) {
						if (oinfo->rb_share_type
						    != SM_EMPTY) {
							oinfo->share_type
							    = oinfo->rb_share_type;
						}
						aliased -= oinfo->rb_aliased;
						pinfo->psamp.vprvt
						    -= oinfo->rb_vprvt;
						pinfo->psamp.rshrd
						    -= oinfo->rb_rshrd;
					}
					/* Clear rollback fields. */
					oinfo->rb_share_type = SM_EMPTY;
					oinfo->rb_aliased = 0;
					oinfo->rb_vprvt = 0;
					oinfo->rb_rshrd = 0;

					if (oinfo->share_type == SM_SHARED
					    && oinfo->ref_count
					    == oinfo->proc_ref_count) {
						/*
						 * This is a private aliased
						 * object.
						 */
						oinfo->rb_share_type
						    = oinfo->share_type;
						oinfo->share_type
						    = SM_PRIVATE_ALIASED;

						oinfo->rb_aliased 
						    += oinfo->resident_page_count
						    * tsamp.pagesize;
						aliased
						    += oinfo->resident_page_count
						    * tsamp.pagesize;

						oinfo->rb_vprvt += oinfo->size;
						pinfo->psamp.vprvt
						    += oinfo->size;
					}

					if (oinfo->share_type
					    != SM_PRIVATE_ALIASED) {
						oinfo->rb_rshrd
						    += oinfo->resident_page_count
						    * tsamp.pagesize;
						pinfo->psamp.rshrd
						    += oinfo->resident_page_count
						    * tsamp.pagesize;
					}

					pinfo->psamp.vprvt
					    += info.private_pages_resident
					    * tsamp.pagesize;
				}
				pinfo->psamp.rprvt
				    += info.private_pages_resident
				    * tsamp.pagesize;

				break;
			}
			case SM_PRIVATE: {
				pinfo->psamp.rprvt
				    += info.private_pages_resident
				    * tsamp.pagesize;
				pinfo->psamp.vprvt += size;
				break;
			}
			case SM_EMPTY:
				/* Do nothing. */
				break;
			case SM_SHARED: {
				if (pinfo->psamp.pid == 0) {
					/* Ignore kernel_task. */
					break;
				}

				/* Insert a record into the oinfo hash table. */
				oinfo = libtop_p_oinfo_insert(info.obj_id,
				    SM_SHARED, info.shared_pages_resident,
				    info.ref_count, size, pinfo);
				if (oinfo == NULL) {
					retval = TRUE;
					goto RETURN;
				}

				/* Roll back, if necessary. */
				if (oinfo->proc_ref_count > 1) {
					if (oinfo->rb_share_type != SM_EMPTY) {
						oinfo->share_type
						    = oinfo->rb_share_type;
					}
					aliased -= oinfo->rb_aliased;
					pinfo->psamp.vprvt -= oinfo->rb_vprvt;
					pinfo->psamp.rshrd -= oinfo->rb_rshrd;
				}
				/* Clear rollback fields. */
				oinfo->rb_share_type = SM_EMPTY;
				oinfo->rb_aliased = 0;
				oinfo->rb_vprvt = 0;
				oinfo->rb_rshrd = 0;

				if (oinfo->share_type == SM_SHARED
				    && oinfo->ref_count
				    == oinfo->proc_ref_count) {
					/* This is a private aliased object. */
					oinfo->rb_share_type
					    = oinfo->share_type;
					oinfo->share_type = SM_PRIVATE_ALIASED;

					oinfo->rb_aliased
					    += oinfo->resident_page_count
					    * tsamp.pagesize;
					aliased
					    += oinfo->resident_page_count
					    * tsamp.pagesize;

					oinfo->rb_vprvt += oinfo->size;
					pinfo->psamp.vprvt += oinfo->size;
				}

				if (oinfo->share_type != SM_PRIVATE_ALIASED) {
					oinfo->rb_rshrd
					    += oinfo->resident_page_count
					    * tsamp.pagesize;
					pinfo->psamp.rshrd
					    += oinfo->resident_page_count
					    * tsamp.pagesize;
				}

				break;
			}
			default:
				assert(0);
				break;
			}
		}
		pinfo->psamp.rprvt += aliased;

		/* Update global memory statistics. */
		tsamp.reg += pinfo->psamp.reg;
		tsamp.rprvt += pinfo->psamp.rprvt;
	}

	if (pinfo->split) {
		/* Subtract out the globally shared text and data regions. */
		pinfo->psamp.vsize -= (SHARED_TEXT_REGION_SIZE
		    + SHARED_DATA_REGION_SIZE);
	}
	/* Update global memory statistics. */
	tsamp.vsize += pinfo->psamp.vsize;

	/*
	 * Get CPU usage statistics.
	 */

	/* Make copies of previous sample values. */
	pinfo->psamp.p_total_time = pinfo->psamp.total_time;

	/* Set total_time. */
	TIME_VALUE_TO_TIMEVAL(&ti.user_time, &pinfo->psamp.total_time);
	TIME_VALUE_TO_TIMEVAL(&ti.system_time, &tv);
	timeradd(&pinfo->psamp.total_time, &tv, &pinfo->psamp.total_time);

	state = LIBTOP_STATE_MAX;
	pinfo->psamp.state = LIBTOP_STATE_MAX;

	/* Get number of threads. */
	error = task_threads(a_task, &thread_table, &table_size);
	if (error != KERN_SUCCESS) {
		state = LIBTOP_STATE_ZOMBIE;
		retval = FALSE;
		goto RETURN;
	}

	/* Set the number of threads and add to the global thread count. */
	pinfo->psamp.th = table_size;
	tsamp.threads += table_size;

	/* Iterate through threads and collect usage stats. */
	thi = &thi_data;
	for (i = 0; i < table_size; i++) {
		count = THREAD_BASIC_INFO_COUNT;
		if (thread_info(thread_table[i], THREAD_BASIC_INFO,
		    (thread_info_t)thi, &count) == KERN_SUCCESS) {
			if ((thi->flags & TH_FLAGS_IDLE) == 0) {
				TIME_VALUE_TO_TIMEVAL(&thi->user_time, &tv);
				timeradd(&pinfo->psamp.total_time, &tv,
				    &pinfo->psamp.total_time);
				TIME_VALUE_TO_TIMEVAL(&thi->system_time, &tv);
				timeradd(&pinfo->psamp.total_time, &tv,
				    &pinfo->psamp.total_time);
			}
			tstate = libtop_p_mach_state_order(thi->run_state,
			    thi->sleep_time);
			if (tstate < state) {
				state = tstate;
				pinfo->psamp.state = tstate;
			}
		}
		if (a_task != mach_task_self()) {
			if ((error = mach_port_deallocate(mach_task_self(),
			    thread_table[i])) != KERN_SUCCESS) {
				libtop_print(libtop_user_data, 
				    "Error in mach_port_deallocate(): %s",
				    mach_error_string(error));
				retval = TRUE;
				goto RETURN;
			}
		}
	}
	if ((error = vm_deallocate(mach_task_self(), (vm_offset_t)thread_table,
	    table_size * sizeof(thread_array_t)) != KERN_SUCCESS)) {
		libtop_print(libtop_user_data,
		    "Error in vm_deallocate(): %s",
		    mach_error_string(error));
		retval = TRUE;
		goto RETURN;
	}


	if (pinfo->psamp.p_seq == 0) {
		/* Set initial values. */
		pinfo->psamp.b_total_time = pinfo->psamp.total_time;
		pinfo->psamp.p_total_time = pinfo->psamp.total_time;
	}

	/*
	 * Get number of Mach ports.
	 */

	/* Make copy of previous sample value. */
	pinfo->psamp.p_prt = pinfo->psamp.prt;

	if (mach_port_names(a_task, &names, &ncnt, &types, &tcnt)
	    != KERN_SUCCESS) {
		/* Error. */
		pinfo->psamp.prt = 0;
		state = LIBTOP_STATE_ZOMBIE;
		retval = FALSE;
		goto RETURN;
	} else {
		pinfo->psamp.prt = ncnt;
		if ((error = vm_deallocate(mach_task_self(), (vm_offset_t)names,
		    ncnt * sizeof(mach_port_array_t))) != KERN_SUCCESS
		    || (error = vm_deallocate(mach_task_self(),
		    (vm_offset_t)types, tcnt * sizeof(mach_port_array_t)))
		    != KERN_SUCCESS) {
			libtop_print(libtop_user_data,
			    "Error in vm_deallocate(): %s",
			    mach_error_string(error));
			retval = TRUE;
			goto RETURN;
		}
	}

	/*
	 * Get event counters.
	 */

	/* Make copy of previous sample value. */
	pinfo->psamp.p_events = pinfo->psamp.events;

	count = TASK_EVENTS_INFO_COUNT;
	if (task_info(a_task, TASK_EVENTS_INFO,
	    (task_info_t)&pinfo->psamp.events, &count) != KERN_SUCCESS) {
		/* Error. */
		state = LIBTOP_STATE_ZOMBIE;
		retval = FALSE;
		goto RETURN;
	} else {
		/*
		 * Initialize b_events and p_events if this is the first sample
		 * for this process.
		 */
		if (pinfo->psamp.p_seq == 0) {
			pinfo->psamp.b_events = pinfo->psamp.events;
			pinfo->psamp.p_events = pinfo->psamp.events;
		}
	}

	retval = FALSE;
	RETURN:
	tsamp.state_breakdown[state]++;
	GONE:
	return retval;
}

/*
 * Get the command name for the process associated with a_pinfo.  For CFM
 * applications, this requires substantial extra work, since the basename of the
 * first program argument is the actual command name.
 *
 * Due to limitations in the KERN_PROCARGS sysctl as implemented in OS X 10.2,
 * changes were made to the sysctl to make finding the process arguments more
 * deterministic.  If TOP_JAGUAR is defined, the old algorithm is used, rather
 * than the simpler new one.
 */
static boolean_t
libtop_p_proc_command(libtop_pinfo_t *a_pinfo, struct kinfo_proc *a_kinfo)
{
	boolean_t	retval;
	unsigned	len;

	if (a_pinfo->psamp.command != NULL) {
		free(a_pinfo->psamp.command);
		a_pinfo->psamp.command = NULL;
	}

	len = strlen(a_kinfo->kp_proc.p_comm);

	if (strncmp(a_kinfo->kp_proc.p_comm, "LaunchCFMApp",len)) {
		/* Normal program. */
		a_pinfo->psamp.command = (char *)malloc(len + 1);
		if (a_pinfo->psamp.command == NULL) {
			retval = TRUE;
			goto RETURN;
		}
		memcpy(a_pinfo->psamp.command, a_kinfo->kp_proc.p_comm,
		    len + 1);
	} else {
		int	mib[3];
		size_t	procargssize;
#ifdef TOP_JAGUAR
		char 	*arg_end, *exec_path;
		int	*ip;
#else
		char	*cp;
#endif
		char	*command_beg, *command, *command_end;

		/*
		 * CFM application.  Get the basename of the first argument and
		 * use that as the command string.
		 */
		assert(a_pinfo->psamp.pid != 0);

		/*
		 * Make a sysctl() call to get the raw argument space of the
		 * process.  The layout is documented in start.s, which is part
		 * of the Csu project.  In summary, it looks like:
		 *
		 * /---------------\ 0x00000000
		 * :               :
		 * :               :
		 * |---------------|
		 * | argc          |
		 * |---------------|
		 * | arg[0]        |
		 * |---------------|
		 * :               :
		 * :               :
		 * |---------------|
		 * | arg[argc - 1] |
		 * |---------------|
		 * | 0             |
		 * |---------------|
		 * | env[0]        |
		 * |---------------|
		 * :               :
		 * :               :
		 * |---------------|
		 * | env[n]        |
		 * |---------------|
		 * | 0             |
		 * |---------------| <-- Beginning of data returned by sysctl()
		 * | exec_path     |     is here.
		 * |:::::::::::::::|
		 * |               |
		 * | String area.  |
		 * |               |
		 * |---------------| <-- Top of stack.
		 * :               :
		 * :               :
		 * \---------------/ 0xffffffff
		 */
		mib[0] = CTL_KERN;
		mib[1] = KERN_PROCARGS;
		mib[2] = a_pinfo->psamp.pid;

		procargssize = libtop_argmax;
#ifdef TOP_JAGUAR
		/* Hack to avoid kernel bug. */
		if (procargssize > 8192) {
			procargssize = 8192;
		}
#endif
		if (sysctl(mib, 3, libtop_arg, &procargssize, NULL, 0) == -1) {
			libtop_print(libtop_user_data,
			    "%s(): Error in sysctl(): %s",
			    __FUNCTION__, strerror(errno));
			retval = TRUE;
			goto RETURN;
		}

#ifdef TOP_JAGUAR
		/* Set ip just above the end of libtop_arg. */
		arg_end = &libtop_arg[procargssize];
		ip = (int *)arg_end;

		/*
		 * Skip the last 2 words, since the last is a 0 word, and
		 * the second to last may be as well, if there are no
		 * arguments.
		 */
		ip -= 3;

		/* Iterate down the arguments until a 0 word is found. */
		for (; *ip != 0; ip--) {
			if (ip == (int *)libtop_arg) {
				goto ERROR;
			}
		}

		/* The saved exec_path is just above the 0 word. */
		ip++;
		exec_path = (char *)ip;

		/*
		 * Get the beginning of the first argument.  It is word-aligned,
		 * so skip padding '\0' bytes.
		 */
		command_beg = exec_path + strlen(exec_path);
		for (; *command_beg == '\0'; command_beg++) {
			if (command_beg >= arg_end) {
				goto ERROR;
			}
		}

		/* Get the basename of command. */
		command = command_end = command_beg + strlen(command_beg) + 1;
		for (command--; command >= command_beg; command--) {
			if (*command == '/') {
				break;
			}
		}
		command++;

		/* Allocate space for the command and copy. */
		len = command_end - command;
		a_pinfo->psamp.command = (char *)malloc(len + 1);
		if (a_pinfo->psamp.command == NULL) {
			retval = TRUE;
			goto RETURN;
		}
		memcpy(a_pinfo->psamp.command, command, len + 1);
#else
		/* Skip the saved exec_path. */
		for (cp = libtop_arg; cp < &libtop_arg[procargssize]; cp++) {
			if (*cp == '\0') {
				/* End of exec_path reached. */
				break;
			}
		}
		if (cp == &libtop_arg[procargssize]) {
			goto ERROR;
		}

		/* Skip trailing '\0' characters. */
		for (; cp < &libtop_arg[procargssize]; cp++) {
			if (*cp != '\0') {
				/* Beginning of first argument reached. */
				break;
			}
		}
		if (cp == &libtop_arg[procargssize]) {
			goto ERROR;
		}
		command_beg = cp;

		/*
		 * Make sure that the command is '\0'-terminated.  This protects
		 * against malicious programs; under normal operation this never
		 * ends up being a problem..
		 */
		for (; cp < &libtop_arg[procargssize]; cp++) {
			if (*cp == '\0') {
				/* End of first argument reached. */
				break;
			}
		}
		if (cp == &libtop_arg[procargssize]) {
			goto ERROR;
		}
		command_end = command = cp;

		/* Get the basename of command. */
		for (command--; command >= command_beg; command--) {
			if (*command == '/') {
				command++;
				break;
			}
		}

		/* Allocate space for the command and copy. */
		len = command_end - command;
		a_pinfo->psamp.command = (char *)malloc(len + 1);
		if (a_pinfo->psamp.command == NULL) {
			retval = TRUE;
			goto RETURN;
		}
		memcpy(a_pinfo->psamp.command, command, len + 1);
#endif
	}

	retval = FALSE;
	RETURN:
	return retval;

	ERROR:
	{
		static const char s[] = "(LaunchCFMApp)";

		/*
		 * Unable to parse the arguments.  Set the command name to
		 * "(LaunchCFMApp)".
		 */
		a_pinfo->psamp.command = malloc(sizeof(s));
		if (a_pinfo->psamp.command == NULL) {
			retval = TRUE;
			goto RETURN;
		}
		memcpy(a_pinfo->psamp.command, s, sizeof(s));

		retval = FALSE;
		goto RETURN;
	}
}

/* Insert a pinfo structure into the pid-ordered tree. */
static void
libtop_p_pinsert(libtop_pinfo_t *a_pinfo)
{
	rb_node_new(&libtop_ptree, a_pinfo, pnode);
	rb_insert(&libtop_ptree, a_pinfo, libtop_p_pinfo_pid_comp,
	    libtop_pinfo_t, pnode);
}

/* Remove a pinfo structure from the pid-ordered tree. */
static void
libtop_p_premove(libtop_pinfo_t *a_pinfo)
{
	rb_remove(&libtop_ptree, a_pinfo, libtop_pinfo_t, pnode);
}

/* Search for a pinfo structure with pid a_pid. */
static libtop_pinfo_t *
libtop_p_psearch(pid_t a_pid)
{
	libtop_pinfo_t	*retval, key;

	key.psamp.pid = a_pid;
	rb_search(&libtop_ptree, &key, libtop_p_pinfo_pid_comp, pnode, retval);
	if (retval == rb_tree_nil(&libtop_ptree)) {
		retval = NULL;
	}

	return retval;
}

/*
 * Compare two pinfo structures according to pid.  This function is used for
 * operations on the pid-sorted tree of pinfo structures.
 */
static int
libtop_p_pinfo_pid_comp(libtop_pinfo_t *a_a, libtop_pinfo_t *a_b)
{
	int	retval;

	if (a_a->psamp.pid < a_b->psamp.pid) {
		retval = -1;
	} else if (a_a->psamp.pid > a_b->psamp.pid) {
		retval = 1;
	} else {
		retval = 0;
	}

	return retval;
}

/* Process comparison wrapper function, used by the red-black tree code. */
static int
libtop_p_pinfo_comp(libtop_pinfo_t *a_a, libtop_pinfo_t *a_b)
{
	int	retval;

	retval = libtop_sort(libtop_sort_data, &a_a->psamp, &a_b->psamp);

	return retval;
}

/*
 * Search for a uid in the uid-->username translation cache.  If a cache entry
 * does not exist, create one.
 */
static libtop_user_t *
libtop_p_usearch(uid_t a_uid)
{
	libtop_user_t	*retval;

	if (dch_search(&libtop_uhash, (void *)a_uid, (void **)&retval)) {
		struct passwd	*pwd;

		/* Not in the cache. */
		retval = (libtop_user_t *)malloc(sizeof(libtop_user_t));
		if (retval == NULL) {
			goto RETURN;
		}
		retval->uid = a_uid;

		setpwent();
		pwd = getpwuid(a_uid);
		if (pwd == NULL) {
			retval = NULL;
			goto RETURN;
		} else {
			snprintf(retval->username, sizeof(retval->username),
			    "%s", pwd->pw_name);
		}
		endpwent();

		dch_insert(&libtop_uhash, (void *)retval->uid, (void *)retval,
		    &retval->chi);
	}

	RETURN:
	return retval;
}

/* Initialize data structures used by the memory object info code. */
static void
libtop_p_oinfo_init(void)
{
	/*
	 * Using the direct hashing functions assumes that
	 * sizeof(int) == sizeof(void *).
	 */
	dch_new(&libtop_oinfo_hash, 4096, 3072, 0,
	    ch_direct_hash, ch_direct_key_comp);
	ql_new(&libtop_oinfo_list);
	libtop_oinfo_nspares = 0;
}

/* Tear down data structures used by the memory object info code. */
static void
libtop_p_oinfo_fini(void)
{
	libtop_oinfo_t	*oinfo;

	/*
	 * Deallocate all oinfo structures by iterating through the oinfo list.
	 */
	for (oinfo = ql_last(&libtop_oinfo_list, link);
	     oinfo != NULL;
	     oinfo = ql_last(&libtop_oinfo_list, link)) {
		ql_tail_remove(&libtop_oinfo_list, libtop_oinfo_t, link);
		free(oinfo);
	}
}

/* Insert or update a memory object info entry. */
static libtop_oinfo_t *
libtop_p_oinfo_insert(int a_obj_id, int a_share_type, int a_resident_page_count,
    int a_ref_count, int a_size, libtop_pinfo_t *a_pinfo)
{
	libtop_oinfo_t	*oinfo;

	if (dch_search(&libtop_oinfo_hash, (void *)a_obj_id, (void **)&oinfo)
	    == FALSE) {
		/* Use existing record. */
		if (oinfo->pinfo != a_pinfo) {
			oinfo->proc_ref_count = 0;
			oinfo->pinfo = a_pinfo;
		}

		oinfo->size += a_size;
		oinfo->proc_ref_count++;
	} else {
		/*
		 * Initialize and insert new record.  Use a cached oinfo
		 * structure, if any exist.
		 */

		if (libtop_oinfo_nspares > 0) {
			oinfo = ql_first(&libtop_oinfo_list);
			ql_first(&libtop_oinfo_list) = qr_next(oinfo, link);
			libtop_oinfo_nspares--;
		} else {
			assert(libtop_oinfo_nspares == 0);
			oinfo
			    = (libtop_oinfo_t *)malloc(sizeof(libtop_oinfo_t));
			if (oinfo == NULL) {
				goto RETURN;
			}
			ql_elm_new(oinfo, link);
			ql_tail_insert(&libtop_oinfo_list, oinfo, link);
		}

		oinfo->pinfo = a_pinfo;
		oinfo->obj_id = a_obj_id;
		oinfo->size = a_size;
		oinfo->share_type = a_share_type;
		oinfo->resident_page_count = a_resident_page_count;
		oinfo->ref_count = a_ref_count;
		oinfo->proc_ref_count = 1;

		dch_insert(&libtop_oinfo_hash, (void *)a_obj_id, (void *)oinfo,
		    &oinfo->chi);
	}

	RETURN:
	return oinfo;
}

/* Reset the memory object info hash.  This is done between samples. */
static void
libtop_p_oinfo_reset(void)
{
	libtop_oinfo_nspares += dch_count(&libtop_oinfo_hash);
	dch_clear(&libtop_oinfo_hash);
}
