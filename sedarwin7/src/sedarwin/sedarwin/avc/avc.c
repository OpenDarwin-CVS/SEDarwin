/*
 * Implementation of the kernel access vector cache (AVC).
 *
 * Authors:  Stephen Smalley, <sds@epoch.ncsc.mil>
 *           James Morris <jmorris@redhat.com>
 *
 * Update:   KaiGai, Kohei <kaigai@ak.jp.nec.com>
 *     Replaced the avc_lock spinlock by RCU.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS"). 
 *
 * Copyright (c) 2005-2006 SPARTA, Inc.
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2,
 *      as published by the Free Software Foundation.
 */

#include <sys/types.h> 
#include <sys/param.h>   
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/mac.h>    
#include <sys/mount.h>   
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#ifdef CAPABILITIES
#include <sys/capability.h>
#endif

#include <sys/mac_policy.h>
#include <kern/lock.h>
#include <kern/zalloc.h>

#include <sedarwin/linux-compat.h>
#include <sedarwin/avc/avc.h>
#include <sedarwin/avc/avc_ss.h>

static const struct av_perm_to_string
{
  u16 tclass;
  u32 value;
  const char *name;
} av_perm_to_string[] = {
#define S_(c, v, s) { c, v, s },
#include <sedarwin/avc/av_perm_to_string.h>
#undef S_
};

static const char *class_to_string[] = {
#define S_(s) s,
#include <sedarwin/avc/class_to_string.h>
#undef S_
};

#define TB_(s) static const char * s [] = {
#define TE_(s) };
#define S_(s) s,
#include <sedarwin/avc/common_perm_to_string.h>
#undef TB_
#undef TE_
#undef S_

static const struct av_inherit
{
    u16 tclass;
    const char **common_pts;
    u32 common_base;
} av_inherit[] = {
#define S_(c, i, b) { c, common_##i##_perm_to_string, b },
#include <sedarwin/avc/av_inherit.h>
#undef S_
};

#define AVC_CACHE_SLOTS			512
#define AVC_CACHE_MAXNODES		558
#define AVC_DEF_CACHE_THRESHOLD		512
#define AVC_CACHE_RECLAIM		16

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
#define avc_cache_stats_incr(field) 				\
do {								\
	per_cpu(avc_cache_stats, get_cpu()).field++;		\
	put_cpu();						\
} while (0)
#else
#define avc_cache_stats_incr(field)	do {} while (0)
#endif

struct avc_entry {
	u32			ssid;
	u32			tsid;
	u16			tclass;
	struct av_decision	avd;
	int			used;	/* used recently */
};

struct avc_node {
	struct avc_entry	ae;
	LIST_ENTRY(avc_node)	list;
};

struct avc_cache {
	LIST_HEAD(, avc_node)	slots[AVC_CACHE_SLOTS];
	lock_t			*slots_lock[AVC_CACHE_SLOTS];
	u32			lru_hint;	/* LRU hint for reclaim scan */
	u32			active_nodes;
	u32			latest_notif;	/* latest revocation notification */
};

struct avc_callback_node {
	int (*callback) (u32 event, u32 ssid, u32 tsid,
	                 u16 tclass, u32 perms,
	                 u32 *out_retained);
	u32 events;
	u32 ssid;
	u32 tsid;
	u16 tclass;
	u32 perms;
	struct avc_callback_node *next;
};

/* Exported via selinufs */
unsigned int avc_cache_threshold = AVC_DEF_CACHE_THRESHOLD;

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
DEFINE_PER_CPU(struct avc_cache_stats, avc_cache_stats) = { 0 };
#endif

int selinux_auditing = 1;
int selinux_enforcing = 0;

extern mutex_t *avc_log_lock;

#define AVC_RDLOCK(n) lock_read(avc_cache.slots_lock[n])
#define AVC_WRLOCK(n) lock_write(avc_cache.slots_lock[n])
#define AVC_RDUNLOCK(n) lock_read_done(avc_cache.slots_lock[n])
#define AVC_WRUNLOCK(n) lock_write_done(avc_cache.slots_lock[n])

static mutex_t *notif_lock;
#define NOTIF_LOCK mutex_lock(notif_lock)
#define NOTIF_UNLOCK mutex_unlock(notif_lock)

static mutex_t *ratelimit_lock;
#define RATELIM_LOCK mutex_lock(ratelimit_lock)
#define RATELIM_UNLOCK mutex_unlock(ratelimit_lock)

static struct avc_cache avc_cache;
static struct avc_callback_node *avc_callbacks;
static zone_t avc_node_cachep;
static uint64_t avc_msg_cost, avc_msg_burst;

static inline int avc_hash(u32 ssid, u32 tsid, u16 tclass)
{
	return (ssid ^ (tsid<<2) ^ (tclass<<4)) & (AVC_CACHE_SLOTS - 1);
}

#if 0
/* XXXMAC - moved to services.c */
/**
 * avc_dump_av - Display an access vector in human-readable form.
 * @tclass: target security class
 * @av: access vector
 */
static void avc_dump_av(struct audit_buffer *ab, u16 tclass, u32 av)
{
	const char **common_pts = NULL;
	u32 common_base = 0;
	int i, i2, perm;

	if (av == 0) {
		audit_log_format(ab, " null");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(av_inherit); i++) {
		if (av_inherit[i].tclass == tclass) {
			common_pts = av_inherit[i].common_pts;
			common_base = av_inherit[i].common_base;
			break;
		}
	}

	audit_log_format(ab, " {");
	i = 0;
	perm = 1;
	while (perm < common_base) {
		if (perm & av) {
			audit_log_format(ab, " %s", common_pts[i]);
			av &= ~perm;
		}
		i++;
		perm <<= 1;
	}

	while (i < sizeof(av) * 8) {
		if (perm & av) {
			for (i2 = 0; i2 < ARRAY_SIZE(av_perm_to_string); i2++) {
				if ((av_perm_to_string[i2].tclass == tclass) &&
				    (av_perm_to_string[i2].value == perm))
					break;
			}
			if (i2 < ARRAY_SIZE(av_perm_to_string)) {
				audit_log_format(ab, " %s",
						 av_perm_to_string[i2].name);
				av &= ~perm;
			}
		}
		i++;
		perm <<= 1;
	}

	if (av)
		audit_log_format(ab, " 0x%x", av);

	audit_log_format(ab, " }");
}
#endif

/**
 * avc_dump_query - Display a SID pair and a class in human-readable form.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 */
static void avc_dump_query(struct audit_buffer *ab, u32 ssid, u32 tsid, u16 tclass)
{
	int rc;
	char *scontext;
	u32 scontext_len;

 	rc = security_sid_to_context(ssid, &scontext, &scontext_len);
	if (rc)
		audit_log_format(ab, "ssid=%d", ssid);
	else {
		audit_log_format(ab, "scontext=%s", scontext);
		kfree(scontext);
	}

	rc = security_sid_to_context(tsid, &scontext, &scontext_len);
	if (rc)
		audit_log_format(ab, " tsid=%d", tsid);
	else {
		audit_log_format(ab, " tcontext=%s", scontext);
		kfree(scontext);
	}
	audit_log_format(ab, " tclass=%s", security_class_to_string(tclass));
}

/**
 * avc_init - Initialize the AVC.
 *
 * Initialize the access vector cache.
 */
void __init avc_init(void)
{
	size_t evsize;
	char *ev;
	int i;

	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		LIST_INIT(&avc_cache.slots[i]);
		avc_cache.slots_lock[i] =
		    lock_alloc(TRUE, ETAP_NO_TRACE, ETAP_NO_TRACE);
	}
	avc_cache.active_nodes = 0;
	avc_cache.lru_hint = 0;

	/* For avc_ratelimit() */
	nanoseconds_to_absolutetime(5000000000ULL, &avc_msg_cost);
	avc_msg_burst = 10 * avc_msg_cost;

	avc_log_lock = mutex_alloc(ETAP_NO_TRACE);
	notif_lock = mutex_alloc(ETAP_NO_TRACE);
	ratelimit_lock = mutex_alloc(ETAP_NO_TRACE);

	avc_node_cachep = zinit(sizeof(struct avc_node),
	    AVC_CACHE_MAXNODES * sizeof(struct avc_node),
	    AVC_CACHE_RECLAIM * sizeof(struct avc_node), "avc node");

	audit_log("AVC INITIALIZED");

	if (preload_find_data("sebsd_enforce", &evsize, &ev)) {
		if (evsize > 0 && ev[0] == '1')
			selinux_enforcing = 1;
	}
}

#if 0
int avc_get_hash_stats(char *page)
{
	int i, chain_len, max_chain_len, slots_used;
	struct avc_node *node;

	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		AVC_RDLOCK(i);
		if (!LIST_EMPTY(&avc_cache.slots[i])) {
			slots_used++;
			chain_len = 0;
			LIST_FOREACH(node, &avc_cache.slots[i], list)
				chain_len++;
			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
		AVC_RDUNLOCK(i);
	}

	return scnprintf(page, PAGE_SIZE, "entries: %d\nbuckets used: %d/%d\n"
			 "longest chain: %d\n",
			 atomic_read(&avc_cache.active_nodes),
			 slots_used, AVC_CACHE_SLOTS, max_chain_len);
}
#endif

static void avc_node_free(struct avc_node *node)
{
	zfree(avc_node_cachep, (vm_offset_t)node);
	avc_cache_stats_incr(frees);
}

static void avc_node_delete(struct avc_node *node)
{
	LIST_REMOVE(node, list);
	avc_node_free(node);
	atomic_dec(&avc_cache.active_nodes);
}

static void avc_node_kill(struct avc_node *node)
{
	zfree(avc_node_cachep, (vm_offset_t)node);
	avc_cache_stats_incr(frees);
	atomic_dec(&avc_cache.active_nodes);
}

static void avc_node_replace(struct avc_node *new, struct avc_node *old)
{
#ifdef LIST_REPLACE
	LIST_REPLACE(old, new, list);
#else
	LIST_INSERT_BEFORE(old, new, list);
	LIST_REMOVE(old, list);
#endif
	avc_node_free(old);
	atomic_dec(&avc_cache.active_nodes);
}

static inline int avc_reclaim_node(void)
{
	struct avc_node *node, *next;
	int hvalue, try, ecx;

	for (try = 0, ecx = 0; try < AVC_CACHE_SLOTS; try++ ) {
		hvalue = atomic_inc_return(&avc_cache.lru_hint) & (AVC_CACHE_SLOTS - 1);

		AVC_WRLOCK(hvalue);
		for (node = LIST_FIRST(&avc_cache.slots[hvalue]);
		    node != NULL; node = next) {
			next = LIST_NEXT(node, list);
			if (--node->ae.used == 0) {
				/* Recently Unused */
				avc_node_delete(node);
				avc_cache_stats_incr(reclaims);
				ecx++;
				if (ecx >= AVC_CACHE_RECLAIM) {
					AVC_WRUNLOCK(hvalue);
					goto out;
				}
			}
		}
		AVC_WRUNLOCK(hvalue);
	}
out:
	return ecx;
}

static struct avc_node *avc_alloc_node(void)
{
	struct avc_node *node;

	node = (struct avc_node *)zalloc_noblock(avc_node_cachep);
	if (!node)
		goto out;

	memset(node, 0, sizeof(struct avc_node));
	node->ae.used = 1;
	avc_cache_stats_incr(allocations);

	if (atomic_inc_return(&avc_cache.active_nodes) > avc_cache_threshold)
		avc_reclaim_node();

out:
	return node;
}

static void avc_node_populate(struct avc_node *node, u32 ssid, u32 tsid, u16 tclass, struct avc_entry *ae)
{
	node->ae.ssid = ssid;
	node->ae.tsid = tsid;
	node->ae.tclass = tclass;
	memcpy(&node->ae.avd, &ae->avd, sizeof(node->ae.avd));
}

/*
 * Note: returns with read lock held for hvalue.
 */
static inline struct avc_node *avc_search_node(u32 ssid, u32 tsid, u16 tclass,
    int *hvaluep)
{
	struct avc_node *node, *ret = NULL;

	*hvaluep = avc_hash(ssid, tsid, tclass);
	AVC_RDLOCK(*hvaluep);
	LIST_FOREACH(node, &avc_cache.slots[*hvaluep], list) {
		if (ssid == node->ae.ssid &&
		    tclass == node->ae.tclass &&
		    tsid == node->ae.tsid) {
			ret = node;
			break;
		}
	}

	if (ret == NULL) {
		/* cache miss */
		goto out;
	}

	/* cache hit */
	if (atomic_read(&ret->ae.used) != 1)
		atomic_set(&ret->ae.used, 1);
out:
	return ret;
}

/**
 * avc_lookup - Look up an AVC entry.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @hvaluep: cache slot of the node on success
 *
 * Look up an AVC entry that is valid for the
 * @requested permissions between the SID pair
 * (@ssid, @tsid), interpreting the permissions
 * based on @tclass.  If a valid AVC entry exists,
 * then this function return the avc_node and read locks its slot.
 * Otherwise, this function returns NULL.
 */
static struct avc_node *avc_lookup(u32 ssid, u32 tsid, u16 tclass, u32 requested, int *hvaluep)
{
	struct avc_node *node;

	avc_cache_stats_incr(lookups);
	node = avc_search_node(ssid, tsid, tclass, hvaluep);

	if (node && ((node->ae.avd.decided & requested) == requested)) {
		avc_cache_stats_incr(hits);
		goto out;
	}

	AVC_RDUNLOCK(*hvaluep);
	node = NULL;
	avc_cache_stats_incr(misses);
out:
	return node;
}

static int avc_latest_notif_update(int seqno, int is_insert)
{
	int ret = 0;

	NOTIF_LOCK;
	if (is_insert) {
		if (seqno < avc_cache.latest_notif) {
			printk(KERN_WARNING "avc:  seqno %d < latest_notif %d\n",
			       seqno, avc_cache.latest_notif);
			ret = EAGAIN;
		}
	} else {
		if (seqno > avc_cache.latest_notif)
			avc_cache.latest_notif = seqno;
	}
	NOTIF_UNLOCK;

	return ret;
}

/**
 * avc_insert - Insert an AVC entry.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @ae: AVC entry
 * @hvaluep: cache slot of the node on success
 *
 * Insert an AVC entry for the SID pair
 * (@ssid, @tsid) and class @tclass.
 * The access vectors and the sequence number are
 * normally provided by the security server in
 * response to a security_compute_av() call.  If the
 * sequence number @ae->avd.seqno is not less than the latest
 * revocation notification, then the function copies
 * the access vectors into a cache entry, returns (WRITE-locked)
 * avc_node inserted. Otherwise, this function returns NULL.
 */
static struct avc_node *avc_insert(u32 ssid, u32 tsid, u16 tclass, struct avc_entry *ae, int *hvaluep)
{
	struct avc_node *pos, *node;

	if (avc_latest_notif_update(ae->avd.seqno, 1))
		return NULL;

	node = avc_alloc_node();
	if (node) {
		*hvaluep = avc_hash(ssid, tsid, tclass);
		avc_node_populate(node, ssid, tsid, tclass, ae);

		AVC_WRLOCK(*hvaluep);

		LIST_FOREACH(pos, &avc_cache.slots[*hvaluep], list) {
			if (pos->ae.ssid == ssid &&
			    pos->ae.tsid == tsid &&
			    pos->ae.tclass == tclass) {
			    	avc_node_replace(node, pos);
				goto found;
			}
		}
		LIST_INSERT_HEAD(&avc_cache.slots[*hvaluep], node, list);
	}
found:
	return node;
}

#ifdef __linux__
static inline void avc_print_ipv6_addr(struct audit_buffer *ab,
				       struct in6_addr *addr, __be16 port,
				       char *name1, char *name2)
{
	if (!ipv6_addr_any(addr))
		audit_log_format(ab, " %s=" NIP6_FMT, name1, NIP6(*addr));
	if (port)
		audit_log_format(ab, " %s=%d", name2, ntohs(port));
}

static inline void avc_print_ipv4_addr(struct audit_buffer *ab, u32 addr,
				       __be16 port, char *name1, char *name2)
{
	if (addr)
		audit_log_format(ab, " %s=" NIPQUAD_FMT, name1, NIPQUAD(addr));
	if (port)
		audit_log_format(ab, " %s=%d", name2, ntohs(port));
}
#endif /* __linux__ */


#define AVC_MSG_COST	avc_msg_cost
#define AVC_MSG_BURST	avc_msg_burst

/*
 * This enforces a rate limit: not more than one kernel message
 * every 5secs to make a denial-of-service attack impossible.
 */
static int avc_ratelimit(void)
{
	static uint64_t toks;
	static uint64_t last_msg;
	static int missed, rc;
	uint64_t now;

	now = mach_absolute_time();

	RATELIM_LOCK;
	toks += now - last_msg;
	last_msg = now;
	if (toks > AVC_MSG_BURST)
		toks = AVC_MSG_BURST;
	if (toks >= AVC_MSG_COST) {
		int lost = missed;
		missed = 0;
		toks -= AVC_MSG_COST;
		RATELIM_UNLOCK;
		if (lost)
			printk(KERN_WARNING "AVC: %d messages suppressed.\n",
			       lost);
		rc = 1;
		goto out;
	}
	missed++;
	RATELIM_UNLOCK;
out:
	return rc;
}

static inline int check_avc_ratelimit(void)
{

	/*
	 * If auditing is not enabled, suppress all messages.
	 */
	if (!selinux_auditing)
		return 0;

	/*
	 * If in permissive mode, display all messages.
	 */
	if (!selinux_enforcing)
		return 1;

	return avc_ratelimit();
}

/**
 * avc_audit - Audit the granting or denial of permissions.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions
 * @avd: access vector decisions
 * @result: result from avc_has_perm_noaudit
 * @a:  auxiliary audit data
 *
 * Audit the granting or denial of permissions in accordance
 * with the policy.  This function is typically called by
 * avc_has_perm() after a permission check, but can also be
 * called directly by callers who use avc_has_perm_noaudit()
 * in order to separate the permission check from the auditing.
 * For example, this separation is useful when the permission check must
 * be performed under a lock, to allow the lock to be released
 * before calling the auditing code.
 */
void avc_audit(u32 ssid, u32 tsid,
               u16 tclass, u32 requested,
               struct av_decision *avd, int result, struct avc_audit_data *a)
{
	struct proc *tsk = current_proc();
	u32 denied, audited;
	struct audit_buffer *ab;

	denied = requested & ~avd->allowed;
	if (denied) {
		audited = denied;
		if (!(audited & avd->auditdeny))
			return;
	} else if (result) {
		audited = denied = requested;
        } else {
		audited = requested;
		if (!(audited & avd->auditallow))
			return;
	}

	if (!check_avc_ratelimit())
		return;

	ab = audit_log_start();
	if (!ab)
		return;		/* audit_panic has been called */
	audit_log_format(ab, "avc:  %s ", denied ? "denied" : "granted");
	avc_dump_av(ab, tclass,audited);
	audit_log_format(ab, " for ");
#ifdef __linux__
	if (a && a->tsk)
		tsk = a->tsk;
#endif
	if (tsk && tsk->p_pid) {
		audit_log_format(ab, " pid=%d comm=", tsk->p_pid);
		audit_log_untrustedstring(ab, tsk->p_comm);
	}
	if (a) {
		switch (a->type) {
		case AVC_AUDIT_DATA_IPC:
			audit_log_format(ab, " key=%d", a->u.ipc_id);
			break;
#ifdef CAPABILITIES
		case AVC_AUDIT_DATA_CAP: {
			const char *capt = capv_to_text(a->u.cap);
			if (capt[7] == '!')
				audit_log_format(ab, " capability=<%lld>",
				    a->u.cap);
			else
				audit_log_format(ab, " capability=%s", capt);
			break;
		}
#endif
		case AVC_AUDIT_DATA_FS:
			if (a->u.fs.vp) {
				struct vnode *vp = a->u.fs.vp;
				struct vattr va;
				if (tsk && /*VOP_ISLOCKED(vp) &&*/
				    !VOP_GETATTR(vp, &va, tsk->p_ucred,
						 tsk)) {
					audit_log_format(ab,
					    " inode=%ld, mountpoint=%s, ",
					    va.va_fileid, 
					    vp->v_mount->mnt_stat.f_mntonname);
				} else {
					audit_log_format(ab,
					    " fs/inode info not available");
				}
			}
			break;
		case AVC_AUDIT_DATA_NET:
#ifdef __linux__
			if (a->u.net.sk) {
				struct sock *sk = a->u.net.sk;
				struct unix_sock *u;
				int len = 0;
				char *p = NULL;

				switch (sk->sk_family) {
				case AF_INET: {
					struct inet_sock *inet = inet_sk(sk);

					avc_print_ipv4_addr(ab, inet->rcv_saddr,
							    inet->sport,
							    "laddr", "lport");
					avc_print_ipv4_addr(ab, inet->daddr,
							    inet->dport,
							    "faddr", "fport");
					break;
				}
				case AF_INET6: {
					struct inet_sock *inet = inet_sk(sk);
					struct ipv6_pinfo *inet6 = inet6_sk(sk);

					avc_print_ipv6_addr(ab, &inet6->rcv_saddr,
							    inet->sport,
							    "laddr", "lport");
					avc_print_ipv6_addr(ab, &inet6->daddr,
							    inet->dport,
							    "faddr", "fport");
					break;
				}
				case AF_UNIX:
					u = unix_sk(sk);
					if (u->dentry) {
						audit_avc_path(u->dentry, u->mnt);
						audit_log_format(ab, " name=");
						audit_log_untrustedstring(ab, u->dentry->d_name.name);
						break;
					}
					if (!u->addr)
						break;
					len = u->addr->len-sizeof(short);
					p = &u->addr->name->sun_path[0];
					audit_log_format(ab, " path=");
					if (*p)
						audit_log_untrustedstring(ab, p);
					else
						audit_log_hex(ab, p, len);
					break;
				}
			}
			
			switch (a->u.net.family) {
			case AF_INET:
				avc_print_ipv4_addr(ab, a->u.net.v4info.saddr,
						    a->u.net.sport,
						    "saddr", "src");
				avc_print_ipv4_addr(ab, a->u.net.v4info.daddr,
						    a->u.net.dport,
						    "daddr", "dest");
				break;
			case AF_INET6:
				avc_print_ipv6_addr(ab, &a->u.net.v6info.saddr,
						    a->u.net.sport,
						    "saddr", "src");
				avc_print_ipv6_addr(ab, &a->u.net.v6info.daddr,
						    a->u.net.dport,
						    "daddr", "dest");
				break;
			}
			if (a->u.net.netif)
				audit_log_format(ab, " netif=%s",
					a->u.net.netif);
#endif /* __linux__ */
			break;
		}
	}
	audit_log_format(ab, " ");
	avc_dump_query(ab, ssid, tsid, tclass);
	audit_log_end(ab);
}

/**
 * avc_add_callback - Register a callback for security events.
 * @callback: callback function
 * @events: security events
 * @ssid: source security identifier or %SECSID_WILD
 * @tsid: target security identifier or %SECSID_WILD
 * @tclass: target security class
 * @perms: permissions
 *
 * Register a callback function for events in the set @events
 * related to the SID pair (@ssid, @tsid) and
 * and the permissions @perms, interpreting
 * @perms based on @tclass.  Returns %0 on success or
 * %ENOMEM if insufficient memory exists to add the callback.
 */
int avc_add_callback(int (*callback)(u32 event, u32 ssid, u32 tsid,
                                     u16 tclass, u32 perms,
                                     u32 *out_retained),
                     u32 events, u32 ssid, u32 tsid,
                     u16 tclass, u32 perms)
{
	struct avc_callback_node *c;
	int rc = 0;

	c = kmalloc(sizeof(*c), GFP_ATOMIC);
	if (!c) {
		rc = ENOMEM;
		goto out;
	}

	c->callback = callback;
	c->events = events;
	c->ssid = ssid;
	c->tsid = tsid;
	c->perms = perms;
	c->next = avc_callbacks;
	avc_callbacks = c;
out:
	return rc;
}

static inline int avc_sidcmp(u32 x, u32 y)
{
	return (x == y || x == SECSID_WILD || y == SECSID_WILD);
}

/**
 * avc_update_node Update an AVC entry
 * @event : Updating event
 * @perms : Permission mask bits
 * @ssid,@tsid,@tclass : identifier of an AVC entry
 *
 * if a valid AVC entry doesn't exist,this function returns ENOENT.
 * if kmalloc() called internal returns NULL, this function returns ENOMEM.
 * otherwise, this function update the AVC entry. The original AVC-entry object
 * is released.
 */
static int avc_update_node(u32 event, u32 perms, u32 ssid, u32 tsid, u16 tclass)
{
	int hvalue, rc = 0;
	struct avc_node *pos, *node, *orig = NULL;

	node = avc_alloc_node();
	if (!node) {
		rc = ENOMEM;
		goto out;
	}

	/* Lock the target slot */
	hvalue = avc_hash(ssid, tsid, tclass);
	AVC_WRLOCK(hvalue);

	LIST_FOREACH(pos, &avc_cache.slots[hvalue], list){
		if ( ssid==pos->ae.ssid &&
		     tsid==pos->ae.tsid &&
		     tclass==pos->ae.tclass ){
			orig = pos;
			break;
		}
	}

	if (!orig) {
		rc = ENOENT;
		avc_node_kill(node);
		goto out_unlock;
	}

	/*
	 * Copy and replace original node.
	 */

	avc_node_populate(node, ssid, tsid, tclass, &orig->ae);

	switch (event) {
	case AVC_CALLBACK_GRANT:
		node->ae.avd.allowed |= perms;
		break;
	case AVC_CALLBACK_TRY_REVOKE:
	case AVC_CALLBACK_REVOKE:
		node->ae.avd.allowed &= ~perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_ENABLE:
		node->ae.avd.auditallow |= perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_DISABLE:
		node->ae.avd.auditallow &= ~perms;
		break;
	case AVC_CALLBACK_AUDITDENY_ENABLE:
		node->ae.avd.auditdeny |= perms;
		break;
	case AVC_CALLBACK_AUDITDENY_DISABLE:
		node->ae.avd.auditdeny &= ~perms;
		break;
	}
	avc_node_replace(node, orig);
out_unlock:
	AVC_WRUNLOCK(hvalue);
out:
	return rc;
}

/**
 * avc_ss_reset - Flush the cache and revalidate migrated permissions.
 * @seqno: policy sequence number
 */
int avc_ss_reset(u32 seqno)
{
	struct avc_callback_node *c;
	int i, rc = 0;
	struct avc_node *node;


	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		AVC_WRLOCK(i);
		while ((node = LIST_FIRST(&avc_cache.slots[i])) != NULL)
			avc_node_delete(node);
		AVC_WRUNLOCK(i);
	}

	for (c = avc_callbacks; c; c = c->next) {
		if (c->events & AVC_CALLBACK_RESET) {
			rc = c->callback(AVC_CALLBACK_RESET,
					 0, 0, 0, 0, NULL);
			if (rc)
				goto out;
		}
	}

	avc_latest_notif_update(seqno, 0);
out:
	return rc;
}

/**
 * avc_has_perm_noaudit - Check permissions but perform no auditing.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @avd: access vector decisions
 *
 * Check the AVC to determine whether the @requested permissions are granted
 * for the SID pair (@ssid, @tsid), interpreting the permissions
 * based on @tclass, and call the security server on a cache miss to obtain
 * a new decision and add it to the cache.  Return a copy of the decisions
 * in @avd.  Return %0 if all @requested permissions are granted,
 * %EACCES if any permissions are denied, or another -errno upon
 * other errors.  This function is typically called by avc_has_perm(),
 * but may also be called directly to separate permission checking from
 * auditing, e.g. in cases where a lock must be held for the check but
 * should be released for the auditing.
 */
int avc_has_perm_noaudit(u32 ssid, u32 tsid,
                         u16 tclass, u32 requested,
                         struct av_decision *avd)
{
	struct avc_node *node;
	struct avc_entry entry, *p_ae;
	int hvalue, found, rc = 0;
	u32 denied;

	node = avc_lookup(ssid, tsid, tclass, requested, &hvalue);
	found = node != NULL;

	if (!found) {
		rc = security_compute_av(ssid,tsid,tclass,requested,&entry.avd);
		if (rc)
			goto out;
		node = avc_insert(ssid,tsid,tclass,&entry,&hvalue);
	}

	p_ae = node ? &node->ae : &entry;

	if (avd)
		memcpy(avd, &p_ae->avd, sizeof(*avd));

	denied = requested & ~(p_ae->avd.allowed);
	if (found)
		AVC_RDUNLOCK(hvalue);		/* locked by avc_lookup() */
	else if (node)
		AVC_WRUNLOCK(hvalue);		/* locked by avc_insert() */

	if (!requested || denied) {
		if (selinux_enforcing)
			rc = EACCES;
		else
			if (node)
				avc_update_node(AVC_CALLBACK_GRANT,requested,
						ssid,tsid,tclass);
	}

out:
	return rc;
}

/**
 * avc_has_perm - Check permissions and perform any appropriate auditing.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @auditdata: auxiliary audit data
 *
 * Check the AVC to determine whether the @requested permissions are granted
 * for the SID pair (@ssid, @tsid), interpreting the permissions
 * based on @tclass, and call the security server on a cache miss to obtain
 * a new decision and add it to the cache.  Audit the granting or denial of
 * permissions in accordance with the policy.  Return %0 if all @requested
 * permissions are granted, %EACCES if any permissions are denied, or
 * another -errno upon other errors.
 */
int avc_has_perm(u32 ssid, u32 tsid, u16 tclass,
                 u32 requested, struct avc_audit_data *auditdata)
{
	struct av_decision avd;
	int rc;

	rc = avc_has_perm_noaudit(ssid, tsid, tclass, requested, &avd);
	avc_audit(ssid, tsid, tclass, requested, &avd, rc, auditdata);
	return rc;
}
