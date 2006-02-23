
/* -*- linux-c -*- */

/*
 * Author:  Stephen Smalley, NAI Labs, <ssmalley@nai.com>
 *
 * The access vector cache was originally written while I was employed by NSA,
 * and has undergone some revisions since I joined NAI Labs, but is largely
 * unchanged.
 */

/*
 * Implementation of the kernel access vector cache (AVC).
 */

#include <linux/types.h>
#include <linux/flask/avc.h>
#include <linux/flask/avc_ss.h>
#include <linux/flask/class_to_string.h>
#include <linux/flask/common_perm_to_string.h>
#include <linux/flask/av_inherit.h>
#include <linux/flask/av_perm_to_string.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "selinux_plug.h"

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
int avc_debug_always_allow = 1;
#endif

spinlock_t avc_lock = SPIN_LOCK_UNLOCKED;

unsigned        avc_cache_stats[AVC_NSTATS];



#if 0
static void avc_hash_eval(char *tag)
{
	int             i, chain_len, max_chain_len, slots_used;
	avc_node_t     *node;

	spin_lock(&avc_lock);

	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		node = avc_cache.slots[i];
		if (node) {
			slots_used++;
			chain_len = 0;
			while (node) {
				chain_len++;
				node = node->next;
			}
			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
	}

	spin_unlock(&avc_lock);

	printk("\n%s avc:  %d entries and %d/%d buckets used, longest chain length %d\n",
	       tag, avc_cache.activeNodes, slots_used, AVC_CACHE_SLOTS, max_chain_len);
}
#else
#define avc_hash_eval(t)
#endif




#define print_ipv4_addr(_addr,_port,_name1,_name2) { \
	if ((_addr)) \
		printk(" %s=%d.%d.%d.%d", (_name1), \
		       NIPQUAD((_addr))); \
	if ((_port)) \
		printk(" %s=%d", (_name2), ntohs((_port))); \
	}


/*
 * Copied from fs/dcache.c:d_path and hacked up to
 * avoid need for vfsmnt, root, and rootmnt parameters.
 */
char * avc_d_path(struct dentry *dentry, 
		  char *buffer, int buflen)
{
	char * end = buffer+buflen;
	char * retval;
	int namelen;

	*--end = '\0';
	buflen--;
	if (!IS_ROOT(dentry) && list_empty(&dentry->d_hash)) {
		buflen -= 10;
		end -= 10;
		memcpy(end, " (deleted)", 10);
	}

	/* Get '/' right */
	retval = end-1;
	*retval = '/';

	for (;;) {
		struct dentry * parent;

		if (IS_ROOT(dentry)) {
			goto global_root;
		}
		parent = dentry->d_parent;
		namelen = dentry->d_name.len;
		if (!namelen)
			goto skip;
		buflen -= namelen + 1;
		if (buflen < 0)
			break;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		retval = end;
skip:
		dentry = parent;
		if (!dentry)
			break;
	}
	return retval;
global_root:
	namelen = dentry->d_name.len;
	buflen -= namelen;
	if (buflen >= 0) {
		retval -= namelen-1;	/* hit the slash */
		memcpy(retval, dentry->d_name.name, namelen);
	}
	return retval;
}

/*
 * Copied from net/core/utils.c:net_ratelimit and modified for
 * use by the AVC audit facility.
 */

int avc_msg_cost = 5*HZ;
int avc_msg_burst = 10*5*HZ;

/* 
 * This enforces a rate limit: not more than one kernel message
 * every 5secs to make a denial-of-service attack impossible.
 */ 
int avc_ratelimit(void)
{
	static spinlock_t ratelimit_lock = SPIN_LOCK_UNLOCKED;
	static unsigned long toks = 10*5*HZ;
	static unsigned long last_msg; 
	static int missed;
	unsigned long flags;
	unsigned long now = jiffies;

	spin_lock_irqsave(&ratelimit_lock, flags);
	toks += now - last_msg;
	last_msg = now;
	if (toks > avc_msg_burst)
		toks = avc_msg_burst;
	if (toks >= avc_msg_cost) {
		int lost = missed;
		missed = 0;
		toks -= avc_msg_cost;
		spin_unlock_irqrestore(&ratelimit_lock, flags);
		if (lost)
			printk(KERN_WARNING "AVC: %d messages suppressed.\n", lost);
		return 1;
	}
	missed++;
	spin_unlock_irqrestore(&ratelimit_lock, flags);
	return 0;
}


#ifdef CONFIG_SECURITY_SELINUX_DEVELOP

static inline int check_avc_ratelimit(void)  
{
	if (avc_debug_always_allow)
		/* If permissive, then never suppress messages. */
		return 1;
	else
		return avc_ratelimit();
}

#else

static inline int check_avc_ratelimit(void)  
{
	return avc_ratelimit();
}

#endif



/*
 * Audit the granting or denial of permissions.
 */
void avc_audit(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass,	/* IN */
	access_vector_t audited,	/* IN */
	struct avc_entry *ae,		/* IN */
	__u32 denied,			/* IN */
	avc_audit_data_t *a)		/* IN */
{
	char *p;

	if (!check_avc_ratelimit())
		return;

	printk("\navc:  %s ", denied ? "denied" : "granted");
	avc_dump_av(tclass,audited);
	printk(" for ");
	if (current && current->pid) {
		printk(" pid=%d", current->pid);
		if (current->mm) {
			struct vm_area_struct *vma = current->mm->mmap;

			while (vma) {
				if ((vma->vm_flags & VM_EXECUTABLE) && 
				    vma->vm_file) {
					p = d_path(vma->vm_file->f_dentry, 
						   vma->vm_file->f_vfsmnt, 
						   avc_audit_buffer,
						   PAGE_SIZE);
					printk(" exe=%s", p);
					break;
				}
				vma = vma->vm_next;
			}
		}
	}
	if (a) {
		switch (a->type) {
		case AVC_AUDIT_DATA_IPC:
			printk(" IPCID=%d", a->u.ipc_id);
			break;
		case AVC_AUDIT_DATA_CAP:
			printk(" capability=%d", a->u.cap);
			break;
		case AVC_AUDIT_DATA_FS:
			if (a->u.fs.dentry) {
				struct inode *inode = a->u.fs.dentry->d_inode;

				p = avc_d_path(a->u.fs.dentry, 
					       avc_audit_buffer,
					       PAGE_SIZE);
				if (p)
					printk(" path=%s", p);

				if (inode) {
					printk(" dev=%s ino=%ld", 
					       kdevname(inode->i_dev),
					       inode->i_ino);
				}
			}

			if (a->u.fs.inode) {
				struct inode *inode = a->u.fs.inode;
				struct dentry *dentry = d_find_alias(inode);

				if (dentry) {
					p = avc_d_path(dentry, 
						       avc_audit_buffer,
						       PAGE_SIZE);
					if (p)
						printk(" path=%s", p);
					dput(dentry);
				}

				printk(" dev=%s ino=%ld", 
				       kdevname(inode->i_dev),inode->i_ino);
			}
			break;
		case AVC_AUDIT_DATA_NET:
			if (a->u.net.sk) {
				struct sock *sk = a->u.net.sk;

				switch (sk->family) {
				case AF_INET:
					print_ipv4_addr(sk->rcv_saddr,
							sk->sport,
							"laddr", "lport");
					print_ipv4_addr(sk->daddr,
							sk->dport,
							"faddr", "fport");
					break;
				case AF_UNIX: 
					if (sk->protinfo.af_unix.dentry) {
						p = d_path(sk->protinfo.af_unix.dentry, 
							   sk->protinfo.af_unix.mnt,
							   avc_audit_buffer,
							   PAGE_SIZE);
						printk(" path=%s", p);
					} else if (sk->protinfo.af_unix.addr) {
						p = avc_audit_buffer;
						memcpy(p,
						       sk->protinfo.af_unix.addr->name->sun_path,
						       sk->protinfo.af_unix.addr->len-sizeof(short));
						if (*p == 0) {
							*p = '@';
							p += sk->protinfo.af_unix.addr->len-sizeof(short);
							*p = 0;
						}
						printk(" path=%s", 
						       avc_audit_buffer);
					}
					break;
				}
			}
			if (a->u.net.daddr) {
				printk(" daddr=%d.%d.%d.%d", 
				       NIPQUAD(a->u.net.daddr));
				if (a->u.net.port)
					printk(" dest=%d", ntohs(a->u.net.port));
			} else if (a->u.net.port)
				printk(" port=%d", ntohs(a->u.net.port));
			if (a->u.net.skb) {
				struct sk_buff *skb = a->u.net.skb;

				if (skb->nh.iph) {
					__u16 source = 0, dest = 0;
					__u8  protocol = skb->nh.iph->protocol;


					if (protocol == IPPROTO_TCP && 
					    skb->h.th) {
						source = skb->h.th->source;
						dest = skb->h.th->dest;
					} 
					if (protocol == IPPROTO_UDP && 
					    skb->h.uh) {
						source = skb->h.uh->source;
						dest = skb->h.uh->dest;
					}

					print_ipv4_addr(skb->nh.iph->saddr,
							source,
							"saddr", "source");
					print_ipv4_addr(skb->nh.iph->daddr,
							dest,
							"daddr", "dest");
				}
			}
			if (a->u.net.netif)
				printk(" netif=%s", a->u.net.netif);
			break;
		}
	}
	printk(" ");
	avc_dump_query(ssid, tsid, tclass);
	printk("\n");
}

/*
 * Toggle the AVC between being permissive and 
 * enforcing permissions.  
 */
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
long sys_avc_toggle(void) 
{
	extern int ss_initialized;
	int error;

	error = task_has_system(current, SYSTEM__AVC_TOGGLE);
	if (error)
		return error;
	avc_debug_always_allow = !avc_debug_always_allow;
	if (!avc_debug_always_allow) {
		avc_ss_reset(avc_cache.latest_notif);
		if (!ss_initialized) {
			error = security_init();
			if (error)
				panic("SELinux:  Could not initialize\n");
		}
	}
	return avc_debug_always_allow;
}

long sys_avc_enforcing(void) 
{
	return !avc_debug_always_allow;
}
#else
long sys_avc_toggle(void) 
{
	return 0;
}

long sys_avc_enforcing(void) 
{
	return 1;
}
#endif


