/*
 * Access vector cache interface for object managers.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
#ifndef _SELINUX_AVC_H_
#define _SELINUX_AVC_H_

#include <sys/malloc.h>
#include <sys/lock.h>

#ifdef CAPABILITIES
#include <sys/capability.h>
#endif

#include <netinet/in.h>

#include <sedarwin/flask.h>
#include <sedarwin/sebsd.h>
#include <sedarwin/avc/av_permissions.h>
#include <sedarwin/ss/security.h>

extern int selinux_auditing;

#define CONFIG_SECURITY_SELINUX_DEVELOP

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
extern int selinux_enforcing;
#else
#define selinux_enforcing 1
#endif

/*
 * An entry in the AVC.
 */
struct avc_entry;

/*
 * A reference to an AVC entry.
 */
struct avc_entry_ref {
	struct avc_entry *ae;
};

/* Initialize an AVC entry reference before first use. */
static inline void avc_entry_ref_init(struct avc_entry_ref *h)
{
	h->ae = NULL;
}

struct vnode;

/* Auxiliary data to use in generating the audit record. */
struct avc_audit_data {
	char    type;
#define AVC_AUDIT_DATA_FS   1
#define AVC_AUDIT_DATA_NET  2
#define AVC_AUDIT_DATA_CAP  3
#define AVC_AUDIT_DATA_IPC  4
	union 	{
		struct {
			struct vnode *vp;
		} fs;
		struct {
			char *netif;
			struct sock *sk;
			u16 family;
			u16 dport;
			u16 sport;
			union {
				struct {
					u32 daddr;
					u32 saddr;
				} v4;
				struct {
					struct in6_addr daddr;
					struct in6_addr saddr;
				} v6;
			} fam;
		} net;
#ifdef CAPABILITIES
		cap_value_t cap;
#endif
		int ipc_id;
	} u;
};

/* Initialize an AVC audit data structure. */
#define AVC_AUDIT_DATA_INIT(_d,_t) \
        { memset((_d), 0, sizeof(struct avc_audit_data)); (_d)->type = AVC_AUDIT_DATA_##_t; }

/*
 * AVC statistics
 */
#define AVC_ENTRY_LOOKUPS        0
#define AVC_ENTRY_HITS	         1
#define AVC_ENTRY_MISSES         2
#define AVC_ENTRY_DISCARDS       3
#define AVC_CAV_LOOKUPS          4
#define AVC_CAV_HITS             5
#define AVC_CAV_PROBES           6
#define AVC_CAV_MISSES           7
#define AVC_NSTATS               8

/*
 * AVC display support
 */
void avc_dump_av(
	struct audit_buffer *ab,
	u16 tclass,	/* IN */
	u32 av);		/* IN */

void avc_dump_query(
	struct audit_buffer *ab,
	u32 ssid,		/* IN */
	u32 tsid,		/* IN */
	u16 tclass);	/* IN */

void avc_dump_cache(char *tag);

/*
 * AVC operations
 */

void avc_init(void);

int avc_lookup(
	u32 ssid,		/* IN */
	u32 tsid,		/* IN */
        u16 tclass,	/* IN */
	u32 requested,	/* IN */
	struct avc_entry_ref *aeref);	/* OUT */

int avc_insert(u32 ssid,		/* IN */
	       u32 tsid,		/* IN */
	       u16 tclass,		/* IN */
	       struct avc_entry *ae,		/* IN */
	       struct avc_entry_ref *out_aeref);	/* OUT */

void avc_audit(u32 ssid, u32 tsid,
               u16 tclass, u32 requested,
               struct av_decision *avd, int result, struct avc_audit_data *auditdata);

int avc_has_perm_noaudit(u32 ssid, u32 tsid,
                         u16 tclass, u32 requested,
                         struct avc_entry_ref *aeref, struct av_decision *avd);

int avc_has_perm(u32 ssid, u32 tsid,
                 u16 tclass, u32 requested,
                 struct avc_entry_ref *aeref, struct avc_audit_data *auditdata);

#define avc_has_perm_audit(ssid,tsid,tclass,perms,ad) \
   avc_has_perm(ssid,tsid,tclass,perms,NULL,ad)

#define avc_has_perm_ref_audit(ssid,tsid,tclass,perms,aeref,auditdata) \
   avc_has_perm(ssid,tsid,tclass,perms,aeref,auditdata)

#define avc_has_perm_ref(ssid,tsid,tclass,perms,aeref) \
   avc_has_perm(ssid,tsid,tclass,perms,aeref,NULL)

#define AVC_CALLBACK_GRANT		1
#define AVC_CALLBACK_TRY_REVOKE		2
#define AVC_CALLBACK_REVOKE		4
#define AVC_CALLBACK_RESET		8
#define AVC_CALLBACK_AUDITALLOW_ENABLE	16
#define AVC_CALLBACK_AUDITALLOW_DISABLE	32
#define AVC_CALLBACK_AUDITDENY_ENABLE	64
#define AVC_CALLBACK_AUDITDENY_DISABLE	128

int avc_add_callback(int (*callback)(u32 event, u32 ssid, u32 tsid,
                                     u16 tclass, u32 perms,
				     u32 *out_retained),
		     u32 events, u32 ssid, u32 tsid,
		     u16 tclass, u32 perms);

#endif /* _SELINUX_AVC_H_ */

