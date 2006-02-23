/*
 * Access vector cache interface for object managers.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
#ifndef _SELINUX_AVC_H_
#define _SELINUX_AVC_H_

#if defined(_KERNEL) || defined(KERNEL)
#include <sys/malloc.h>
#include <sys/lock.h>
#ifndef __APPLE__
#include <sys/mutex.h>
#endif
#else /* _KERNEL */
#include <unistd.h>
#endif /* _KERNEL */

#ifdef CAPABILITIES
#include <sys/capability.h>
#endif

#include <sedarwin/flask.h>
#include <sedarwin/sebsd.h>
#include <sedarwin/avc/av_permissions.h>
#include <sedarwin/ss/security.h>

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
			u16 port;
			u32 daddr;
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
	security_class_t tclass,	/* IN */
	access_vector_t av);		/* IN */

void avc_dump_query(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
	security_class_t tclass);	/* IN */

void avc_dump_cache(char *tag);

/*
 * AVC operations
 */

/* Initialize the AVC */
void avc_init(void);

int avc_lookup(
	security_id_t ssid,		/* IN */
	security_id_t tsid,		/* IN */
        security_class_t tclass,	/* IN */
	access_vector_t requested,	/* IN */
	struct avc_entry_ref *aeref);	/* OUT */

int avc_insert(security_id_t ssid,		/* IN */
	       security_id_t tsid,		/* IN */
	       security_class_t tclass,		/* IN */
	       struct avc_entry *ae,		/* IN */
	       struct avc_entry_ref *out_aeref);	/* OUT */

void avc_audit(security_id_t ssid, security_id_t tsid,
               security_class_t tclass, access_vector_t requested,
               struct av_decision *avd, int result, struct avc_audit_data *auditdata);

int avc_has_perm_noaudit(security_id_t ssid, security_id_t tsid,
                         security_class_t tclass, access_vector_t requested,
                         struct avc_entry_ref *aeref, struct av_decision *avd);

int avc_has_perm(security_id_t ssid, security_id_t tsid,
                 security_class_t tclass, access_vector_t requested,
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

int avc_add_callback(int (*callback)(u32 event, security_id_t ssid, security_id_t tsid,
                                     security_class_t tclass, access_vector_t perms,
				     access_vector_t *out_retained),
		     u32 events, security_id_t ssid, security_id_t tsid,
		     security_class_t tclass, access_vector_t perms);

#endif /* _LINUX_AVC_H_ */

