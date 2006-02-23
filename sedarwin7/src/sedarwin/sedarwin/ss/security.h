/*
 * Security server interface.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
#ifndef _SELINUX_SECURITY_H_
#define _SELINUX_SECURITY_H_

#include <sedarwin/flask_types.h>
#include <sedarwin/flask.h>

#define SECSID_NULL			0x00000000 /* unspecified SID */
#define SECSID_WILD			0xffffffff /* wildcard SID */
#define SECCLASS_NULL			0x0000 /* no class */

#define SELINUX_MAGIC 0xf97cff8c

/* Identify specific policy version changes */
#define POLICYDB_VERSION_BASE		15
#define POLICYDB_VERSION_BOOL		16
#define POLICYDB_VERSION_IPV6		17
#define POLICYDB_VERSION_NLCLASS	18

/* Range of policy versions we understand*/
#define POLICYDB_VERSION_MIN   POLICYDB_VERSION_BASE
#define POLICYDB_VERSION_MAX   POLICYDB_VERSION_NLCLASS

#ifdef CONFIG_SECURITY_SELINUX_BOOTPARAM
extern int selinux_enabled;
#else
#define selinux_enabled 1
#endif

#ifdef CONFIG_SECURITY_SELINUX_MLS
#define selinux_mls_enabled 1
#else
#define selinux_mls_enabled 0
#endif

int security_load_policy(void * data, size_t len);

struct av_decision {
	access_vector_t allowed;
	access_vector_t decided;
	access_vector_t auditallow;
	access_vector_t auditdeny;
	u32 seqno;
};

int security_compute_av(security_id_t ssid, security_id_t tsid,
	security_class_t tclass, access_vector_t requested,
	struct av_decision *avd);

int security_transition_sid(security_id_t ssid, security_id_t tsid,
	security_class_t tclass, security_id_t *out_sid);

int security_member_sid(security_id_t ssid, security_id_t tsid,
	security_class_t tclass, security_id_t *out_sid);

int security_change_sid(security_id_t ssid, security_id_t tsid,
	security_class_t tclass, security_id_t *out_sid);

int security_sid_to_context(u32 sid, char **scontext,
	u32 *scontext_len);

int security_context_to_sid(char *scontext, u32 scontext_len,
	security_id_t *out_sid);

int security_get_user_sids(u32 callsid, char *username,
			   u32 **sids, u32 *nel);

int security_port_sid(u16 domain, u16 type, u8 protocol, u16 port,
	security_id_t *out_sid);

int security_netif_sid(char *name, u32 *if_sid,
	security_id_t *msg_sid);

int security_node_sid(u16 domain, void *addr, u32 addrlen,
	security_id_t *out_sid);

#define SECURITY_FS_USE_XATTR		1 /* use xattr */
#define SECURITY_FS_USE_TRANS		2 /* use transition SIDs, e.g. devpts/tmpfs */
#define SECURITY_FS_USE_TASK		3 /* use task SIDs, e.g. pipefs/sockfs */
#define SECURITY_FS_USE_GENFS		4 /* use the genfs support */
#define SECURITY_FS_USE_NONE		5 /* no labeling support */
#define SECURITY_FS_USE_MNTPOINT	6 /* use mountpoint labeling */

int security_fs_use(const char *fstype, unsigned int *behavior,
	security_id_t *sid);

int security_genfs_sid(const char *fstype, char *name, security_class_t sclass,
	security_id_t *sid);

#define security_free_context(ctx) ({ if (ctx) free(ctx, M_SEBSD); })

int security_get_bool_string(int *len, char *out);
int security_commit_pending_bools();
int security_set_bool(char *name, int value);
int security_get_bool(char *name, int *value, int *pending);

#endif /* _SELINUX_SECURITY_H_ */

