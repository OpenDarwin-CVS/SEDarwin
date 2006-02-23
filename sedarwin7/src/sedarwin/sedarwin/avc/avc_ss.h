/*
 * Access vector cache interface for the security server.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
#ifndef _SELINUX_AVC_SS_H_
#define _SELINUX_AVC_SS_H_

#include <sedarwin/flask_types.h>
#include <sedarwin/linux-compat.h>
#include <sedarwin/flask.h>

int avc_ss_grant(security_id_t ssid, security_id_t tsid, security_class_t tclass, access_vector_t perms, u32 seqno);

int avc_ss_try_revoke(security_id_t ssid, security_id_t tsid, security_class_t tclass,
    access_vector_t perms, u32 seqno, access_vector_t *out_retained);

int avc_ss_revoke(security_id_t ssid, security_id_t tsid, security_class_t tclass, access_vector_t perms, u32 seqno);

int avc_ss_reset(u32 seqno);

int avc_ss_set_auditallow(security_id_t ssid, security_id_t tsid, security_class_t tclass, access_vector_t perms,
			  u32 seqno, u32 enable);

int avc_ss_set_auditdeny(security_id_t ssid, security_id_t tsid, security_class_t tclass, access_vector_t perms,
			 u32 seqno, u32 enable);

#endif /* _SELINUX_AVC_SS_H_ */

