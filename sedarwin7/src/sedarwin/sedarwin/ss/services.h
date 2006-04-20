/*
 * Implementation of the security services.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
#ifndef _SS_SERVICES_H_
#define _SS_SERVICES_H_

#include <sedarwin/ss/policydb.h>
#include <sedarwin/ss/sidtab.h>

/*
 * The security server uses two global data structures
 * when providing its services:  the SID table (sidtab)
 * and the policy database (policydb).
 */
extern struct sidtab sidtab;
extern struct policydb policydb;

/*
 * Security server locks, as allocated by security_init().
 */
extern lock_t *policy_rwlock;
extern mutex_t *load_sem;

#endif	/* _SS_SERVICES_H_ */

