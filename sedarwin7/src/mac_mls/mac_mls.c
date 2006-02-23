/*-
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2001-2004 Networks Associates Technology, Inc.
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
 * $FreeBSD: src/sys/security/mac_mls/mac_mls.c,v 1.52 2003/08/21 14:34:54 rwatson Exp $
 */

/*
 * Developed by the TrustedBSD Project.
 * MLS fixed label mandatory confidentiality policy.
 */

#include <sys/types.h>
#include <sys/extattr.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lctx.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <sys/sysctl.h>
#include <sys/libkern.h>
#include <sys/ucred.h>
#include <sys/mac_policy.h>

#include <vm/vm_kern.h>
#include <kern/kalloc.h>
#include <mach/kmod.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <sys/fcntl.h>

#include <string.h>

#include "mac_mls.h"

#undef  MLS_TESTING

#ifdef MLS_TESTING

#warning Will not enforce MLS protection levels since MLS_TESTING is defined

#define MLS_FAILURE(args...) printf(args)
#define MLS_RETURN(err) ({ if(err) \
    printf ("mac_mls.c:%d: want to return: %s", __LINE__, #err); return 0; })

#define MLS_MESSAGE(args...) ({ if (mac_mls_enabled > 1) printf(args); })

#else /* MLS_TESTING */

#define MLS_FAILURE(args...) panic(args)
#define MLS_RETURN(err) return (err)
#define MLS_MESSAGE(args...)

#endif /* MLS_TESTING */

/*
 * Permission checks with auditing. The check flags can be combined in a 
 * single call. To use the MLS_RETURN_CHECK macro, the caller's scope must
 * have the subject and object labels (mls part) stored in "subj" and "obj".
 */

#define MLS_CHECK_S_DOM_O 1 /* e.g. read    */
#define MLS_CHECK_O_DOM_S 2 /* e.g. write   */
#define MLS_CHECK_EQUAL   3
#define MLS_CHECK_PRIV    4 /* special privilege: (low-high) or equal */

#define MLS_RETURN_CHECK(dir) \
	do { int err = mls_check(subj, obj, dir); MLS_RETURN(err); } while (0)

#ifdef APPLE
#define	TUNABLE_INT(x, y)
#define atomic_add_int(P, V)         (*(u_int*)(P) += (V))
#define atomic_subtract_int(P, V)    (*(u_int*)(P) -= (V))
#endif /* APPLE */

#define	SLOT(l)	((struct mac_mls *)LABEL_TO_SLOT((l), mac_mls_slot).l_ptr)

struct mac_policy_conf mac_mls_mac_policy_conf;

/*
 * SYSCTL entry points
 */

SYSCTL_DECL(_security_mac);

SYSCTL_NODE(_security_mac, OID_AUTO, mls, CTLFLAG_RW, 0,
    "TrustedBSD mac_mls policy controls");

static int	mac_mls_label_size = sizeof(struct mac_mls);
SYSCTL_INT(_security_mac_mls, OID_AUTO, label_size, CTLFLAG_RD,
    &mac_mls_label_size, 0, "Size of struct mac_mls");

static int	mac_mls_enabled = 1;
SYSCTL_INT(_security_mac_mls, OID_AUTO, enabled, CTLFLAG_RW,
    &mac_mls_enabled, 0, "Enforce MAC/MLS policy");
TUNABLE_INT("security.mac.mls.enabled", &mac_mls_enabled);

static int	destroyed_not_inited;
SYSCTL_INT(_security_mac_mls, OID_AUTO, destroyed_not_inited, CTLFLAG_RD,
    &destroyed_not_inited, 0, "Count of labels destroyed but not inited");

static int	ptys_equal = 0;
SYSCTL_INT(_security_mac_mls, OID_AUTO, ptys_equal, CTLFLAG_RW,
    &ptys_equal, 0, "Label pty devices as mls/equal on create");
TUNABLE_INT("security.mac.mls.ptys_equal", &ptys_equal);

static int	revocation_enabled = 0;
SYSCTL_INT(_security_mac_mls, OID_AUTO, revocation_enabled, CTLFLAG_RW,
    &revocation_enabled, 0, "Revoke access to objects on relabel");
TUNABLE_INT("security.mac.mls.revocation_enabled", &revocation_enabled);

static int	max_compartments = MAC_MLS_MAX_COMPARTMENTS;
SYSCTL_INT(_security_mac_mls, OID_AUTO, max_compartments, CTLFLAG_RD,
    &max_compartments, 0, "Maximum compartments the policy supports");

static int	mac_mls_slot;

/*
 * Utility functions
 */

static __inline int
mls_bit_set_empty(u_char *set) {
	int i;

	for (i = 0; i < MAC_MLS_MAX_COMPARTMENTS >> 3; i++)
		if (set[i] != 0)
			return (0);
	return (1);
}

static struct mac_mls *
mls_alloc(int flag)
{
	struct mac_mls *mac_mls;

	if (flag == M_WAITOK)
		mac_mls = (struct mac_mls *)kalloc(sizeof(struct mac_mls));
	else
		mac_mls = (struct mac_mls *)kalloc_noblock(sizeof(struct mac_mls));
	if (mac_mls != NULL)
		bzero(mac_mls, sizeof(struct mac_mls));

	return (mac_mls);
}

static void
mls_free(struct mac_mls *mac_mls)
{

	if (mac_mls != NULL)
		kfree((vm_offset_t)mac_mls, sizeof(struct mac_mls));
	else
		atomic_add_int(&destroyed_not_inited, 1);
}

static int
mls_atmostflags(struct mac_mls *mac_mls, int flags)
{

	if ((mac_mls->mm_flags & flags) != mac_mls->mm_flags)
	  MLS_RETURN (EINVAL);

	return (0);
}

/*
 * Does the level of subject A allow operations on object B?
 */

static int
mac_mls_dominate_element(struct mac_mls_element *a,
    struct mac_mls_element *b)
{
	int bit;

	KASSERT((a != NULL), ("mac_mls_dominate_element: a is NULL"));
	KASSERT((b != NULL), ("mac_mls_dominate_element: b is NULL"));
	switch (a->mme_type) {
	case MAC_MLS_TYPE_EQUAL:
	case MAC_MLS_TYPE_HIGH:
		return (1);

	case MAC_MLS_TYPE_LOW:
		switch (b->mme_type) {
		case MAC_MLS_TYPE_LEVEL:
		case MAC_MLS_TYPE_HIGH:
			return (0);

		case MAC_MLS_TYPE_EQUAL:
		case MAC_MLS_TYPE_LOW:
			return (1);

		default:
			MLS_FAILURE ("b->mme_type invalid");
		}

	case MAC_MLS_TYPE_LEVEL:
		switch (b->mme_type) {
		case MAC_MLS_TYPE_EQUAL:
		case MAC_MLS_TYPE_LOW:
			return (1);

		case MAC_MLS_TYPE_HIGH:
			return (0);

		case MAC_MLS_TYPE_LEVEL:
			for (bit = 1; bit <= MAC_MLS_MAX_COMPARTMENTS; bit++)
				if (!MAC_MLS_BIT_TEST(bit,
				    a->mme_compartments) &&
				    MAC_MLS_BIT_TEST(bit, b->mme_compartments))
					return (0);
			return (a->mme_level >= b->mme_level);

		default:
			MLS_FAILURE ("b->mme_type invalid");
		}

	default:
		MLS_FAILURE ("a->mme_type invalid");
	}

	return (0);
}

/*
 * Does the range of level of subject A fall into the range of allowable
 * levels on object B?
 */
static int
mac_mls_range_in_range(struct mac_mls *rangea, struct mac_mls *rangeb)
{

	return (mac_mls_dominate_element(&rangeb->mm_rangehigh,
	    &rangea->mm_rangehigh) &&
	    mac_mls_dominate_element(&rangea->mm_rangelow,
	    &rangeb->mm_rangelow));
}

/*
 * Does the effective level of subject fall into the range of allowable
 * levels on object
 */
static int
mac_mls_effective_in_range(struct mac_mls *effective, struct mac_mls *range)
{

	KASSERT((effective->mm_flags & MAC_MLS_FLAG_EFFECTIVE) != 0,
	    ("mac_mls_effective_in_range: a not effective"));
	KASSERT((range->mm_flags & MAC_MLS_FLAG_RANGE) != 0,
	    ("mac_mls_effective_in_range: b not range"));

	return (mac_mls_dominate_element(&range->mm_rangehigh,
	    &effective->mm_effective) &&
	    mac_mls_dominate_element(&effective->mm_effective,
	    &range->mm_rangelow));

	return (1);
}

static int
mac_mls_dominate_effective(struct mac_mls *a, struct mac_mls *b)
{
	KASSERT((a != NULL), ("mac_mls_dominate_effective: a is NULL"));
	KASSERT((b != NULL), ("mac_mls_dominate_effective: b is NULL"));
	KASSERT((a->mm_flags & MAC_MLS_FLAG_EFFECTIVE) != 0,
	    ("mac_mls_dominate_effective: a not effective"));
	KASSERT((b->mm_flags & MAC_MLS_FLAG_EFFECTIVE) != 0,
	    ("mac_mls_dominate_effective: b not effective"));

	return (mac_mls_dominate_element(&a->mm_effective, &b->mm_effective));
}

static int
mac_mls_equal_element(struct mac_mls_element *a, struct mac_mls_element *b)
{

	if (a->mme_type == MAC_MLS_TYPE_EQUAL ||
	    b->mme_type == MAC_MLS_TYPE_EQUAL)
		return (1);

	if (a->mme_type != b->mme_type)
		return (0);

	if (a->mme_type == MAC_MLS_TYPE_LEVEL) {
		int bit;

		if (a->mme_level != b->mme_level)
			return (0);

		for (bit = 1; bit <= MAC_MLS_MAX_COMPARTMENTS; bit++)
			if (MAC_MLS_BIT_TEST(bit, a->mme_compartments) !=
			    MAC_MLS_BIT_TEST(bit, b->mme_compartments))
				return (0);
	}

	return (1);
}

static int
mac_mls_equal_effective(struct mac_mls *a, struct mac_mls *b)
{

	KASSERT((a->mm_flags & MAC_MLS_FLAG_EFFECTIVE) != 0,
	    ("mac_mls_equal_effective: a not effective"));
	KASSERT((b->mm_flags & MAC_MLS_FLAG_EFFECTIVE) != 0,
	    ("mac_mls_equal_effective: b not effective"));

	return (mac_mls_equal_element(&a->mm_effective, &b->mm_effective));
}

static int
mac_mls_contains_equal(struct mac_mls *mac_mls)
{

	if (mac_mls->mm_flags & MAC_MLS_FLAG_EFFECTIVE)
		if (mac_mls->mm_effective.mme_type == MAC_MLS_TYPE_EQUAL)
			return (1);

	if (mac_mls->mm_flags & MAC_MLS_FLAG_RANGE) {
		if (mac_mls->mm_rangelow.mme_type == MAC_MLS_TYPE_EQUAL)
			return (1);
		if (mac_mls->mm_rangehigh.mme_type == MAC_MLS_TYPE_EQUAL)
			return (1);
	}

	return (0);
}

static int
mac_mls_subject_privileged(struct mac_mls *mac_mls)
{

	KASSERT((mac_mls->mm_flags & MAC_MLS_FLAGS_BOTH) ==
	    MAC_MLS_FLAGS_BOTH,
	    ("mac_mls_subject_privileged: subject doesn't have both labels"));

	/* If the effective is EQUAL, it's ok. */
	if (mac_mls->mm_effective.mme_type == MAC_MLS_TYPE_EQUAL)
		return (0);

	/* If either range endpoint is EQUAL, it's ok. */
	if (mac_mls->mm_rangelow.mme_type == MAC_MLS_TYPE_EQUAL ||
	    mac_mls->mm_rangehigh.mme_type == MAC_MLS_TYPE_EQUAL)
		return (0);

	/* If the range is low-high, it's ok. */
	if (mac_mls->mm_rangelow.mme_type == MAC_MLS_TYPE_LOW &&
	    mac_mls->mm_rangehigh.mme_type == MAC_MLS_TYPE_HIGH)
		return (0);

	/* It's not ok. */
	MLS_RETURN (EPERM);
}

static int
mac_mls_valid(struct mac_mls *mac_mls)
{

	KASSERT((mac_mls != NULL), ("mac_mls_valid: mac_mls is NULL"));
	if (mac_mls->mm_flags & MAC_MLS_FLAG_EFFECTIVE) {
		switch (mac_mls->mm_effective.mme_type) {
		case MAC_MLS_TYPE_LEVEL:
			break;

		case MAC_MLS_TYPE_EQUAL:
		case MAC_MLS_TYPE_HIGH:
		case MAC_MLS_TYPE_LOW:
			if (mac_mls->mm_effective.mme_level != 0 ||
			    !MAC_MLS_BIT_SET_EMPTY(
			    mac_mls->mm_effective.mme_compartments))
				MLS_RETURN (EINVAL);
			break;

		default:
			MLS_RETURN (EINVAL);
		}
	} else {
		if (mac_mls->mm_effective.mme_type != MAC_MLS_TYPE_UNDEF)
			MLS_RETURN (EINVAL);
	}

	if (mac_mls->mm_flags & MAC_MLS_FLAG_RANGE) {
		switch (mac_mls->mm_rangelow.mme_type) {
		case MAC_MLS_TYPE_LEVEL:
			break;

		case MAC_MLS_TYPE_EQUAL:
		case MAC_MLS_TYPE_HIGH:
		case MAC_MLS_TYPE_LOW:
			if (mac_mls->mm_rangelow.mme_level != 0 ||
			    !MAC_MLS_BIT_SET_EMPTY(
			    mac_mls->mm_rangelow.mme_compartments))
				MLS_RETURN (EINVAL);
			break;

		default:
			MLS_RETURN (EINVAL);
		}

		switch (mac_mls->mm_rangehigh.mme_type) {
		case MAC_MLS_TYPE_LEVEL:
			break;

		case MAC_MLS_TYPE_EQUAL:
		case MAC_MLS_TYPE_HIGH:
		case MAC_MLS_TYPE_LOW:
			if (mac_mls->mm_rangehigh.mme_level != 0 ||
			    !MAC_MLS_BIT_SET_EMPTY(
			    mac_mls->mm_rangehigh.mme_compartments))
				MLS_RETURN (EINVAL);
			break;

		default:
			MLS_RETURN (EINVAL);
		}
		if (!mac_mls_dominate_element(&mac_mls->mm_rangehigh,
		    &mac_mls->mm_rangelow))
			MLS_RETURN (EINVAL);
	} else {
		if (mac_mls->mm_rangelow.mme_type != MAC_MLS_TYPE_UNDEF ||
		    mac_mls->mm_rangehigh.mme_type != MAC_MLS_TYPE_UNDEF)
			MLS_RETURN (EINVAL);
	}

	return (0);
}

static void
mac_mls_set_range(struct mac_mls *mac_mls, u_short typelow,
    u_short levellow, u_char *compartmentslow, u_short typehigh,
    u_short levelhigh, u_char *compartmentshigh)
{

	mac_mls->mm_rangelow.mme_type = typelow;
	mac_mls->mm_rangelow.mme_level = levellow;
	if (compartmentslow != NULL)
		memcpy(mac_mls->mm_rangelow.mme_compartments,
		    compartmentslow,
		    sizeof(mac_mls->mm_rangelow.mme_compartments));
	mac_mls->mm_rangehigh.mme_type = typehigh;
	mac_mls->mm_rangehigh.mme_level = levelhigh;
	if (compartmentshigh != NULL)
		memcpy(mac_mls->mm_rangehigh.mme_compartments,
		    compartmentshigh,
		    sizeof(mac_mls->mm_rangehigh.mme_compartments));
	mac_mls->mm_flags |= MAC_MLS_FLAG_RANGE;
}

static void
mac_mls_set_effective(struct mac_mls *mac_mls, u_short type, u_short level,
    u_char *compartments)
{

	KASSERT((mac_mls != NULL), ("mac_mls_set_effective: mac_mls is NULL"));
	mac_mls->mm_effective.mme_type = type;
	mac_mls->mm_effective.mme_level = level;
	if (compartments != NULL)
		memcpy(mac_mls->mm_effective.mme_compartments, compartments,
		    sizeof(mac_mls->mm_effective.mme_compartments));
	mac_mls->mm_flags |= MAC_MLS_FLAG_EFFECTIVE;
}

static void
mac_mls_copy_range(struct mac_mls *labelfrom, struct mac_mls *labelto)
{

	KASSERT((labelfrom->mm_flags & MAC_MLS_FLAG_RANGE) != 0,
	    ("mac_mls_copy_range: labelfrom not range"));

	labelto->mm_rangelow = labelfrom->mm_rangelow;
	labelto->mm_rangehigh = labelfrom->mm_rangehigh;
	labelto->mm_flags |= MAC_MLS_FLAG_RANGE;
}

static void
mac_mls_copy_effective(struct mac_mls *labelfrom, struct mac_mls *labelto)
{

	KASSERT((labelfrom != NULL),
	    ("mac_mls_copy_effective: labelfrom is NULL"));
	KASSERT((labelto != NULL),
	    ("mac_mls_copy_effective: labelto is NULL"));
	KASSERT((labelfrom->mm_flags & MAC_MLS_FLAG_EFFECTIVE) != 0,
	    ("mac_mls_copy_effective: labelfrom not effective"));

	labelto->mm_effective = labelfrom->mm_effective;
	labelto->mm_flags |= MAC_MLS_FLAG_EFFECTIVE;
}

static void
mac_mls_copy(struct mac_mls *source, struct mac_mls *dest)
{

	KASSERT((source != NULL), ("mac_mls_copy: source is NULL"));
	KASSERT((dest != NULL), ("mac_mls_copy: dest is NULL"));
	if (source->mm_flags & MAC_MLS_FLAG_EFFECTIVE)
		mac_mls_copy_effective(source, dest);
	if (source->mm_flags & MAC_MLS_FLAG_RANGE)
		mac_mls_copy_range(source, dest);
}

/*
 * Policy module operations.
 * Visible through mac_policy_ops table below
 */
static void
mac_mls_destroy(struct mac_policy_conf *conf)
{

	MLS_MESSAGE("MAC MLS policy now destroyed\n");
}

static void
mac_mls_init(struct mac_policy_conf *conf)
{

	MLS_MESSAGE("MAC MLS policy is initialized\n");
}

static void
mac_mls_init_bsd(struct mac_policy_conf *conf)
{

	sysctl_register_oid(&sysctl__security_mac_mls);
	sysctl_register_oid(&sysctl__security_mac_mls_label_size);
	sysctl_register_oid(&sysctl__security_mac_mls_enabled);
	sysctl_register_oid(&sysctl__security_mac_mls_destroyed_not_inited);
	sysctl_register_oid(&sysctl__security_mac_mls_ptys_equal);
	sysctl_register_oid(&sysctl__security_mac_mls_revocation_enabled);
	sysctl_register_oid(&sysctl__security_mac_mls_max_compartments);
}

/*
 * Label operations.
 */
static void
mac_mls_init_label(struct label *label)
{

	SLOT(label) = mls_alloc(M_WAITOK);
}

static int
mac_mls_init_label_waitcheck(struct label *label, int flag)
{

	SLOT(label) = mls_alloc(flag);
	if (SLOT(label) == NULL) {
		MLS_MESSAGE("mac_mls_init_label_waitcheck : ENOMEM\n");
		return (ENOMEM);
	}

	return (0);
}

static void
mac_mls_destroy_label(struct label *label)
{

	mls_free(SLOT(label));
	SLOT(label) = NULL;
}

/*
 * mac_mls_compartment_to_string() takes an sbuf, range of compartments,
 * and flag indicating whether this is the first entry in a list of
 * compartments.  A string representing the compartment range will be
 * appended to the sbuf, or -1 will be returned if there wasn't space.
 */
static int
mac_mls_compartment_to_string(struct sbuf *sb, int start, int stop, int first)
{
	char *pluses, *prefix;

	if (stop == start + 1)
		pluses = "+";
	else
		pluses = "++";

	if (first)
		prefix = ":";
	else
		prefix = "+";

	if (stop == start)
		return (sbuf_printf(sb, "%s%d", prefix, start));
	else
		return (sbuf_printf(sb, "%s%d%s%d", prefix, start, pluses,
		    stop));
}

/*
 * mac_mls_element_to_string() accepts an sbuf and MLS element.  It
 * converts the MLS element to a string and stores the result in the
 * sbuf; if there isn't space in the sbuf, -1 is returned.
 */
static int
mac_mls_element_to_string(struct sbuf *sb, struct mac_mls_element *element)
{
	int i, first, start, stop, prevbit;

	switch (element->mme_type) {
	case MAC_MLS_TYPE_HIGH:
		return (sbuf_printf(sb, "high"));

	case MAC_MLS_TYPE_LOW:
		return (sbuf_printf(sb, "low"));

	case MAC_MLS_TYPE_EQUAL:
		return (sbuf_printf(sb, "equal"));

	case MAC_MLS_TYPE_LEVEL:
		if (sbuf_printf(sb, "%d", element->mme_level) == -1)
			return (-1);

		first = 1;		/* Need a ':' and no '+'. */
		start = 0; stop = 0;	/* No starting range. */
		prevbit = 0;		/* Was previous bit set? */
		for (i = 1; i <= MAC_MLS_MAX_COMPARTMENTS; i++) {
			if (MAC_MLS_BIT_TEST(i, element->mme_compartments)) {
				if (prevbit)
					stop = i;
				else {
					start = i;
					stop = i;
				}
				prevbit = 1;
			} else {
				if (prevbit) {
					if (mac_mls_compartment_to_string(sb,
					    start, stop, first) == -1)
						return (-1);
					if (first)
						first = 0;
				}
				prevbit = 0;
			}
		}
		/*
		 * If the last bit was set, we need to close that range to
		 * terminate the string.
		 */
		if (prevbit) {
			if (mac_mls_compartment_to_string(sb, start, stop,
			    first) == -1)
				return (-1);
		}
		return (0);

	default:
		MLS_FAILURE("invalid type (%d)", element->mme_type);
	}

	return (-1);  /* Unreachable */
}

/*
 * mac_mls_to_string() converts an MLS label to a string, and places
 * the results in the passed sbuf.  It returns 0 on success, or EINVAL
 * if there isn't room in the sbuf.  Note: the sbuf will be modified
 * even in a failure case, so the caller may need to revert the sbuf
 * by restoring the offset if that's undesired.
 */
static int
mac_mls_to_string(struct sbuf *sb, struct mac_mls *mac_mls)
{

	if (mac_mls->mm_flags & MAC_MLS_FLAG_EFFECTIVE) {
		if (mac_mls_element_to_string(sb, &mac_mls->mm_effective)
		    == -1) {
			MLS_MESSAGE("mac_mls_to_string : EINVAL\n");
			return (EINVAL);
		}
	}

	if (mac_mls->mm_flags & MAC_MLS_FLAG_RANGE) {
		if (sbuf_putc(sb, '(') == -1) {
			MLS_MESSAGE("mac_mls_to_string : EINVAL\n");
			return (EINVAL);
		}

		if (mac_mls_element_to_string(sb, &mac_mls->mm_rangelow)
		    == -1) {
			MLS_MESSAGE("mac_mls_to_string : EINVAL\n");
			return (EINVAL);
		}

		if (sbuf_putc(sb, '-') == -1) {
			MLS_MESSAGE("mac_mls_to_string : EINVAL\n");
			return (EINVAL);
		}

		if (mac_mls_element_to_string(sb, &mac_mls->mm_rangehigh)
		    == -1) {
			MLS_MESSAGE("mac_mls_to_string : EINVAL\n");
			return (EINVAL);
		}

		if (sbuf_putc(sb, ')') == -1) {
			MLS_MESSAGE("mac_mls_to_string : EINVAL\n");
			return (EINVAL);
		}
	}

	return (0);
}

static int
mac_mls_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb)
{
	struct mac_mls *mac_mls;

	mac_mls = SLOT(label);

	return (mac_mls_to_string(sb, mac_mls));
}

static int
mac_mls_parse_element(struct mac_mls_element *element, char *string)
{
	char *compartment, *end, *level;
	int i, inset, setbase, value;

	if (strcmp(string, "high") == 0 ||
	    strcmp(string, "hi") == 0) {
		element->mme_type = MAC_MLS_TYPE_HIGH;
		element->mme_level = 0;
	} else if (strcmp(string, "low") == 0 ||
	    strcmp(string, "lo") == 0) {
		element->mme_type = MAC_MLS_TYPE_LOW;
		element->mme_level = 0;
	} else if (strcmp(string, "equal") == 0 ||
	    strcmp(string, "eq") == 0) {
		element->mme_type = MAC_MLS_TYPE_EQUAL;
		element->mme_level = 0;
	} else {
		element->mme_type = MAC_MLS_TYPE_LEVEL;

		/*
		 * Numeric level piece of the element.
		 */
		level = strsep(&string, ":");
		value = strtol(level, &end, 10);
		if (end == level || *end != '\0') {
			MLS_MESSAGE("mac_mls_parse_element : EINVAL\n");
			return (EINVAL);
		}
		if (value < 0 || value > 65535) {
			MLS_MESSAGE("mac_mls_parse_element : EINVAL\n");
			return (EINVAL);
		}
		element->mme_level = value;

		/*
		 * Optional compartment piece of the element.  If none
		 * are included, we assume that the label has no
		 * compartments.
		 */
		if (string == NULL)
			return (0);
		if (*string == '\0')
			return (0);

		/*
		 * Because we support a notation that accepts 'X++Y' for a
		 * set of continuous compartment values, we must keep track
		 * of the most recent possible start value.  Initialize the
		 * tracking to (-1) to indicate that we don't have a base
		 * for the set yet.
		 */
		setbase = -1;
		inset = 0;
		while ((compartment = strsep(&string, "+")) != NULL) {
			if (*compartment == '\0') {
				/* No base yet. */
				if (setbase == -1) {
					MLS_MESSAGE("mac_mls_parse_element : EINVAL\n");
					return (EINVAL);
				}
				/* Already in set. */
				if (inset != 0) {
					MLS_MESSAGE("mac_mls_parse_element : EINVAL\n");
					return (EINVAL);
				}
				inset = 1;
				continue;
			}
			/*
			 * An actual entry in the list, possible following
			 * a continuous compartment set.
			 */
			value = strtol(compartment, &end, 10);
			if (compartment == end || *end != '\0') {
				MLS_MESSAGE("mac_mls_parse_element : EINVAL\n");
				return (EINVAL);
			}
			if (value < 1 || value > MAC_MLS_MAX_COMPARTMENTS) {
				MLS_MESSAGE("mac_mls_parse_element : EINVAL\n");
				return (EINVAL);
			}
			if (inset) {
				for (i = setbase; i <= value; i++) {
					MAC_MLS_BIT_SET(i,
					    element->mme_compartments);
				}
				inset = 0;
			} else
				MAC_MLS_BIT_SET(value,
				    element->mme_compartments);
			setbase = value;
		}
	}
	return (0);
}

/*
 * Note: destructively consumes the string, make a local copy before
 * calling if that's a problem.
 */
static int
mac_mls_parse(struct mac_mls *mac_mls, char *string)
{
	char *rangehigh, *rangelow, *effective;
	int error;

	effective = strsep(&string, "(");
	if (*effective == '\0')
		effective = NULL;

	if (string != NULL) {
		rangelow = strsep(&string, "-");
		if (string == NULL) {
			MLS_MESSAGE("mac_mls_parse : EINVAL\n");
			return (EINVAL);
		}
		rangehigh = strsep(&string, ")");
		if (string == NULL) {
			MLS_MESSAGE("mac_mls_parse : EINVAL\n");
			return (EINVAL);
		}
		if (*string != '\0') {
			MLS_MESSAGE("mac_mls_parse : EINVAL\n");
			return (EINVAL);
		}
	} else {
		rangelow = NULL;
		rangehigh = NULL;
	}

	KASSERT((rangelow != NULL && rangehigh != NULL) ||
	    (rangelow == NULL && rangehigh == NULL),
	    ("mac_mls_parse: range mismatch"));

	bzero(mac_mls, sizeof(*mac_mls));
	if (effective != NULL) {
		error = mac_mls_parse_element(&mac_mls->mm_effective, effective);
		if (error)
			return (error);
		mac_mls->mm_flags |= MAC_MLS_FLAG_EFFECTIVE;
	}

	if (rangelow != NULL) {
		error = mac_mls_parse_element(&mac_mls->mm_rangelow,
		    rangelow);
		if (error)
			return (error);
		error = mac_mls_parse_element(&mac_mls->mm_rangehigh,
		    rangehigh);
		if (error)
			return (error);
		mac_mls->mm_flags |= MAC_MLS_FLAG_RANGE;
	}

	error = mac_mls_valid(mac_mls);
	if (error)
		return (error);

	return (0);
}

static int
mac_mls_internalize_label(struct label *label, char *element_name,
    char *element_data)
{
	struct mac_mls *mac_mls, mac_mls_temp;
	int error;

	error = mac_mls_parse(&mac_mls_temp, element_data);
	if (error)
		return (error);

	mac_mls = SLOT(label);
	*mac_mls = mac_mls_temp;

	return (0);
}

static void
mac_mls_init_mbuf_failed_label(struct label *label)
{
/*
	For now this function sets the label to "mls/equal" to minimize
	the initial code breakage.  This label needs to be changed to
	a value more appropriate.
*/
	struct mac_mls *mac_mls;

	KASSERT((label != NULL),
	    ("mac_mls_init_mbuf_failed_label: label is NULL\n"));
	SLOT(label) = mls_alloc(M_NOWAIT);
	mac_mls = SLOT(label);
	KASSERT((mac_mls != NULL),
	    ("mac_mls_init_mbuf_failed_label failed.\n"));
	mac_mls->mm_flags = MAC_MLS_FLAG_EFFECTIVE;
	mac_mls->mm_effective.mme_type = MAC_MLS_TYPE_EQUAL;
	KASSERT ((mac_mls_valid(mac_mls) == 0),
	    ("mac_mls_init_mbuf_failed_label: built invalid label\n"));
}

static void
mac_mls_init_mbuf_unknown_source_label(struct label *label)
{
/*
	For now this function sets the label to "mls/equal" to minimize
	the initial code breakage.  This label needs to be changed to
	a value more appropriate.
*/
	struct mac_mls *mac_mls;

	KASSERT((label != NULL),
	    ("mac_mls_init_mbuf_unknown_source_label: label is NULL\n"));
	SLOT(label) = mls_alloc(M_NOWAIT);
	mac_mls = SLOT(label);
	KASSERT((mac_mls != NULL),
	    ("mac_mls_init_mbuf_unknown_source_label failed.\n"));
	mac_mls->mm_flags = MAC_MLS_FLAG_EFFECTIVE;
	mac_mls->mm_effective.mme_type = MAC_MLS_TYPE_EQUAL;
	KASSERT ((mac_mls_valid(mac_mls) == 0),
	    ("mac_mls_init_mbuf_unknown_source_label: built invalid label\n"));
}

static void
mac_mls_init_tcp_label(struct label *label)
{
/*
	For now this function sets the label to "mls/equal" to minimize
	the initial code breakage.  This label needs to be changed to
	a value more appropriate.
*/
	struct mac_mls *mac_mls;

	KASSERT((label != NULL),
	    ("mac_mls_init_tcp_label: label is NULL\n"));
	SLOT(label) = mls_alloc(M_NOWAIT);
	mac_mls = SLOT(label);
	KASSERT((mac_mls != NULL), ("mac_mls_init_tcp_label failed.\n"));
	mac_mls->mm_flags = MAC_MLS_FLAG_EFFECTIVE;
	mac_mls->mm_effective.mme_type = MAC_MLS_TYPE_EQUAL;
	KASSERT ((mac_mls_valid(mac_mls) == 0),
	    ("mac_mls_init_tcp_label: built invalid label\n"));
}

static void
mac_mls_copy_label(struct label *src, struct label *dest)
{

	*SLOT(dest) = *SLOT(src);
}

/*
 * Audit a single MLS label. The name should describe the purpose
 * of the label (e.g. "directory" or "relabel_to"). Note that subject and
 * many object labels are added to the audit trail by the audit system itself.
 */
static void
mls_audit_label(const char *name, struct mac_mls *l)
{
	struct sbuf sb;
	int ret;	
	
	if (!kau_will_audit())
		return;
	
	if (sbuf_new(&sb, NULL, 0, SBUF_AUTOEXTEND) == NULL)
		MLS_FAILURE("mls_audit_label: failed to allocate an sbuf for auditing\n");
	sbuf_printf(&sb, "%s: ", name);
	mac_mls_to_string(&sb, l);
	sbuf_finish(&sb);
	ret = mac_audit_text (sbuf_data(&sb), &mac_mls_mac_policy_conf);
	if (ret)
		MLS_FAILURE("mls_audit_label: audit failed (err code %d)\n", ret);	
	sbuf_delete(&sb);
}

static int
mls_check(struct mac_mls *subj, struct mac_mls *obj, int check)
{

	if (check & MLS_CHECK_S_DOM_O)
		if (!mac_mls_dominate_effective(subj, obj))
			return (EACCES);
	if (check & MLS_CHECK_O_DOM_S)
		if (!mac_mls_dominate_effective(obj, subj))
			return (EACCES);
	if (check & MLS_CHECK_PRIV)
		if (!mac_mls_subject_privileged(subj))
			return (EPERM);

	return (0);
}

/*
 * Labeling event operations: file system objects, and things that look
 * a lot like file system objects.
 */
static void
mac_mls_create_devfs_device(struct ucred *cr, struct mount *mp,
    dev_t dev, struct devnode *de, struct label *label, const char *fullpath)
{
	struct mac_mls *mac_mls;
	int mls_type;

	mac_mls = SLOT(label);
	if (strcmp(fullpath, "null") == 0 ||
	    strcmp(fullpath, "zero") == 0 ||
	    strcmp(fullpath, "random") == 0 ||
	    strncmp(fullpath, "fd/", strlen("fd/")) == 0)
		mls_type = MAC_MLS_TYPE_EQUAL;
	else if (strcmp(fullpath, "kmem") == 0 ||
	    strcmp(fullpath, "mem") == 0)
		mls_type = MAC_MLS_TYPE_HIGH;
	else if (ptys_equal &&
	    (strncmp(fullpath, "ttyp", strlen("ttyp")) == 0 ||
	    strncmp(fullpath, "ptyp", strlen("ptyp")) == 0))
		mls_type = MAC_MLS_TYPE_EQUAL;
	else
		mls_type = MAC_MLS_TYPE_LOW;
	mac_mls_set_effective(mac_mls, mls_type, 0, NULL);
}

static void
mac_mls_create_devfs_directory(struct mount *mp, char *dirname,
    int dirnamelen, struct devnode *de, struct label *label,
    const char *fullpath)
{
	struct mac_mls *mac_mls;

	mac_mls = SLOT(label);
	mac_mls_set_effective(mac_mls, MAC_MLS_TYPE_LOW, 0, NULL);
}

static void
mac_mls_create_devfs_symlink(struct ucred *cred, struct mount *mp,
    struct devnode *dd, struct label *ddlabel, struct devnode *de,
    struct label *delabel, const char *fullpath)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred->cr_label);
	dest = SLOT(delabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_mount(struct ucred *cred, struct mount *mp,
    struct label *mntlabel, struct label *fslabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred->cr_label);
	dest = SLOT(mntlabel);
	mac_mls_copy_effective(source, dest);
	dest = SLOT(fslabel);
	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_init_port_label(struct label *label)
{

	SLOT(label) = mls_alloc(M_WAITOK);
}

static void
mac_mls_create_port (struct label *it, struct label *st, struct label *port)
{
	struct mac_mls *source, *dest;

	source = SLOT(it);
	dest = SLOT(port);
	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_kernel_port(struct label *port, int isreply)
{
	struct mac_mls *dest;

	dest = SLOT(port);
	mac_mls_set_effective(dest, MAC_MLS_TYPE_EQUAL, 0, NULL);
}

static void
mac_mls_create_task (struct task *parent, struct task *child, struct label *pl,
    struct label *chl, struct label *chpl)
{
	struct mac_mls *source, *dest;

	source = SLOT(pl);
	dest = SLOT(chl);
	mac_mls_copy_effective(source, dest);
	dest = SLOT(chpl);
	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_kernel_task(struct task *t, struct label *tl, struct label *tportl)
{
	struct mac_mls *dest;

	dest = SLOT(tl);
	mac_mls_set_effective(dest, MAC_MLS_TYPE_HIGH, 0, NULL);
	dest = SLOT(tportl);
	mac_mls_set_effective(dest, MAC_MLS_TYPE_HIGH, 0, NULL);
}

static void
mac_mls_copy_cred_to_task (struct label *cred, struct label *task)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred);
	dest = SLOT(task);

	mac_mls_copy(source, dest);	
}

static void
mac_mls_update_port_from_cred_label(struct label *cred, struct label *port)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred);
	dest = SLOT(port);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_relabel_vnode(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, struct label *label)
{
	struct mac_mls *source, *dest;

	source = SLOT(label);
	dest = SLOT(vnodelabel);

	mac_mls_copy(source, dest);
}


static void
mac_mls_update_devfsdirent(struct mount *mp, struct devnode *devfs_dirent,
    struct label *direntlabel, struct vnode *vp, struct label *vnodelabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(vnodelabel);
	dest = SLOT(direntlabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_associate_vnode_devfs(struct mount *mp, struct label *fslabel,
    struct devnode *de, struct label *delabel, struct vnode *vp,
    struct label *vlabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(delabel);
	dest = SLOT(vlabel);

	mac_mls_copy_effective(source, dest);
}

static int
mac_mls_associate_vnode_extattr(struct mount *mp, struct label *fslabel,
    struct vnode *vp, struct label *vlabel)
{
	struct mac_mls temp, *source, *dest;
	struct proc *p = current_proc();
	int buflen, error;

	source = SLOT(fslabel);
	dest = SLOT(vlabel);

	buflen = sizeof(temp);
	bzero(&temp, buflen);

	error = vn_extattr_get(vp, IO_NODELOCKED, MAC_MLS_EXTATTR_NAMESPACE,
	    MAC_MLS_EXTATTR_NAME, &buflen, (char *) &temp, p);
	if (error == ENOATTR || error == EOPNOTSUPP) {
		/* Fall back to the fslabel. */
		mac_mls_copy_effective(source, dest);
		return (0);
	} else if (error)
		return (error);

	if (buflen != sizeof(temp)) {
		printf("mac_mls_associate_vnode_extattr: bad size %d\n",
		    buflen);
		MLS_MESSAGE("mac_mls_associate_vnode_extattr : EPERM\n");
		return (EPERM);
	}
	if (mac_mls_valid(&temp) != 0) {
		printf("mac_mls_associate_vnode_extattr: invalid\n");
		MLS_MESSAGE("mac_mls_associate_vnode_extattr : EPERM\n");
		return (EPERM);
	}
	if ((temp.mm_flags & MAC_MLS_FLAGS_BOTH) != MAC_MLS_FLAG_EFFECTIVE) {
		printf("mac_mls_associated_vnode_extattr: not effective\n");
		MLS_RETURN (EPERM);
	}

	mac_mls_copy_effective(&temp, dest);
	return (0);
}

static void
mac_mls_associate_vnode_singlelabel(struct mount *mp,
    struct label *fslabel, struct vnode *vp, struct label *vlabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(fslabel);
	dest = SLOT(vlabel);

	mac_mls_copy_effective(source, dest);
}

static int
mac_mls_create_vnode_extattr(struct ucred *cred, struct mount *mp,
    struct label *fslabel, struct vnode *dvp, struct label *dlabel,
    struct vnode *vp, struct label *vlabel, struct componentname *cnp)
{
	struct mac_mls *source, *dest, temp;
	struct proc *p = current_proc();
	size_t buflen;
	int error;

	buflen = sizeof(temp);
	bzero(&temp, buflen);

	source = SLOT(cred->cr_label);
	dest = SLOT(vlabel);
	mac_mls_copy_effective(source, &temp);

	error = vn_extattr_set(vp, IO_NODELOCKED, MAC_MLS_EXTATTR_NAMESPACE,
	    MAC_MLS_EXTATTR_NAME, buflen, (char *) &temp, p);
	if (error == 0)
		mac_mls_copy_effective(source, dest);

	return (error);
}

static int
mac_mls_setlabel_vnode_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vlabel, struct label *intlabel)
{
	struct proc *p = current_proc();
	struct mac_mls *source, temp;
	size_t buflen;
	int error;

	buflen = sizeof(temp);
	bzero(&temp, buflen);

	source = SLOT(intlabel);
	if ((source->mm_flags & MAC_MLS_FLAG_EFFECTIVE) == 0)
        {
            return (0);
        }

	mac_mls_copy_effective(source, &temp);

	error = vn_extattr_set(vp, IO_NODELOCKED, MAC_MLS_EXTATTR_NAMESPACE,
	    MAC_MLS_EXTATTR_NAME, buflen, (char *) &temp, p);

	return (error);
}


static void
mac_mls_create_posix_sem(struct ucred *cred, struct pseminfo *sem,
    struct label *semlabel, const char *name)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred->cr_label);
	dest = SLOT(semlabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_posix_shm(struct ucred *cred, struct pshminfo *shm,
    struct label *shmlabel, const char *name)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred->cr_label);
	dest = SLOT(shmlabel);

	mac_mls_copy_effective(source, dest);
}

#ifdef LATER
/*
 * Labeling event operations: System V IPC objects.
 */
static void
mac_mls_create_sysv_sem(struct ucred *cred, struct semid_kernel *semakptr,
    struct label *semalabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred->cr_label);
	dest = SLOT(semalabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_sysv_shm(struct ucred *cred, struct shmid_kernel *shmsegptr,
    struct label *shmlabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred->cr_label);
	dest = SLOT(shmlabel);

	mac_mls_copy_effective(source, dest);
}
#endif /* LATER */

/*
 * Labeling event operations: network objects.
 */
static void
mac_mls_create_socket(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred->cr_label);
	dest = SLOT(solabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_socket_from_socket(
    struct socket *oldsock, struct label *oldlabel,
    struct socket *newsock, struct label *newlabel)
{
	struct mac_mls *source, *dest;

	KASSERT((oldlabel != NULL),
	    ("mac_mls_create_socket_from_socket: oldlabel is NULL"));
	KASSERT((newlabel != NULL),
	    ("mac_mls_create_socket_from_socket: newlabel is NULL"));
	source = SLOT(oldlabel);
	dest = SLOT(newlabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_relabel_socket(struct ucred *cred, struct socket *so,
    struct label *oldlabel, struct label *newlabel)
{
	struct mac_mls *source, *dest;
	int error;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_relabel_socket: cred->cr_label is NULL"));
	KASSERT((newlabel != NULL),
	    ("mac_mls_relabel_socket: newlabel is NULL"));
	source = SLOT(newlabel);
	dest = SLOT(oldlabel);
	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_mbuf_from_socket(struct socket *so, struct label *socketlabel,
    struct mbuf *m, struct label *mbuflabel)
{
	struct mac_mls *source, *dest;

	KASSERT((socketlabel != NULL),
	    ("mac_mls_create_mbuf_from_socket: socketlabel is NULL"));
	KASSERT((mbuflabel != NULL),
	    ("mac_mls_create_mbuf_from_socket: mbuflabel is NULL"));
	source = SLOT(socketlabel);
	dest = SLOT(mbuflabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_set_socket_peer_from_mbuf(struct mbuf *mbuf, struct label *mbuflabel,
    struct socket *socket, struct label *socketpeerlabel)
{
	struct mac_mls *source, *dest;

	KASSERT((mbuflabel != NULL),
	    ("mac_mls_set_socket_peer_from_mbuf: mbuflabel is NULL"));
	KASSERT((socketpeerlabel != NULL),
	    ("mac_mls_set_socket_peer_from_mbuf: socketpeerlabel is NULL"));
	source = SLOT(mbuflabel);
	dest = SLOT(socketpeerlabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_set_socket_peer_from_socket(struct socket *oldsocket,
    struct label *oldsocketlabel, struct socket *newsocket,
    struct label *newsocketpeerlabel)
{
	struct mac_mls *source, *dest;

	KASSERT((oldsocketlabel != NULL),
	    ("mac_mls_set_socket_peer_from_socket: oldsocketlabel is NULL"));
	KASSERT((newsocketpeerlabel != NULL),
	    ("mac_mls_set_socket_peer_from_socket: newsocketpeerlabel is NULL"));
	source = SLOT(oldsocketlabel);
	dest = SLOT(newsocketpeerlabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_bpfdesc(struct ucred *cred, struct bpf_d *bpf_d,
    struct label *bpflabel)
{
	struct mac_mls *source, *dest;

	KASSERT((bpflabel != NULL),
	    ("mac_mls_create_bpfdesc: bpflabel is NULL"));
	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_create_bpfdesc: cred->cr_label is NULL"));
	source = SLOT(cred->cr_label);
	dest = SLOT(bpflabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_ifnet(struct ifnet *ifnet, struct label *ifnetlabel)
{
	struct mac_mls *dest;
	int type;

	dest = SLOT(ifnetlabel);

	if (ifnet->if_type == IFT_LOOP)
		type = MAC_MLS_TYPE_EQUAL;
	else
		type = MAC_MLS_TYPE_LOW;

	mac_mls_set_effective(dest, type, 0, NULL);
	mac_mls_set_range(dest, type, 0, NULL, type, 0, NULL);
}

static void
mac_mls_create_datagram_from_ipq(struct ipq *ipq, struct label *ipqlabel,
    struct mbuf *datagram, struct label *datagramlabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(ipqlabel);
	dest = SLOT(datagramlabel);

	/* Just use the head, since we require them all to match. */
	mac_mls_copy_effective(source, dest);
}


static void
mac_mls_create_mbuf_from_mbuf(struct mbuf *oldmbuf,
    struct label *oldmbuflabel, struct mbuf *newmbuf,
    struct label *newmbuflabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(oldmbuflabel);
	dest = SLOT(newmbuflabel);

	/*
	 * Because the source mbuf may not yet have been "created",
	 * just initialized, we do a conditional copy.  Since we don't
	 * allow mbufs to have ranges, do a KASSERT to make sure that
	 * doesn't happen.
	 */
	KASSERT((source->mm_flags & MAC_MLS_FLAG_RANGE) == 0,
	    ("mac_mls_create_mbuf_from_mbuf: source mbuf has range"));
	mac_mls_copy(source, dest);
}

static void
mac_mls_create_mbuf_linklayer(struct ifnet *ifnet, struct label *ifnetlabel,
    struct mbuf *mbuf, struct label *mbuflabel)
{
	struct mac_mls *dest;

	dest = SLOT(mbuflabel);

	mac_mls_set_effective(dest, MAC_MLS_TYPE_EQUAL, 0, NULL);
}

static void
mac_mls_create_mbuf_from_bpfdesc(struct bpf_d *bpf_d, struct label *bpflabel,
    struct mbuf *mbuf, struct label *mbuflabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(bpflabel);
	dest = SLOT(mbuflabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_mbuf_multicast_encap(struct mbuf *oldmbuf,
    struct label *oldmbuflabel, struct ifnet *ifnet, struct label *ifnetlabel,
    struct mbuf *newmbuf, struct label *newmbuflabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(oldmbuflabel);
	dest = SLOT(newmbuflabel);

	mac_mls_copy_effective(source, dest);
}

static void
mac_mls_create_mbuf_netlayer(struct mbuf *oldmbuf, struct label *oldmbuflabel,
    struct mbuf *newmbuf, struct label *newmbuflabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(oldmbuflabel);
	dest = SLOT(newmbuflabel);

	mac_mls_copy_effective(source, dest);
}

static int
mac_mls_fragment_match(struct mbuf *fragment, struct label *fragmentlabel,
    struct ipq *ipq, struct label *ipqlabel)
{
	struct mac_mls *a, *b;

	a = SLOT(ipqlabel);
	b = SLOT(fragmentlabel);

	return (mac_mls_equal_effective(a, b));
}

static void
mac_mls_relabel_ifnet(struct ucred *cred, struct ifnet *ifnet,
    struct label *ifnetlabel, struct label *newlabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(newlabel);
	dest = SLOT(ifnetlabel);

	mac_mls_copy(source, dest);
}

static void
mac_mls_update_ipq(struct mbuf *fragment, struct label *fragmentlabel,
    struct ipq *ipq, struct label *ipqlabel)
{

	/* NOOP: we only accept matching labels, so no need to update */
}

/*
 * Labeling event operations: processes.
 */
static void
mac_mls_create_cred(struct ucred *cred_parent, struct ucred *cred_child)
{
	struct mac_mls *source, *dest;

	source = SLOT(cred_parent->cr_label);
	dest = SLOT(cred_child->cr_label);

	mac_mls_copy_effective(source, dest);
	mac_mls_copy_range(source, dest);
}

static void
mac_mls_create_proc0(struct ucred *cred)
{
	struct mac_mls *dest;

	dest = SLOT(cred->cr_label);

	mac_mls_set_effective(dest, MAC_MLS_TYPE_EQUAL, 0, NULL);
	mac_mls_set_range(dest, MAC_MLS_TYPE_LOW, 0, NULL, MAC_MLS_TYPE_HIGH,
	    0, NULL);
}

static void
mac_mls_create_proc1(struct ucred *cred)
{
	struct mac_mls *dest;

	dest = SLOT(cred->cr_label);

	mac_mls_set_effective(dest, MAC_MLS_TYPE_EQUAL, 0, NULL);
	mac_mls_set_range(dest, MAC_MLS_TYPE_LOW, 0, NULL, MAC_MLS_TYPE_HIGH,
	    0, NULL);
}

static void
mac_mls_relabel_cred(struct ucred *cred, struct label *newlabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(newlabel);
	dest = SLOT(cred->cr_label);

	mac_mls_copy(source, dest);
}

#ifdef LATER
/*
 * Label cleanup/flush operations.
 */
static void
mac_mls_cleanup_sysv_sem_label(struct label *semalabel)
{

	bzero(SLOT(semalabel), sizeof(struct mac_mls));
}

static void
mac_mls_cleanup_sysv_shm_label(struct label *shmlabel)
{

	bzero(SLOT(shmlabel), sizeof(struct mac_mls));
}
#endif /* LATER */

/*
 * Access control checks.
 */
static int
mac_mls_check_system_audit(struct ucred *cred, void *record, int length)
{
	struct mac_mls *subj;
	int error;

	subj = SLOT(cred->cr_label);
	error = mac_mls_subject_privileged(subj);

	return(error);
}

static int
mac_mls_check_system_auditon(struct ucred *cred, int cmd)
{
	struct mac_mls *subj;
	int error;

	subj = SLOT(cred->cr_label);
	error = mac_mls_subject_privileged(subj);

	return(error);
}

static int
mac_mls_check_system_auditctl(struct ucred *cred, struct vnode *vp, struct label *vl)
{
	struct mac_mls *subj, *obj;
	int error;

	subj = SLOT(cred->cr_label);
	error = mac_mls_subject_privileged(subj);

	if (error == 0) {
		if (vl != NULL) {
			obj = SLOT(vl);
			if (obj->mm_effective.mme_type != MAC_MLS_TYPE_HIGH)
				error = EPERM;
		}
	}

	return(error);
}

static int
mac_mls_check_proc_getauid(struct ucred *cred)
{
	struct mac_mls *subj;
	int error;

	subj = SLOT(cred->cr_label);
	error = mac_mls_subject_privileged(subj);

	return(error);
}

static int
mac_mls_check_proc_setauid(struct ucred *cred, uid_t auid)
{
	struct mac_mls *subj;
	int error;

	subj = SLOT(cred->cr_label);
	error = mac_mls_subject_privileged(subj);

	return(error);
}

static int
mac_mls_check_proc_getaudit(struct ucred *cred)
{
	struct mac_mls *subj;
	int error;

	subj = SLOT(cred->cr_label);
	error = mac_mls_subject_privileged(subj);

	return(error);
}

static int
mac_mls_check_proc_setaudit(struct ucred *cred, struct auditinfo *ai)
{
	struct mac_mls *subj;
	int error;

	subj = SLOT(cred->cr_label);
	error = mac_mls_subject_privileged(subj);

	return(error);
}

static int
mac_mls_check_proc_setlcid (struct proc *p0, struct proc *p,
			    pid_t pid, pid_t lcid)
{
	struct mac_mls *source, *dest;

	/* Create/Join/Leave */
	if (pid == LCID_PROC_SELF)
		return (0);

	switch (lcid) {
	case LCID_REMOVE:	/* Orphan */

		/* loginwindow.app/MAC.loginPlugin orphaned process. */
		dest = SLOT(p->p_ucred->cr_label);

		mac_mls_set_effective(dest, MAC_MLS_TYPE_EQUAL, 0, NULL);
		mac_mls_set_range(dest, MAC_MLS_TYPE_LOW, 0, NULL,
				  MAC_MLS_TYPE_HIGH, 0, NULL);
		break;

	case LCID_CREATE:	/* Create */
		/* nop */
		break;
	default:		/* Adopt */

		/* loginwindow.app/MAC.loginPlugin adopted process. */

		source = SLOT(p0->p_ucred->cr_label);
		dest = SLOT(p->p_ucred->cr_label);

		mac_mls_copy(source, dest);

		break;
	}

	return (0);
}

static int
mac_mls_audit_preselect(struct ucred *cred, unsigned short syscode,
        void *args)
{
	struct mac_mls *subj;
	u_short type;
	char buf[256];

	subj = SLOT(cred->cr_label);

	/* Use the default preselection mask if the subject is privileged */
	if(0 == mac_mls_subject_privileged(subj))
		return (MAC_AUDIT_DEFAULT);

	type = subj->mm_effective.mme_type;

	/* Always audit here */
	if (type == MAC_MLS_TYPE_HIGH)
		return (MAC_AUDIT_YES);

	/* Never audit here */
	if (type == MAC_MLS_TYPE_LOW)
		return (MAC_AUDIT_NO);

	/* Anything else, use the default preselection masks */
	return (MAC_AUDIT_DEFAULT);
}

static int
mac_mls_audit_postselect(struct ucred *cred, unsigned short syscode,
        void *args, int error, int retval)
{
	struct mac_mls *subj;
	u_short type;
	char buf[256];

	subj = SLOT(cred->cr_label);
	type = subj->mm_effective.mme_type;

	/* For high, low or privileged, don't supress any records */
	if((0 == mac_mls_subject_privileged(subj)) ||
	   (type == MAC_MLS_TYPE_HIGH) || 
	   (type == MAC_MLS_TYPE_HIGH))
		return MAC_AUDIT_DEFAULT;

	/* Don't audit success */ 
	if(!error)
		return MAC_AUDIT_NO;

	return (MAC_AUDIT_DEFAULT);
}

static int
mac_mls_check_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	struct mac_mls *subj, *new;
	int error;

	subj = SLOT(cred->cr_label);
	new = SLOT(newlabel);

	mls_audit_label("relabel_to", new);

	/*
	 * If there is an MLS label update for the credential, it may be
	 * an update of effective, range, or both.
	 */
	error = mls_atmostflags(new, MAC_MLS_FLAGS_BOTH);
	if (error)
		return (error);

	/*
	 * If the MLS label is to be changed, authorize as appropriate.
	 */
	if (new->mm_flags & MAC_MLS_FLAGS_BOTH) {
		/*
		 * If the change request modifies both the MLS label effective
		 * and range, check that the new effective will be in the
		 * new range.
		 */
		if ((new->mm_flags & MAC_MLS_FLAGS_BOTH) ==
		    MAC_MLS_FLAGS_BOTH &&
		    !mac_mls_effective_in_range(new, new))
			MLS_RETURN (EINVAL);

		/*
		 * To change the MLS effective label on a credential, the
		 * new effective label must be in the current range.
		 */
		if (new->mm_flags & MAC_MLS_FLAG_EFFECTIVE &&
		    !mac_mls_effective_in_range(new, subj))
			MLS_RETURN (EPERM);

		/*
		 * To change the MLS range label on a credential, the
		 * new range must be in the current range.
		 */
		if (new->mm_flags & MAC_MLS_FLAG_RANGE &&
		    !mac_mls_range_in_range(new, subj))
			MLS_RETURN (EPERM);

		/*
		 * To have EQUAL in any component of the new credential
		 * MLS label, the subject must already have EQUAL in
		 * their label, or a range of (low-high).
		 */
		if (mac_mls_contains_equal(new)) {
			error = mac_mls_subject_privileged(subj);
			if (error)
				return (error);
		}
	}

	return (0);
}

static int
mac_mls_check_cred_visible(struct ucred *u1, struct ucred *u2)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(u1->cr_label);
	obj = SLOT(u2->cr_label);

	/* XXX: range */
	if (!mac_mls_dominate_effective(subj, obj))
		MLS_RETURN (ESRCH);

	return (0);
}

static int
mac_mls_check_posix_sem_open(struct ucred *cred, struct pseminfo *sem,
    struct label *semlabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(semlabel);

	if (!mac_mls_dominate_effective(subj, obj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_posix_sem_write(struct ucred *cred, struct pseminfo *sem,
    struct label *semlabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(semlabel);

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_posix_sem_rw(struct ucred *cred, struct pseminfo *sem,
    struct label *semlabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(semlabel);

	if (!mac_mls_dominate_effective(subj, obj) ||
	    !mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_posix_sem_unlink(struct ucred *cred, struct pseminfo *sem,
    struct label *semlabel, const char *semname)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(semlabel);

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_posix_shm_truncate(struct ucred *cred, struct pshminfo *shm,
    struct label *shmlabel, size_t s)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(shmlabel);

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_posix_shm_unlink(struct ucred *cred, struct pshminfo *shm,
    struct label *shmlabel, const char *shmname)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(shmlabel);

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_posix_shm_read(struct ucred *cred, struct pshminfo *shm,
    struct label *shmlabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(shmlabel);

	if (!mac_mls_dominate_effective(subj, obj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_posix_shm_mmap(struct ucred *cred, struct pshminfo *shm,
    struct label *shmlabel, int flags, int prot)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(shmlabel);

	/* pshm doesn't allow private mappings, no need to check the flags */

	if (flags & PROT_READ && !mac_mls_dominate_effective(subj, obj))
		MLS_RETURN (EACCES);
	if (flags & PROT_WRITE && !mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_socket_accept(struct ucred *cred, struct socket *socket,
    struct label *socklabel, struct sockaddr *addr)
{
	struct mac_mls *subj, *obj;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_accept: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_accept: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);
	MLS_RETURN_CHECK(MLS_CHECK_EQUAL);
}

static int
mac_mls_check_socket_bind(struct ucred *cred, struct socket *socket,
    struct label *socklabel, struct sockaddr *addr)
{
	struct mac_mls *subj, *obj;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_bind: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_bind: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);
	MLS_RETURN_CHECK(MLS_CHECK_EQUAL);
}

static int
mac_mls_check_socket_connect(struct ucred *cred, struct socket *socket,
    struct label *socklabel, struct sockaddr *addr)
{
	struct mac_mls *subj, *obj;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_connect: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_connect: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);
	MLS_RETURN_CHECK(MLS_CHECK_EQUAL);
}

static int
mac_mls_check_socket_deliver(struct socket *so, struct label *so_label,
    struct mbuf *m, struct label *m_label)
{
	struct mac_mls *src, *dest;

	KASSERT((m_label != NULL),
	    ("mac_mls_check_socket_deliver: m_label is NULL"));
	KASSERT((so_label != NULL),
	    ("mac_mls_check_socket_deliver: so_label is NULL"));
	if (!mac_mls_enabled)
		return (0);

	src = SLOT(m_label);
	dest = SLOT(so_label);

	if (!mac_mls_dominate_effective(dest, src))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_socket_poll(struct ucred *cred, struct socket *socket,
    struct label *socklabel)
{
	struct mac_mls *subj, *obj;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_poll: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_poll: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);
	MLS_RETURN_CHECK(MLS_CHECK_EQUAL);
}

static int
mac_mls_check_socket_listen(struct ucred *cred, struct socket *socket,
    struct label *socklabel)
{
	struct mac_mls *subj, *obj;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_listen: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_listen: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);
	MLS_RETURN_CHECK(MLS_CHECK_EQUAL);
}

static int
mac_mls_check_socket_receive(struct ucred *cred, struct socket *socket,
    struct label *socklabel)
{
	struct mac_mls *subj, *obj;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_receive: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_receive: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);
	MLS_RETURN_CHECK(MLS_CHECK_EQUAL);
}

static int
mac_mls_check_socket_relabel(struct ucred *cred, struct socket *so,
    struct label *socklabel, struct label *newlabel)
{
	struct mac_mls *subj, *obj, *new;
	int error;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_relabel: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_relabel: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	new = SLOT(newlabel);
	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);

	/*
	 * If there is an MLS label update for the socket, it may be
	 * an update of effective.
	 */
	error = mls_atmostflags(new, MAC_MLS_FLAG_EFFECTIVE);
	if (error)
		return (error);

	/*
	 * To relabel a socket, the old socket effective must be in the subject
	 * range.
	 */
	if (!mac_mls_effective_in_range(obj, subj))
		return (EPERM);
	
	/*
	 * If the MLS label is to be changed, authorize as appropriate.
	 */
	if (new->mm_flags & MAC_MLS_FLAG_EFFECTIVE) {
	  /*
	   * To relabel a socket, the new socket effective must be in
	   * the subject range.
	   */
		if (!mac_mls_effective_in_range(new, subj))
			return (EPERM);

		/*
		 * To change the MLS label on the socket to contain EQUAL,
		 * the subject must have appropriate privilege.
		 */
		if (mac_mls_contains_equal(new)) {
			error = mac_mls_subject_privileged(subj);
			if (error)
				return (error);
		}
	}

	return (0);
}

static int
mac_mls_check_socket_select(struct ucred *cred, struct socket *so,
    struct label *socklabel)
{
	struct mac_mls *subj, *obj;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_select: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_select: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);
	MLS_RETURN_CHECK(MLS_CHECK_EQUAL);
}

static int
mac_mls_check_socket_send(struct ucred *cred, struct socket *so,
    struct label *socklabel)
{
	struct mac_mls *subj, *obj;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_send: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_send: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);
	MLS_RETURN_CHECK(MLS_CHECK_EQUAL);
}

static int
mac_mls_check_socket_stat(struct ucred *cred, struct socket *so,
    struct label *socklabel)
{
	struct mac_mls *subj, *obj;

	KASSERT((cred->cr_label != NULL),
	    ("mac_mls_check_socket_stat: cred->cr_label is NULL"));
	KASSERT((socklabel != NULL),
	    ("mac_mls_check_socket_stat: socklabel is NULL"));
	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(socklabel);
	MLS_RETURN_CHECK(MLS_CHECK_EQUAL);
}

#ifdef LATER
static int
mac_mls_check_sysv_semctl(struct ucred *cred, struct semid_kernel *semakptr,
    int cmd)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(&semakptr->label);

	switch(cmd) {
	case IPC_RMID:
	case IPC_SET:
	case SETVAL:
	case SETALL:
		if (!mac_mls_dominate_effective(obj, subj))
			MLS_RETURN (EACCES);
		break;

	case IPC_STAT:
	case GETVAL:
	case GETPID:
	case GETNCNT:
	case GETZCNT:
	case GETALL:
		if (!mac_mls_dominate_effective(subj, obj))
			MLS_RETURN (EACCES);
		break;

	default:
		MLS_RETURN (EACCES);
	}

	return (0);
}

static int
mac_mls_check_sysv_semget(struct ucred *cred, struct semid_kernel *semakptr)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(&semakptr->label);

	if (!mac_mls_dominate_effective(subj, obj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_sysv_semop(struct ucred *cred, struct semid_kernel *semakptr,
    size_t accesstype)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(&semakptr->label);

	if( accesstype & SEM_R )
		if (!mac_mls_dominate_effective(subj, obj))
			MLS_RETURN (EACCES);

	if( accesstype & SEM_A )
		if (!mac_mls_dominate_effective(obj, subj))
			MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_sysv_shmat(struct ucred *cred, struct shmid_kernel *shmsegptr,
    int shmflg)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(&shmsegptr->label);

	if (!mac_mls_dominate_effective(subj, obj))
		MLS_RETURN (EACCES);
	if ((shmflg & SHM_RDONLY) == 0)
		if (!mac_mls_dominate_effective(obj, subj))
			MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_sysv_shmctl(struct ucred *cred, struct shmid_kernel *shmsegptr,
    int cmd)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(&shmsegptr->label);

	switch(cmd) {
	case IPC_RMID:
	case IPC_SET:
		if (!mac_mls_dominate_effective(obj, subj))
			MLS_RETURN (EACCES);
		break;

	case IPC_STAT:
	case SHM_STAT:
		if (!mac_mls_dominate_effective(subj, obj))
			MLS_RETURN (EACCES);
		break;

	default:
		MLS_RETURN (EACCES);
	}

	return (0);
}

#if 0
/*
 * TODO: Do we check the integrity of the implicit write access caused
 * by the bookkeeping tasks associated with the shmdt call, which may
 * modify/delete the shmseg meta-data and/or the shared segment itself?
 */
static int
mac_mls_check_sysv_shmdt(struct ucred *cred, struct shmid_kernel *shmsegptr)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(&shmsegptr->label);

	if (!mac_mls_dominate_effective(obj, subj))
		return (EACCES);

	return (0);
}
#endif

static int
mac_mls_check_sysv_shmget(struct ucred *cred, struct shmid_kernel *shmsegptr,
    int shmflg)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(&shmsegptr->label);

	if (!mac_mls_dominate_effective(subj, obj))
		MLS_RETURN (EACCES);

	return (0);
}
#endif /* LATER */

static int
mac_mls_check_mount_stat(struct ucred *cred, struct mount *mp,
    struct label *mntlabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(mntlabel);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_port_send(struct label *task, struct label *port)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(task);
	obj = SLOT(port);

	if (subj != NULL && obj != NULL &&
	    !mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_port_hold_receive(struct label *task, struct label *port)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(task);
	obj = SLOT(port);

	if (!mac_mls_dominate_effective(subj, obj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_port_hold_send(struct label *task, struct label *port)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(task);
	obj = SLOT(port);

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_port_relabel(struct label *task, struct label *oldlabel, struct label *newlabel)
{
	struct mac_mls *old, *new, *subj;
	int error;

	old = SLOT(oldlabel);
	new = SLOT(newlabel);
	subj = SLOT(task);

	/*
	 * If there is an MLS label update for the port, it must be a
	 * effective label.
	 */
	error = mls_atmostflags(new, MAC_MLS_FLAG_EFFECTIVE);
	if (error)
		return (error);

	/*
	 * To perform a relabel of the port (MLS label or not), MLS must
	 * authorize the relabel.
	 */
	if (!mac_mls_effective_in_range(old, subj))
		MLS_RETURN (EPERM);

	/*
	 * If the MLS label is to be changed, authorize as appropriate.
	 */
	if (new->mm_flags & MAC_MLS_FLAG_EFFECTIVE) {
		/*
		 * To change the MLS label on an object, the new label
		 * must be in the subject range.
		 */
		if (!mac_mls_effective_in_range(new, subj))
			MLS_RETURN (EPERM);

		/*
		 * To change the MLS label on an object to be EQUAL,
		 * the subject must have appropriate privilege.
		 */
		if (mac_mls_contains_equal(new)) {
			error = mac_mls_subject_privileged(subj);
			if (error)
				return (error);
		}
	}

	return (0);
}

static int
mac_mls_check_proc_debug(struct ucred *cred, struct proc *proc)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(proc->p_ucred->cr_label);

	/* XXX: range checks */
	MLS_RETURN_CHECK (MLS_CHECK_EQUAL);
}

static int
mac_mls_check_proc_sched(struct ucred *cred, struct proc *proc)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(proc->p_ucred->cr_label);

	/* XXX: range checks */
	MLS_RETURN_CHECK (MLS_CHECK_EQUAL);
}

static int
mac_mls_check_proc_signal(struct ucred *cred, struct proc *proc, int signum)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(proc->p_ucred->cr_label);

	/* XXX: range checks */
	MLS_RETURN_CHECK (MLS_CHECK_EQUAL);
}

static int
mac_mls_check_system_swapon(struct ucred *cred, struct vnode *vp,
    struct label *label)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(label);

	MLS_RETURN_CHECK (MLS_CHECK_EQUAL);
}

static int
mac_mls_check_vnode_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(dlabel);
	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_chroot(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(dlabel);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_create(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp, struct vattr *vap)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(dlabel);

	/* Audit here to capture the parent directory's label */
	mls_audit_label("directory", obj);

	MLS_RETURN_CHECK (MLS_CHECK_O_DOM_S);
}

static int
mac_mls_check_vnode_delete(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(dlabel);

	/* Audit here to capture the parent directory's label */
	mls_audit_label("directory", obj);

	if (mls_check(subj, obj, MLS_CHECK_O_DOM_S))
		MLS_RETURN (EACCES);

	obj = SLOT(label);

	if (mls_check(subj, obj, MLS_CHECK_O_DOM_S))
		MLS_RETURN (EACCES);

	return (0);
}

#if 0
static int
mac_mls_check_vnode_deleteextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(label);

	if (!mac_mls_dominate_effective(obj, subj))
		return (EACCES);

	return (0);
}
#endif

static int
mac_mls_check_vnode_exchangedata(struct ucred *cred,
    struct vnode *v1, struct label *vl1, struct vnode *v2, struct label *vl2)
{
	int error;
	struct mac_mls *subj, *obj;

	subj = SLOT(cred->cr_label);
	obj = SLOT(vl1);

	error = mls_check(subj, obj, MLS_CHECK_S_DOM_O | MLS_CHECK_O_DOM_S);
	if (error)
		return (error);

	obj = SLOT(vl2);
	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O | MLS_CHECK_O_DOM_S);
}

static int
mac_mls_check_vnode_exec(struct ucred *cred, struct vnode *vp,
    struct label *label, struct label *execlabel)
{
	struct mac_mls *subj, *obj, *exec;
	int error;

	if (execlabel != NULL) {
		/*
		 * We currently don't permit labels to be changed at
		 * exec-time as part of MLS, so disallow non-NULL
		 * MLS label elements in the execlabel.
		 */
		exec = SLOT(execlabel);
		error = mls_atmostflags(exec, 0);
		if (error)
			return (error);
	}

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(label);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_getattrlist(struct ucred *cred, struct vnode *vp,
    struct label *vlabel, struct attrlist *alist, struct uio *attrblk)
{
	struct mac_mls *subj, *obj;

	subj = SLOT(cred->cr_label);
	obj = SLOT(vlabel);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *label, int attrnamespace, const char *name, struct uio *uio)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(label);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_link(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(dlabel);

	/* Audit here to capture the parent directory's label */
	mls_audit_label("directory", obj);

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	obj = SLOT(label);

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

#if 0
static int
mac_mls_check_vnode_listextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(label);

	if (!mac_mls_dominate_effective(subj, obj))
		return (EACCES);

	return (0);
}
#endif

static int
mac_mls_check_vnode_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct componentname *cnp)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(dlabel);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_mmap(struct ucred *cred, struct vnode *vp,
    struct label *label, int prot, int flags, int *maxprot)
{
	struct mac_mls *subj, *obj;
	int sdo, ods;

	/*
	 * Rely on the use of open()-time protections to handle
	 * non-revocation cases.
	 */
	if (!mac_mls_enabled || !revocation_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(label);
	sdo = mac_mls_dominate_effective(subj, obj);
	ods = mac_mls_dominate_effective(obj, subj);

	if (!sdo) {
		if (prot & (VM_PROT_READ | VM_PROT_EXECUTE))
			MLS_RETURN (EACCES);
		(*maxprot) &= ~VM_PROT_READ;
		(*maxprot) &= ~VM_PROT_EXECUTE;
	}
	if (!ods && flags & MAP_SHARED) {
		if (prot & VM_PROT_WRITE)
			MLS_RETURN (EACCES);
		(*maxprot) &= ~VM_PROT_WRITE;
	}

	return (0);
}

static int
mac_mls_check_vnode_open(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, int fmode)
{
	struct mac_mls *subj, *obj;
        int acc_mode = 0;

	if (fmode & O_TRUNC)
	  acc_mode |= VWRITE;
	if (fmode & FWRITE)
	  acc_mode |= VWRITE;
	if (fmode & FREAD)
	  acc_mode |= VREAD;

	if (!acc_mode)
		return 0;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(vnodelabel);

	/* XXX privilege override for admin? */
	int checks = 0;
	if (acc_mode & (VREAD | VEXEC))
		checks |= MLS_CHECK_S_DOM_O;
	if (acc_mode & (VWRITE | VADMIN))
		checks |= MLS_CHECK_O_DOM_S;

	MLS_RETURN_CHECK (checks);
}

static int
mac_mls_check_vnode_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *label)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled || !revocation_enabled)
		return (0);

	subj = SLOT(active_cred->cr_label);
	obj = SLOT(label);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *label)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled || !revocation_enabled)
		return (0);

	subj = SLOT(active_cred->cr_label);
	obj = SLOT(label);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_readdir(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(dlabel);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(vnodelabel);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, struct label *newlabel)
{
	struct mac_mls *old, *new, *subj;
	int error;

	old = SLOT(vnodelabel);
	new = SLOT(newlabel);
	subj = SLOT(cred->cr_label);

	mls_audit_label("object", old);
	mls_audit_label("relabel_to", new);

	/*
	 * If there is an MLS label update for the vnode, it must be a
	 * effective label.
	 */
	error = mls_atmostflags(new, MAC_MLS_FLAG_EFFECTIVE);
	if (error)
		return (error);

	/*
	 * To perform a relabel of the vnode (MLS label or not), MLS must
	 * authorize the relabel.
	 */
	if (!mac_mls_effective_in_range(old, subj))
		MLS_RETURN (EPERM);

	/*
	 * If the MLS label is to be changed, authorize as appropriate.
	 */
	if (new->mm_flags & MAC_MLS_FLAG_EFFECTIVE) {
		/*
		 * To change the MLS label on a vnode, the new vnode label
		 * must be in the subject range.
		 */
		if (!mac_mls_effective_in_range(new, subj))
			MLS_RETURN (EPERM);

		/*
		 * To change the MLS label on the vnode to be EQUAL,
		 * the subject must have appropriate privilege.
		 */
		if (mac_mls_contains_equal(new)) {
			error = mac_mls_subject_privileged(subj);
			if (error)
				return (error);
		}
	}

	return (0);
}


static int
mac_mls_check_vnode_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label,
    struct componentname *cnp)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(dlabel);

	mls_audit_label("source directory", obj);

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	obj = SLOT(label);

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	return (0);
}

static int
mac_mls_check_vnode_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dlabel, struct vnode *vp, struct label *label, int samedir,
    struct componentname *cnp)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(dlabel);

	mls_audit_label("target directory", obj);
	if (vp)
		mls_audit_label("target file", SLOT(label));

	if (!mac_mls_dominate_effective(obj, subj))
		MLS_RETURN (EACCES);

	if (vp != NULL) {
		obj = SLOT(label);

		if (!mac_mls_dominate_effective(obj, subj))
			MLS_RETURN (EACCES);
	}

	return (0);
}

static int
mac_mls_check_vnode_revoke(struct ucred *cred, struct vnode *vp,
    struct label *label)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(label);

	MLS_RETURN_CHECK (MLS_CHECK_O_DOM_S);
}

static int
mac_mls_check_vnode_setattrlist(struct ucred *cred, struct vnode *vp,
    struct label *vlabel, struct attrlist *alist, struct uio *attrblk)
{
	struct mac_mls *subj, *obj;

	subj = SLOT(cred->cr_label);
	obj = SLOT(vlabel);

	MLS_RETURN_CHECK (MLS_CHECK_O_DOM_S);
}

static int
mac_mls_check_vnode_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, int attrnamespace, const char *name,
    struct uio *uio)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(vnodelabel);

	MLS_RETURN_CHECK (MLS_CHECK_O_DOM_S);

	/* XXX: protect the MAC EA in a special way? */
}

static int
mac_mls_check_vnode_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, u_long flags)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(vnodelabel);

	MLS_RETURN_CHECK (MLS_CHECK_O_DOM_S);
}

static int
mac_mls_check_vnode_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, mode_t mode)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(vnodelabel);

	MLS_RETURN_CHECK (MLS_CHECK_O_DOM_S);
}

static int
mac_mls_check_vnode_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, uid_t uid, gid_t gid)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(vnodelabel);

	MLS_RETURN_CHECK (MLS_CHECK_O_DOM_S);
}

static int
mac_mls_check_vnode_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vnodelabel, struct timespec atime, struct timespec mtime)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(cred->cr_label);
	obj = SLOT(vnodelabel);

	MLS_RETURN_CHECK (MLS_CHECK_O_DOM_S);
}

static int
mac_mls_check_vnode_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vnodelabel)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled)
		return (0);

	subj = SLOT(active_cred->cr_label);
	obj = SLOT(vnodelabel);

	MLS_RETURN_CHECK (MLS_CHECK_S_DOM_O);
}

static int
mac_mls_check_vnode_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *label)
{
	struct mac_mls *subj, *obj;

	if (!mac_mls_enabled || !revocation_enabled)
		return (0);

	subj = SLOT(active_cred->cr_label);
	obj = SLOT(label);

	MLS_RETURN_CHECK (MLS_CHECK_O_DOM_S);
}


static int
mac_mls_check_proc_wait(struct ucred *cred, struct proc *proc)
{
    struct mac_mls *subj, *obj;

    if (!mac_mls_enabled)
        return (0);

    subj = SLOT(cred->cr_label);
    obj = SLOT(proc->p_ucred->cr_label);

    /* TODO: should this be mac_mls_dominate_effective() or mac_mls_equal_effective() ? */
#if 0
    return (mac_mls_dominate_effective(subj, obj) ? 0 : EACCES);
#else
    if (mac_mls_dominate_effective(subj, obj))
        return 0;
    else
    {
        MLS_RETURN(EACCES);
    }
#endif
}

static void
mac_mls_create_fragment(struct mbuf *datagram,
	struct label *datagramlabel, struct mbuf *fragment,
	struct label *fragmentlabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(datagramlabel);
	dest = SLOT(fragmentlabel);

	mac_mls_copy_effective(source, dest);
	mac_mls_copy_range(source, dest);
}

static void
mac_mls_create_mbuf_from_ifnet(struct ifnet *ifnet, struct label *ifnetlabel,
    struct mbuf *m, struct label *mbuflabel)
{
	struct mac_mls *source, *dest;

	source = SLOT(ifnetlabel);
	dest = SLOT(mbuflabel);

	mac_mls_copy_effective(source, dest);
	mac_mls_copy_range(source, dest);
}


static struct mac_policy_ops mac_mls_ops =
{
    .mpo_init_bsd                       = mac_mls_init_bsd,
    .mpo_check_cred_relabel             = mac_mls_check_cred_relabel,
    .mpo_check_cred_visible             = mac_mls_check_cred_visible,
    .mpo_destroy_cred_label             = mac_mls_destroy_label,
    .mpo_externalize_cred_label         = mac_mls_externalize_label,
    .mpo_externalize_cred_audit_label   = mac_mls_externalize_label,
    .mpo_init_cred_label                = mac_mls_init_label,
    .mpo_internalize_cred_label         = mac_mls_internalize_label,
    .mpo_create_cred                    = mac_mls_create_cred,
    .mpo_relabel_cred                   = mac_mls_relabel_cred,
    .mpo_copy_devfs_label               = mac_mls_copy_label,
    .mpo_create_devfs_device            = mac_mls_create_devfs_device,
    .mpo_create_devfs_directory         = mac_mls_create_devfs_directory,
    .mpo_create_devfs_symlink           = mac_mls_create_devfs_symlink,
    .mpo_destroy_devfsdirent_label      = mac_mls_destroy_label,
    .mpo_init_devfsdirent_label         = mac_mls_init_label,
    .mpo_update_devfsdirent             = mac_mls_update_devfsdirent,
    .mpo_destroy                        = mac_mls_destroy,
    .mpo_init                           = mac_mls_init,
    .mpo_check_mount_stat               = mac_mls_check_mount_stat,
    .mpo_destroy_mount_fs_label         = mac_mls_destroy_label,
    .mpo_destroy_mount_label            = mac_mls_destroy_label,
    .mpo_init_mount_fs_label            = mac_mls_init_label,
    .mpo_init_mount_label               = mac_mls_init_label,
    .mpo_create_mount                   = mac_mls_create_mount,
    .mpo_init_port_label		= mac_mls_init_port_label,
    .mpo_init_task_label		= mac_mls_init_label,
    .mpo_destroy_port_label		= mac_mls_destroy_label,
    .mpo_destroy_task_label		= mac_mls_destroy_label,
    .mpo_copy_port_label		= mac_mls_copy_label,
    .mpo_update_port_from_cred_label	= mac_mls_update_port_from_cred_label,
    .mpo_copy_cred_to_task		= mac_mls_copy_cred_to_task,
    .mpo_create_port                    = mac_mls_create_port,
    .mpo_create_kernel_port		= mac_mls_create_kernel_port,
    .mpo_check_port_relabel		= mac_mls_check_port_relabel,
    .mpo_check_port_send		= mac_mls_check_port_send,
    .mpo_check_port_hold_send		= mac_mls_check_port_hold_send,
    .mpo_check_port_hold_receive	= mac_mls_check_port_hold_receive,
    .mpo_create_task                    = mac_mls_create_task,
    .mpo_create_kernel_task		= mac_mls_create_kernel_task,
    .mpo_check_proc_debug               = mac_mls_check_proc_debug,
    .mpo_check_proc_sched               = mac_mls_check_proc_sched,
    .mpo_check_proc_signal              = mac_mls_check_proc_signal,
    .mpo_check_proc_wait                = mac_mls_check_proc_wait,
    .mpo_destroy_proc_label             = mac_mls_destroy_label,
    .mpo_init_proc_label                = mac_mls_init_label,
    .mpo_create_proc0                   = mac_mls_create_proc0,
    .mpo_create_proc1                   = mac_mls_create_proc1,
    .mpo_check_system_swapon            = mac_mls_check_system_swapon,
    .mpo_associate_vnode_devfs          = mac_mls_associate_vnode_devfs,
    .mpo_associate_vnode_extattr        = mac_mls_associate_vnode_extattr,
    .mpo_associate_vnode_singlelabel    = mac_mls_associate_vnode_singlelabel,
    .mpo_check_vnode_access             = mac_mls_check_vnode_open,
    .mpo_check_vnode_chdir              = mac_mls_check_vnode_chdir,
    .mpo_check_vnode_chroot             = mac_mls_check_vnode_chroot,
    .mpo_check_vnode_create             = mac_mls_check_vnode_create,
    .mpo_check_vnode_delete             = mac_mls_check_vnode_delete,
    .mpo_check_vnode_exchangedata       = mac_mls_check_vnode_exchangedata,
    .mpo_check_vnode_getattrlist        = mac_mls_check_vnode_getattrlist,
    .mpo_check_vnode_setattrlist        = mac_mls_check_vnode_setattrlist,
/*  .mpo_check_vnode_deleteextattr      = mac_mls_check_vnode_deleteextattr,*/
    .mpo_check_vnode_exec               = mac_mls_check_vnode_exec,
    .mpo_check_vnode_getextattr         = mac_mls_check_vnode_getextattr,
    .mpo_check_vnode_link               = mac_mls_check_vnode_link,
/*  .mpo_check_vnode_listextattr        = mac_mls_check_vnode_listextattr,*/
    .mpo_check_vnode_lookup             = mac_mls_check_vnode_lookup,
    .mpo_check_vnode_mmap               = mac_mls_check_vnode_mmap,
    .mpo_check_vnode_open               = mac_mls_check_vnode_open,
    .mpo_check_vnode_poll               = mac_mls_check_vnode_poll,
    .mpo_check_vnode_read               = mac_mls_check_vnode_read,
    .mpo_check_vnode_readdir            = mac_mls_check_vnode_readdir,
    .mpo_check_vnode_readlink           = mac_mls_check_vnode_readlink,
    .mpo_check_vnode_relabel            = mac_mls_check_vnode_relabel,
    .mpo_check_vnode_rename_from        = mac_mls_check_vnode_rename_from,
    .mpo_check_vnode_rename_to          = mac_mls_check_vnode_rename_to,
    .mpo_check_vnode_revoke             = mac_mls_check_vnode_revoke,
    .mpo_check_vnode_setextattr         = mac_mls_check_vnode_setextattr,
    .mpo_check_vnode_setflags           = mac_mls_check_vnode_setflags,
    .mpo_check_vnode_setmode            = mac_mls_check_vnode_setmode,
    .mpo_check_vnode_setowner           = mac_mls_check_vnode_setowner,
    .mpo_check_vnode_setutimes          = mac_mls_check_vnode_setutimes,
    .mpo_check_vnode_stat               = mac_mls_check_vnode_stat,
    .mpo_check_vnode_write              = mac_mls_check_vnode_write,
    .mpo_copy_vnode_label               = mac_mls_copy_label,
    .mpo_create_vnode_extattr           = mac_mls_create_vnode_extattr,
    .mpo_destroy_vnode_label            = mac_mls_destroy_label,
    .mpo_externalize_vnode_label        = mac_mls_externalize_label,
    .mpo_externalize_vnode_audit_label  = mac_mls_externalize_label,
    .mpo_init_vnode_label               = mac_mls_init_label,
    .mpo_internalize_vnode_label        = mac_mls_internalize_label,
    .mpo_setlabel_vnode_extattr         = mac_mls_setlabel_vnode_extattr,
    .mpo_relabel_vnode                  = mac_mls_relabel_vnode,

    .mpo_init_posix_sem_label		= mac_mls_init_label,
    .mpo_destroy_posix_sem_label       	= mac_mls_destroy_label,
    .mpo_create_posix_sem		= mac_mls_create_posix_sem,
    .mpo_check_posix_sem_open		= mac_mls_check_posix_sem_open,
    .mpo_check_posix_sem_post		= mac_mls_check_posix_sem_write,
    .mpo_check_posix_sem_unlink		= mac_mls_check_posix_sem_unlink,
    .mpo_check_posix_sem_wait		= mac_mls_check_posix_sem_rw,

    .mpo_init_posix_shm_label		= mac_mls_init_label,
    .mpo_destroy_posix_shm_label       	= mac_mls_destroy_label,
    .mpo_create_posix_shm		= mac_mls_create_posix_shm,
    .mpo_check_posix_shm_open		= mac_mls_check_posix_shm_read,
    .mpo_check_posix_shm_mmap		= mac_mls_check_posix_shm_mmap,
    .mpo_check_posix_shm_stat		= mac_mls_check_posix_shm_read,
    .mpo_check_posix_shm_truncate	= mac_mls_check_posix_shm_truncate,
    .mpo_check_posix_shm_unlink		= mac_mls_check_posix_shm_unlink,

    .mpo_init_tcp_label                 = mac_mls_init_tcp_label,
    .mpo_init_mbuf_failed_label         = mac_mls_init_mbuf_failed_label,
    .mpo_init_mbuf_socket_label         = mac_mls_init_label_waitcheck,
    .mpo_init_mbuf_unknown_source_label = mac_mls_init_mbuf_unknown_source_label,
    .mpo_init_socket_label              = mac_mls_init_label_waitcheck,
    .mpo_init_socket_peer_label         = mac_mls_init_label_waitcheck,
    .mpo_copy_mbuf_socket_label         = mac_mls_copy_label,
    .mpo_copy_socket_label              = mac_mls_copy_label,
    .mpo_destroy_mbuf_socket_label      = mac_mls_destroy_label,
    .mpo_destroy_socket_label           = mac_mls_destroy_label,
    .mpo_destroy_socket_peer_label      = mac_mls_destroy_label,
    .mpo_internalize_socket_label       = mac_mls_internalize_label,
    .mpo_externalize_socket_label       = mac_mls_externalize_label,
    .mpo_externalize_socket_peer_label  = mac_mls_externalize_label,
    .mpo_create_mbuf_from_socket        = mac_mls_create_mbuf_from_socket,
    .mpo_create_socket                  = mac_mls_create_socket,
    .mpo_create_socket_from_socket      = mac_mls_create_socket_from_socket,
    .mpo_relabel_socket                 = mac_mls_relabel_socket,
    .mpo_set_socket_peer_from_mbuf      = mac_mls_set_socket_peer_from_mbuf,
    .mpo_set_socket_peer_from_socket    = mac_mls_set_socket_peer_from_socket,
    .mpo_check_socket_accept            = mac_mls_check_socket_accept,
    .mpo_check_socket_bind              = mac_mls_check_socket_bind,
    .mpo_check_socket_connect           = mac_mls_check_socket_connect,
    .mpo_check_socket_deliver           = mac_mls_check_socket_deliver,
    .mpo_check_socket_listen            = mac_mls_check_socket_listen,
    .mpo_check_socket_poll              = mac_mls_check_socket_poll,
    .mpo_check_socket_receive           = mac_mls_check_socket_receive,
    .mpo_check_socket_relabel           = mac_mls_check_socket_relabel,
    .mpo_check_socket_select            = mac_mls_check_socket_select,
    .mpo_check_socket_send              = mac_mls_check_socket_send,
    .mpo_check_socket_stat              = mac_mls_check_socket_stat,

    .mpo_check_system_audit             = mac_mls_check_system_audit,
    .mpo_check_system_auditon           = mac_mls_check_system_auditon,
    .mpo_check_system_auditctl          = mac_mls_check_system_auditctl,
    .mpo_check_proc_getauid             = mac_mls_check_proc_getauid,
    .mpo_check_proc_setauid             = mac_mls_check_proc_setauid,
    .mpo_check_proc_getaudit            = mac_mls_check_proc_getaudit,
    .mpo_check_proc_setaudit            = mac_mls_check_proc_setaudit,
    .mpo_check_proc_setlcid		= mac_mls_check_proc_setlcid,
    .mpo_audit_preselect                = mac_mls_audit_preselect,
    .mpo_audit_postselect               = mac_mls_audit_postselect,
};


static char *labelnamespaces[MAC_MLS_LABEL_NAME_COUNT] = {MAC_MLS_LABEL_NAME};
struct mac_policy_conf mac_mls_mac_policy_conf = {
	"mac_mls",				/* policy name */
	"TrustedBSD MAC/MLS",			/* full name */
	labelnamespaces,			/* label namespace */
	MAC_MLS_LABEL_NAME_COUNT,		/* namespace count */
	&mac_mls_ops,				/* policy operations */
	0,					/* loadtime flags*/
	&mac_mls_slot,				/* security field */
	0					/* runtime flags */
};
/*
 * vim:sw=8 noet:
 */

#ifdef KEXT
static kern_return_t
kmod_start(kmod_info_t *ki, void *xd)
{

	return (mac_policy_register(&mac_mls_mac_policy_conf));
}

static kern_return_t
kmod_stop(kmod_info_t *ki, void *xd)
{

	return (mac_policy_unregister(&mac_mls_mac_policy_conf));
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(security.mls,  "1.0",  _start, _stop)
kmod_start_func_t *_realmain = kmod_start;
kmod_stop_func_t *_antimain = kmod_stop;
int _kext_apple_cc = __APPLE_CC__ ;
#endif /* KEXT */
