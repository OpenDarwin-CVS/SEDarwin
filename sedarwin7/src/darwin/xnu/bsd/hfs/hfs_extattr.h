/*-
 * Copyright (c) 1999-2001 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
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
 */
/*
 * Developed by the TrustedBSD Project.
 * Support for extended filesystem attributes.
 */

#ifndef _HFS_HFS_EXTATTR_H_
#define	_HFS_HFS_EXTATTR_H_

#define	HFS_EXTATTR_MAGIC		0x00b5d5ec
#define	HFS_EXTATTR_VERSION		0x00000003
#define	HFS_EXTATTR_FSROOTSUBDIR	".attribute"
#define	HFS_EXTATTR_SUBDIR_SYSTEM	"system"
#define	HFS_EXTATTR_SUBDIR_USER		"user"
#define	HFS_EXTATTR_MAXEXTATTRNAME	65	/* including null */

#define	HFS_EXTATTR_ATTR_FLAG_INUSE	0x00000001	/* attr has been set */
#define	HFS_EXTATTR_PERM_KERNEL		0x00000000
#define	HFS_EXTATTR_PERM_ROOT		0x00000001
#define	HFS_EXTATTR_PERM_OWNER		0x00000002
#define	HFS_EXTATTR_PERM_ANYONE		0x00000003

#define	HFS_EXTATTR_UEPM_INITIALIZED	0x00000001
#define	HFS_EXTATTR_UEPM_STARTED	0x00000002

#define	HFS_EXTATTR_CMD_START		0x00000001
#define	HFS_EXTATTR_CMD_STOP		0x00000002
#define	HFS_EXTATTR_CMD_ENABLE		0x00000003
#define	HFS_EXTATTR_CMD_DISABLE		0x00000004

struct hfs_extattr_fileheader {
	u_int	uef_magic;	/* magic number for sanity checking */
	u_int	uef_version;	/* version of attribute file */
	u_int	uef_size;	/* size of attributes, w/o header */
};

struct hfs_extattr_header {
	u_int	ueh_flags;	/* flags for attribute */
	u_int	ueh_len;	/* local defined length; <= uef_size */
	u_int32_t	ueh_i_gen;	/* generation number for sanity */
	/* data follows the header */
};

#ifdef KERNEL

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_EXTATTR);
#endif

struct vnode;
LIST_HEAD(hfs_extattr_list_head, hfs_extattr_list_entry);
struct hfs_extattr_list_entry {
	LIST_ENTRY(hfs_extattr_list_entry)	uele_entries;
	struct hfs_extattr_fileheader		uele_fileheader;
	int	uele_attrnamespace;
	char	uele_attrname[HFS_EXTATTR_MAXEXTATTRNAME];
	struct vnode	*uele_backing_vnode;
};

struct lock__bsd__;
struct lock;
struct ucred;
struct hfs_extattr_per_mount {
	struct lock__bsd__	uepm_lock;
	struct hfs_extattr_list_head	uepm_list;
	struct ucred	*uepm_ucred;
	int	uepm_flags;
};

void	hfs_extattr_uepm_init(struct hfs_extattr_per_mount *uepm);
void	hfs_extattr_uepm_destroy(struct hfs_extattr_per_mount *uepm,
	    struct proc *p);
int	hfs_extattr_start(struct mount *mp, struct proc *p);
int	hfs_extattr_autostart(struct mount *mp, struct proc *p);
int	hfs_extattr_stop(struct mount *mp, struct proc *p);
int	hfs_extattrctl(struct mount *mp, int cmd, struct vnode *filename,
	    int attrnamespace, const char *attrname, struct proc *p);
int	hfs_getextattr(struct vop_getextattr_args *ap);
int	hfs_deleteextattr(struct vop_deleteextattr_args *ap);
int	hfs_setextattr(struct vop_setextattr_args *ap);
void	hfs_extattr_vnode_inactive(struct vnode *vp, struct proc *p);

#endif /* !KERNEL */

#endif /* !_HFS_HFS_EXTATTR_H_ */
