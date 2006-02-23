/*-
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2002, 2003 Networks Associates Technology, Inc.
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
 */

/*
 * Support for filesystem extended attribute: HFS-specific support functions.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/lock.h>
#include <sys/dirent.h>
#include <sys/extattr.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>

#include "hfs_extattr.h"
#include "hfs.h"

#ifdef HFS_EXTATTR

/* XXX/TBD: This should be available via a sysctl */
static hfs_extattr_sync = 0;

static int	hfs_extattr_disable(struct hfsmount *hfsmp, int attrnamespace,
		    const char *attrname, struct proc *p);

/*
 * Lock functions copied/ported From FreeBSD 5.1, including comments...
 *
 * Per-FS attribute lock protecting attribute operations.
 * XXX Right now there is a lot of lock contention due to having a single
 * lock per-FS; really, this should be far more fine-grained.
 */
static void
hfs_extattr_uepm_lock(struct hfsmount *hfsmp, struct proc *p)
{

	/* Ideally, LK_CANRECURSE would not be used, here. */
	lockmgr(&hfsmp->hfs_extattr.uepm_lock, LK_EXCLUSIVE | LK_RETRY |
		LK_CANRECURSE, 0, p);
}

static void
hfs_extattr_uepm_unlock(struct hfsmount *hfsmp, struct proc *p)
{

	lockmgr(&hfsmp->hfs_extattr.uepm_lock, LK_RELEASE, 0, p);
}

/*
 * Determine whether the name passed is a valid name for an actual
 * attribute.
 *
 * Invalid currently consists of:
 *	 NULL pointer for attrname
 *	 zero-length attrname (used to retrieve application attribute list)
 */
static int
hfs_extattr_valid_attrname(int attrnamespace, const char *attrname)
{

	if (attrname == NULL)
		return (0);
	if (strlen(attrname) == 0)
		return (0);
	return (1);
}

/*
 * Locate an attribute given a name and mountpoint.
 * Must be holding uepm lock for the mount point.
 */
static struct hfs_extattr_list_entry *
hfs_extattr_find_attr(struct hfsmount *hfsmp, int attrnamespace,
    const char *attrname)
{
	struct hfs_extattr_list_entry	*search_attribute;

	for (search_attribute = LIST_FIRST(&hfsmp->hfs_extattr.uepm_list);
	    search_attribute;
	    search_attribute = LIST_NEXT(search_attribute, uele_entries)) {
		if (!(strncmp(attrname, search_attribute->uele_attrname,
		    HFS_EXTATTR_MAXEXTATTRNAME)) &&
		    (attrnamespace == search_attribute->uele_attrnamespace)) {
			return (search_attribute);
		}
	}

	return (0);
}


/*
 * Initialize per-FS structures supporting extended attributes.  Do not
 * start extended attributes yet.
 */
void
hfs_extattr_uepm_init(struct hfs_extattr_per_mount *uepm)
{

	uepm->uepm_flags = 0;

	LIST_INIT(&uepm->uepm_list);
	/* XXX is PVFS right, here? */
	lockinit(&uepm->uepm_lock, PVFS, "extattr", 0, 0);
	uepm->uepm_flags |= HFS_EXTATTR_UEPM_INITIALIZED;
}


/*
 * Destroy per-FS structures supporting extended attributes.  Assumes
 * that EAs have already been stopped, and will panic if not.
 */
void
hfs_extattr_uepm_destroy(struct hfs_extattr_per_mount *uepm, struct proc *p)
{

        if (!(uepm->uepm_flags & HFS_EXTATTR_UEPM_INITIALIZED))
                panic("hfs_extattr_uepm_destroy: not initialized");

        if ((uepm->uepm_flags & HFS_EXTATTR_UEPM_STARTED))
                panic("hfs_extattr_uepm_destroy: called while still started");

	simple_lock(&mountlist_slock);
	uepm->uepm_flags &= ~HFS_EXTATTR_UEPM_INITIALIZED;
	lockmgr(&uepm->uepm_lock, LK_RELEASE | LK_INTERLOCK | LK_REENABLE,  
                    &mountlist_slock, p);
}

/*
 * Start extended attribute support on an FS.
 */
int
hfs_extattr_start(struct mount *mp, struct proc *p)
{
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	int error = 0;

	hfs_extattr_uepm_lock(hfsmp, p);

	if (!(hfsmp->hfs_extattr.uepm_flags & HFS_EXTATTR_UEPM_INITIALIZED)) {
		error = EOPNOTSUPP;
		goto unlock;
	}
	if (hfsmp->hfs_extattr.uepm_flags & HFS_EXTATTR_UEPM_STARTED) {
		error = EBUSY;
		goto unlock;
	}

	hfsmp->hfs_extattr.uepm_flags |= HFS_EXTATTR_UEPM_STARTED;
	crhold(p->p_ucred);
	hfsmp->hfs_extattr.uepm_ucred = p->p_ucred;

 unlock:
	hfs_extattr_uepm_unlock(hfsmp, p);

	return (error);
}

/*
 * Helper routine: given a locked parent directory and filename, return
 * the locked vnode of the inode associated with the name.  Will not
 * follow symlinks, may return any type of vnode.  Lock on parent will
 * be released even in the event of a failure.  In the event that the
 * target is the parent (i.e., "."), there will be two references and
 * one lock, requiring the caller to possibly special-case.
 */
#define	UE_GETDIR_LOCKPARENT            1
#define	UE_GETDIR_LOCKPARENT_DONT       2
static int
hfs_extattr_lookup(struct vnode *start_dvp, int lockparent, char *dirname,
    struct vnode **vp, struct proc *p)
{
	struct vop_cachedlookup_args vargs;
	struct componentname cnp;
	struct vnode *target_vp;
	int error;

	bzero(&cnp, sizeof(cnp));
	cnp.cn_nameiop = LOOKUP;
	cnp.cn_flags = ISLASTCN;
	if (lockparent == UE_GETDIR_LOCKPARENT)
		cnp.cn_flags |= LOCKPARENT;
	cnp.cn_proc = p;
	cnp.cn_cred = p->p_ucred;
	MALLOC_ZONE(cnp.cn_pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	cnp.cn_pnlen = MAXPATHLEN;
	cnp.cn_nameptr = cnp.cn_pnbuf;
	error = copystr(dirname, cnp.cn_pnbuf, MAXPATHLEN,
	    (size_t *) &cnp.cn_namelen);
	if (error) {
		if (lockparent == UE_GETDIR_LOCKPARENT_DONT) {
			VOP_UNLOCK(start_dvp, 0, p);
		}
		_FREE_ZONE(cnp.cn_pnbuf, cnp.cn_pnlen, M_NAMEI);
		return (error);
	}
	cnp.cn_namelen--;	/* trim nul termination */
	vargs.a_desc = NULL;
	vargs.a_dvp = start_dvp;
	vargs.a_vpp = &target_vp;
	vargs.a_cnp = &cnp;
	error = hfs_lookup(&vargs);
	_FREE_ZONE(cnp.cn_pnbuf, cnp.cn_pnlen, M_NAMEI);
	if (error) {
		/*
		 * Error condition, may have to release the lock on the parent
		 * if hfs_lookup() didn't.
		 */
		if (lockparent == UE_GETDIR_LOCKPARENT_DONT)
			VOP_UNLOCK(start_dvp, 0, p);

		/*
		 * Check that hfs_lookup() didn't release the lock when we
		 * didn't want it to.
		 */
		/*
		if (lockparent == UE_GETDIR_LOCKPARENT)
			panic("hfs_extattr_lookup: lockparent but PDIRUNLOCK");
		*/
		return (error);
	}
/*
	if (target_vp == start_dvp)
		panic("hfs_extattr_lookup: target_vp == start_dvp");
*/

/*
	if (target_vp != start_dvp &&
	    (lockparent == UE_GETDIR_LOCKPARENT_DONT))
		panic("hfs_extattr_lookup: !lockparent but !PDIRUNLOCK");

	if (lockparent == UE_GETDIR_LOCKPARENT)
		panic("hfs_extattr_lookup: lockparent but PDIRUNLOCK");
*/

	*vp = target_vp;
	return (0);
}

/*
 * Enable a named attribute on the specified filesystem; provide an
 * unlocked backing vnode to hold the attribute data.
 */
static int
hfs_extattr_enable(struct hfsmount *hfsmp, int attrnamespace,
    const char *attrname, struct vnode *backing_vnode, struct proc *p)
{
	struct hfs_extattr_list_entry	*attribute;
	struct mount	*mp = HFSTOVFS(hfsmp);
	struct iovec	aiov;
	struct uio	auio;
	int	error = 0;

	if (!hfs_extattr_valid_attrname(attrnamespace, attrname))
		return (EINVAL);
	if (backing_vnode->v_type != VREG)
		return (EINVAL);

	MALLOC(attribute, struct hfs_extattr_list_entry *,
	    sizeof(struct hfs_extattr_list_entry), M_EXTATTR, M_WAITOK);
	if (attribute == NULL)
		return (ENOMEM);

	if (!(hfsmp->hfs_extattr.uepm_flags & HFS_EXTATTR_UEPM_STARTED)) {
		error = EOPNOTSUPP;
		goto free_exit;
	}

	if (hfs_extattr_find_attr(hfsmp, attrnamespace, attrname)) {
		error = EEXIST;
		goto free_exit;
	}

	strncpy(attribute->uele_attrname, attrname,
	    HFS_EXTATTR_MAXEXTATTRNAME);
	attribute->uele_attrnamespace = attrnamespace;
	bzero(&attribute->uele_fileheader,
	    sizeof(struct hfs_extattr_fileheader));
	
	attribute->uele_backing_vnode = backing_vnode;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	aiov.iov_base = (caddr_t) &attribute->uele_fileheader;
	aiov.iov_len = sizeof(struct hfs_extattr_fileheader);
	auio.uio_resid = sizeof(struct hfs_extattr_fileheader);
	auio.uio_offset = (off_t) 0;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_procp = p;

	VOP_LEASE(backing_vnode, p, p->p_ucred, LEASE_WRITE);
	vn_lock(backing_vnode, LK_SHARED | LK_RETRY, p);
	error = VOP_READ(backing_vnode, &auio, IO_NODELOCKED,
	    hfsmp->hfs_extattr.uepm_ucred);

	if (error)
		goto unlock_free_exit;

	if (auio.uio_resid != 0) {
		error = EINVAL;
		goto unlock_free_exit;
	}

	if (attribute->uele_fileheader.uef_magic != HFS_EXTATTR_MAGIC) {
		error = EINVAL;
		goto unlock_free_exit;
	}

	if (attribute->uele_fileheader.uef_version != HFS_EXTATTR_VERSION) {
		error = EINVAL;
		goto unlock_free_exit;
	}

	LIST_INSERT_HEAD(&hfsmp->hfs_extattr.uepm_list, attribute,
	    uele_entries);

	/*
	 * Since at least one attribute is on, set the mount flags
	 * to indicate that this filesystem provides multilabel support
	 */
	mp->mnt_flag |= MNT_MULTILABEL;

	VOP_UNLOCK(backing_vnode, 0, p);
	return (0);

unlock_free_exit:
	VOP_UNLOCK(backing_vnode, 0, p);

free_exit:
	FREE(attribute, M_EXTATTR);
	return (error);
}

/*
 * Enable an EA using the passed filesystem, backing vnode, attribute name,
 * namespace, and proc.  Will perform a VOP_OPEN() on the vp, so expects vp
 * to be locked when passed in.  The vnode will be returned unlocked,
 * regardless of success/failure of the function.  As a result, the caller
 * will always need to vrele(), but not vput().
 */
static int
hfs_extattr_enable_with_open(struct hfsmount *hfsmp, struct vnode *vp,
    int attrnamespace, const char *attrname, struct proc *p)
{
	int error;

        if (UBCINFOEXISTS(vp) && !ubc_hold(vp)) {
		error = ENOENT;
		VOP_UNLOCK(vp, 0, p);
		return error;
	}
	
	error = VOP_OPEN(vp, FREAD|FWRITE, p->p_ucred, p);
	if (error) {
		ubc_rele(vp);
		VOP_UNLOCK(vp, 0, p);
		return (error);
	}

        if(++vp->v_writecount <= 0)
		panic("hfs_extattr_enable_with_open:v_writecount");

	vref(vp);

	VOP_UNLOCK(vp, 0, p);

	error = hfs_extattr_enable(hfsmp, attrnamespace, attrname, vp, p);
	if (error != 0)
		vn_close(vp, FREAD|FWRITE, p->p_ucred, p);


	return (error);
}

/*
 * Given a locked directory vnode, iterate over the names in the directory
 * and use hfs_extattr_lookup() to retrieve locked vnodes of potential
 * attribute files.  Then invoke hfs_extattr_enable_with_open() on each
 * to attempt to start the attribute.  Leaves the directory locked on
 * exit.
 */

/*
 * Defining DIRBLKSIZ as the same value as ufs can't possibly be right 
 * reading the comments prior to hfs_readdir() shows the confusion.
 */
#define DIRBLKSIZ 1024 
static int
hfs_extattr_iterate_directory(struct hfsmount *hfsmp, struct vnode *dvp,
    int attrnamespace, struct proc *p)
{
	struct vop_readdir_args vargs;
	struct dirent *dp, *edp;
	struct vnode *attr_vp;
	struct uio auio;
	struct iovec aiov;
	char *dirbuf;
	int error, eofflag = 0, readcnt;

	if (dvp->v_type != VDIR)
		return (ENOTDIR);

	MALLOC(dirbuf, char *, DIRBLKSIZ, M_TEMP, M_WAITOK);

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_procp = p;
	auio.uio_offset = 0;

	vargs.a_desc = NULL;
	vargs.a_vp = dvp;
	vargs.a_uio = &auio;
	vargs.a_cred = p->p_ucred;
	vargs.a_eofflag = &eofflag;
	vargs.a_ncookies = NULL;
	vargs.a_cookies = NULL;

	while (!eofflag) {
		auio.uio_resid = DIRBLKSIZ;
		aiov.iov_base = dirbuf;
		aiov.iov_len = DIRBLKSIZ;
		error = hfs_readdir(&vargs);
		if (error) {
			return (error);
		}

		readcnt = DIRBLKSIZ - auio.uio_resid;
		edp = (struct dirent *)&dirbuf[readcnt];
		for (dp = (struct dirent *)dirbuf; dp < edp; ) {
#if (BYTE_ORDER == LITTLE_ENDIAN)
			dp->d_type = dp->d_namlen;
			dp->d_namlen = 0;
#else
			dp->d_type = 0;
#endif
			if (dp->d_reclen == 0)
				break;
			error = hfs_extattr_lookup(dvp, UE_GETDIR_LOCKPARENT,
			    dp->d_name, &attr_vp, p);
			if (error) {
				printf("hfs_extattr_iterate_directory: lookup "
				    "%s %d\n", dp->d_name, error);
			} else if (attr_vp == dvp) {
				vrele(attr_vp);
			} else if (attr_vp->v_type != VREG) {
				vput(attr_vp);
			} else {
				error = hfs_extattr_enable_with_open(hfsmp,
				    attr_vp, attrnamespace, dp->d_name, p);
				vrele(attr_vp);
				if (!error) {
					printf("HFS autostarted EA %s\n",
					    dp->d_name);
				}
			}
			dp = (struct dirent *) ((char *)dp + dp->d_reclen);
			if (dp >= edp)
				break;
		}
	}
	FREE(dirbuf, M_TEMP);
	
	return (0);
}


/*
 * Auto-start of extended attributes, to be executed (optionally) at
 * mount-time.
 */
int
hfs_extattr_autostart(struct mount *mp, struct proc *p)
{

	struct vnode *rvp, *attr_dvp, *attr_system_dvp, *attr_user_dvp;
	int error;

	/*
	 * Does HFS_EXTATTR_FSROOTSUBDIR exist off the filesystem root?
	 * If so, automatically start EA's.
	 */
	error = VFS_ROOT(mp, &rvp);
	if (error) {
		return (error);
	}

	error = hfs_extattr_lookup(rvp, UE_GETDIR_LOCKPARENT_DONT,
	    HFS_EXTATTR_FSROOTSUBDIR, &attr_dvp, p);
	if (error) {
		/* rvp ref'd but now unlocked */
		vrele(rvp);
		return (error);
	}
	if (rvp == attr_dvp) {
		/* Should never happen. */
		vrele(attr_dvp);
		vput(rvp);
		return (EINVAL);
	}
	vrele(rvp);

	if (attr_dvp->v_type != VDIR) {
		printf("hfs_extattr_autostart: %s != VDIR\n",
		    HFS_EXTATTR_FSROOTSUBDIR);
		goto return_vput_attr_dvp;
	}

	error = hfs_extattr_start(mp, p);
	if (error) {
		goto return_vput_attr_dvp;
	}

	/*
	 * Look for two subdirectories: HFS_EXTATTR_SUBDIR_SYSTEM,
	 * HFS_EXTATTR_SUBDIR_USER.  For each, iterate over the sub-directory,
	 * and start with appropriate type.  Failures in either don't
	 * result in an over-all failure.  attr_dvp is left locked to
	 * be cleaned up on exit.
	 */
	error = hfs_extattr_lookup(attr_dvp, UE_GETDIR_LOCKPARENT,
	    HFS_EXTATTR_SUBDIR_SYSTEM, &attr_system_dvp, p);
	if (!error) {
		error = hfs_extattr_iterate_directory(VFSTOHFS(mp),
		    attr_system_dvp, EXTATTR_NAMESPACE_SYSTEM, p);
		vput(attr_system_dvp);
	}

	error = hfs_extattr_lookup(attr_dvp, UE_GETDIR_LOCKPARENT,
	    HFS_EXTATTR_SUBDIR_USER, &attr_user_dvp, p);
	if (!error) {
		error = hfs_extattr_iterate_directory(VFSTOHFS(mp),
		    attr_user_dvp, EXTATTR_NAMESPACE_USER, p);
		vput(attr_user_dvp);
	}

	/* Mask startup failures in sub-directories. */
	error = 0;

return_vput_attr_dvp:
	vput(attr_dvp);

	return (error);
}

/*
 * Stop extended attribute support on an FS.
 */
int
hfs_extattr_stop(struct mount *mp, struct proc *p)
{

	struct hfs_extattr_list_entry	*uele;
	struct hfsmount	*hfsmp = VFSTOHFS(mp);
	int	error = 0;

	hfs_extattr_uepm_lock(hfsmp, p);

	if (!(hfsmp->hfs_extattr.uepm_flags & HFS_EXTATTR_UEPM_STARTED)) {
		error = EOPNOTSUPP;
		goto unlock;
	}

	while (LIST_FIRST(&hfsmp->hfs_extattr.uepm_list) != NULL) {
		uele = LIST_FIRST(&hfsmp->hfs_extattr.uepm_list);
		hfs_extattr_disable(hfsmp, uele->uele_attrnamespace,
		    uele->uele_attrname, p);
	}

	hfsmp->hfs_extattr.uepm_flags &= ~HFS_EXTATTR_UEPM_STARTED;

	crfree(hfsmp->hfs_extattr.uepm_ucred);
	hfsmp->hfs_extattr.uepm_ucred = NULL;

unlock:
	hfs_extattr_uepm_unlock(hfsmp, p);

	return (error);
}

/*
 * Real work associated with retrieving a named attribute--assumes that
 * the attribute lock has already been grabbed.
 */
static int
hfs_extattr_get(struct vnode *vp, int attrnamespace, const char *name,
    struct uio *uio, size_t *size, struct ucred *cred, struct proc *p)
{

	struct hfs_extattr_list_entry	*attribute;
	struct hfs_extattr_header	ueh;
	struct iovec	local_aiov;
	struct uio	local_aio;
	struct mount	*mp = vp->v_mount;
	struct hfsmount	*hfsmp = VFSTOHFS(mp);
	struct cnode	*cp = VTOC(vp);
	off_t	base_offset;
	size_t	len, old_len;
	int	error = 0;

	if (!(hfsmp->hfs_extattr.uepm_flags & HFS_EXTATTR_UEPM_STARTED))
		return (EOPNOTSUPP);

	if (strlen(name) == 0)
		return (EINVAL);

/*
 * XXX/TBD:
 */
/*
	error = extattr_check_cred(vp, attrnamespace, cred, p, IREAD);
	if (error)
		return (error);
*/

	attribute = hfs_extattr_find_attr(hfsmp, attrnamespace, name);
	if (!attribute)
		return (ENOATTR);

	/*
	 * Allow only offsets of zero to encourage the read/replace
	 * extended attribute semantic.  Otherwise we can't guarantee
	 * atomicity, as we don't provide locks for extended attributes.
	 */
	if (uio != NULL && uio->uio_offset != 0)
		return (ENXIO);

	/*
	 * Find base offset of header in file based on file header size, and
	 * data header size + maximum data size, indexed by inode number.
	 */
	base_offset = sizeof(struct hfs_extattr_fileheader) +
	    cp->c_fileid * (sizeof(struct hfs_extattr_header) +
	    attribute->uele_fileheader.uef_size);

	/*
	 * Read in the data header to see if the data is defined, and if so
	 * how much.
	 */
	bzero(&ueh, sizeof(struct hfs_extattr_header));
	local_aiov.iov_base = (caddr_t) &ueh;
	local_aiov.iov_len = sizeof(struct hfs_extattr_header);
	local_aio.uio_iov = &local_aiov;
	local_aio.uio_iovcnt = 1;
	local_aio.uio_rw = UIO_READ;
	local_aio.uio_segflg = UIO_SYSSPACE;
	local_aio.uio_procp = p;
	local_aio.uio_offset = base_offset;
	local_aio.uio_resid = sizeof(struct hfs_extattr_header);
	
	/*
	 * Acquire locks.
	 */
	VOP_LEASE(attribute->uele_backing_vnode, p, cred, LEASE_READ);
	/*
	 * Don't need to get a lock on the backing file if the getattr is
	 * being applied to the backing file, as the lock is already held.
	 */
	if (attribute->uele_backing_vnode != vp)
		vn_lock(attribute->uele_backing_vnode, LK_SHARED |
		    LK_RETRY, p);

	error = VOP_READ(attribute->uele_backing_vnode, &local_aio,
	    IO_NODELOCKED, hfsmp->hfs_extattr.uepm_ucred);
	if (error)
		goto vopunlock_exit;

	/* Defined? */
	if ((ueh.ueh_flags & HFS_EXTATTR_ATTR_FLAG_INUSE) == 0) {
		error = ENOATTR;
		goto vopunlock_exit;
	}

#ifdef HFS_GENERATIONS
	/* XXX/TBD: is there something similiar in hfs? */

	/* Valid for the current inode generation? */
	if (ueh.ueh_i_gen != ip->i_gen) {
		/*
		 * The inode itself has a different generation number
		 * than the attribute data.  For now, the best solution
		 * is to coerce this to undefined, and let it get cleaned
		 * up by the next write or extattrctl clean.
		 */
		printf("hfs_extattr_get (%s): inode number inconsistency (%d, %jd)\n",
		    mp->mnt_stat.f_mntonname, ueh.ueh_i_gen, (intmax_t)ip->i_gen);
		error = ENOATTR;
		goto vopunlock_exit;
	}
#endif

	/* Local size consistency check. */
	if (ueh.ueh_len > attribute->uele_fileheader.uef_size) {
		error = ENXIO;
		goto vopunlock_exit;
	}

	/* Return full data size if caller requested it. */
	if (size != NULL)
		*size = ueh.ueh_len;

	/* Return data if the caller requested it. */
	if (uio != NULL) {
		/* Allow for offset into the attribute data. */
		uio->uio_offset = base_offset + sizeof(struct
		    hfs_extattr_header);

		/*
		 * Figure out maximum to transfer -- use buffer size and
		 * local data limit.
		 */
		len = MIN(uio->uio_resid, ueh.ueh_len);
		old_len = uio->uio_resid;
		uio->uio_resid = len;

		error = VOP_READ(attribute->uele_backing_vnode, uio,
		    IO_NODELOCKED, hfsmp->hfs_extattr.uepm_ucred);
		if (error)
			goto vopunlock_exit;

		uio->uio_resid = old_len - (len - uio->uio_resid);
	}

vopunlock_exit:

	if (uio != NULL)
		uio->uio_offset = 0;

	if (attribute->uele_backing_vnode != vp)
		VOP_UNLOCK(attribute->uele_backing_vnode, 0, p);

	return (error);
}

/*
 * Real work associated with setting a vnode's extended attributes;
 * assumes that the attribute lock has already been grabbed.
 */
static int
hfs_extattr_set(struct vnode *vp, int attrnamespace, const char *name,
    struct uio *uio, struct ucred *cred, struct proc *p)
{
	struct hfs_extattr_list_entry	*attribute;
	struct hfs_extattr_header	ueh;
	struct iovec	local_aiov;
	struct uio	local_aio;
	struct mount	*mp = vp->v_mount;
	struct hfsmount	*hfsmp = VFSTOHFS(mp);
	struct cnode	*cp = VTOC(vp);
	off_t	base_offset;
	int	error = 0, ioflag;

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);
	if (!(hfsmp->hfs_extattr.uepm_flags & HFS_EXTATTR_UEPM_STARTED))
		return (EOPNOTSUPP);
	if (!hfs_extattr_valid_attrname(attrnamespace, name))
		return (EINVAL);

/*
 * XXX/TBD:
 */
/*
	error = extattr_check_cred(vp, attrnamespace, cred, td, IWRITE);
	if (error)
		return (error);
*/
	attribute = hfs_extattr_find_attr(hfsmp, attrnamespace, name);

	if (!attribute) {
		return (ENOATTR);
	}

	/*
	 * Early rejection of invalid offsets/length.
	 * Reject: any offset but 0 (replace)
	 *	 Any size greater than attribute size limit
 	 */
	if (uio->uio_offset != 0 ||
	    uio->uio_resid > attribute->uele_fileheader.uef_size) {
		return (ENXIO);
	}

	/*
	 * Find base offset of header in file based on file header size, and
	 * data header size + maximum data size, indexed by inode number.
	 */
	base_offset = sizeof(struct hfs_extattr_fileheader) +
	    cp->c_fileid * (sizeof(struct hfs_extattr_header) +
	    attribute->uele_fileheader.uef_size);

	/*
	 * Write out a data header for the data.
	 */
	ueh.ueh_len = uio->uio_resid;
	ueh.ueh_flags = HFS_EXTATTR_ATTR_FLAG_INUSE;
#ifdef HFS_GENERATIONS
	/* XXX/TBD: is there something similiar in hfs? */
	ueh.ueh_i_gen = ip->i_gen;
#endif
	local_aiov.iov_base = (caddr_t) &ueh;
	local_aiov.iov_len = sizeof(struct hfs_extattr_header);
	local_aio.uio_iov = &local_aiov;
	local_aio.uio_iovcnt = 1;
	local_aio.uio_rw = UIO_WRITE;
	local_aio.uio_segflg = UIO_SYSSPACE;
	local_aio.uio_procp = p;
	local_aio.uio_offset = base_offset;
	local_aio.uio_resid = sizeof(struct hfs_extattr_header);

	/*
	 * Acquire locks.
	 */
	VOP_LEASE(attribute->uele_backing_vnode, p, cred, LEASE_WRITE);

	/*
	 * Don't need to get a lock on the backing file if the setattr is
	 * being applied to the backing file, as the lock is already held.
	 */
	if (attribute->uele_backing_vnode != vp)
		vn_lock(attribute->uele_backing_vnode, 
		    LK_EXCLUSIVE | LK_RETRY, p);

	ioflag = IO_NODELOCKED;
	if (hfs_extattr_sync)
		ioflag |= IO_SYNC;
	error = VOP_WRITE(attribute->uele_backing_vnode, &local_aio, ioflag,
	    hfsmp->hfs_extattr.uepm_ucred);
	if (error) {
		goto vopunlock_exit;
	}

	if (local_aio.uio_resid != 0) {
		error = ENXIO;
		goto vopunlock_exit;
	}

	/*
	 * Write out user data.
	 */
	uio->uio_offset = base_offset + sizeof(struct hfs_extattr_header);

	ioflag = IO_NODELOCKED;
	if (hfs_extattr_sync)
		ioflag |= IO_SYNC;
	error = VOP_WRITE(attribute->uele_backing_vnode, uio, ioflag,
	    hfsmp->hfs_extattr.uepm_ucred);

vopunlock_exit:
	uio->uio_offset = 0;

	if (attribute->uele_backing_vnode != vp)
		VOP_UNLOCK(attribute->uele_backing_vnode, 0, p);

	return (error);
}

/*
 * Real work associated with removing an extended attribute from a vnode.
 * Assumes the attribute lock has already been grabbed.
 */
static int
hfs_extattr_rm(struct vnode *vp, int attrnamespace, const char *name,
    struct ucred *cred, struct proc *p)
{

	return (EOPNOTSUPP);
}

/*
 * Vnode operating to retrieve a named extended attribute.
 */
int
hfs_getextattr(struct vop_getextattr_args *ap)
/*
vop_getextattr {
	IN struct vnode *a_vp;
	IN int a_attrnamespace;
	IN const char *a_name;
	INOUT struct uio *a_uio;
	OUT size_t *a_size;
	IN struct ucred *a_cred;
	IN struct proc *a_p;
};
*/
{
	struct mount	*mp = ap->a_vp->v_mount;
	struct hfsmount *hfsmp = VTOHFS(ap->a_vp);
	int	error;


	hfs_extattr_uepm_lock(hfsmp, ap->a_p);

	error = hfs_extattr_get(ap->a_vp, ap->a_attrnamespace, ap->a_name,
	    ap->a_uio, ap->a_size, ap->a_cred, ap->a_p);

	hfs_extattr_uepm_unlock(hfsmp, ap->a_p);

	return (error);
}

/*
 * Vnode operation to set a named attribute.
 */
int
hfs_setextattr(struct vop_setextattr_args *ap)
/*
vop_setextattr {
	IN struct vnode *a_vp;
	IN int a_attrnamespace;
	IN const char *a_name;
	INOUT struct uio *a_uio;
	IN struct ucred *a_cred;
	IN struct proc *a_p;
};
*/
{
	struct mount	*mp = ap->a_vp->v_mount;
	struct hfsmount *hfsmp = VTOHFS(ap->a_vp);

	int	error;

	/*
	 * XXX: No longer a supported way to delete extended attributes.
	 */
	if (ap->a_uio == NULL)
		return (EOPNOTSUPP);

	hfs_extattr_uepm_lock(hfsmp, ap->a_p);

	error = hfs_extattr_set(ap->a_vp, ap->a_attrnamespace, ap->a_name,
	    ap->a_uio, ap->a_cred, ap->a_p);

	hfs_extattr_uepm_unlock(hfsmp, ap->a_p);

	return (error);
}

/*
 * Vnode operation to remove a named attribute.
 */
int
hfs_deleteextattr(struct vop_deleteextattr_args *ap)
/*
vop_deleteextattr {
	IN struct vnode *a_vp;
	IN int a_attrnamespace;
	IN const char *a_name;
	IN struct ucred *a_cred;
	IN struct proc *a_p;
};
*/
{
	struct mount	*mp = ap->a_vp->v_mount;
	struct hfsmount *hfsmp = VTOHFS(ap->a_vp);

	int	error;

	printf("hfs_deleteextattr called\n");
	hfs_extattr_uepm_lock(hfsmp, ap->a_p);

	error = hfs_extattr_rm(ap->a_vp, ap->a_attrnamespace, ap->a_name,
	    ap->a_cred, ap->a_p);


	hfs_extattr_uepm_unlock(hfsmp, ap->a_p);

	return (error);
}

/*
 * Disable extended attribute support on an FS.
 */
static int
hfs_extattr_disable(struct hfsmount *hfsmp, int attrnamespace,
    const char *attrname, struct proc *p)
{
	struct hfs_extattr_list_entry	*uele;
	int	error = 0;

	if (!hfs_extattr_valid_attrname(attrnamespace, attrname)) {
		return (EINVAL);
	}

	uele = hfs_extattr_find_attr(hfsmp, attrnamespace, attrname);
	if (!uele) {
		return (ENOATTR);
	}

	LIST_REMOVE(uele, uele_entries);

	vn_lock(uele->uele_backing_vnode, LK_SHARED | LK_RETRY, p);
/* XXX/TBD */
/*	ASSERT_VOP_LOCKED(uele->uele_backing_vnode, "hfs_extattr_disable"); */
	VOP_UNLOCK(uele->uele_backing_vnode, 0, p);
	error = vn_close(uele->uele_backing_vnode, FREAD|FWRITE,
	    p->p_ucred, p);

	FREE(uele, M_EXTATTR);

	return (error);
}

#endif /* !HFS_EXTATTR */
