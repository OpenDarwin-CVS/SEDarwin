/*-
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by NAI Labs, the
 * Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 * $FreeBSD$
 */

#ifdef __FreeBSD__
#include <sedarwin/ss/fileutils.h>
#include <sedarwin/ss/global.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/proc.h>

int
fclose(FILE *fp)
{
	int error;

	mtx_lock(&Giant);
	error = vn_close(fp->FILE_vp, fp->FILE_saved_open_flags,
	    curthread->td_ucred, curthread);
	mtx_unlock(&Giant);
	sebsd_free(fp, M_TEMP);
	return (error);
}

FILE *
sebsd_fopen(const char *path, const char *type, enum uio_seg pathseg)
{
	struct nameidata nd;
	struct thread *td = curthread;
	FILE *fp;
	int error;

	if (strcmp(type, "r") != 0)
		return (NULL);
	fp = sebsd_malloc(sizeof(*fp), M_TEMP, M_WAITOK | M_ZERO);
	fp->FILE_saved_open_flags = FREAD;
	mtx_lock(&Giant);	
	NDINIT(&nd, LOOKUP, LOCKLEAF, pathseg, path, td);
	error = vn_open(&nd, &fp->FILE_saved_open_flags, 0, -1);
	if (error) {
		mtx_unlock(&Giant);
		return (NULL);
	}

	NDFREE(&nd, NDF_ONLY_PNBUF);
	VOP_UNLOCK(nd.ni_vp, 0, td);
	mtx_unlock(&Giant);	

	fp->FILE_vp = nd.ni_vp;
	fp->FILE_uio.uio_iov = &fp->FILE_iov;
	fp->FILE_uio.uio_iovcnt = 1;
	fp->FILE_uio.uio_segflg = UIO_SYSSPACE;
	fp->FILE_uio.uio_offset = 0;
	if (nd.ni_vp->v_type != VREG) {
		(void)fclose(fp);
		return (NULL);
	}
	return (fp);
}

FILE *
fopen(const char *path, const char *type)
{

	return (sebsd_fopen(path, type, UIO_SYSSPACE));
}

size_t
fread(void *ptr, size_t size, size_t nmemb, FILE *fp)
{
	struct thread *td = curthread;

	if (size == 0)
		return (0);

	fp->FILE_uio.uio_iov->iov_base = ptr;
	fp->FILE_uio.uio_resid = fp->FILE_uio.uio_iov->iov_len = size * nmemb;
	fp->FILE_uio.uio_td = td;
	mtx_lock(&Giant);	
	vn_lock(fp->FILE_vp, LK_SHARED | LK_RETRY | LK_NOPAUSE, td);
	(void)VOP_READ(fp->FILE_vp, &fp->FILE_uio, 0, td->td_ucred);
	VOP_UNLOCK(fp->FILE_vp, 0, td);
	mtx_unlock(&Giant);	
	return (((size * nmemb) - fp->FILE_uio.uio_resid) / size);
}

#endif /* __FreeBSD__ */
