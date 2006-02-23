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

#ifndef _SYS_SECURITY_SEBSD_LABELS_H
#define _SYS_SECURITY_SEBSD_LABELS_H

#include <sedarwin/sebsd.h>
#include <sedarwin/linux-compat.h>
#include <sedarwin/flask_types.h>
#include <sedarwin/avc/avc.h>

struct task_security_struct {
	security_id_t osid;
	security_id_t sid;
	struct avc_entry_ref avcr;
};

struct file_security_struct {
	security_id_t sid;
};

struct vnode_security_struct {
	security_id_t task_sid;
	security_id_t sid;
	security_class_t sclass;
	struct avc_entry_ref avcr;
};

struct network_security_struct {
	security_id_t sid;
	security_id_t task_sid;
	struct avc_entry_ref avcr;
};

struct ipc_security_struct {
	security_id_t sid;
	security_class_t sclass;
	struct avc_entry_ref avcr;
};

struct mount_security_struct {
	security_id_t sid;              /* SID of file system */
#ifndef __FreeBSD__
	struct psidtab *psidtab;        /* persistent SID mapping */
#endif
	unsigned char uses_psids;       /* uses persistent SID flag */
#ifndef __FreeBSD__
	unsigned char initialized;      /* initialization flag */
#endif
	unsigned char uses_task;        /* use creating task SID for inodes */
	unsigned char uses_genfs;       /* use security_genfs_sid for inodes */
	unsigned char proc;             /* call procfs_set_sid */
	unsigned char uses_trans;       /* call security_transition_sid */
};

struct mount_fs_security_struct {
	security_id_t sid;              /* default object SID of file system */
};
#endif /* _SYS_SECURITY_SEBSD_LABELS_H */
