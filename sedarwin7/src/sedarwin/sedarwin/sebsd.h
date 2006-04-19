/*-
 * Copyright (c) 2002 Networks Associates Technologies, Inc.
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

#ifndef _SYS_SECURITY_SEBSD_H
#define _SYS_SECURITY_SEBSD_H

#include <sedarwin/flask_types.h>

#define SELINUX_MAGIC 0xf97cff8c
#define	SEBSD_ID_STRING			"sebsd"
#define	SEBSD_MAC_EXTATTR_NAME		"sebsd"
#define	SEBSD_MAC_EXTATTR_NAMESPACE	EXTATTR_NAMESPACE_SYSTEM
#define	SEBSD_MAC_LABEL_NAMESPACES	"sebsd"
#define	SEBSD_MAC_LABEL_NAME_COUNT	1

extern int	avc_debug_always_allow;

#if defined(_KERNEL) || defined (KERNEL)

#if !defined(_M_SEBSD_DEF) && !defined(APPLE)
MALLOC_DECLARE(M_SEBSD);
#define _M_SEBSD_DEF
#endif

extern int sebsd_verbose;

extern void sebsd_register_sysctls(void);
extern int security_init(void);
#if 0
extern int sebsd_syscall(struct thread *td, int call, void *args);
extern int thread_has_system(struct thread *td, access_vector_t perm);
extern int thread_has_security(struct thread *td, access_vector_t perm);
#endif
#else /* !_KERNEL */
extern int sebsd_enabled(void);
extern int sebsd_enforcing(void);
extern int sebsd_load_policy(const char *);
extern int sebsd_load_migscs(const char *);
#endif /* !_KERNEL */

#endif /* _SYS_SECURITY_SEBSD_H */
