/*
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by NAI Labs,
 * the Security Research Division of Network Associates, Inc. under
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
 * $FreeBSD: $
 */

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/mac_constant.h>

#include <security/mac_biba/mac_biba.h>
#include <security/mac_mls/mac_mls.h>

/*
 * The following label defines "system high", used by the TrustedBSD
 * userland Trusted Code Base (TCB).  It is assigned during the install
 * process to TCB files, and used by privileged processes when setting
 * rights on files that are part of the TCB (/etc/passwd and so on).
 * Changing this label has serious consequences both in terms of
 * propagation (recompile everything, make sure the kernel default
 * label matches, etc), as well as security (changing this may break
 * assumptions throughout the system).  Don't change it unless you
 * know what you're doing.  Seriously.
 */

#define	BIBA_ELEMENT_HIGH	{ MAC_BIBA_TYPE_HIGH, 0 }
#define	BIBA_ELEMENT_EQUAL	{ MAC_BIBA_TYPE_EQUAL, 0 }
#define	BIBA_ELEMENT_UNDEF	{ MAC_BIBA_TYPE_UNDEF, 0 }
#define	MLS_ELEMENT_LOW		{ MAC_MLS_TYPE_LOW, 0 }
#define	MLS_ELEMENT_EQUAL	{ MAC_MLS_TYPE_EQUAL, 0 }
#define	MLS_ELEMENT_UNDEF	{ MAC_MLS_TYPE_UNDEF, 0 }

struct mac mac_userland_system_high_label = {
	MAC_FLAG_INITIALIZED,
	{ MAC_BIBA_FLAG_SINGLE | MAC_BIBA_FLAG_RANGE,
	  BIBA_ELEMENT_HIGH, BIBA_ELEMENT_HIGH, BIBA_ELEMENT_HIGH },
	{ MAC_MLS_FLAG_SINGLE | MAC_MLS_FLAG_RANGE,
	  MLS_ELEMENT_LOW, MLS_ELEMENT_LOW, MLS_ELEMENT_LOW },
	{ "system_d" }
};

/*
 * Label the syslog daemon should run with.
 */
struct mac mac_userland_syslogd_label = {
	MAC_FLAG_INITIALIZED,
	{ MAC_BIBA_FLAG_SINGLE | MAC_BIBA_FLAG_RANGE,
	  BIBA_ELEMENT_HIGH, BIBA_ELEMENT_HIGH, BIBA_ELEMENT_HIGH },
	{ MAC_MLS_FLAG_SINGLE | MAC_MLS_FLAG_RANGE,
	  MLS_ELEMENT_LOW, MLS_ELEMENT_LOW, MLS_ELEMENT_LOW },
	{"syslog_d"}
};

/*
 * Label used by syslogd for /dev/log socket.
 */
struct mac mac_userland_dev_log_label = {
	MAC_FLAG_INITIALIZED,
	{ MAC_BIBA_FLAG_SINGLE,
	  BIBA_ELEMENT_EQUAL, BIBA_ELEMENT_UNDEF, BIBA_ELEMENT_UNDEF },
	{ MAC_MLS_FLAG_SINGLE,
	  MLS_ELEMENT_EQUAL, MLS_ELEMENT_UNDEF, MLS_ELEMENT_UNDEF },
	{"dev_log_t"}
};
