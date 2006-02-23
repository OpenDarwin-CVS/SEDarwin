
/*-
 * Copyright (c) 2003, 2004 Networks Associates Technology, Inc.
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

#include <security/mac_internal.h>

extern struct mac_label_element_list_t mac_label_element_list;

void
mac_init_task_label(struct label *label)
{

	mac_init_label(label);
	MAC_PERFORM(init_task_label, label);
}

void
mac_copy_cred_to_task(struct label *cred, struct label *task)
{

	MAC_PERFORM(copy_cred_to_task, cred, task);
}

void
mac_destroy_task_label(struct label *label)
{

	MAC_PERFORM(destroy_task_label, label);
	mac_destroy_label(label);
}

void
mac_create_task(struct task *parent, struct task *child, struct label *pl,
    struct label *chl, struct label *chportl)
{

	MAC_PERFORM(create_task, parent, child, pl, chl, chportl);
}

void
mac_create_kernel_task(struct task *t, struct label *tl, struct label *tportl)
{

	MAC_PERFORM(create_kernel_task, t, tl, tportl);
}

int
mac_externalize_task_label(struct label *label, char *elements,
    char *outbuf, size_t outbuflen, int flags)
{
	int error = 0;

	if (elements[0] == '*') {
		int count;
		MAC_EXTERNALIZE_REGISTERED_LABELS(cred, label, outbuf, 
		    outbuflen, count);
	} else
		MAC_EXTERNALIZE_LIST(cred, label, elements, outbuf, outbuflen);

	return (error);
}
