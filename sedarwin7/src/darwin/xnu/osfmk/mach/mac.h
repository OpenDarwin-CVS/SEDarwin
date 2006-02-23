
/*-
 * Copyright (c) 2004 Networks Associates Technology, Inc.
 * All rights reserved.
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
 */

#include <mach/message.h>
#include <kern/task.h>

/* tasks */
void mac_init_task (struct task *t, struct label *tlabel);
void mac_destroy_task_label (struct label *tlabel);
void mac_create_task (struct task *parent, struct task *child, struct label *pl,
		      struct label *chl, struct label *chportl);
void mac_create_kernel_task (struct task *t, struct label *tlabel, struct label *tportl);

void mac_update_task_label (struct label *plabel, struct task *t);

void mac_modify_task_label (struct task *pt, void *arg,
			    void (*f)(struct label *l, void *arg));

/* ports */
void mac_init_port_label (struct label *l);
void mac_destroy_port_label (struct label *l);
void mac_create_port (struct label *it, struct label *st, struct label *plabel);
void mac_create_kernel_port (struct label *plabel, int isreply);
void mac_update_port_kobject (struct label *plabel, int kotype);
void mac_copy_port_label (struct label *src, struct label *dest);
void mac_update_port_from_cred_label (struct label *src, struct label *dest);
int mac_check_port_relabel (struct label *task, struct label *oldl, struct label *newl);

int mac_check_port_send (struct label *task, struct label *port);
int mac_check_port_make_send (struct label *task, struct label *port);
int mac_check_port_move_receive (struct label *task, struct label *port);
int mac_check_port_copy_send (struct label *task, struct label *port);

int mac_check_port_hold_send (struct label *task, struct label *port);
int mac_check_port_hold_receive (struct label *task, struct label *port);

int mac_check_task_service_access (task_t self, task_t obj, const char *perm);

int mac_request_object_label (struct label *subj, struct label *obj,
    const char *serv, struct label *out);

int mac_check_ipc_method (struct label *task, struct label *port, int msgid);

