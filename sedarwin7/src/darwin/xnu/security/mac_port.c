
/*-
 * Copyright (c) 2003, 2004 Networks Associates Technology, Inc.
 * All rights reserved.
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
#include <mach/message.h>

void
mac_init_port_label(struct label *l)
{

	mac_init_label(l);
	MAC_PERFORM (init_port_label, l);
}

void
mac_destroy_port_label(struct label *l)
{

	MAC_PERFORM (destroy_port_label, l);
	mac_destroy_label(l);
}

void
mac_copy_port_label(struct label *src, struct label *dest)
{

	MAC_PERFORM(copy_port_label, src, dest);
}

void
mac_update_port_from_cred_label(struct label *src, struct label *dest)
{

	MAC_PERFORM(update_port_from_cred_label, src, dest);
}

void
mac_create_port(struct label *it, struct label *st, struct label *port)
{

	MAC_PERFORM(create_port, it, st, port);
}

void
mac_create_kernel_port(struct label *port, int isreply)
{

	MAC_PERFORM(create_kernel_port, port, isreply);
}

void
mac_update_port_kobject(struct label *port, int kotype)
{

	MAC_PERFORM(update_port_kobject, port, kotype);
}

int
mac_internalize_port_label(struct label *label, char *string)
{
	int error;

	MAC_INTERNALIZE_LIST(cred, label, string);

	return (error);
}

int
mac_externalize_port_label(struct label *label, char *elements,
    char *outbuf, size_t outbuflen, int flags)
{
	int error;

	MAC_EXTERNALIZE_LIST(cred, label, elements, outbuf, outbuflen);

	return (error);
}

int
mac_check_port_relabel(struct label *task, struct label *old,
    struct label *newlabel)
{
	int error;

	MAC_CHECK(check_port_relabel, task, old, newlabel);

	return (error);
}

int
mac_check_port_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_send, task, port);

	return (error);
}

int
mac_check_port_receive(struct label *task, struct label *sender)
{
	int error;

	MAC_CHECK(check_port_receive, task, sender);

	return (error);
}

int
mac_check_port_make_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_make_send, task, port);

	return (error);
}

int
mac_check_port_make_send_once(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_make_send_once, task, port);

	return (error);
}

int
mac_check_port_copy_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_copy_send, task, port);

	return (error);
}

int
mac_check_port_move_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_move_send, task, port);

	return (error);
}

int
mac_check_port_move_send_once(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_move_send_once, task, port);

	return (error);
}

int
mac_check_port_move_receive(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_move_receive, task, port);

	return (error);
}

int
mac_check_port_hold_send(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_hold_send, task, port);

	return (error);
}

int
mac_check_port_hold_send_once(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_hold_send_once, task, port);

	return (error);
}

int
mac_check_port_hold_receive(struct label *task, struct label *port)
{
	int error;

	MAC_CHECK(check_port_hold_receive, task, port);

	return (error);
}

int
mac_check_ipc_method(struct label *task, struct label *port, int msgid)
{
	int error;

	MAC_CHECK(check_ipc_method, task, port, msgid);

	return (error);
}
