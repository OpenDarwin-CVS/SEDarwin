/*-
 * Copyright (c) 2005, 2006 SPARTA, Inc.
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
#include <mach/mac.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_labelh.h>
#include <kern/task.h>

kern_return_t
mach_get_task_label_text(
	task_t		t,
	labelstr_t	policies,
	labelstr_t	outl)
{
	tasklabel_lock(t);
	mac_externalize_task_label(&t->maclabel, policies, outl, 512, 0);
	tasklabel_unlock(t);
  
	return KERN_SUCCESS;
}

int
mac_check_task_service_access(
	task_t       self,
	task_t       obj,
	const char * perm)
{
	tasklabel_lock2(self, obj);

	int rc = mac_check_service_access(
		&self->maclabel, &obj->maclabel, 
		"mach_task", perm);

	tasklabel_unlock2(self, obj);

	return rc;
}

kern_return_t
mac_check_named_access(
	ipc_space_t space,
	labelstr_t  subj,
	labelstr_t  obj,
	labelstr_t  serv,
	labelstr_t  perm)
{
	struct label subjl, objl;

	mac_init_task_label(&subjl);
	int rc = mac_internalize_port_label(&subjl, subj);
	if (rc) {
		mac_destroy_task_label(&subjl);
		return KERN_INVALID_ARGUMENT;
	}
	mac_init_task_label(&objl);
	rc = mac_internalize_port_label(&objl, obj);
	if (rc) {
		mac_destroy_task_label(&subjl);
		mac_destroy_task_label(&objl);
		return KERN_INVALID_ARGUMENT;
	}

	rc = mac_check_service_access(&subjl, &objl, serv, perm);
	mac_destroy_task_label(&subjl);
	mac_destroy_task_label(&objl);

	switch (rc) {
	case 0:
		return KERN_SUCCESS;
	case 22:
		/* EINVAL */
		return KERN_INVALID_ARGUMENT;
	default:
		return KERN_NO_ACCESS;
	}
}

kern_return_t
mac_check_name_port_access(
	ipc_space_t      space,
	labelstr_t       subj,
	mach_port_name_t obj,
	labelstr_t       serv,
	labelstr_t       perm)
{
	struct label  subjl;
	ipc_entry_t   entry;
	ipc_object_t  objp;
	kern_return_t kr;
	struct label  *objl;

	if (space == IS_NULL || space->is_task == NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(obj))
		return KERN_INVALID_NAME;

	mac_init_task_label(&subjl);
	int rc = mac_internalize_port_label(&subjl, subj);
	if (rc) {
		mac_destroy_task_label(&subjl);
		return KERN_INVALID_ARGUMENT;
	}

	kr = ipc_right_lookup_write(space, obj, &entry);
	if (kr != KERN_SUCCESS) {
		mac_destroy_task_label(&subjl);
		return kr;
	}

	objp = entry->ie_object;
	io_lock (objp);
	is_write_unlock (space);

	objl = io_getlabel(objp);
	if (objl == NULL) {
		io_unlock(objp);
		return KERN_INVALID_ARGUMENT;
	}

	rc = mac_check_service_access(&subjl, objl, serv, perm);
	io_unlocklabel(objp);
	io_unlock (objp);

	mac_destroy_task_label(&subjl);
	switch (rc) {
	case 0:
		return KERN_SUCCESS;
	case 22:
		/* EINVAL */
		return KERN_INVALID_ARGUMENT;
	default:
		return KERN_NO_ACCESS;
	}
}

kern_return_t
mac_check_port_access(
	ipc_space_t      space,
	mach_port_name_t sub,
	mach_port_name_t obj,
	labelstr_t       serv,
	labelstr_t       perm)
{
	ipc_entry_t    subi, obji;
	ipc_object_t   subp, objp;
	kern_return_t  kr;
	struct label  *objl, *subl;
	int            rc;

	if (space == IS_NULL || space->is_task == NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(obj) || !MACH_PORT_VALID(sub))
		return KERN_INVALID_NAME;

	kr = ipc_right_lookup_two_write(space, obj, &obji, sub, &subi);
	if (kr != KERN_SUCCESS)
		return kr;

	objp = obji->ie_object;
	subp = subi->ie_object;

	ipc_port_multiple_lock(); /* serialize (not necessary for LH, but simpler) */
	io_lock(objp);
	io_lock(subp);
	is_write_unlock (space);

	objl = io_getlabel(objp);
	if (objl == NULL)
		goto errout;
	subl = io_getlabel(subp);
	if (subl == NULL)
		goto errout;

	rc = mac_check_service_access(subl, objl, serv, perm);
	io_unlocklabel(subp);
	io_unlock(subp);
	io_unlocklabel(objp);
	io_unlock(objp);
	ipc_port_multiple_unlock();

	switch (rc) {
	case 0:
		return KERN_SUCCESS;
	case 22:
		/* EINVAL */
		return KERN_INVALID_ARGUMENT;
	default:
		return KERN_NO_ACCESS;
	}

errout:
	io_unlocklabel(subp);
	io_unlock(subp);
	io_unlocklabel(objp);
	io_unlock(objp);
	ipc_port_multiple_unlock();
	return KERN_INVALID_ARGUMENT;
}

kern_return_t
mac_request_label(
	ipc_space_t      space,
	mach_port_name_t sub,
	mach_port_name_t obj,
	labelstr_t       serv,
	mach_port_name_t *outlabel)
{
	ipc_entry_t    subi, obji;
	ipc_object_t   subp, objp;
	kern_return_t  kr;
	struct label  *objl, *subl, outl;
	int            rc;

	if (space == IS_NULL || space->is_task == NULL)
		return KERN_INVALID_TASK;

	if (!MACH_PORT_VALID(obj) || !MACH_PORT_VALID(sub))
		return KERN_INVALID_NAME;

	kr = ipc_right_lookup_two_write(space, obj, &obji, sub, &subi);
	if (kr != KERN_SUCCESS)
		return kr;

	objp = obji->ie_object;
	subp = subi->ie_object;

	ipc_port_multiple_lock(); /* serialize (not necessary for LH, but simpler) */
	io_lock(objp);
	io_lock(subp);
	is_write_unlock (space);

	objl = io_getlabel(objp);
	if (objl == NULL)
		goto errout;
	subl = io_getlabel(subp);
	if (subl == NULL)
		goto errout;

	mac_init_port_label(&outl);
	rc = mac_request_object_label(subl, objl, serv, &outl);
	io_unlocklabel(subp);
	io_unlock(subp);
	io_unlocklabel(objp);
	io_unlock(objp);
	ipc_port_multiple_unlock();

	switch (rc) {
	case 0:
		kr = labelh_new_user(space, &outl, outlabel);
		break;
	case 22:
		/* EINVAL */
		kr = KERN_INVALID_ARGUMENT;
		break;
	default:
		kr = KERN_NO_ACCESS;
		break;
	}

	if (kr != KERN_SUCCESS)
		mac_destroy_port_label(&outl);

	return kr;

errout:
	io_unlocklabel(subp);
	io_unlock(subp);
	io_unlocklabel(objp);
	io_unlock(objp);
	ipc_port_multiple_unlock();
	return KERN_INVALID_ARGUMENT;
}
