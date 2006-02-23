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

#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_labelh.h>
#include <kern/ipc_kobject.h>

zone_t ipc_labelh_zone;

/*
 * Create a new label handle in the task described by the specified space.
 * The specified label is used in the label handle.  The associated port
 * name is copied out to namep and the task is granted send and receive rights.
 */
kern_return_t
labelh_new_user(ipc_space_t space, struct label *inl, mach_port_name_t *namep)
{
	kern_return_t kr;
	ipc_labelh_t lh;
	ipc_entry_t entry;
	ipc_port_t port;

	if (space == IS_NULL || space->is_task == NULL)
		return (KERN_INVALID_TASK);

	/* XXX - perform entrypoint check here */

	/*
	 * Note: the calling task will have a receive right for the port.
	 * This is different from label handles that reference tasks
	 * where the kernel holds the receive right and the caller only
	 * gets a send right.
	 */
	kr = ipc_port_alloc(space, namep, &port);
	if (kr != KERN_SUCCESS)
		return (kr);
	ip_reference(port);	/* ipc_port_alloc() does not add a reference */

	/* Convert right to MACH_PORT_TYPE_SEND_RECEIVE */
	port->ip_mscount++;
	port->ip_srights++;
	is_write_lock(space);
	entry = ipc_entry_lookup(space, *namep);
	if (entry != IE_NULL)
		entry->ie_bits |= MACH_PORT_TYPE_SEND;
	is_write_unlock(space);

	/* Allocate new label handle, insert port and label. */
	lh = (ipc_labelh_t)zalloc(ipc_labelh_zone);
	io_lock_init(lh);
	lh->lh_port = port;
	lh->lh_label = *inl;
	lh->lh_type = 0;
	lh->lh_references = 1;

	/* Must call ipc_kobject_set() with port unlocked. */
	ip_unlock(lh->lh_port);
	ipc_kobject_set(lh->lh_port, (ipc_kobject_t)lh, IKOT_LABELH);

	return (KERN_SUCCESS);
}

kern_return_t
mac_label_new(ipc_space_t space, mach_port_name_t *namep, vm_offset_t labelstr)
{
	struct label inl;
	kern_return_t kr;

	mac_init_port_label(&inl);
	if (mac_internalize_port_label(&inl, labelstr))
		return (KERN_INVALID_ARGUMENT);

	kr = labelh_new_user(space, &inl, namep);
	if (kr != KERN_SUCCESS) {
		mac_destroy_port_label(&inl);
		return (kr);
	}

	return (KERN_SUCCESS);
}

/*
 * This function should be used to allocate label handles
 * that are stored in other kernel objects, such as tasks.
 * They must be released along with that object.
 * The caller gets one reference, which can be applied to either the
 * port or the ipc_label_t structure itself.
 */
ipc_labelh_t
labelh_new(void)
{
	ipc_labelh_t lh;

	lh = (ipc_labelh_t)zalloc(ipc_labelh_zone);
	io_lock_init(lh);
	lh->lh_port = ipc_port_alloc_kernel();
	lh->lh_type = 0;
	lh->lh_references = 1;
	ip_unlock(lh->lh_port);

	/* Must call ipc_kobject_set() with port unlocked. */
	ipc_kobject_set(lh->lh_port, (ipc_kobject_t)lh, IKOT_LABELH);

	return (lh);
}

/*
 * Call with old label handle locked.
 * Returned label handle is unlocked.
 */
ipc_labelh_t
labelh_duplicate(ipc_labelh_t old)
{
	ipc_labelh_t lh;

	lh = labelh_new();
	ip_lock(lh->lh_port);
	mac_init_port_label(&lh->lh_label);
	mac_copy_port_label(&old->lh_label, &lh->lh_label);
	ip_unlock(lh->lh_port);
	return (lh);
}

/*
 * Call with old label handle locked.
 * Returned label handle is locked.
 */
ipc_labelh_t
labelh_modify(ipc_labelh_t old)
{
	ipc_labelh_t lh;

	if (old->lh_references == 1)
		return (old);
	lh = labelh_duplicate(old);
	lh_release(old);
	lh_check_unlock(old);
	lh_lock(lh);
	return (lh);
}

/*
 * Add or drop a reference on an (unlocked) label handle.
 */
ipc_labelh_t
labelh_reference(ipc_labelh_t lh)
{
	lh_lock(lh);
	lh_reference(lh);
	lh_unlock(lh);
	return (lh);
}

void
labelh_release(ipc_labelh_t lh)
{
	lh_lock(lh);
	lh_release(lh);
	lh_check_unlock(lh);
}

void
lh_free(ipc_labelh_t lh)
{
	ipc_object_release(&lh->lh_port->ip_object);
	mac_destroy_port_label(&lh->lh_label);
	zfree(ipc_labelh_zone, (vm_offset_t)lh);
}
