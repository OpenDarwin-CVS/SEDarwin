/*-
 * Copyright (c) 2005 SPARTA, Inc.
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

kern_return_t mac_label_new (ipc_space_t task, mach_port_name_t *name,
			     vm_offset_t labelstr)
{
  ipc_labelh_t lh;
  struct label inl;
  ipc_port_t   port, sport;
  kern_return_t kr;

  if (task == IS_NULL)
    return (KERN_INVALID_TASK);

  mac_init_port_label (&inl);
  if (mac_internalize_port_label (&inl, labelstr))
    return KERN_INVALID_ARGUMENT;

  port = ipc_port_alloc_kernel();

  lh = (ipc_labelh_t) zalloc(ipc_labelh_zone);
  io_lock_init(lh);
  lh->lh_port = port;
  lh->lh_type = 0;
  lh->lh_references = 1;
  lh->lh_label = inl;
  ipc_kobject_set(port, (ipc_kobject_t)lh, IKOT_LABELH);

  sport = ipc_port_make_send_locked(port);
  ip_release(port);
  ip_unlock(port);
  *name = ipc_port_copyout_send (port,task);
  return 0;
}

/* This function should be used to allocate label handles
   that are stored in other kernel objects, such as tasks.
   They must be released along with that object.
   The caller gets one reference, which can be applied to either the
   port or the ipc_label_t structure itself.
*/
ipc_labelh_t labelh_new ()
{
  ipc_labelh_t lh = (ipc_labelh_t) zalloc(ipc_labelh_zone);
  io_lock_init(lh);
  lh->lh_port = ipc_port_alloc_kernel();
  lh->lh_type = 0;
  lh->lh_references = 1;
  ipc_kobject_set(lh->lh_port, (ipc_kobject_t)lh, IKOT_LABELH);
  ip_unlock(lh->lh_port);
  return lh;
}

/* call with old locked; returned object is unlocked */

ipc_labelh_t labelh_duplicate (ipc_labelh_t old)
{
  ipc_labelh_t lh = (ipc_labelh_t) zalloc(ipc_labelh_zone);
  io_lock_init(lh);
  lh->lh_port = ipc_port_alloc_kernel();
  lh->lh_type = 0;
  lh->lh_references = 1;
  ipc_kobject_set(lh->lh_port, (ipc_kobject_t)lh, IKOT_LABELH);
  mac_init_port_label (&lh->lh_label);
  mac_copy_port_label (&old->lh_label, &lh->lh_label);
  ip_unlock(lh->lh_port);
  return lh;
}

/* call with old locked; returns a locked object */

ipc_labelh_t labelh_modify (ipc_labelh_t old)
{
  if (old->lh_references == 1)
    return old;
  ipc_labelh_t lh = labelh_duplicate (old);
  lh_release(old);
  lh_check_unlock (old);
  lh_lock (lh);
  return lh;
}

/* add or drop a reference on a label handle; not locked */

ipc_labelh_t labelh_reference (ipc_labelh_t lh)
{
  lh_lock(lh);
  lh_reference(lh);
  lh_unlock(lh);
  return lh;
}

void labelh_release(ipc_labelh_t lh)
{
  lh_lock(lh);
  lh_release(lh);
  lh_check_unlock(lh);
}

void lh_free (ipc_labelh_t lh)
{
    ipc_object_release(&lh->lh_port->ip_object);
    mac_destroy_port_label (&lh->lh_label);
    zfree(ipc_labelh_zone, (vm_offset_t)lh);
}
