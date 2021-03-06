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

/* ca - Perform an arbitrary access check. 
   Subject and object labels use the normal framework label format.
   Permissions and permission classes are currently only defined for
   the SEDarwin policy module; the class definitions are found in 
   policy/flask/security_classes and the permission definitions are
   found in policy/flask/access_vectors.

   This is not a query, but an actual access check. Systems running in a
   non-enforcing mode will always indicate allowed. 
*/

#include <stdio.h>
#include <mach/mach_types.h>
#include <mach/security.h>

int
main (int argc, char *argv[])
{
	if (argc < 5) {
		printf("usage: %s <subject> <object> <perm class> <permission>\n",
		    argv[0]);
		return (1);
	}

	mach_port_t subl, objl;
	int r = mac_label_new(mach_task_self(), &subl, argv[1]);
	if (r) {
		printf ("bad label: %s\n", argv[1]);
		return 1;
	}
	r = mac_label_new (mach_task_self(), &objl, argv[2]);
	if (r) {
		printf ("bad label: %s\n", argv[2]);
		return (1);
	}

	char sublt[512], objlt[512];
	r = mach_get_label_text(mach_task_self(), subl, "sebsd", sublt);
	if (r) {
		printf ("error reading back subject label\n");
		return (1);
	}
	r = mach_get_label_text(mach_task_self(), objl, "sebsd", objlt);
	if (r) {
		printf ("error reading back object label\n");
		return (1);
	}

	r = mac_check_port_access (mach_task_self(), 
	    subl, objl, argv[3], argv[4]);
	printf("access %s %s:%s { %s } = %d\n",
	    argv[1], argv[2], argv[3], argv[4], r);

	r = mach_port_destroy (mach_task_self(), subl);
	if (r)
		printf ("error freeing subject label\n");
	r = mach_port_destroy (mach_task_self(), objl);
	if (r)
		printf ("error freeing object label\n");
 
	return (0);
}
