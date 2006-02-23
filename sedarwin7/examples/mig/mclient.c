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

client portions of sample MiG code

*/

#import	<mach/mach.h>
#import	<mach/message.h>
#include "mtestu.h"

int main (int argc, const char *argv[])
{
        kern_return_t   ret;
	mach_port_t     bootstrapPort;
	mach_port_t     mtest;

	/* Begin by getting a bootstrap port to request port info for the 
	   service we want to talk to */
        ret = task_get_bootstrap_port(mach_task_self(), &bootstrapPort);
        if (ret != KERN_SUCCESS) {
                mach_error("task_get_bootstrap_port:", ret);
                exit(1);
        }

	/* Perform lookup to get port of the service we want to talk to */
        ret = bootstrap_look_up(bootstrapPort, argc>1 ? argv[1] : "migtest1", &mtest);
        if (ret != KERN_SUCCESS) {
                mach_error("look up:", ret);
                exit(1);
        }

	/* Call to printi() to print an integer via RPC */
	ret = printi (mtest, 16);
	if (ret != KERN_SUCCESS)
		mach_error("printi", ret);

	int ia[6];

	ia[0] = 0; ia[1] = 1; ia[2] = 2;

	/* Call to printia() to print an array of integers via RPC */
	ret = printia (mtest, ia, 3);
	if (ret != KERN_SUCCESS)
		mach_error("printia", ret);

	return 0;
}
