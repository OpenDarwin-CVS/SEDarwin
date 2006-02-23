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


 server portions of MiG sample code 

*/

#import	<mach/mach.h>
#import	<mach/message.h>
#include "mtests.h"

/* Prints an integer.

   serv:   port of server
   access: access decision from MAC framework
   i:      int to print
   label:  label handle for message sender

*/
int printi (mach_port_t serv, int access, int i, msg_labels_t label)
{
	char labeltext[512];

	/* textualize the label by asking the policy for the text version */
	mach_get_label_text(mach_task_self(), label.sender, "sebsd", labeltext);
	printf ("access=%d i=%d label=%s\n", access, i, labeltext);
	return 0;
}

/* Prints an array of integers.

   serv:   port of server
   access: access decision from MAC framework
   ar:     array to print
   nar:    number of elements in array. This is added by MiG.

*/
int printia (mach_port_t serv, int access, intarray ar, mach_msg_type_number_t nar)
{
	int i;
	printf ("printia access=%d\n", access);
	for (i = 0; i < nar; i++)
		printf ("  %d\n", ar[i]);
	return 0;
}

int main (int argc, const char *argv[])
{
	kern_return_t ret;
	mach_port_t sport, bootstrap;

	/* Get a receive right so we can receive messages. */
	ret = mach_port_allocate (mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &sport);

        if (ret != KERN_SUCCESS) {
                mach_error("port_allocate:", ret);
                exit(1);
        }

 	/* Add a make_send right to the server port */
	ret = mach_port_insert_right(mach_task_self(), sport,
				     sport, MACH_MSG_TYPE_MAKE_SEND);
        if (ret != KERN_SUCCESS) {
                mach_error("port insert right:", ret);
                exit(1);
        }

	/* Get a bootstrap port to register port info for the service we 
           want to provide 
	*/
	ret = task_get_bootstrap_port(mach_task_self(), &bootstrap);
        if (ret != KERN_SUCCESS) {
                mach_error("task_get_bootstrap_port:", ret);
                exit(1);
        }

        /*
         * Check the name in.  The ASCII name will be
         *  "migtest1"; any client wishing to
         *  communicate with the time server must 
         *  know to use this name.
         */
        ret = bootstrap_register(bootstrap, "migtest1", sport); 
        if (ret != KERN_SUCCESS) {
                mach_error("bootstrap register:", ret);
                exit(1);
        }

	mach_msg_return_t mresult;

	/* Main event loop */
	for (;;) {
		/* Note that since this server knows that it will be receiving
		   labels, it requests a label trailer. Also note the requesting
		   of the MACH_RCV_TRAILER_AV which carries the access decision
		   from the policies loaded.
		 */
		mresult = mach_msg_server(
			mtest_server,
			8192, sport,
			MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_LABELS)|
                        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AV)|
                        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0));
		if (mresult != MACH_MSG_SUCCESS)
			mach_error(mresult, "mach_msg_server");
	}
}

