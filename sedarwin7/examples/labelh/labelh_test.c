/*-
 * Copyright (c) 2006 SPARTA, Inc.
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

#import	<mach/mach.h>
#import	<mach/message.h>

#include <mach/mach_error.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "security.h"

extern char *__progname;

void usage(void);

int
main (int argc, char **argv)
{
        kern_return_t		kr;
	mach_port_name_t	labelHandle, portName;
	char			*textlabel, textbuf[512];
	int			ch, count, dealloc, destroy, getnew, getport;
	int			gettask, reqlabel, i;

	count = 1;
	dealloc = destroy = getnew = gettask = getport = reqlabel = 0;

	/* XXX - add port lh and request lh */
	while ((ch = getopt(argc, argv, "c:dn:prtx")) != -1) {
		switch (ch) {
		case 'c':
			count = atoi(optarg);
			break;

		case 'd':
			dealloc = 1;
			break;

		case 'n':
			getnew = 1;
			textlabel = optarg;
			break;

		case 'p':
			getport = 1;
			break;

		case 'r':
			reqlabel = 1;
			break;

		case 't':
			gettask = 1;
			break;

		case 'x':
			destroy = 1;
			break;

		default:
			usage();
		}
	}

	if (getnew + gettask + getport + reqlabel != 1)
		usage();

	/* Get a new port. */
	if (getport || reqlabel) {
		kr = mach_port_allocate(mach_task_self(),
		    MACH_PORT_RIGHT_RECEIVE, &portName);
		if (kr != KERN_SUCCESS) {
			mach_error("mach_port_allocate():", kr);
			exit(1);
		}
	}

	for (i = 0; i < count; i++) {
		if (getnew) {
			/* Get a new label handle */
			kr = mac_label_new(mach_task_self(), &labelHandle,
			    textlabel);
			if (kr != KERN_SUCCESS) {
				fprintf(stderr, "mac_label_new(%s)", textlabel);
				mach_error(":", kr);
				exit(1);
			}
			printf("new label handle: 0x%x (%s)\n", labelHandle,
			    textlabel);
		}
		if (gettask) {
			/* Get label handle for our task */
			kr = mach_get_task_label(mach_task_self(),
			    &labelHandle);
			if (kr != KERN_SUCCESS) {
				mach_error("mach_get_task_label():", kr);
				exit(1);
			}
			kr = mach_get_task_label_text(mach_task_self(),
			    "sebsd", textbuf);
			if (kr != KERN_SUCCESS) {
				mach_error("mach_get_task_label_text():", kr);
				exit(1);
			}
			printf("task label handle: 0x%x (%s)\n", labelHandle,
			    textbuf);
		}
		if (getport) {
			/* Get a label handle for the new port */
			kr = mach_get_label(mach_task_self(), portName,
			    &labelHandle);
			if (kr != KERN_SUCCESS) {
				mach_error("mach_get_label():", kr);
				exit(1);
			}
			kr = mach_get_label_text(mach_task_self(), labelHandle,
			    "sebsd", textbuf);
			if (kr != KERN_SUCCESS) {
				mach_error("mach_get_label_text():", kr);
				exit(1);
			}
			printf("port label handle: 0x%x (%s)\n", labelHandle,
			    textbuf);
		}
		if (reqlabel) {
			/* Compute label handle based on port and task. */
			kr = mac_request_label(mach_task_self(), portName,
			    mach_task_self(), "mach_task", &labelHandle);
			if (kr != KERN_SUCCESS) {
				mach_error("mac_request_label():", kr);
				exit(1);
			}
			kr = mach_get_label_text(mach_task_self(), labelHandle,
			    "sebsd", textbuf);
			if (kr != KERN_SUCCESS) {
				mach_error("mach_get_label_text():", kr);
				exit(1);
			}
			printf("computed label handle: 0x%x (%s)\n",
			    labelHandle, textbuf);
		}
		if (dealloc) {
			/* Deallocate the label handle */
			kr = mach_port_deallocate(mach_task_self(), labelHandle);
			if (kr != KERN_SUCCESS) {
				mach_error("mach_port_deallocate:", kr);
				exit(1);
			}
			printf("successfully deallocated the label handle\n");
		}
		if (destroy) {
			/* Destroy the label handle */
			kr = mach_port_destroy(mach_task_self(), labelHandle);
			if (kr != KERN_SUCCESS) {
				mach_error("mach_port_destroy:", kr);
				exit(1);
			}
			printf("successfully destroyed the label handle\n");
		}
	}

	exit(0);
}

void
usage(void)
{
	fprintf(stderr, "usage: %s [-c count] [-dx] -n text_label | -t | -r | -p\n",
	    __progname);
	exit(1);
}
