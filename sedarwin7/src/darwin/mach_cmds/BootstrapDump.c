/*
    File:       BootstrapDump.c

    Contains:   A program to dump the Mach bootstrap port namespace.

    Written by: DTS

    Copyright:  Copyright (c) 2002 by Apple Computer, Inc., All Rights Reserved.

    Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple Computer, Inc.
                ("Apple") in consideration of your agreement to the following terms, and your
                use, installation, modification or redistribution of this Apple software
                constitutes acceptance of these terms.  If you do not agree with these terms,
                please do not use, install, modify or redistribute this Apple software.

                In consideration of your agreement to abide by the following terms, and subject
                to these terms, Apple grants you a personal, non-exclusive license, under Apple’s
                copyrights in this original Apple software (the "Apple Software"), to use,
                reproduce, modify and redistribute the Apple Software, with or without
                modifications, in source and/or binary forms; provided that if you redistribute
                the Apple Software in its entirety and without modifications, you must retain
                this notice and the following text and disclaimers in all such redistributions of
                the Apple Software.  Neither the name, trademarks, service marks or logos of
                Apple Computer, Inc. may be used to endorse or promote products derived from the
                Apple Software without specific prior written permission from Apple.  Except as
                expressly stated in this notice, no other rights or licenses, express or implied,
                are granted by Apple herein, including but not limited to any patent rights that
                may be infringed by your derivative works or by other works in which the Apple
                Software may be incorporated.

                The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
                WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
                WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
                PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
                COMBINATION WITH YOUR PRODUCTS.

                IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR
                CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
                GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
                ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION
                OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT
                (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN
                ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Change History (most recent first):

$Log$
Revision 1.1  2006/02/23 16:34:27  deker
Initial revision


*/
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <servers/bootstrap.h>
#include <mach/mach.h>

static const char *gProgramName;

static void PrintUsage(const char *command)
{
    fprintf(stderr, "%s: Usage: BootstrapPortDump [ pid ]\n", gProgramName);
}

static const char *policies = "?sebsd,?ipctrace,?mls";

int main (int argc, const char * argv[]) 
{
    kern_return_t 	err;
    kern_return_t 	junk;
    pid_t		pid;
    mach_port_t		task;
    mach_port_t 	bootstrapPort;
    name_array_t 	serviceNames;
    unsigned int 	serviceNameCount;
    name_array_t 	serverNames;
    unsigned int 	serverNameCount;
    bool_array_t 	active;
    unsigned int 	activeCount;
    unsigned int 	i;
    
    task          = MACH_PORT_NULL;
    bootstrapPort = MACH_PORT_NULL;
    serviceNames  = NULL;
    serverNames   = NULL;
    active        = NULL;
    
    // Set gProgramName to the last path component of argv[0]
    
    gProgramName = strrchr(argv[0], '/');
    if (gProgramName == NULL) {
        gProgramName = argv[0];
    } else {
        gProgramName += 1;
    }
    
    // Parse our arguments.

    err = 0;
    switch (argc) {
        case 1:
            pid = getpid();
            break;
        case 2:
            {
                char *firstInvalid;
                
                pid = (pid_t) strtol(argv[1], &firstInvalid, 10);
                if ( (argv[1][0] == 0) || (*firstInvalid != 0) ) {
                    PrintUsage(argv[0]);
                    err = EINVAL;
                }
            }
            break;
        default:
            PrintUsage(argv[0]);
            err = EINVAL;
            break;
    }
    
    // Get the bootstrap port for the target process.
    
    if (err == 0) {
	err = task_for_pid(mach_task_self(), pid, &task);
    }
    if (err == 0) {
        err = task_get_bootstrap_port(task, &bootstrapPort);
    }

    char label[512];
    label[0] = 0;

    mach_get_label_text (mach_task_self(), bootstrapPort, policies, label);
    printf ("Namespace label: %s\n", label);
    
    // Get the list of registered services.
    
    if (err == 0) {
        err = bootstrap_info(bootstrapPort, &serviceNames, &serviceNameCount, 
                                            &serverNames, &serverNameCount, 
                                            &active, &activeCount);
    }
    if (err == 0) {
        if ( (serviceNameCount != serverNameCount) || (serverNameCount != activeCount) ) {
            fprintf(stderr, "%s: Count mismatch (%u/%u/%u)\n", gProgramName, serviceNameCount, serverNameCount, activeCount);
            err = EINVAL;
        }
    }
    
    // Print the list.
    
    if (err == 0) {
        for (i = 0; i < serviceNameCount; i++) {
            const char *activeStr;
            
            switch (active[i]) {
                case BOOTSTRAP_STATUS_INACTIVE:
                    activeStr = " is inactive";
                    break;
                case BOOTSTRAP_STATUS_ACTIVE:
                    activeStr = "";		// active is expected, so don't clutter up printout
                    break;
                case BOOTSTRAP_STATUS_ON_DEMAND:
                    activeStr = " on demand";
                    break;
                default:
                    activeStr = " is unknown";
                    break;
            }

	    mach_port_t sp;
	    if (KERN_SUCCESS == bootstrap_look_up (bootstrapPort, serviceNames[i], &sp))
		    mach_get_label_text (mach_task_self(), sp, policies, label);

            if ( serverNames[i][0] != 0 ) {
	      printf("\"%s\" by \"%s\"%s label:%s\n", serviceNames[i], serverNames[i], activeStr, label);
            } else {
	      printf("\"%s\"%s label:%s\n", serviceNames[i], activeStr, label);
            }
        }
    }
    
    // Clean up.  This isn't necessary for this tool (because the resources 
    // will be cleaned up when we quit), but it's possible that someone might 
    // cut'n'paste this code into a larger application, and we want to 
    // demonstrate how to do the right thing.
    
    if (task != MACH_PORT_NULL) {
        junk = mach_port_deallocate(mach_task_self(), task);
        assert(junk == 0);
    }
    if (bootstrapPort != MACH_PORT_NULL) {
        junk = mach_port_deallocate(mach_task_self(), bootstrapPort);
        assert(junk == 0);
    }
    if (serviceNames != NULL) {
        junk = vm_deallocate(mach_task_self(), (vm_address_t) serviceNames, serviceNameCount * sizeof(*serviceNames));
        assert(junk == 0);
    }
    if (serverNames != NULL) {
        junk = vm_deallocate(mach_task_self(), (vm_address_t) serverNames, serverNameCount * sizeof(*serverNames));
        assert(junk == 0);
    }
    if (active != NULL) {
        junk = vm_deallocate(mach_task_self(), (vm_address_t) active, activeCount * sizeof(*active));
        assert(junk == 0);
    }
    
    if (err != 0) {
        fprintf(stderr, "%s: Failed with error %d.\n", gProgramName, err);
    }
    
    return (err == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
