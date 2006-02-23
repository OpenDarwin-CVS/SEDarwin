/*
 * Copyright (c) 2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef __SYS_INTERFACES__
#define __SYS_INTERFACES__

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>

typedef struct
{
	char *name;
	short flags;
	struct in_addr addr;
	struct in_addr mask;
	struct in_addr netaddr;
	struct in_addr bcast;
} interface_t;

typedef struct
{
	unsigned int count;
	interface_t *interface;
} interface_list_t;

interface_list_t *sys_interfaces(void);
void sys_interfaces_release(interface_list_t *l);
int sys_is_my_address(interface_list_t *l, struct in_addr *a);
int sys_is_my_network(interface_list_t *l, struct in_addr *a);

#endif	/* __SYS_INTERFACES__ */
