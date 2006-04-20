/* Authors: Jason Tang <jtang@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef SEMANAGE_CONF_H
#define SEMANAGE_CONF_H

#include <semanage/handle.h>
#include <sys/types.h>
#include <sys/stat.h>

/* libsemanage has its own configuration file.	It has two main parts:
 *  - single options
 *  - external programs to execute whenever a policy is to be loaded
 */

typedef struct semanage_conf {
	enum semanage_connect_type store_type;
	char *store_path;	/* used for both socket path and policy dir */
	int server_port;
	int policyvers;		/* version for server generated policies */
        int expand_check;
	mode_t file_mode;
	struct external_prog *load_policy;
	struct external_prog *setfiles;
	struct external_prog *genhomedircon;
	struct external_prog *mod_prog, *linked_prog, *kernel_prog;
} semanage_conf_t;

/* A linked list of verification programs.  Each one is called in
 * order of appearance within the configuration file.
 */
typedef struct external_prog {
	char *path;
	char *args;
	struct external_prog *next;
} external_prog_t;

semanage_conf_t *semanage_conf_parse(const char *config_filename);
void semanage_conf_destroy(semanage_conf_t *conf);

#endif
