/* Author: Jason Tang     <jtang@tresys.com>
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

%{

#include "semanage_conf.h"

#include <sepol/policydb.h>
#include <selinux/selinux.h>
#include <semanage/handle.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

extern int semanage_lex();                /* defined in conf-scan.c */
int semanage_error(char *msg);

extern FILE *semanage_in;
extern char *semanage_text;

static int parse_module_store(char *arg);
static void semanage_conf_external_prog_destroy(external_prog_t *ep);
static int new_external_prog(external_prog_t **chain);

static semanage_conf_t *current_conf;
static external_prog_t *new_external;
static int parse_errors;

#define PASSIGN(p1,p2) { free(p1); p1 = p2; }

%}

%union {
        int d;
        char *s;
}

%token MODULE_STORE VERSION EXPAND_CHECK FILE_MODE
%token LOAD_POLICY_START SETFILES_START
%token VERIFY_MOD_START VERIFY_LINKED_START VERIFY_KERNEL_START BLOCK_END
%token PROG_PATH PROG_ARGS
%token <s> ARG
%type <d> verify_start_tok

%%

config_file:    config_line config_file
        |       /* empty */
        ;

config_line:    single_opt
        |       command_block
        |       verify_block
        ;

single_opt:     module_store
        |       version
        |       expand_check
        |       file_mode
        ;

module_store:   MODULE_STORE '=' ARG {
                        if (parse_module_store($3) != 0) {
                                parse_errors++;
                                YYABORT;
                        }
                }

        ;

version:        VERSION '=' ARG  {
                        current_conf->policyvers = atoi($3);
                        free($3);
                        if (current_conf->policyvers < sepol_policy_kern_vers_min() ||
                            current_conf->policyvers > sepol_policy_kern_vers_max()) {
                                parse_errors++;
                                YYABORT;
                        }
                }
        ;

expand_check:   EXPAND_CHECK '=' ARG  {
                        current_conf->expand_check = atoi($3);
                        free($3);
                }
        ;

file_mode:   FILE_MODE '=' ARG  {
                        current_conf->file_mode = strtoul($3, NULL, 8);
                        free($3);
                }
        ;

command_block: 
                command_start external_opts BLOCK_END  {
                        if (new_external->path == NULL) {
                                parse_errors++;
                                YYABORT;
                        }
                }
        ;

command_start:
                LOAD_POLICY_START {
                        semanage_conf_external_prog_destroy(current_conf->load_policy);
                        current_conf->load_policy = NULL;
                        if (new_external_prog(&current_conf->load_policy) == -1) {
                                parse_errors++;
                                YYABORT;
                        }
                }
        |       SETFILES_START {
                        semanage_conf_external_prog_destroy(current_conf->setfiles);
                        current_conf->setfiles = NULL;
                        if (new_external_prog(&current_conf->setfiles) == -1) {
                                parse_errors++;
                                YYABORT;
                        }
                }
        ;

verify_block:   verify_start external_opts BLOCK_END  {
                        if (new_external->path == NULL) {
                                parse_errors++;
                                YYABORT;
                        }
                }
        ;

verify_start:   verify_start_tok {
                        if ($1 == -1) {
                                parse_errors++;
                                YYABORT;
                        }
                }
        ;

verify_start_tok: VERIFY_MOD_START  {$$ = new_external_prog(&current_conf->mod_prog);}
        |       VERIFY_LINKED_START {$$ = new_external_prog(&current_conf->linked_prog);}
        |       VERIFY_KERNEL_START {$$ = new_external_prog(&current_conf->kernel_prog);}
        ;

external_opts:  external_opt external_opts
        |       /* empty */
        ;

external_opt:   PROG_PATH '=' ARG  { PASSIGN(new_external->path, $3); }
        |       PROG_ARGS '=' ARG  { PASSIGN(new_external->args, $3); }
        ;

%%

static int semanage_conf_init(semanage_conf_t *conf) {
	conf->store_type = SEMANAGE_CON_DIRECT;
	conf->store_path = strdup(basename(selinux_policy_root()));
	conf->policyvers = sepol_policy_kern_vers_max();
	conf->expand_check = 1;
	conf->file_mode = 0644;

	if ((conf->load_policy = calloc(1, sizeof(*(current_conf->load_policy)))) == NULL) {
		return -1;
	}
	if ((conf->load_policy->path = strdup("/usr/sbin/load_policy")) == NULL) {
		return -1;
	}
	conf->load_policy->args = NULL;
	
	if ((conf->setfiles = calloc(1, sizeof(*(current_conf->setfiles)))) == NULL) {
		return -1;
	}
	if ((conf->setfiles->path = strdup("/usr/sbin/setfiles")) == NULL ||
	    (conf->setfiles->args = strdup("-q -c $@ $<")) == NULL) {
		return -1;
	}

	if ((conf->genhomedircon= calloc(1, sizeof(*(current_conf->genhomedircon)))) == NULL) {
		return -1;
	}
	if ((conf->genhomedircon->path = strdup("/usr/sbin/genhomedircon")) == NULL ||
	    (conf->genhomedircon->args = strdup("-t $@")) == NULL) {
		return -1;
	}

	return 0;
}

/* Parse a libsemanage configuration file.  THIS FUNCTION IS NOT
 * THREAD-SAFE!	 Return a newly allocated semanage_conf_t *.  If the
 * configuration file could be read, parse it; otherwise rely upon
 * default values.  If the file could not be parsed correctly or if
 * out of memory return NULL.
 */
semanage_conf_t *semanage_conf_parse(const char *config_filename) {
	if ((current_conf = calloc(1, sizeof(*current_conf))) == NULL) {
		return NULL;
	}
	if (semanage_conf_init(current_conf) == -1) {
		goto cleanup;
	}
	if ((semanage_in = fopen(config_filename, "r")) == NULL) {
		/* configuration file does not exist or could not be
		 * read.  THIS IS NOT AN ERROR.	 just rely on the
		 * defaults. */
		return current_conf;
	}
	parse_errors = 0;
	semanage_parse();
	fclose(semanage_in);
	if (parse_errors != 0) {
		goto cleanup;
	}
	return current_conf;
 cleanup:
	semanage_conf_destroy(current_conf);
	return NULL;
}

static void semanage_conf_external_prog_destroy(external_prog_t *ep) {
	while (ep != NULL) {
		external_prog_t *next = ep->next;
		free(ep->path);
		free(ep->args);
		free(ep);
		ep = next;
	}
}

/* Deallocates all space associated with a configuration struct,
 * including the pointer itself. */
void semanage_conf_destroy(semanage_conf_t *conf) {
	if (conf != NULL) {
		free(conf->store_path);
		semanage_conf_external_prog_destroy(conf->load_policy);
		semanage_conf_external_prog_destroy(conf->setfiles);
		semanage_conf_external_prog_destroy(conf->genhomedircon);
		semanage_conf_external_prog_destroy(conf->mod_prog);
		semanage_conf_external_prog_destroy(conf->linked_prog);
		semanage_conf_external_prog_destroy(conf->kernel_prog);
		free(conf);
	}
}

int semanage_error(char *msg) {
	parse_errors++;
	return 0;
}

/* Take the string argument for a module store.	 If it is exactly the
 * word "direct" then have libsemanage directly manipulate the module
 * store. The policy path will default to the active policy directory.
 * Otherwise if it begins with a forward slash interpret it as
 * an absolute path to a named socket, to which a policy server is
 * listening on the other end.	Otherwise treat it as the host name to
 * an external server; if there is a colon in the name then everything
 * after gives a port number.  The default port number is 4242.
 * Returns 0 on success, -1 if out of memory, -2 if a port number is
 * illegal.
 */
static int parse_module_store(char *arg) {
	/* arg is already a strdup()ed copy of yytext */
	if (arg == NULL) {
		return -1;
	}
	free(current_conf->store_path);
	if (strcmp(arg, "direct") == 0) {
		current_conf->store_type = SEMANAGE_CON_DIRECT;
		current_conf->store_path = strdup(basename(selinux_policy_root()));
		current_conf->server_port = -1;
		free(arg);
	}
	else if(*arg == '/') {
		current_conf->store_type = SEMANAGE_CON_POLSERV_LOCAL;
		current_conf->store_path = arg;
		current_conf->server_port = -1;
	}
	else {
		char *s;
		current_conf->store_type = SEMANAGE_CON_POLSERV_REMOTE;
		if ((s = strchr(arg, ':')) == NULL) {
			current_conf->store_path = arg;
			current_conf->server_port = 4242;
		}
		else {
			char *endptr;
			*s = '\0';
			current_conf->store_path = arg;
			current_conf->server_port = strtol(s + 1, &endptr, 10);
			if (*(s + 1) == '\0' || *endptr != '\0') {
				return -2;
			}
		}
	}
	return 0;
}

/* Helper function; called whenever configuration file specifies
 * another external program.  Returns 0 on success, -1 if out of
 * memory.
 */
static int new_external_prog(external_prog_t **chain) {
	if ((new_external = calloc(1, sizeof(*new_external))) == NULL) {
		return -1;
	}
	/* hook this new external program to the end of the chain */
	if (*chain == NULL) {
		*chain = new_external;
	}
	else {
		external_prog_t *prog = *chain;
		while (prog->next != NULL) {
			prog = prog->next;
		}
		prog->next = new_external;
	}
	return 0;
}
