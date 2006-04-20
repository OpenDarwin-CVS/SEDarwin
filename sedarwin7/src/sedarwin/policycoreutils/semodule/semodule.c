/* Authors: Karl MacMillan <kmacmillan@tresys.com>
 *          Joshua Brindle <jbrindle@tresys.com>
 *          Jason Tang <jtang@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License as
 *      published by the Free Software Foundation, version 2.
 */

#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <semanage/modules.h>

enum client_modes { NO_MODE, INSTALL_M, UPGRADE_M, BASE_M, REMOVE_M,
                    LIST_M, RELOAD };
/* list of modes in which one ought to commit afterwards */
static const int do_commit[] = {
        0, 1, 1, 1, 1,
        0, 0
};

struct command {
        enum client_modes mode;
        char *arg;
};
static struct command *commands = NULL;
static int num_commands = 0;

/* options given on command line */
static int verbose;
static int reload;
static int no_reload;
static int create_store;
static int build;

static semanage_handle_t *sh = NULL;
static char *store;

extern char *optarg;
extern int optind;

static void cleanup(void) {
        while(--num_commands >= 0) {
                free(commands[num_commands].arg);
        }
        free(commands);
}

/* mmap() a file to '*data', returning the total number of bytes in
 * the file.  Returns 0 if file could not be opened or mapped. */
static size_t map_file(char *filename, char **data) {
        int fd;
        struct stat sb;
        if ((fd = open(filename, O_RDONLY)) == -1) {
                return 0;
        }
        if (fstat(fd, &sb) == -1 ||
            (*data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) ==
MAP_FAILED) {
                sb.st_size = 0;
        }
        close(fd);
        return sb.st_size;
}

/* Signal handlers. */
static void handle_signal(int sig_num) {
        if (sig_num == SIGINT || sig_num == SIGQUIT || sig_num == SIGTERM) {
                /* catch these signals, and then drop them */
        }
}

static void set_store(char *storename) {
	/* For now this only supports a store name, later on this 
	 * should support an address for a remote connection */

	if ((store = strdup(storename)) == NULL) {
		fprintf(stderr, "Out of memory!\n");
		goto bad;
	}	

	return;

bad:
	cleanup();
	exit(1);
}

/* Establish signal handlers for the process. */
static void create_signal_handlers(void) {
        if (signal(SIGINT, handle_signal) == SIG_ERR ||
            signal(SIGQUIT, handle_signal) == SIG_ERR ||
            signal(SIGTERM, handle_signal) == SIG_ERR) {
                fprintf(stderr, "Could not set up signal handler.\n");
                exit(255);
        }
}

static void usage(char *progname)
{
        printf("usage:  %s [options]... MODE [MODES]...\n", progname);
        printf("Manage SELinux policy modules.\n");
        printf("MODES:\n");
	printf("  -R, --reload		    reload policy\n");
	printf("  -B, --build		    build and reload policy\n");
        printf("  -i,--install=MODULE_PKG   install a new module\n");
        printf("  -u,--upgrade=MODULE_PKG   upgrade existing module\n");
        printf("  -b,--base=MODULE_PKG      install new base module\n"); 
        printf("  -r,--remove=MODULE_NAME   remove existing module\n");
        printf("  -l,--list-modules         display list of installed modules\n");
        printf("Other options:\n");
	printf("  -s,--store	   name of the store to operate on\n");
	printf("  -n,--noreload	   do not reload policy after commit\n");
        printf("  -h,--help        print this message and quit\n");
        printf("  -v,--verbose     be verbose\n");
}

/* Sets the global mode variable to new_mode, but only if no other
 * mode has been given. */
static void set_mode(enum client_modes new_mode, char *arg) {
        struct command *c;
        char *s;
        if ((c = realloc(commands, sizeof(*c) * (num_commands + 1))) == NULL) {
                fprintf(stderr, "Out of memory!\n");
                cleanup();
                exit(1);
        }
        commands = c;
        commands[num_commands].mode = new_mode;
        commands[num_commands].arg = NULL;        
        num_commands++;
        if (arg != NULL) {
                if ((s = strdup(arg)) == NULL) {
                        fprintf(stderr, "Out of memory!\n");
                        cleanup();
                        exit(1);
                }
                commands[num_commands - 1].arg = s;
        }
}

/* Parse command line and set global options. */
static void parse_command_line(int argc, char **argv) {
        static struct option opts [] = {
		{"store", required_argument, NULL, 's'},
                {"base", required_argument, NULL, 'b'},
                {"help", 0, NULL, 'h'},
                {"install", required_argument, NULL, 'i'},
                {"list-modules", 0, NULL, 'l'},
                {"verbose", 0, NULL, 'v'},
                {"remove", required_argument, NULL, 'r'},
                {"upgrade", required_argument, NULL, 'u'},
		{"reload", 0, NULL, 'R'},
		{"noreload", 0, NULL, 'n'},
                {"build", 0, NULL, 'B'},
                {NULL, 0, NULL, 0}
        };
        int i;
        verbose = 0;
	reload = 0;
	no_reload = 0;
	create_store = 0;
        while ((i = getopt_long(argc, argv, "s:b:hi:lvqr:u:RnB", opts, NULL)) != -1) {
                switch (i) {
                case 'b': set_mode(BASE_M, optarg); create_store = 1; break;
                case 'h': usage(argv[0]); exit(0);
                case 'i': set_mode(INSTALL_M, optarg); break;
                case 'l': set_mode(LIST_M, NULL); break;
                case 'v': verbose = 1; break;
                case 'r': set_mode(REMOVE_M, optarg); break;
                case 'u': set_mode(UPGRADE_M,optarg); break;
		case 's': set_store(optarg); break;
		case 'R': reload = 1; break;
		case 'n': no_reload = 1; break;
		case 'B': build = 1; break;
                case '?':
                default: {
                        usage(argv[0]);
                        exit(1);
                }
            }
        }
	if (optind < argc) {
		fprintf (stderr, "Extraneous arguments:  ");
		while (optind < argc)
			fprintf (stderr, "%s", argv[optind++]);
		fprintf(stderr, "\n");
		usage (argv [0]);
                cleanup();
		exit (1);
	}
	if ((build || reload) && num_commands) {
		fprintf(stderr, "build or reload should not be used with other commands\n");
		usage(argv[0]);
		exit(1);
	}
        if (num_commands == 0 && reload == 0 && build == 0) {
                fprintf(stderr, "At least one mode must be specified.\n");
                usage(argv[0]);
                exit(1);
        }
}
    
int main(int argc, char *argv[]) {
        int i, commit = 0;
        int result;
        int status = EXIT_FAILURE;

        create_signal_handlers();
        parse_command_line(argc, argv);

	if (build) commit = 1;
        
	sh = semanage_handle_create();
	if (!sh) {
                fprintf(stderr, "%s:  Could not create semanage handle\n", argv[0]);
                goto cleanup;
	}

	if (store) {
		/* Set the store we want to connect to, before connecting.
		 * this will always set a direct connection now, an additional
		 * option will need to be used later to specify a policy server 
		 * location */
		semanage_select_store(sh, store, SEMANAGE_CON_DIRECT);
	}
	
	/* if installing base module create store if necessary, for bootstrapping */
	semanage_set_create_store(sh, create_store);
	
	if (!create_store) {
		if (!semanage_is_managed(sh)) {
			fprintf(stderr, "%s: SELinux policy is not managed or store cannot be accessed.\n", argv[0]);
			goto cleanup;
		}
	
		if (semanage_access_check(sh) < SEMANAGE_CAN_READ) {
			fprintf(stderr, "%s: Cannot read policy store.\n", argv[0]);
			goto cleanup;
		}
	}

        if ((result = semanage_connect(sh)) < 0) {
                fprintf(stderr, "%s:  Could not connect to policy handler\n", argv[0]);
                goto cleanup;
        }

	if (reload) {
		if ((result = semanage_reload_policy(sh)) < 0) {
			fprintf(stderr, "%s:  Could not reload policy\n", argv[0]);
			goto cleanup;
		}
	}

	if (build) {
		if ((result = semanage_begin_transaction(sh)) < 0) {
			fprintf(stderr, "%s:  Could not begin transaction\n", argv[0]);
			goto cleanup;
		}
	}

        for (i = 0; i < num_commands; i++) {
                enum client_modes mode = commands[i].mode;
                char *mode_arg = commands[i].arg;
                char *data;
                size_t data_len;
                if (mode == INSTALL_M || mode == UPGRADE_M || mode == BASE_M) {
                        if ((data_len = map_file(mode_arg, &data)) == 0) {
                                fprintf(stderr, "%s:  Could not read file '%s':\n", argv[0], mode_arg);
                                goto cleanup;
                        }
                }
                switch (mode) {
                case INSTALL_M: {
                        if (verbose) {
                                printf("Attempting to install module '%s':\n", mode_arg);
                        }
                        result = semanage_module_install(sh, data, data_len);
                        break;
                }
                case UPGRADE_M: {
                        if (verbose) {
                                printf("Attempting to upgrade module '%s':\n", mode_arg);
                        }
                        result = semanage_module_upgrade(sh, data, data_len);
                        break;
                }
                case BASE_M: {
                        if (verbose) {
                                printf("Attempting to install base module '%s':\n", mode_arg);
                        }
                        result = semanage_module_install_base(sh, data, data_len);
                        break;
                }
                case REMOVE_M: {
                        if (verbose) {
                                printf("Attempting to remove module '%s':\n", mode_arg);
                        }
                        result = semanage_module_remove(sh, mode_arg);
                        break;
                }
                case LIST_M: {
                        semanage_module_info_t *modinfo;
                        int num_modules;
                        if (verbose) {
                                printf("Attempting to list active modules:\n");
                        }
                        if ((result = semanage_module_list(sh, &modinfo, &num_modules)) >= 0) {
                                int j;
                                if (num_modules == 0) {
                                        printf("No modules.\n");
                                }
                                for (j = 0; j < num_modules; j++) {
                                        semanage_module_info_t *m = semanage_module_list_nth(modinfo, j);
                                        printf("%s\t%s\n",
                                               semanage_module_get_name(m),
                                               semanage_module_get_version(m));
                                        semanage_module_info_datum_destroy(m);
                                }
                                free(modinfo);
                        }
                        break;
                }
                default: {
                        fprintf(stderr, "%s:  Unknown mode specified.\n", argv[0]);
			usage(argv[0]);
                        goto cleanup;
                }
                }
                commit += do_commit[mode];
                if (mode == INSTALL_M || mode == UPGRADE_M || mode == BASE_M) {
                        munmap(data, data_len);
                }
                if (result < 0) {
			fprintf(stderr, "%s:  Failed on %s!\n", argv[0], mode_arg ?: "list");
                        goto cleanup;
                }
                else if (verbose) {
                        printf("Ok: return value of %d.\n", result);
                }
        }
        
        if (commit) {
		if (verbose)
			printf("Committing changes:\n");
		if (no_reload)
			semanage_set_reload(sh, 0);
		if (build)
			semanage_set_rebuild(sh, 1);
 		result = semanage_commit(sh);
        }
        
        if (result < 0) {
                fprintf(stderr, "%s:  Failed!\n", argv[0]);
                goto cleanup;
        }
        else if (commit && verbose) {
                printf("Ok: transaction number %d.\n", result);
        }

        if (semanage_disconnect(sh) < 0) {
                fprintf(stderr, "%s:  Error disconnecting\n", argv[0]);
                goto cleanup;
        }
        status = EXIT_SUCCESS;

 cleanup:
	if (semanage_is_connected(sh)) {
	        if (semanage_disconnect(sh) < 0) {
			fprintf(stderr, "%s:  Error disconnecting\n", argv[0]);
		}
	}
        semanage_handle_destroy(sh);
        cleanup();
        exit(status);
}
