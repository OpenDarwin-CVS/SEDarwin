/*
 * This program allows a user to change their SELinux RBAC role and/or
 * SELinux TE type (domain) in a manner similar to the way the
 * traditional UNIX su program allows a user to change their identity.
 * 
 * This program was based on the version from SELinux with:
 * 	Authors:  Tim Fraser , 
 *      	     Anthony Colatrella <amcolat@epoch.ncsc.mil>
 * 	Various bug fixes by Stephen Smalley <sds@epoch.ncsc.mil>
 */

#include <sys/cdefs.h>

#include <sys/types.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>

#include <pam/pam_appl.h>
#include <pam/pam_misc.h>
#include <sys/mac.h>
#include <sedarwin/sebsd.h>
#include <sedarwin/flask_types.h>

#define SEBSD_SERVICE_NAME "sebsd_newrole"

extern char **environ;

void usage(void);

static inline char *
xstrdup(const char *s)
{
	char *s2;

	s2 = strdup(s);
	if (!s2) {
		fprintf(stderr, "Out of memory!\n");
		exit(1);
	}

	return s2;
}


int
authenticate_via_pam(const struct passwd *pw)
{
	int result = 0;
	int error;
	pam_handle_t *pam_handle;

	/* 
	 * This is a jump table of functions for PAM to use when it
	 * wants to communicate with the user.  We'll be using
	 * misc_conv(), which is provided for us via pam_misc.h.
	 */

	struct pam_conv pam_conversation = {
	  misc_conv,
	  NULL
	};

	error = pam_start(SEBSD_SERVICE_NAME, pw->pw_name, &pam_conversation, 
	    &pam_handle);
	if (error != PAM_SUCCESS) {
		fprintf(stderr, "Error, failed to initialize PAM\n");
		exit(1);
	}

	/* Ask PAM to authenticate the user running this program */
	error = pam_authenticate(pam_handle,0);
	if (error == PAM_SUCCESS) {
		result = 1;
	} else {
		printf("Debug: error %d (%s)\n", error, pam_strerror(pam_handle, error));
	}

	pam_end(pam_handle, PAM_SUCCESS);
	
	return(result);
}

int
main(int argc, char *argv[])
{
	int ch;
	char *ep;
	char *role = NULL;
	char *type = NULL;
	char *old_context, *new_context, *labeltext;
	char * context;
	struct passwd *pw;
	struct passwd pw_copy;
	mac_t execlabel;

	if (!sebsd_enabled()) {
		fprintf(stderr, "Sorry, sebsd_newrole may only be used when "
		    "the SEBSD security module is loaded\n");
		exit(1);
	}

	while ((ch = getopt(argc, argv, "r:t:")) != -1) {
		switch (ch) {
		case 'r':
			if (role) {
				fprintf(stderr, 
				    "Error, multiple roles specified\n");
				usage();
			}
			role = optarg;
			break;
		case 't':
			if (type) {
				fprintf(stderr, 
				    "Error, multiple types specified\n");
				usage();
			}
			type = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/*
	 * Verify that only the correct combination of arguments were given
	 */
	if (!(role || type))
		usage();

	/* 
	 * Fill in a default type if one hasn't been specified 
	 */
	if (role && !type) {
		if (get_default_type(role, &type)) {
			fprintf(stderr, "Error, couldn't get default type.\n");
			exit(1);
		}
	}

	if ((old_context = getseccontext()) == NULL) {
		fprintf(stderr, "Error, could not retrieve user context\n");
		exit(1);
	}

	context = context_new(old_context);
	
	if( !(pw=getpwnam(context_user_get(context))) ) {
		fprintf(stderr,"Error, could not find passwd entry.\n");
		exit(1);
	}


	pw_copy = *pw;
	pw = &pw_copy;
	pw->pw_name = xstrdup(pw->pw_name);
	pw->pw_dir = xstrdup(pw->pw_dir);
	pw->pw_shell = xstrdup(pw->pw_shell);

	printf("Authenticating %s.\n",pw->pw_name);

	/* Authenticate the user running this program. */
	if(!authenticate_via_pam(pw)) {
		fprintf(stderr,"Error, incorrect password for %s\n", 
		    pw->pw_name);
		return(1);
	}
	errno = 0;

	/*
	 * Construct a new context based on our old context and the
	 * arguments specified on the command line.
	 */
	if (role) {
		if (context_role_set(context, role)) {
			fprintf(stderr,
			    "Error, failed to set new role %s\n", role);
			exit(1);
		}
	}
	if (type) {
		if (context_type_set(context, type)) {
			fprintf(stderr,
			    "Error, failed to set new type %s\n", type);
			exit(1);
		}
	}

	new_context = context_str(context);
	if (new_context == NULL) {
		fprintf(stderr, "Error, failed to create new context\n");
		exit(1);
	}

	if (asprintf(&labeltext, "sebsd/%s", new_context) == -1 ||
	    mac_from_text(&execlabel, labeltext) != 0) {
		fprintf(stderr, "Error, failed to create new context\n");
		exit(1);
	}
	free(labeltext);

	int error;
	if (argc == 0) {
		char *shell_argv[2];

		shell_argv[0] = pw->pw_shell;
		shell_argv[1] = NULL;
		printf("Executing default shell (%s) with context %s\n", 
		    pw->pw_shell, new_context);
		error = mac_execve(pw->pw_shell, shell_argv, environ, execlabel);
	} else {
		printf("Executing program (%s) with context %s\n", 
		    argv[0], new_context);
		error = mac_execve(argv[0], argv, environ, execlabel);
	}
	if (error)
	  perror ("exec");
}

void
usage(void)
{

	fprintf(stderr, "usage: sebsd_newrole -r role [ -t type ] [ args ]\n");
	exit(1);
}
