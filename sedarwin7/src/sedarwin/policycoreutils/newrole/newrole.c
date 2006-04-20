/************************************************************************
 *
 * newrole
 *
 * SYNOPSIS:
 *
 * This program allows a user to change their SELinux RBAC role and/or
 * SELinux TE type (domain) in a manner similar to the way the traditional
 * UNIX su program allows a user to change their identity.
 *
 * USAGE:
 *
 * newrole [ -r role ] [ -t type ] [ -l level ] [ -V ] [ -- args ]
 *
 * BUILD OPTIONS:
 *
 * option USE_PAM:
 *
 * Set the USE_PAM constant if you want to authenticate users via PAM.
 * If USE_PAM is not set, users will be authenticated via direct
 * access to the shadow password file.
 *
 * If you decide to use PAM must be told how to handle newrole.  A
 * good rule-of-thumb might be to tell PAM to handle newrole in the
 * same way it handles su, except that you should remove the pam_rootok.so
 * entry so that even root must re-authenticate to change roles. 
 *
 * If you choose not to use PAM, make sure you have a shadow passwd file
 * in /etc/shadow.  You can use a symlink if your shadow passwd file
 * lives in another directory.  Example:
 *   su
 *   cd /etc
 *   ln -s /etc/auth/shadow shadow
 *
 * If you decide not to use PAM, you will also have to make newrole
 * setuid root, so that it can read the shadow passwd file.
 * 
 *
 * option CANTSPELLGDB:
 *
 * If you set CANTSPELLGDB you will turn on some debugging printfs.
 *
 *
 * Authors:  Tim Fraser , 
 *           Anthony Colatrella <amcolat@epoch.ncsc.mil>
 * Various bug fixes by Stephen Smalley <sds@epoch.ncsc.mil>
 *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>               /* for malloc(), realloc(), free() */
#include <pwd.h>                  /* for getpwuid() */
#include <sys/types.h>            /* to make getuid() and getpwuid() happy */
#include <sys/wait.h>		  /* for wait() */
#include <getopt.h>               /* for getopt_long() form of getopt() */
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <selinux/selinux.h>      /* for is_selinux_enabled() */
#include <selinux/flask.h>        /* for SECCLASS_CHR_FILE */
#include <selinux/context.h>      /* for context-mangling functions */
#include <selinux/get_default_type.h>
#include <selinux/get_context_list.h> /* for SELINUX_DEFAULTUSER */
#include <sys/mac.h>
#include <signal.h>
#ifdef USE_AUDIT
#include <libaudit.h>
#endif
#ifdef LOG_AUDIT_PRIV
#ifndef USE_AUDIT
#error LOG_AUDIT_PRIV needs the USE_AUDIT option
#endif
#include <sys/prctl.h>
#include <sys/capability.h>
#endif
#ifdef USE_NLS
#include <locale.h>			    /* for setlocale() */
#include <libintl.h>			    /* for gettext() */
#define _(msgid) gettext (msgid)
#else
#define _(msgid) (msgid)
#endif
#ifndef PACKAGE
#define PACKAGE "policycoreutils"   /* the name of this package lang translation */
#endif

/* USAGE_STRING describes the command-line args of this program. */
#define USAGE_STRING "USAGE: newrole [ -r role ] [ -t type ] [ -l level ] [ -V ] [ -- args ]"

#define DEFAULT_CONTEXT_SIZE 255  /* first guess at context size */

extern char **environ;

char *xstrdup(const char *s)
{
  char *s2;

  s2 = strdup(s);
  if (!s2) {
	  fprintf(stderr, _("Out of memory!\n"));
	  exit(1);
  }
  return s2;
}

static char *
build_new_range(char *newlevel, const char *range)
{
  char *newrangep = NULL;
  const char *tmpptr;
  size_t len;

  /* a missing or empty string */
  if (!range || !strlen(range) || !newlevel || !strlen(newlevel))
    return NULL;

  /* if the newlevel is actually a range - just use that */
  if (strchr(newlevel, '-')) {
      newrangep = strdup(newlevel);
      return newrangep;
  }

  /* look for MLS range */
  tmpptr = strchr(range, '-');

  if (tmpptr) {
    /* we are inserting into a ranged MLS context */
    len = strlen(newlevel) + 1 + strlen(tmpptr + 1) + 1;
    newrangep = (char *)malloc(len);
    if (!newrangep)
      return NULL;
    snprintf(newrangep, len, "%s-%s", newlevel, tmpptr + 1);
  } else {
    /* we are inserting into a currently non-ranged MLS context */
    if (!strcmp(newlevel, range)) {
      newrangep = strdup(range);
    } else {
      len = strlen(newlevel) + 1 + strlen(range) + 1;
      newrangep = (char *)malloc(len);
      if (!newrangep)
        return NULL;
      snprintf(newrangep, len, "%s-%s", newlevel, range);
    }
  }

  return newrangep;
}

#ifdef USE_PAM

/************************************************************************
 *
 * All PAM code goes in this section.
 *
 ************************************************************************/

#include <unistd.h>               /* for getuid(), exit(), getopt() */

#include <pam/pam_appl.h>    /* for PAM functions */
#include <pam/pam_misc.h>  

#define SERVICE_NAME "newrole"    /* the name of this program for PAM */

int authenticate_via_pam( const struct passwd *, const char * );

/* authenticate_via_pam()
 *
 * in:     pw - struct containing data from our user's line in 
 *                         the passwd file.
 * out:    nothing
 * return: value   condition
 *         -----   ---------
 *           1     PAM thinks that the user authenticated themselves properly
 *           0     otherwise
 *
 * This function uses PAM to authenticate the user running this
 * program.  This is the only function in this program that makes PAM
 * calls.
 *
 */

int authenticate_via_pam( const struct passwd *pw, const char *ttyn ) {

  int result = 0;    /* our result, set to 0 (not authenticated) by default */
  int rc;	     /* pam return code */
  pam_handle_t *pam_handle;      /* opaque handle used by all PAM functions */
  const char *tty_name;

  /* This is a jump table of functions for PAM to use when it wants to *
   * communicate with the user.  We'll be using misc_conv(), which is  *
   * provided for us via pam_misc.h.                                   */
  struct pam_conv pam_conversation = {
    misc_conv,
    NULL
  };

  /* Make `p_pam_handle' a valid PAM handle so we can use it when *
   * calling PAM functions.                                       */
  rc = pam_start( SERVICE_NAME,
		pw->pw_name,
		&pam_conversation,
		&pam_handle );
  if( rc != PAM_SUCCESS ) {
    fprintf( stderr, _("failed to initialize PAM\n") );
    exit( -1 );
  }

  if( strncmp(ttyn, "/dev/", 5) == 0 )
    tty_name = ttyn+5;
  else
    tty_name = ttyn;

  rc = pam_set_item( pam_handle, PAM_TTY, tty_name );
  if( rc != PAM_SUCCESS ) {
    fprintf( stderr, _("failed to set PAM_TTY\n") );
    goto out;
  }

  /* Ask PAM to authenticate the user running this program */
  rc = pam_authenticate(pam_handle,0);
  if( rc != PAM_SUCCESS ) {
    goto out;
  }

  /* Ask PAM to verify acct_mgmt */
  rc = pam_acct_mgmt(pam_handle,0);
  if( rc == PAM_SUCCESS ) {
    result = 1;  /* user authenticated OK! */
  } 

  /* We're done with PAM.  Free `pam_handle'. */
out:
  pam_end( pam_handle, rc );
 
  return( result );

} /* authenticate_via_pam() */

#else /* else !USE_PAM */


/************************************************************************
 *
 * All shadow passwd code goes in this section.
 *
 ************************************************************************/


#include <unistd.h>                         /* for getuid(), exit(), crypt() */
#include <shadow.h>                         /* for shadow passwd functions */
#include <string.h>                         /* for strlen(), memset() */

#define PASSWORD_PROMPT _("Password:")         /* prompt for getpass() */

int authenticate_via_shadow_passwd( const struct passwd * );

/* authenticate_via_shadow_passwd()
 *
 * in:     pw - struct containing data from our user's line in 
 *                         the passwd file.
 * out:    nothing
 * return: value   condition
 *         -----   ---------
 *           1     user authenticated themselves properly according to the
 *                 shadow passwd file.
 *           0     otherwise
 *
 * This function uses the shadow passwd file to thenticate the user running
 * this program.
 *
 */

int authenticate_via_shadow_passwd( const struct passwd *pw ) {

  struct spwd *p_shadow_line; /* struct derived from shadow passwd file line */
  char *unencrypted_password_s;        /* unencrypted password input by user */
  char *encrypted_password_s; /* user's password input after being crypt()ed */

  /* Make `p_shadow_line' point to the data from the current user's *
   * line in the shadow passwd file.                                */
  setspent();            /* Begin access to the shadow passwd file. */
  p_shadow_line = getspnam( pw->pw_name );
  endspent();            /* End access to the shadow passwd file. */
  if( !( p_shadow_line ) ) {
    fprintf( stderr, _("Cannot find your entry in the shadow passwd file.\n"));
    exit( -1 );
  }

  /* Ask user to input unencrypted password */
  if( ! ( unencrypted_password_s = getpass( PASSWORD_PROMPT ) ) ) {
    fprintf( stderr, _("getpass cannot open /dev/tty\n"));
    exit( -1 );
  }

  /* Use crypt() to encrypt user's input password.  Clear the *
   * unencrypted password as soon as we're done, so it is not * 
   * visible to memory snoopers.                              */
  encrypted_password_s = crypt( unencrypted_password_s,
				p_shadow_line->sp_pwdp );
  memset( unencrypted_password_s, 0, strlen( unencrypted_password_s ) );

  /* Return 1 (authenticated) iff the encrypted version of the user's *
   * input password matches the encrypted password stored in the      *
   * shadow password file.                                            */
  return( !strcmp( encrypted_password_s, p_shadow_line->sp_pwdp ) );

} /* authenticate_via_shadow_passwd() */

#endif /* if/else USE_PAM */

/*
 * This function checks to see if the shell is known in /etc/shells.
 * If so, it returns 1. On error or illegal shell, it returns 0.
 */
static int verify_shell(const char *shell_name)
{
  int found = 0;
  const char *buf;

  if( !shell_name )
    return found;

  while( (buf = getusershell()) != NULL ) {
    /* ignore comments */
    if( *buf == '#' )
      continue;

    /* check the shell skipping newline char */
    if( ! strcmp (shell_name, buf) ) {
      found = 1;
      break;
    }
  }
  endusershell();
  return found;
}

/*
 * This function will drop the capabilities so that we are left
 * only with access to the audit system. If the user is root, we leave
 * the capabilities alone since they already should have access to the
 * audit netlink socket.
 */
#ifdef LOG_AUDIT_PRIV
static void drop_capabilities(void)
{
  uid_t uid = getuid();

  if (uid) { /* Non-root path */
    cap_t new_caps, tmp_caps;
    cap_value_t cap_list[] = { CAP_AUDIT_WRITE };
    cap_value_t tmp_cap_list[] = { CAP_AUDIT_WRITE, CAP_SETUID };

    new_caps = cap_init();
    tmp_caps = cap_init();
    if (!new_caps || !tmp_caps) {
      fprintf(stderr, _("Error initing capabilities, aborting.\n"));
      exit(-1);
    }
    cap_set_flag(new_caps, CAP_PERMITTED, 1, cap_list, CAP_SET);
    cap_set_flag(new_caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET);
    cap_set_flag(tmp_caps, CAP_PERMITTED, 2, tmp_cap_list, CAP_SET);
    cap_set_flag(tmp_caps, CAP_EFFECTIVE, 2, tmp_cap_list, CAP_SET);

    /* Keep capabilities across uid change */
    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

    /* We should still have root's caps, so drop most capabilities now */
    if (cap_set_proc(tmp_caps)) {
      fprintf(stderr, _("Error dropping capabilities, aborting\n"));
      exit(-1);
    }
    cap_free(tmp_caps);

    /* Change uid */
    if (setresuid(uid, uid, uid)) {
      fprintf(stderr, _("Error changing uid, aborting.\n"));
      exit(-1);
    }

    /* Now get rid of this ability */
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) < 0) {
      fprintf(stderr, _("Error resetting KEEPCAPS, aborting\n"));
      exit(-1);
    }

    /* Finish dropping capabilities. */
    if (cap_set_proc(new_caps)) {
      fprintf(stderr, _("Error dropping SETUID capability, aborting\n"));
      exit(-1);
    }
    cap_free(new_caps);
  }
}
#endif

/************************************************************************
 *
 * All code used for both PAM and shadow passwd goes in this section.
 *
 ************************************************************************/

int main( int argc, char *argv[] ) {

  security_context_t new_context=NULL;	   /* our target security context */
  security_context_t old_context=NULL;	   /* our original securiy context */
  security_context_t tty_context=NULL;	   /* The current context of tty file */
  security_context_t new_tty_context=NULL; /* The new context of tty file */
  security_context_t chk_tty_context= NULL;

  context_t context;		 	 /* manipulatable form of new_context */


  struct passwd *pw;                 /* struct derived from passwd file line */
  struct passwd pw_copy;

  int clflag;                        /* holds codes for command line flags */
  int flag_index;                    /* flag index in argv[] */
  const struct option long_options[] = {   /* long option flags for getopt() */
    { "role", 1, 0, 'r' },
    { "type", 1, 0, 't' },
    { "level", 1, 0, 'l' },
    { "version", 0, 0, 'V' },
    { NULL, 0, 0, 0 }
  };
  char *role_s = NULL;               /* role spec'd by user in argv[] */
  char *type_s = NULL;               /* type spec'd by user in argv[] */
  char *level_s = NULL;              /* level spec'd by user in argv[] */
  char *ttyn   = NULL;		     /* tty path */
  pid_t childPid=0;			     
  uid_t uid;
  int fd;
  int enforcing;
  sigset_t empty;
  char *labeltext;
  mac_t label;

#ifdef LOG_AUDIT_PRIV
  drop_capabilities();
#endif

  /* Empty the signal mask in case someone is blocking a signal */
  sigemptyset( &empty );
  (void) sigprocmask( SIG_SETMASK, &empty, NULL );
  
  /* Terminate on SIGHUP. */
  signal(SIGHUP, SIG_DFL);

#ifdef USE_NLS
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif

  /*
   *
   * Step 1:  Handle command-line arguments.
   *
   */


  if( !is_selinux_enabled() ) {
    fprintf( stderr, 
	     _("Sorry, newrole may be used only when the SEBSD module " 
	     "is loaded.\n") );
    exit(-1);
  }
  enforcing = security_getenforce();
  if (enforcing < 0) {
    fprintf(stderr, _("Could not determine enforcing mode.\n"));
    exit(-1);
  }

  while (1) {
    clflag=getopt_long(argc,argv,"r:t:l:V",long_options,&flag_index);
    if (clflag == -1)
	break;
    
    switch( clflag ) {
    case 'V':
	printf("newrole: %s version %s\n",PACKAGE,VERSION);
	exit(0);
	break;
    case 'r':
      /* If role_s is already set, the user spec'd multiple roles - bad. */
      if( role_s ) {
	fprintf( stderr, _("Error: multiple roles specified\n"));
	exit( -1 );
      }
      role_s = optarg;  /* save the role string spec'd by user */
      break;

    case 't':
      /* If type_s is already set, the user spec'd multiple types - bad. */
      if( type_s ) {
	fprintf( stderr, _("Error: multiple types specified\n"));
	exit( -1 );
      }
      type_s = optarg;  /* save the type string spec'd by user */
      break;

    case 'l':
      if(!is_selinux_mls_enabled() ) {
        fprintf(stderr, _("Sorry, -l may be used with SEBSD MLS support.\n"));
        exit(-1);
      }
      /* If level_s is already set, the user spec'd multiple levels - bad. */
      if(level_s) {
	fprintf( stderr, _("Error: multiple levels specified\n"));
	exit( -1 );
      }
      level_s = optarg;  /* save the level string spec'd by user */
      break;

    default:
      fprintf(stderr, "%s\n",USAGE_STRING);
      exit(-1);
    } /* switch( clflag ) */
  } /* while command-line flags remain for newrole */

  
  /* Verify that the combination of command-line arguments we were *
   * given is a viable one.                                        */
  if( !(role_s || type_s || level_s) ) {
    fprintf(stderr, "%s\n",USAGE_STRING);
    exit(-1);
  }

  /* Fill in a default type if one hasn't been specified */
  if( role_s && !type_s ) {
    if( get_default_type(role_s,&type_s) )
      {
	fprintf(stderr,_("Couldn't get default type.\n"));
	exit(-1);
      }
#ifdef CANTSPELLGDB
  printf( "Your type will be %s.\n", type_s );
#endif  
  }

  /*
   *
   * Step 2:  Authenticate the user.
   *
   */

  /*
   * Get the context of the caller, and extract
   * the username from the context.  Don't rely on the Linux
   * uid information - it isn't trustworthy.
   */

  /* Put the caller's context into `old_context'. */
  /* 
   * XXX: Technically this should be getprevcon().  Change it once
   * that's implemented.
   */
  if( 0!=(getcon(&old_context)) ) {
    fprintf(stderr,_("failed to get old_context.\n"));
    exit(-1);
  }

#ifdef CANTSPELLGDB
  printf( "Your old context was %s\n", old_context );
#endif

  /* 
   * Create a context structure so that we extract and modify 
   * components easily. 
   */
  context=context_new(old_context);
  if(context == 0) {
    fprintf(stderr,_("failed to get new context.\n"));
    exit(-1);
  }

  /*
   * Determine the Linux user identity to re-authenticate.
   * If supported and set, use the login uid, as this should be more stable.
   * Otherwise, use the real uid.
   * The SELinux user identity is no longer used, as Linux users are now
   * mapped to SELinux users via seusers and the SELinux user identity space
   * is separate.
   */
#ifdef USE_AUDIT
  uid = audit_getloginuid();
  if (uid == (uid_t)-1)
	  uid = getuid();
#else
  uid = getuid();
#endif    
  
  /* Get the passwd info for the Linux user identity. */
  pw = getpwuid(uid);
  if( !pw ) {
    fprintf(stderr,_("cannot find your entry in the passwd file.\n"));
    exit(-1);
  }
  pw_copy = *pw;
  pw = &pw_copy;
  pw->pw_name = xstrdup(pw->pw_name);
  pw->pw_dir = xstrdup(pw->pw_dir);
  pw->pw_shell = xstrdup(pw->pw_shell);

  if (verify_shell(pw->pw_shell) == 0) {
	fprintf(stderr, _("Error!  Shell is not valid.\n"));
	exit(-1);
  }

  /* Get the tty name. Pam will need it. */
  ttyn=ttyname(0);
  if (!ttyn || *ttyn == '\0') {
	fprintf(stderr, _("Error!  Could not retrieve tty information.\n"));
	exit(-1);
  }

  printf(_("Authenticating %s.\n"),pw->pw_name);

  /* 
   * Re-authenticate the user running this program.
   * This is just to help confirm user intent (vs. invocation by
   * malicious software), not to authorize the operation (which is covered
   * by policy).  Trusted path mechanism would be preferred.
   */
#ifdef USE_PAM
  if( !authenticate_via_pam(pw, ttyn) ) 
#else /* !USE_PAM */
  if( !authenticate_via_shadow_passwd(pw) ) 
#endif /* if/else USE_PAM */
    {
      fprintf(stderr,_("newrole: incorrect password for %s\n"), pw->pw_name);
      return(-1);
    }
  /* If we reach here, then we have authenticated the user. */
#ifdef CANTSPELLGDB
  printf( "You are authenticated!\n" );
#endif  

  /*
   *
   * Step 3:  Construct a new context based on our old context and the
   *          arguments specified on the command line.
   *
   */

  /* The first step in constructing a new context for the new shell we  *
   * plan to exec is to take our old context in `context' as a   *
   * starting point, and modify it according to the options the user *
   * specified on the command line.                                  */

  /* If the user specified a new role on the command line (if `role_s'   *
   * is set), then replace the old role in `context' with this new role. */
  if( role_s ) {
    if( context_role_set(context,role_s)) {
      fprintf(stderr,_("failed to set new role %s\n"),role_s);
      exit(-1);
    }
#ifdef CANTSPELLGDB
    printf("Your new role is %s\n",context_role_get(context));
#endif
  } /* if user specified new role */

  /* If the user specified a new type on the command line (if `type_s'   *
   * is set), then replace the old type in `context' with this new type. */
  if( type_s ) {
    if( context_type_set(context,type_s)) {
      fprintf(stderr,_("failed to set new type %s\n"),type_s);
      exit(-1);
    }
#ifdef CANTSPELLGDB
    printf("Your new type is %s\n",context_type_get(context));
#endif
  } /* if user specified new type */

  /* If the user specified a new level on the command line (if `level_s'   *
   * is set), then replace the old level in `context' with this new level. */
  if(level_s) {
    char *range_s = build_new_range(level_s, context_range_get(context));
    if (!range_s) {
      fprintf(stderr, _("failed to build new range with level %s\n"), level_s);
      exit(-1);
    }
    if(context_range_set(context, range_s)) {
      fprintf(stderr, _("failed to set new range %s\n"), range_s);
      free(range_s);
      exit(-1);
    }
    free(range_s);
#ifdef CANTSPELLGDB
    printf("Your new range is %s\n", context_range_get(context));
#endif
  } /* if user specified new level */

  /* The second step in creating the new context is to convert our modified *
   * `context' structure back to a context string and then to a Context.    */

  if( !(new_context=context_str(context))) {
    fprintf(stderr,_("failed to convert new context to string\n") );
    exit(-1);
  }


#ifdef CANTSPELLGDB
  printf("Your new context is %s\n",new_context);
#endif

  /*
   *
   * Step 4:  Handle relabeling of the tty.
   *
   */

  /* Re-open TTY descriptor */
  fd = open(ttyn, O_RDWR);
  if (fd < 0) {
	fprintf(stderr, _("Error!  Could not open %s.\n"), ttyn);
	exit(-1);
  }

  tty_context = NULL;
  if (fgetfilecon(fd, &tty_context) < 0) {
	fprintf(stderr, _("%s!  Could not get current context for %s, not relabeling tty.\n"), enforcing ? "Error" : "Warning", ttyn);
        if (enforcing)
	  exit(-1);
  }
#ifdef CANTSPELLGDB
  if (tty_context)
    printf("Your tty %s was labeled with context %s\n", ttyn, tty_context);
#endif

  new_tty_context = NULL;
  if (tty_context && (security_compute_relabel(new_context,tty_context,SECCLASS_CHR_FILE,&new_tty_context) < 0)) {
       fprintf(stderr, _("%s!  Could not get new context for %s, not relabeling tty.\n"), enforcing ? "Error" : "Warning", ttyn);
       if (enforcing)
         exit(-1);
  }

#ifdef CANTSPELLGDB
  if (new_tty_context)
    printf("Relabeling tty %s to context %s\n", ttyn, new_tty_context);
#endif

  if (new_tty_context) {
    if (fsetfilecon(fd,new_tty_context) < 0) {
      fprintf(stderr, _("%s!  Could not set new context for %s\n"), enforcing ? "Error" : "Warning", ttyn);
      freecon(new_tty_context);
      new_tty_context = NULL;
      if (enforcing)
        exit(-1);
    }
  }

  /* Fork, allowing parent to clean up after shell has executed */
  childPid=fork();
  if( childPid<0 ) {
    int errsv=errno;
    fprintf(stderr,_("newrole: failure forking: %s"),strerror(errsv));
    if (fsetfilecon(fd,tty_context) < 0)
      fprintf(stderr, _("Warning!  Could not restore context for %s\n"), ttyn);
    freecon(tty_context);
    exit(-1);
  } else if (childPid) {
    /* PARENT */
    int rc;
    do {
      rc = wait(NULL);
    } while (rc < 0 && errno == EINTR);

    if( !new_tty_context || !tty_context )
      exit(0);

    /* Verify that the tty still has the context set by newrole. */
    if (fgetfilecon(fd,&chk_tty_context) < 0) {
      fprintf(stderr, "Could not fgetfilecon %s.\n", ttyn);
      exit (-1);
    }

    if (strcmp(chk_tty_context, new_tty_context)) {
      fprintf(stderr,_("%s changed labels.\n"), ttyn);
      exit(-1);
    }

    freecon(new_tty_context);

#ifdef CANTSPELLGDB
    printf("Restoring tty %s back to context %s\n", ttyn, tty_context);
#endif

    fsetfilecon(fd,tty_context);
    freecon(tty_context);

    /* Done! */
    exit(0);
  }

  /* CHILD */

  close(fd);

  /* Close and reopen descriptors 0 through 2 */
  if( close(0) || close(1) || close(2) )
    {
      fprintf(stderr,_("Could not close descriptors.\n"));
      exit(-1);
    }
  fd = open(ttyn,O_RDONLY);
  if (fd != 0) {
      exit(-1);
  }
  fd = open(ttyn,O_WRONLY);  
  if (fd != 1) {
      exit(-1);
  }
  fd = open(ttyn,O_WRONLY);  
  if (fd != 2) {
      exit(-1);
  }

  /*
   *
   * Step 5:  Execute a new shell with the new context in `new_context'. 
   *
   */

  if (optind < 1) optind = 1;
  argv[optind-1] = pw->pw_shell;
#ifdef CANTSPELLGDB
  {
	  int i;
	  printf("Executing ");
	  for (i = optind-1; i < argc; i++)
		  printf("%s ", argv[i]);
	  printf("with context %s\n", new_context);
  }
#endif
  if (asprintf(&labeltext, "sebsd/%s", new_context) == -1 ||
	mac_from_text(&label, labeltext) != 0) {
	  fprintf(stderr, "Could not set exec context to %s.\n", new_context);
	  exit(-1);
  }
  free(labeltext);

#ifdef LOG_AUDIT_PRIV
  /* Send audit message */
  {
    char *msg;
    int rc;
    int audit_fd = audit_open();      
    if (audit_fd < 0) {
       fprintf(stderr, _("Error connecting to audit system.\n"));
       exit(-1);
    }
    if (asprintf(&msg, "newrole: old-context=%s new-context=%s",
             old_context, new_context) < 0) {
       fprintf(stderr, _("Error allocating memory.\n"));
       exit(-1);
    }
    rc = audit_log_user_message(audit_fd, AUDIT_USER_ROLE_CHANGE,
                               msg, NULL, NULL, ttyn, 1);
    if (rc <= 0) {
       fprintf(stderr, _("Error sending audit message.\n"));
       exit(-1);
    }
    free(msg);
    close(audit_fd);
  }
#endif
  freecon(old_context);
  mac_execve(argv[optind-1], argv+optind-1, environ, label);
  
  /* If we reach here, then we failed to exec the new shell. */
  perror(_("failed to exec shell\n"));
  return(-1);
} /* main() */

