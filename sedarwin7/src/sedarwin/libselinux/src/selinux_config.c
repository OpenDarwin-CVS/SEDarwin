#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>

#define SELINUXDIR "/etc/selinux/"
#define SELINUXCONFIG SELINUXDIR "config"
#define SELINUXDEFAULT "targeted"
#define SELINUXTYPETAG "SELINUXTYPE="
#define SELINUXTAG "SELINUX="

/* Indices for file paths arrays. */
#define BINPOLICY         0
#define CONTEXTS_DIR      1    
#define FILE_CONTEXTS     2
#define DEFAULT_CONTEXTS  3
#define USER_CONTEXTS     4
#define FAILSAFE_CONTEXT  5
#define DEFAULT_TYPE      6
#define BOOLEANS          7
#define NEL               8

/* New layout is relative to SELINUXDIR/policytype. */
static char *file_paths[NEL];
static char *file_path_suffixes[NEL] = {
	"/policy/policy",
	"/contexts",
	"/contexts/files/file_contexts",
	"/contexts/default_contexts",
	"/contexts/users/",
	"/contexts/failsafe_context",
	"/contexts/default_type",
	"/booleans"
};

/* Old layout had fixed locations. */
#define SECURITYCONFIG "/etc/sysconfig/selinux"
#define SECURITYDIR "/etc/security"
static char *compat_file_paths[NEL] = {
	SECURITYDIR "/selinux/policy",
	SECURITYDIR,
	SECURITYDIR "/selinux/file_contexts",
	SECURITYDIR "/default_contexts",
	SECURITYDIR "/default_contexts.user/",
	SECURITYDIR "/failsafe_context",
	SECURITYDIR "/default_type",
	SECURITYDIR "/booleans"
};

static char **active_file_paths;

int selinux_getenforcemode(int *enforce) {
  int ret=-1;
  FILE *cfg = fopen(SELINUXCONFIG,"r");
  char buf[4097];
  int len=sizeof(SELINUXTAG)-1;
  if (!cfg) {
    cfg = fopen(SECURITYCONFIG,"r");
  }
  if (cfg) {
    while (fgets(buf, 4096, cfg)) {
      if (strncmp(buf,SELINUXTAG,len))
	continue;
      if (!strncmp(buf+len,"enforcing",sizeof("enforcing")-1)) {
	*enforce = 1;
	ret=0;
	break;
      } else if (!strncmp(buf+len,"permissive",sizeof("permissive")-1)) {
	*enforce = 0;
	ret=0;
	break;
      } else if (!strncmp(buf+len,"disabled",sizeof("disabled")-1)) {
	*enforce = -1;
	ret=0;
	break;
      }
    }
    fclose(cfg);
  }
  return ret;
}

static char *selinux_policyroot = NULL;

static void init_selinux_policyroot(void) __attribute__ ((constructor));

static void init_selinux_policyroot(void)
{
  char *type=SELINUXDEFAULT;
  int i=0, len=sizeof(SELINUXTYPETAG)-1, len2;
  char buf[4097];
  FILE *cfg;
  if (selinux_policyroot) return;
  if (access(SELINUXDIR, F_OK) != 0) {
	  selinux_policyroot = SECURITYDIR;
	  active_file_paths = compat_file_paths;
	  return;
  }
  cfg = fopen(SELINUXCONFIG,"r");
  if (cfg) {
    while (fgets(buf, 4096, cfg)) {
      if (strncmp(buf,SELINUXTYPETAG,len)==0) {
	type=buf+len;
	break;
      }
    }
    fclose(cfg);
  }
  i=strlen(type)-1;
  while ((i>=0) && 
	 (isspace(type[i]) || iscntrl(type[i]))) {
    type[i]=0;
    i--;
  }
  len=sizeof(SELINUXDIR) + strlen(type);
  selinux_policyroot=malloc(len);
  if (!selinux_policyroot)
	  return;
  snprintf(selinux_policyroot,len, "%s%s", SELINUXDIR, type);
  
  for (i = 0; i < NEL; i++) {
	  len2 = len + strlen(file_path_suffixes[i])+1;
	  file_paths[i] = malloc(len2);
	  if (!file_paths[i])
		  return;
	  snprintf(file_paths[i], len2, "%s%s", selinux_policyroot, file_path_suffixes[i]);
  }
  active_file_paths = file_paths;
}

char *selinux_default_type_path() 
{
	return active_file_paths[DEFAULT_TYPE];
}

char *selinux_policy_root() {
	return selinux_policyroot;
}

char *selinux_default_context_path() {
	return active_file_paths[DEFAULT_CONTEXTS];
}

char *selinux_failsafe_context_path() {
	return active_file_paths[FAILSAFE_CONTEXT];
}

char *selinux_binary_policy_path() {
	return active_file_paths[BINPOLICY];
}

char *selinux_file_context_path() {
	return active_file_paths[FILE_CONTEXTS];
}

char *selinux_contexts_path() {
	return active_file_paths[CONTEXTS_DIR];
}

char *selinux_user_contexts_path() {
	return active_file_paths[USER_CONTEXTS];
}

char *selinux_booleans_path() {
	return active_file_paths[BOOLEANS];
}

