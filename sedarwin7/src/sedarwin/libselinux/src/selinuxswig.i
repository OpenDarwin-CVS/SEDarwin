/* Author: Dan Walsh
 *
 * Copyright (C) 2004-2005 Red Hat
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


%module selinux
%{
	#include "selinux/selinux.h"
%}
%apply int *OUTPUT { int * };
%apply int *OUTPUT { size_t * };

%typemap(in, numinputs=0) security_context_t *(security_context_t temp) {
	$1 = &temp;
}
%typemap(argout) security_context_t * {
	$result = t_output_helper($result, PyString_FromString(*$1));
}

extern int is_selinux_enabled(void);
extern int is_selinux_mls_enabled(void);
extern int getcon(security_context_t *con);
extern int setcon(security_context_t con);
extern int getpidcon(int pid, security_context_t *con);
extern int getprevcon(security_context_t *con);
extern int getexeccon(security_context_t *con);
extern int setexeccon(security_context_t con);
extern int getfscreatecon(security_context_t *con);
extern int setfscreatecon(security_context_t context);
extern int getfilecon(const char *path, security_context_t *con);
extern int lgetfilecon(const char *path, security_context_t *con);
extern int fgetfilecon(int fd, security_context_t *con);
extern int setfilecon(const char *path, security_context_t con);
extern int lsetfilecon(const char *path, security_context_t con);
extern int fsetfilecon(int fd, security_context_t con);
extern int getpeercon(int fd, security_context_t *con);
extern int selinux_mkload_policy(int preservebools);
extern int selinux_init_load_policy(int *enforce);
extern int security_set_boolean_list(size_t boolcnt, 
				     SELboolean *boollist, 
				     int permanent);
extern int security_load_booleans(char *path);
extern int security_check_context(security_context_t con);
extern int security_canonicalize_context(security_context_t con,
					 security_context_t *canoncon);
extern int security_getenforce(void);
extern int security_setenforce(int value);
extern int security_policyvers(void);
extern int security_get_boolean_names(char ***names, int *len);
extern int security_get_boolean_pending(const char *name);
extern int security_get_boolean_active(const char *name);
extern int security_set_boolean(const char *name, int value);
extern int security_commit_booleans(void);

/* Set flags controlling operation of matchpathcon_init or matchpathcon. */
#define MATCHPATHCON_BASEONLY 1 /* Only process the base file_contexts file. */
#define MATCHPATHCON_NOTRANS  2 /* Do not perform any context translation. */
extern void set_matchpathcon_flags(unsigned int flags);
extern int matchpathcon_init(const char *path);
extern int matchpathcon(const char *path,
			mode_t mode,
			security_context_t *con);

extern int matchmediacon(const char *media,
		 security_context_t *con);

extern int selinux_getenforcemode(int *enforce);
extern const char *selinux_policy_root(void);
extern const char *selinux_binary_policy_path(void);
extern const char *selinux_failsafe_context_path(void);
extern const char *selinux_removable_context_path(void);
extern const char *selinux_default_context_path(void);
extern const char *selinux_user_contexts_path(void);
extern const char *selinux_file_context_path(void);
extern const char *selinux_homedir_context_path(void);
extern const char *selinux_media_context_path(void);
extern const char *selinux_contexts_path(void);
extern const char *selinux_booleans_path(void);
extern const char *selinux_customizable_types_path(void);
extern const char *selinux_users_path(void);
extern const char *selinux_usersconf_path(void);
extern const char *selinux_translations_path(void);
extern const char *selinux_path(void);
extern int selinux_check_passwd_access(access_vector_t requested);
extern int checkPasswdAccess(access_vector_t requested);
extern int rpm_execcon(unsigned int verified, 
		       const char *filename, 
		       char *const argv[], char *const envp[]);

extern int is_context_customizable (security_context_t scontext);

extern int selinux_trans_to_raw_context(char *trans, 
					security_context_t *rawp);
extern int selinux_raw_to_trans_context(char *raw, 
					security_context_t *transp);

%typemap(in, numinputs=0) char **(char *temp) {
	$1 = &temp;
}

%typemap(argout) char ** {
	$result = t_output_helper($result, PyString_FromString(*$1));
}
extern int getseuserbyname(const char *linuxuser, char **seuser, char **level);
