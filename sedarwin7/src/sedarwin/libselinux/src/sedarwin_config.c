#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include "dso.h"

#define	SEDARWIN_DIR		"/etc/sedarwin"
#define	SEDARWIN_CONTEXTS	"/etc/sedarwin/contexts"

int
selinux_getenforcemode(int *enforce)
{
	int i, error;
	size_t isize = sizeof(i);

	error = sysctlbyname("security.mac.sebsd.enforcing", &i,
	    &isize, NULL, 0);
	*enforce = error ? -1 : i;
	return (error);
}

const char *
selinux_default_type_path(void)
{
	return (SEDARWIN_CONTEXTS "/default_type");
}
hidden_def(selinux_default_type_path)

const char *
selinux_policy_root(void)
{
	return (SEDARWIN_DIR "/policy");
}

const char *
selinux_path(void)
{
	return (SEDARWIN_DIR);
}
hidden_def(selinux_path)

const char *
selinux_default_context_path(void)
{
	return (SEDARWIN_CONTEXTS "/default_contexts");
}
hidden_def(selinux_default_context_path)

const char *
selinux_failsafe_context_path(void)
{
	return (SEDARWIN_CONTEXTS "/failsafe_context");
}
hidden_def(selinux_failsafe_context_path)

const char *
selinux_removable_context_path(void)
{
	return (SEDARWIN_CONTEXTS "/removable_context");
}
hidden_def(selinux_removable_context_path)

const char *
selinux_binary_policy_path(void)
{
	return (SEDARWIN_DIR "/policy/policy.bin");
}
hidden_def(selinux_binary_policy_path) 

const char *
selinux_file_context_path(void)
{
	return (SEDARWIN_CONTEXTS "/files/file_contexts");
}
hidden_def(selinux_file_context_path)

const char *
selinux_homedir_context_path(void)
{
	return (SEDARWIN_CONTEXTS "/files/homedir_template");
}
hidden_def(selinux_homedir_context_path)

const char *
selinux_media_context_path(void)
{
	return (SEDARWIN_CONTEXTS "/files/media");
}
hidden_def(selinux_media_context_path)

const char *
selinux_customizable_types_path(void) 
{
	return (SEDARWIN_CONTEXTS "/customizable_types");
}
hidden_def(selinux_customizable_types_path)

const char *
selinux_contexts_path(void)
{
	return (SEDARWIN_CONTEXTS);
} 

const char *
selinux_user_contexts_path(void)
{
	return (SEDARWIN_CONTEXTS "/users/");
}
hidden_def(selinux_user_contexts_path)

const char *
selinux_booleans_path(void)
{
	return (SEDARWIN_DIR "/booleans");
}
hidden_def(selinux_booleans_path)

const char *
selinux_users_path(void)
{
	return (SEDARWIN_DIR "/users/");
}
hidden_def(selinux_users_path)

const char *
selinux_usersconf_path(void)
{
	return (SEDARWIN_DIR "/seusers");
}
hidden_def(selinux_usersconf_path)

const char *
selinux_translations_path() 
{
	return (SEDARWIN_DIR "/setrans.conf");
}
hidden_def(selinux_translations_path)
