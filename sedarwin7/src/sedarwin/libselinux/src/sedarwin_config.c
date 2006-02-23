
#include "sebsd.h"

char *selinux_default_type_path()
{
	/*return _DEFTYPE_PATH;*/
	return "/etc/sedarwin/default_type";
}

char *selinux_booleans_path()
{
	return "/etc/sedarwin/booleans";
}

char *selinux_default_context_path()
{
	return "/etc/sedarwin/default_contexts";
}

char *selinux_failsafe_context_path()
{
	return "/etc/sedarwin/failsafe_context";
}

char *selinux_user_contexts_path()
{
	return "/etc/sedarwin/user_context";
}
