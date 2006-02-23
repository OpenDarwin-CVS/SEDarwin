#include <sys/cdefs.h>
#ifdef __FreeBSD__
__FBSDID("$FreeBSD$");
#endif

#define _BSD_SOURCE
#include <sys/types.h>

#include <unistd.h>

#define PAM_SM_SESSION

#if defined(__FreeBSD__)
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>
#elif defined(__APPLE__)
#include <pam_appl.h>
#include <pam_modules.h>
#include <pam_mod_misc.h>

#include <sys/lctx.h>
#endif

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh __unused, int flags __unused,
		     int argc __unused, const char *argv[] __unused)
{
	int error;

	/* Already in a Login Context */
	if (getlcid(LCID_PROC_SELF) > 0)
		return (PAM_SUCCESS);

	error = setlcid(LCID_PROC_SELF, LCID_CREATE);
	if (error)
		return (PAM_SYSTEM_ERR);

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh __unused, int flags __unused,
		      int argc __unused, const char *argv[] __unused)
{

	return (PAM_SUCCESS);
}

#ifdef __FreeBSD__
PAM_MODULE_ENTRY("pam_lctx");
#endif
