#import "MLS.h"

#include <syslog.h>

@implementation MLS

- (void) setUser: (uid_t)userID { return; }

- (MACstatus)
policyCanLogin
{
	NSString *sv;
	const char *cs;
	int error;

	sv = [labelEntry stringValue];

	if ([sv length] == 0)
		return (MAC_LOGIN_RETRY);

	cs = [sv lossyCString];

	/* This doesn't actually validate the label */
	error = mac_from_text(&label, cs);
	if (error != 0) {
		syslog(LOG_ERR, "%s(): mac_from_text(..., \"%s\"): %m",
			__func__, cs);
		return (MAC_LOGIN_RETRY);
	}

	syslog(LOG_INFO, "%s(): Using label \"%s\"", __func__, cs);

	error = mac_set_proc(label);
	if (error) {
		syslog(LOG_ERR, "mac_set_proc(): %m");
		return (MAC_LOGIN_RETRY);
	}

	return (MAC_LOGIN_OK);
}

- (void)
policyWillLogin
{
#if 0
	int error;

	error = mac_set_proc(label);
	if (error)
		syslog(LOG_ERR, "mac_set_proc(): %m");
#endif

	mac_free(label);
	return;
}

- (void) policyWillLogout { return; }
- (void) sessionAdoptPID: (pid_t)pid Name: (const char *)name { return; }
- (void) sessionOrphanPID: (pid_t)pid Name: (const char *)name { return; }
@end
