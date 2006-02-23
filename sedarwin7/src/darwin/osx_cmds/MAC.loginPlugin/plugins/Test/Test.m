#import "Test.h"

@implementation Test

- (void) setUser: (uid_t)userID { return; }

- (MACstatus)
policyCanLogin
{

	if ([[labelEntry stringValue] length] == 0)
		return (MAC_LOGIN_RETRY);
	else
		return (MAC_LOGIN_OK);
}

- (void) policyWillLogin { return; }
- (void) policyWillLogout { return; }

- (void) sessionAdoptPID: (pid_t)pid Name: (const char *)name { return; }
- (void) sessionOrphanPID: (pid_t)pid Name: (const char *)name { return; }

@end
