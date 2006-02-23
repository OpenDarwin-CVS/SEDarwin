/* MACpolicyPlugin */

#import <Foundation/Foundation.h>

typedef enum {
	MAC_LOGIN_OK = 0,
	MAC_LOGIN_FAIL = 1,
	MAC_LOGIN_RETRY = 2
} MACstatus;

@protocol MACpolicyPlugin
- (void) setUser: (uid_t)userID;
- (MACstatus) policyCanLogin;
- (void) policyWillLogin;
- (void) policyWillLogout;

/* Session management */
- (void) sessionAdoptPID: (pid_t)pid Name: (const char *)name;
- (void) sessionOrphanPID: (pid_t)pid Name: (const char *)name;
@end
