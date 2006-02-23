/*
 * $Id$
 */

@protocol loginPlugin <NSObject>
/*
 * Called when loginwindow starts
 */
- (void)didStartup;

/*
 * Called after successfully authentication but before loginwindow has
 * setuid to the user
 */
- (BOOL)isLoginAllowedForUserID: (uid_t)userID;

/*
 * Called after Finder launch but before other system apps
 */
- (void)didLogin;

/*
 * Called after isLoginAllowedForUserID: has returned TRUE but before
 * loginwindow has setuid to the user
 */
- (void)willLogin;

/*
 * Called before user is logged out
 */
- (void)willLogout;

/*
 * Called before loginwindow.app termiates
 */
- (void)willTerminate;
@end
