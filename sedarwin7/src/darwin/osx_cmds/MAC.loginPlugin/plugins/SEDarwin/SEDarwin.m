#import "SEDarwin.h"
#include <syslog.h>
#include <unistd.h>

static void
display_alert(NSString *message)
{
	NSAlert *alert = [[NSAlert alloc] init];
	NSWindow *window = [alert window];

	[window setLevel:NSFloatingWindowLevel];
	[alert addButtonWithTitle:@"OK"];
	[alert setMessageText:message];
	[alert setInformativeText:@"You are unable to login at this time."];
	[alert setAlertStyle:NSCriticalAlertStyle];
	[alert runModal];
	[alert release];
}

@implementation SEDarwin

- (void) setUser: (uid_t)userID {
	security_context_t curcon, *contexts;
	struct passwd *pwd;
	int ncontexts, i;

	if (username != NULL) {
		free(username);
		username = NULL;
	}

	if ((pwd = getpwuid(userID)) == NULL) {
		syslog(LOG_ERR, "%s(): unable to find user with uid %u",
		    __func__, userID);
		display_alert([NSString stringWithFormat:@"Unable to find user with uid %u", userID]);
		return;
	}
	if ((username = strdup(pwd->pw_name)) == NULL) {
		syslog(LOG_ERR, "%s(): %m", __func__);
		display_alert(@"Unable to allocate memory");
		return;
	}

	if (!sebsd_enabled())
		return;

	/*
	 * Get an ordered list of possible contexts for the user and
	 * use them to populate the popup button (in the same order).
	 */
	if (getcon(&curcon) != 0) {
		syslog(LOG_ERR, "%s(): unable to get current context",
		    __func__);
		display_alert(@"Unable to get current context");
		free(username);
		username = NULL;
		return;
	}
	ncontexts = get_ordered_context_list(username, curcon, &contexts);
	freecon(curcon);
	if (ncontexts <= 0) {
		syslog(LOG_ERR, "%s(): unable to get context list for user %s",
		    __func__, username);
		display_alert([NSString stringWithFormat:@"Unable to get context list for user %s", username]);
		free(username);
		username = NULL;
		return;
	}

	[ contextSelector removeAllItems ];
	for (i = 0; i < ncontexts; i++) {
		NSString *ns = [ NSString stringWithCString:contexts[i] ];
		[ contextSelector addItemWithTitle:ns ];
	}
	[ contextSelector selectItemAtIndex:0 ];
	[ contextSelector synchronizeTitleAndSelectedItem ]; // XXX - needed?
	freeconary(contexts);
}

- (MACstatus) policyCanLogin {
	NSString *sv;
	const char *cs;
	char *textlabel;

	if (username == NULL) {
		/* We already displayed an alert in setUser()... */
		return (MAC_LOGIN_FAIL);
	}

	/* XXX - use SELINUX_DEFAULTUSER and fill in selector if not enabled? */
	if (!sebsd_enabled())
		return (MAC_LOGIN_OK);

	/*
	 * Get the selected context from the popup button and
	 * convert it to a label.
	 */
	sv = [ contextSelector titleOfSelectedItem ];
	cs = [ sv lossyCString ];

	if (asprintf(&textlabel, "sebsd/%s", cs) == -1) {
		syslog(LOG_ERR, "%s(): %m", __func__);
		display_alert(@"Unable to allocate memory.");
		return (MAC_LOGIN_FAIL);
	}

	if (mac_from_text(&label, textlabel) != 0) {
		syslog(LOG_ERR, "%s(): mac_from_text(..., \"%s\"): %m",
		    __func__, textlabel);
		display_alert(@"Unable to create MAC label.");
		free(textlabel);
		return (MAC_LOGIN_FAIL);
	}

	if (mac_set_proc(label) != 0) {
		syslog(LOG_ERR, "%s(): mac_set_proc(..., \"%s\"): %m",
		    __func__, textlabel);
		display_alert(@"Unable to set process label.");
		mac_free(label);
		free(textlabel);
		return (MAC_LOGIN_FAIL);
	}

	return (MAC_LOGIN_OK);
}

- (void) policyWillLogin {
	free(username);
	if (label != NULL)	/* XXX */
		mac_free(label);
}

- (void) policyWillLogout { return; }
- (void) sessionAdoptPID: (pid_t)pid Name: (const char *)name {return;} 
- (void) sessionOrphanPID: (pid_t)pid Name: (const char *)name {return;}
@end
