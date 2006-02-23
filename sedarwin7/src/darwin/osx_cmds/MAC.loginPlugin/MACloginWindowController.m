#import "MACloginWindowController.h"

@implementation MACloginWindowController

- (IBAction)
continue: (id)sender
{

	retval = [policy policyCanLogin];
	switch (retval) {
	case MAC_LOGIN_OK:
	case MAC_LOGIN_FAIL:
		[win close];
		break;
	case MAC_LOGIN_RETRY:
		break;
	default:
		break;
	}
}

- (IBAction)
abort: (id)sender
{
	retval = MAC_LOGIN_FAIL;
	[win close];
}

/*
 * Responsible for adding the view to the "box" and resizing
 * the window etc.
 */
- (void)setView:(NSView *)_view { [box setContentView: _view]; }
- (void)setPolicy:(NSObject *)_policy { policy = _policy; }

/* Delegate selectors for NSWindow */
- (void)
windowWillClose: (NSNotification *)notification
{
	[NSApp stopModalWithCode: retval];
}

- (void)
dealloc
{
	[box release];
	[win release];
	[super dealloc];
}
@end
