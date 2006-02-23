/* MACloginWindowController */

#import <Cocoa/Cocoa.h>

#import "NSBorderlessWindow.h"
#import "MACpolicyPlugin.h"

@interface MACloginWindowController : NSObject
{
	IBOutlet NSBox *box;
	IBOutlet NSBorderlessWindow *win;
	NSObject <MACpolicyPlugin> *policy;
	MACstatus retval;
}
- (IBAction) continue: (id)sender;
- (IBAction) abort: (id)sender;

- (void) setView: (NSView *) _view;
- (void) setPolicy: (NSObject *) _policy;

@end
