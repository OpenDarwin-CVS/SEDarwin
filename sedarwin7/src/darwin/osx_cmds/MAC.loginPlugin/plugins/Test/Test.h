/* Test */

#import <Cocoa/Cocoa.h>

#import "MACpolicyPlugin.h"

@interface Test : NSObject <MACpolicyPlugin>
{
	IBOutlet NSView *view;

	IBOutlet NSTextField *labelEntry;
	IBOutlet NSTextField *policyEntry;
}
@end
