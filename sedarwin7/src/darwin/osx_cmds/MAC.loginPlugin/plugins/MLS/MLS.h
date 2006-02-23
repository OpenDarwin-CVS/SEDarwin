/* MLS */

#import <Cocoa/Cocoa.h>
#import "MACpolicyPlugin.h"

#include <sys/types.h>
#include <sys/mac.h>

@interface MLS : NSObject <MACpolicyPlugin>
{
	mac_t	label;

	IBOutlet NSTextField *labelEntry;
	IBOutlet NSView *view;
}
@end
