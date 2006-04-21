/* SEDarwin */

#import <Cocoa/Cocoa.h>
#import "MACpolicyPlugin.h"

#include <sys/types.h>
#include <sys/mac.h> 
#include <pwd.h> 
#include <selinux/selinux.h>
#include <selinux/get_context_list.h>

@interface SEDarwin : NSObject <MACpolicyPlugin>
{
	mac_t	label;
	char	*username;

	IBOutlet NSView *view;
	IBOutlet NSPopUpButton *contextSelector;
}
@end
