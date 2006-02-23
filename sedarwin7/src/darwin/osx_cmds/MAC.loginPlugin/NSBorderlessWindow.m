#import "NSBorderlessWindow.h"

@implementation NSBorderlessWindow

- (BOOL) worksWhenModal { return (YES); }
- (BOOL) canBecomeKeyWindow { return (YES); }

/*
 * As the NSWindow 'center' selector doesn't do what
 * you would expect, provide something that does.
 */
- (void)
center
{
     
	NSRect vFrame = [[NSScreen mainScreen] frame];
	NSRect wFrame = [self frame];

	[self setFrame:
		NSMakeRect(
			(vFrame.size.width  - wFrame.size.width)  * 0.5,
	  		(vFrame.size.height - wFrame.size.height) * 0.5,
	  		wFrame.size.width, wFrame.size.height)
		display: YES
	];
}

/*
 * We override both initWithContentRect selectors to clear
 * NSTitledWindowMask from the styleMask
 */

- (id)
initWithContentRect: (NSRect)contentRect
 	  styleMask: (unsigned int)styleMask
	    backing: (NSBackingStoreType)backingType
	      defer: (BOOL)flag
{
	styleMask &= ~NSTitledWindowMask;
	return [super initWithContentRect: contentRect
			 	styleMask: styleMask
				  backing: backingType
				    defer: flag
	];
}

- (id)
initWithContentRect: (NSRect)contentRect
 	  styleMask: (unsigned int)styleMask
	    backing: (NSBackingStoreType)backingType
	      defer: (BOOL)flag
	     screen: (NSScreen *)aScreen
{
	styleMask &= ~NSTitledWindowMask;
	return [super initWithContentRect: contentRect
			 	styleMask: styleMask
				  backing: backingType
				    defer: flag
				   screen: aScreen
	];
}

@end
