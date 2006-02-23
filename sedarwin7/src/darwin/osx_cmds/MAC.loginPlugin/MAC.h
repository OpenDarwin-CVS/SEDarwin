/*
 *  MAC.h
 *  MAC.loginPlugin
 *
 *  Created by Matthew N. Dodd on 5/26/05.
 *  Copyright 2005 SPARTA, Inc. All rights reserved.
 */

#import <Cocoa/Cocoa.h>
#import "loginPlugin.h"

#import "MACloginWindowController.h"
#import "NSBorderlessWindow.h"
#import "MACpolicyPlugin.h"

@interface MAC : NSObject <loginPlugin>
{
	MACloginWindowController *mac_wc;
	NSBorderlessWindow *mac_w;
	NSObject <MACpolicyPlugin> *policy;
}
- (void) loadPluginswithBundle: (NSBundle *)bundle;
@end
