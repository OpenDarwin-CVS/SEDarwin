//
//  Color.m
//  MAC.loginPlugin
//
//  Created by Matthew N. Dodd on 6/16/05.
//  Copyright 2005 SPARTA, Inc. All rights reserved.
//

#import "Color.h"

@implementation Color
- (void) setUser: (uid_t)userID { return; }
- (MACstatus) policyCanLogin { return (MAC_LOGIN_OK); }
- (void) policyWillLogin { return; }
- (void) policyWillLogout { return; }

- (void) sessionAdoptPID: (pid_t)pid Name: (const char *)name { return; }
- (void) sessionOrphanPID: (pid_t)pid Name: (const char *)name { return; }
@end
