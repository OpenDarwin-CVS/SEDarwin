/*
 *  MAC.m
 *  MAC.loginPlugin
 *
 *  Created by Matthew N. Dodd on 5/26/05.
 *  Copyright 2005 SPARTA, Inc. All rights reserved.
 */

#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <err.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/syslimits.h>

#include "lctx.h"

#import "MAC.h"
#import "MACpolicyPlugin.h"

/* Support code should probably go live in its own file... */

static pid_t
getpid_by_name (const char *name)
{
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
	struct kinfo_proc *kp;
	size_t sz, ne;
	int error, i;
	pid_t rp;

	/* Get the required buffer size. */
	error = sysctl(mib, 4, NULL, &sz, NULL, 0);
	if (error) {
		syslog(LOG_ERR, "sysctl(): %m");
		return (-1);
	}

	/* Size of list may change between sysctl() calls. */
retry:
	kp = (struct kinfo_proc *)malloc(sz);
	memset(kp, 0, sz);

	/* Get the list of processes. */
	error = sysctl(mib, 4, kp, &sz, NULL, 0);
	if (error) {
		/* Size changed... */
		if (errno == ENOMEM) {
			free(kp);
			/* XXX: We could loop forever... */
			goto retry;
		}
		syslog(LOG_ERR, "sysctl(): %m");
		return (-1);
	}

	rp = -1;
	ne = sz / sizeof(struct kinfo_proc);
	for (i = 0; i < ne; i++) {
		if (kp[i].kp_proc.p_stat == SZOMB ||
		    strcmp(kp[i].kp_proc.p_comm, name) != 0)
			continue;
		/* Humm... Found multiple entries. */
		if (rp != -1) {
			free(kp);
			syslog(LOG_WARNING,
				"%s(): found multiple processes for \"%s\"",
				__func__, name);
			return (-1);
		}
		rp = kp[i].kp_proc.p_pid;
	}
	free(kp);

	return (rp);
}

#define	MAC_CONFIG_PATH	"/etc/MAClogin.conf"

struct dentry {
        const char *name;
        pid_t pid;
};
static struct dentry *dlist;	/* List of processes to delegate. */
static int	ndentries;	/* Number of entries in list. */
static int	ndmax;		/* Maximum number of entries in allocation. */
static void	dlist_add (const char *);
static int	read_mac_config (const char *);
static void	config_set_plugin(const char *, int, char *);
const char *mac_plugin = NULL;

static int
read_mac_config (const char *path)
{
	FILE *fp;
	char buf[LINE_MAX];
	char *bp;
	int line;
	int i;

	fp = fopen(path, "r");
	if (fp == NULL) {
		syslog(LOG_ERR, "fopen(\"%s\"): %m", path);
		return(-1);
	}

	/* Allocate a few entries up front. */
	ndentries = 0;
	ndmax = 8;
	dlist = malloc(sizeof(struct dentry) * ndmax);
	if (dlist == NULL) {
		syslog(LOG_ERR, "malloc(): %m");
		return(-1);
	}
	memset(dlist, 0, sizeof(struct dentry) * ndmax);

	i = 0;
	line = 0;
	memset(buf, 0, LINE_MAX);
	while ((bp = fgets(buf, LINE_MAX, fp)) != NULL) {
		line++;

		/* Trim comments. */
		bp = index(buf, '#');
		if (bp)
			*bp = '\0';

		/* Eat trailing whitespace. */
		bp = buf + (strlen(buf) - 1);
		while (isspace(*bp))
			*bp-- = '\0';

		/* Eat leading whitespace. */
		bp = buf;
		while (isspace(*bp))
			bp++;

		/* Skip empty lines. */
		if (strlen(bp) == 0)
			continue;

		if (strncasecmp(bp, "plugin", 6) == 0) {
			config_set_plugin(path, line, bp);
		} else {
			dlist_add(bp);
			syslog(LOG_ALERT, "%s() - adding \"%s\"", __func__, bp);
		}
	}
	fclose(fp);

	if (mac_plugin == NULL)
		return (-1);
	return (0);
}

static void
config_set_plugin (const char *path, int line, char *buf)
{
	char *bp;

	if (mac_plugin != NULL) {
		syslog(LOG_ALERT, "%s, line %d: duplicate plugin specified",
			path, line);
		return;
	}

	if ((bp = index(buf, '=')) == NULL) {
		syslog(LOG_ALERT, "%s, line %d: expected \'plugin =\'",
			path, line);
		return;
	}
	bp++;
	/* Eat leading whitespace. */
	while (isspace(*bp))
		bp++;

	/* Skip empty lines. */
	if (strlen(bp) == 0) {
		syslog(LOG_ALERT, "%s, line %d: plugin name not specified",
			path, line);
		return;
	}
	mac_plugin = strdup(bp);
	syslog(LOG_ALERT, "%s() - using plugin \"%s\"", __func__, mac_plugin);

	return;
}

static void
dlist_add (const char *name)
{
	struct dentry *dtmp;

	if (ndentries > ndmax) {
		dtmp = realloc(dlist,
			sizeof(struct dentry) * (ndmax * 2));
		/* OOM */
		if (dtmp == NULL)
			return;
		dlist = dtmp;
		ndmax *= 2;
	}
	dlist[ndentries].name = strdup(name);
	dlist[ndentries].pid = -1;
	ndentries++;

	return;
}

@implementation MAC

/* loginPlugin selectors */

- (void)
didStartup
{
	NSBundle *b = nil;
	NSNib *n = nil;
	NSArray *tlobjs = nil;
	NSEnumerator *e = nil;
	id o;

	syslog(LOG_ALERT, "%s()", __func__);

	b = [NSBundle bundleWithPath:
			 @"/System/Library/LoginPlugins/MAC.loginPlugin"];
	n = [[NSNib alloc] initWithNibNamed: @"MAC" bundle: b];

	/* XXX: should raise exception? */
	if (n == nil)
		goto out;

	[n instantiateNibWithOwner: self topLevelObjects: &tlobjs];

	e = [tlobjs objectEnumerator];
	while ((o = [e nextObject]) != nil) {
		if ([o isMemberOfClass: [MACloginWindowController class]]) {
			[o retain];
			mac_wc = o;
		} else
		if ([o isMemberOfClass: [NSBorderlessWindow class]]) {
			[o retain];
			mac_w = o;
		}
		syslog(LOG_ALERT, "%s(): %s", __func__, NAMEOF(o));
	}

	if (mac_wc == nil || mac_w == nil)
		syslog(LOG_ALERT, "mac_wc or mac_w nil!");
		/* XXX: raise exception? */

	[mac_w setLevel: NSModalPanelWindowLevel];

	/* XXX: If we don't find the specified plugin maybe we should fail?
	 * 	Maybe we should load the plugins in -init but instantiate
	 *	them here.
	 */
	[self loadPluginswithBundle: b];

out:
	if (b != nil)
		[b release];
	if (n != nil)
		[n release];
}

- (void) didLogin { syslog(LOG_ALERT, "%s()", __func__); }

- (BOOL)
isLoginAllowedForUserID: (uid_t) userID
{
	MACstatus retval;

/* XXX
 * What happens if we have a MACpolicyPlugin that doesn't supply
 * a "View"?  This seems like it should be a valid condition.
 * If we have no view we should call the MACpolicyPlugin selector
 * 'policyLogin' directly.
 */

	syslog(LOG_ALERT, "%s()", __func__);
	[policy setUser: userID];
	retval = [NSApp runModalForWindow: mac_w];
	[mac_w orderOut: self];

	if (retval == MAC_LOGIN_FAIL)
		return (NO);
	return (YES);
}

- (void)
willLogin
{
	int lcid;
	int i;

	[policy policyWillLogin];

	/*
	 * This code should probably be in isLoginAllowedForUserID
	 * as failure below should result in login failing...
	 */
	lcid = getlcid(LCID_PROC_SELF);
	for (i = 0; i < ndentries; i++) {
		dlist[i].pid = getpid_by_name(dlist[i].name);
		if (dlist[i].pid == -1) {
			syslog(LOG_ALERT, "Unable to find PID for \"%s\"",
				dlist[i].name);
		} else {
			if (setlcid(dlist[i].pid, lcid) == -1)
				syslog(LOG_ALERT, "setlcid(%d, %d): %m",
					dlist[i].pid, lcid);
			[policy sessionAdoptPID: dlist[i].pid Name: dlist[i].name];
		}
	}

	syslog(LOG_ALERT, "%s()", __func__);

	return;
}

- (void) willLogout
{
	syslog(LOG_ALERT, "%s()", __func__);

	[policy policyWillLogout];
}

- (void) willTerminate	{ syslog(LOG_ALERT, "%s()", __func__); }

- (void)
loadPluginswithBundle: (NSBundle *)bundle
{
	NSDirectoryEnumerator *de;
	NSNib *n;
	Class pc;
	NSBundle *pb;
	NSString *sp;
	NSString *p;
	NSString *ps;
	NSString *mainnib;

	syslog(LOG_ALERT, "%s()", __func__);

	sp = [bundle builtInPlugInsPath];
	de = [[NSFileManager defaultManager] enumeratorAtPath: sp];
	ps = [[NSString stringWithCString: mac_plugin]
		stringByAppendingPathExtension: @"MACpolicyPlugin"];
	syslog(LOG_ALERT, "%s(): looking for plugin %s", __func__,
			[ps lossyCString]);

	if (de == nil)
		return;
	while ((p = [de nextObject]) != nil) {
		if (![[p pathExtension] isEqualToString: @"MACpolicyPlugin"])
			continue;
		if (![p isEqualToString: ps])
			continue;
		syslog(LOG_ALERT, "%s(): plugin %s", __func__,
			[p lossyCString]);
		pb = [NSBundle bundleWithPath:
			[sp stringByAppendingPathComponent: p]];
		if (pb == nil)
			continue;
		pc = [pb principalClass];
		syslog(LOG_ALERT, "%s(): %s", __func__, NAMEOF(pc));

		if (![pc conformsToProtocol: @protocol(MACpolicyPlugin)])
			continue;
		mainnib = [[pb infoDictionary] objectForKey: @"NSMainNibFile"];
		if (mainnib == nil)
			continue;
		n = [[NSNib alloc] initWithNibNamed: mainnib bundle: pb];
		if (n == nil)
			continue;

/* XXX: this is a quick hack to see if this works... */

        	NSArray *tlobjs = nil;
		NSEnumerator *e = nil;
		id o;

		[n instantiateNibWithOwner: self topLevelObjects: &tlobjs];
		e = [tlobjs objectEnumerator];
		while ((o = [e nextObject]) != nil) {
			if ([o isMemberOfClass: [NSView class]]) {
				[mac_wc setView: o];
				syslog(LOG_ALERT, "%s(): %s", __func__, NAMEOF(o));
			}
			if ([o conformsToProtocol: @protocol(MACpolicyPlugin)]) {
				policy = o;
				[mac_wc setPolicy: policy];
			}
		}
        }
}

- (id)
init
{
	/* Read config file. */
	if (read_mac_config(MAC_CONFIG_PATH))
		return (nil);

	/* Create new login context. */
	setlcid(LCID_PROC_SELF, LCID_CREATE);

	syslog(LOG_ALERT, "%s()", __func__);
	return ([super init]);
}

- (void)
dealloc
{
	int lcid;
	int i;

	syslog(LOG_ALERT, "%s()", __func__);

	lcid = getlcid(LCID_PROC_SELF);
	for (i = 0; i < ndentries; i++) {
		/* We didn't find the process initially... */
		if (dlist[i].pid == -1)
			continue;
		/* The process isn't in our login context? */
		if (getlcid(dlist[i].pid) != lcid)
			continue;
		if (setlcid(dlist[i].pid, LCID_REMOVE) == -1)
			syslog(LOG_ALERT, "setlcid(%d, %d): %m",
				dlist[i].pid, -1);
		[policy sessionOrphanPID: dlist[i].pid Name: dlist[i].name];
		free((void *)dlist[i].name);
	}
	free(dlist);

	if (mac_plugin != NULL)
		free((void *)mac_plugin);

	[mac_wc release];
	[super dealloc];
}
@end
