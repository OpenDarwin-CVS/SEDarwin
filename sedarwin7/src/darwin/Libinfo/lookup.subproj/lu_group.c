/*
 * Copyright (c) 1999-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Unix group lookup
 * Copyright (C) 1989 by NeXT, Inc.
 */

#include <stdlib.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <grp.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <unistd.h>
#include <pthread.h>

#include "_lu_types.h"
#include "lookup.h"
#include "lu_utils.h"
#include "lu_overrides.h"

#define GROUP_CACHE_SIZE 10
#define DEFAULT_GROUP_CACHE_TTL 10

static pthread_mutex_t _group_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static void *_group_cache[GROUP_CACHE_SIZE] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
static unsigned int _group_cache_best_before[GROUP_CACHE_SIZE] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static unsigned int _group_cache_index = 0;
static unsigned int _group_cache_ttl = DEFAULT_GROUP_CACHE_TTL;

static pthread_mutex_t _group_lock = PTHREAD_MUTEX_INITIALIZER;

#define GR_GET_NAME 1
#define GR_GET_GID 2
#define GR_GET_ENT 3

static void 
free_group_data(struct group *g)
{
	char **mem;

	if (g == NULL) return;

	if (g->gr_name != NULL) free(g->gr_name);
	if (g->gr_passwd != NULL) free(g->gr_passwd);

	mem = g->gr_mem;
	if (mem != NULL)
	{
		while (*mem != NULL) free(*mem++);
		free(g->gr_mem);
	}
}

static void 
free_group(struct group *g)
{
	if (g == NULL) return;
	free_group_data(g);
	free(g);
 }

static void
free_lu_thread_info_group(void *x)
{
	struct lu_thread_info *tdata;

	if (x == NULL) return;

	tdata = (struct lu_thread_info *)x;
	
	if (tdata->lu_entry != NULL)
	{
		free_group((struct group *)tdata->lu_entry);
		tdata->lu_entry = NULL;
	}

	_lu_data_free_vm_xdr(tdata);

	free(tdata);
}

static struct group *
extract_group(XDR *xdr)
{
	int i, j, nkeys, nvals, status;
	char *key, **vals;
	struct group *g;

	if (xdr == NULL) return NULL;

	if (!xdr_int(xdr, &nkeys)) return NULL;

	g = (struct group *)calloc(1, sizeof(struct group));
	g->gr_gid = -2;

	for (i = 0; i < nkeys; i++)
	{
		key = NULL;
		vals = NULL;
		nvals = 0;

		status = _lu_xdr_attribute(xdr, &key, &vals, &nvals);
		if (status < 0)
		{
			free_group(g);
			return NULL;
		}

		if (nvals == 0)
		{
			free(key);
			continue;
		}

		j = 0;

		if ((g->gr_name == NULL) && (!strcmp("name", key)))
		{
			g->gr_name = vals[0];
			j = 1;
		}
		else if ((g->gr_passwd == NULL) && (!strcmp("passwd", key)))
		{
			g->gr_passwd = vals[0];
			j = 1;
		}
		else if ((g->gr_gid == (gid_t)-2) && (!strcmp("gid", key)))
		{
			g->gr_gid = atoi(vals[0]);
			if ((g->gr_gid == 0) && (strcmp(vals[0], "0"))) g->gr_gid = -2;
		}
		else if ((g->gr_mem == NULL) && (!strcmp("users", key)))
		{
			g->gr_mem = vals;
			j = nvals;
			vals = NULL;
		}

		free(key);
		if (vals != NULL)
		{
			for (; j < nvals; j++) free(vals[j]);
			free(vals);
		}
	}

	if (g->gr_name == NULL) g->gr_name = strdup("");
	if (g->gr_passwd == NULL) g->gr_passwd = strdup("");
	if (g->gr_mem == NULL) g->gr_mem = (char **)calloc(1, sizeof(char *));

	return g;
}

static struct group *
copy_group(struct group *in)
{
	struct group *g;
	int i, len;

	if (in == NULL) return NULL;

	g = (struct group *)calloc(1, sizeof(struct group));

	g->gr_name = LU_COPY_STRING(in->gr_name);
	g->gr_passwd = LU_COPY_STRING(in->gr_passwd);
	g->gr_gid = in->gr_gid;

	len = 0;
	if (in->gr_mem != NULL)
	{
		for (len = 0; in->gr_mem[len] != NULL; len++);
	}

	g->gr_mem = (char **)calloc(len + 1, sizeof(char *));
	for (i = 0; i < len; i++)
	{
		g->gr_mem[i] = strdup(in->gr_mem[i]);
	}

	return g;
}

static int
copy_group_r(struct group *in, struct group *out, char *buffer, int buflen)
{
	int i, len, hsize;
	unsigned long addr;
	char *bp, *ap;

	if (in == NULL) return -1;
	if (out == NULL) return -1;

	if (buffer == NULL) buflen = 0;

	/* Calculate size of input */
	hsize = 0;
	if (in->gr_name != NULL) hsize += strlen(in->gr_name);
	if (in->gr_passwd != NULL) hsize += strlen(in->gr_passwd);

	/* NULL pointer at end of list */
	hsize += sizeof(char *);

	len = 0;
	if (in->gr_mem != NULL)
	{
		for (len = 0; in->gr_mem[len] != NULL; len++)
		{
			hsize += sizeof(char *);
			hsize += strlen(in->gr_mem[len]);
		}
	}

	/* Check buffer space */
	if (hsize > buflen) return -1;

	/* Copy result into caller's struct group, using buffer for memory */
	bp = buffer;

	out->gr_name = NULL;
	if (in->gr_name != NULL)
	{
		out->gr_name = bp;
		hsize = strlen(in->gr_name) + 1;
		memmove(bp, in->gr_name, hsize);
		bp += hsize;
	}

	out->gr_passwd = NULL;
	if (in->gr_passwd != NULL)
	{
		out->gr_passwd = bp;
		hsize = strlen(in->gr_passwd) + 1;
		memmove(bp, in->gr_passwd, hsize);
		bp += hsize;
	}

	out->gr_gid = in->gr_gid;

	out->gr_mem = NULL;
	ap = bp + ((len + 1) * sizeof(char *));

	if (in->gr_mem != NULL)
	{
		out->gr_mem = (char **)bp;
		for (i = 0; i < len; i++)
		{
			addr = (unsigned long)ap;
			memmove(bp, &addr, sizeof(unsigned long));
			bp += sizeof(unsigned long);

			hsize = strlen(in->gr_mem[i]) + 1;
			memmove(ap, in->gr_mem[i], hsize);
			ap += hsize;
		}
	}
	
	memset(bp, 0, sizeof(unsigned long));
	bp = ap;

	return 0;
}

static void
recycle_group(struct lu_thread_info *tdata, struct group *in)
{
	struct group *g;

	if (tdata == NULL) return;
	g = (struct group *)tdata->lu_entry;

	if (in == NULL)
	{
		free_group(g);
		tdata->lu_entry = NULL;
	}

	if (tdata->lu_entry == NULL)
	{
		tdata->lu_entry = in;
		return;
	}

	free_group_data(g);

	g->gr_name = in->gr_name;
	g->gr_passwd = in->gr_passwd;
	g->gr_gid = in->gr_gid;
	g->gr_mem = in->gr_mem;

	free(in);
}

__private_extern__ unsigned int
get_group_cache_ttl()
{
	return _group_cache_ttl;
}

__private_extern__ void
set_group_cache_ttl(unsigned int ttl)
{
	int i;

	pthread_mutex_lock(&_group_cache_lock);

	_group_cache_ttl = ttl;

	if (ttl == 0)
	{
		for (i = 0; i < GROUP_CACHE_SIZE; i++)
		{
			if (_group_cache[i] == NULL) continue;

			free_group((struct group *)_group_cache[i]);
			_group_cache[i] = NULL;
			_group_cache_best_before[i] = 0;
		}
	}

	pthread_mutex_unlock(&_group_cache_lock);
}

static void
cache_group(struct group *gr)
{
	struct timeval now;
	struct group *grcache;

	if (_group_cache_ttl == 0) return;
	if (gr == NULL) return;

	pthread_mutex_lock(&_group_cache_lock);

	grcache = copy_group(gr);

	gettimeofday(&now, NULL);

	if (_group_cache[_group_cache_index] != NULL)
		free_group((struct group *)_group_cache[_group_cache_index]);

	_group_cache[_group_cache_index] = grcache;
	_group_cache_best_before[_group_cache_index] = now.tv_sec + _group_cache_ttl;
	_group_cache_index = (_group_cache_index + 1) % GROUP_CACHE_SIZE;

	pthread_mutex_unlock(&_group_cache_lock);
}

static struct group *
cache_getgrnam(const char *name)
{
	int i;
	struct group *gr, *res;
	struct timeval now;

	if (_group_cache_ttl == 0) return NULL;
	if (name == NULL) return NULL;

	pthread_mutex_lock(&_group_cache_lock);

	gettimeofday(&now, NULL);

	for (i = 0; i < GROUP_CACHE_SIZE; i++)
	{
		if (_group_cache_best_before[i] == 0) continue;
		if ((unsigned int)now.tv_sec > _group_cache_best_before[i]) continue;

		gr = (struct group *)_group_cache[i];

		if (gr->gr_name == NULL) continue;

		if (!strcmp(name, gr->gr_name))
		{
			res = copy_group(gr);
			pthread_mutex_unlock(&_group_cache_lock);
			return res;
		}
	}

	pthread_mutex_unlock(&_group_cache_lock);
	return NULL;
}

static struct group *
cache_getgrgid(int gid)
{
	int i;
	struct group *gr, *res;
	struct timeval now;

	if (_group_cache_ttl == 0) return NULL;

	pthread_mutex_lock(&_group_cache_lock);

	gettimeofday(&now, NULL);

	for (i = 0; i < GROUP_CACHE_SIZE; i++)
	{
		if (_group_cache_best_before[i] == 0) continue;
		if ((unsigned int)now.tv_sec > _group_cache_best_before[i]) continue;

		gr = (struct group *)_group_cache[i];

		if ((gid_t)gid == gr->gr_gid)
		{
			res = copy_group(gr);
			pthread_mutex_unlock(&_group_cache_lock);
			return res;
		}
	}

	pthread_mutex_unlock(&_group_cache_lock);
	return NULL;
}

static struct group *
lu_getgrgid(int gid)
{
	struct group *g;
	unsigned int datalen;
	XDR inxdr;
	static int proc = -1;
	int count;
	char *lookup_buf;
	
	if (proc < 0)
	{
		if (_lookup_link(_lu_port, "getgrgid", &proc) != KERN_SUCCESS)
		{
			return NULL;
		}
	}

	gid = htonl(gid);
	datalen = 0;
	lookup_buf = NULL;

	if (_lookup_all(_lu_port, proc, (unit *)&gid, 1, &lookup_buf, &datalen) != KERN_SUCCESS)
	{
		return NULL;
	}

	datalen *= BYTES_PER_XDR_UNIT;
	if ((lookup_buf == NULL) || (datalen == 0)) return NULL;

	xdrmem_create(&inxdr, lookup_buf, datalen, XDR_DECODE);

	count = 0;
	if (!xdr_int(&inxdr, &count))
	{
		xdr_destroy(&inxdr);
		vm_deallocate(mach_task_self(), (vm_address_t)lookup_buf, datalen);
		return NULL;
	}

	if (count == 0)
	{
		xdr_destroy(&inxdr);
		vm_deallocate(mach_task_self(), (vm_address_t)lookup_buf, datalen);
		return NULL;
	}

	g = extract_group(&inxdr);
	xdr_destroy(&inxdr);
	vm_deallocate(mach_task_self(), (vm_address_t)lookup_buf, datalen);

	return g;
}

static struct group *
lu_getgrnam(const char *name)
{
	struct group *g;
	unsigned int datalen;
	char namebuf[_LU_MAXLUSTRLEN + BYTES_PER_XDR_UNIT];
	XDR outxdr;
	XDR inxdr;
	static int proc = -1;
	int count;
	char *lookup_buf;

	if (proc < 0)
	{
		if (_lookup_link(_lu_port, "getgrnam", &proc) != KERN_SUCCESS)
		{
			return NULL;
		}
	}

	xdrmem_create(&outxdr, namebuf, sizeof(namebuf), XDR_ENCODE);

	if (!xdr__lu_string(&outxdr, (_lu_string *)&name))
	{
		xdr_destroy(&outxdr);
		return NULL;
	}

	datalen = 0;
	lookup_buf = NULL;

	if (_lookup_all(_lu_port, proc, (unit *)namebuf, xdr_getpos(&outxdr) / BYTES_PER_XDR_UNIT, &lookup_buf, &datalen) != KERN_SUCCESS)
	{
		return NULL;
	}

	xdr_destroy(&outxdr);

	datalen *= BYTES_PER_XDR_UNIT;
	if ((lookup_buf == NULL) || (datalen == 0)) return NULL;

	xdrmem_create(&inxdr, lookup_buf, datalen, XDR_DECODE);

	count = 0;
	if (!xdr_int(&inxdr, &count))
	{
		xdr_destroy(&inxdr);
		vm_deallocate(mach_task_self(), (vm_address_t)lookup_buf, datalen);
		return NULL;
	}

	if (count == 0)
	{
		xdr_destroy(&inxdr);
		vm_deallocate(mach_task_self(), (vm_address_t)lookup_buf, datalen);
		return NULL;
	}

	g = extract_group(&inxdr);
	xdr_destroy(&inxdr);
	vm_deallocate(mach_task_self(), (vm_address_t)lookup_buf, datalen);

	return g;
}

int
_old_getgrouplist(const char *uname, int agroup, int *groups, int *grpcnt)
{
	struct group *grp;
	int i, ngroups;
	int ret, maxgroups;

	ret = 0;
	ngroups = 0;
	maxgroups = *grpcnt;

	/*
	 * When installing primary group, duplicate it;
	 * the first element of groups is the effective gid
	 * and will be overwritten when a setgid file is executed.
	 */
	groups[ngroups++] = agroup;
	if (maxgroups > 1) groups[ngroups++] = agroup;

	/*
	 * Scan the group file to find additional groups.
	 */
	setgrent();

	while ((grp = getgrent()))
	{
		if (grp->gr_gid == (gid_t)agroup) continue;
		for (i = 0; grp->gr_mem[i]; i++)
		{
			if (!strcmp(grp->gr_mem[i], uname))
			{
				if (ngroups >= maxgroups)
				{
					ret = -1;
					break;
				}

				groups[ngroups++] = grp->gr_gid;
				break;
			}
		}
	}

	endgrent();
	*grpcnt = ngroups;
	return ret;
}

static int
lu_getgrouplist(const char *name, int basegid, int *groups, int *grpcnt, int dupbase)
{
	unsigned int datalen;
	XDR outxdr;
	XDR inxdr;
	static int proc = -1;
	char *lookup_buf;
	char namebuf[_LU_MAXLUSTRLEN + BYTES_PER_XDR_UNIT];
	int ngroups;
	int a_group;
	int i, j, count;

	if (groups == NULL) return -1;
	if (*grpcnt == 0) return -1;

	ngroups = 0;
	groups[ngroups++] = basegid;
	if (*grpcnt == 1) return 0;

	if (dupbase != 0)
	{
		/* getgrouplist duplicates the primary group! */
		groups[ngroups++] = basegid;
		if (*grpcnt == 2) return 0;
	}

	if (proc < 0)
	{
		if (_lookup_link(_lu_port, "initgroups", &proc) != KERN_SUCCESS)
		{
			return -1;
		}
	}

	xdrmem_create(&outxdr, namebuf, sizeof(namebuf), XDR_ENCODE);
	if (!xdr__lu_string(&outxdr, (_lu_string *)&name))
	{
		xdr_destroy(&outxdr);
		return -1;
	}

	datalen = 0;
	lookup_buf = NULL;

	if (_lookup_all(_lu_port, proc, (unit *)namebuf,
		xdr_getpos(&outxdr) / BYTES_PER_XDR_UNIT, &lookup_buf, &datalen)
		!= KERN_SUCCESS)
	{
		xdr_destroy(&outxdr);
		return -1;
	}

	xdr_destroy(&outxdr);

	datalen *= BYTES_PER_XDR_UNIT;
	if ((lookup_buf == NULL) || (datalen == 0)) return NULL;

	xdrmem_create(&inxdr, lookup_buf, datalen, XDR_DECODE);

	if (!xdr_int(&inxdr, &count))
	{
		xdr_destroy(&inxdr);
		vm_deallocate(mach_task_self(), (vm_address_t)lookup_buf, datalen);
		return -1;
	}

	for (i = 0; i < count; i++)
	{
		if (!xdr_int(&inxdr, &a_group)) break;

		j = 0;
		if (dupbase != 0) j = 1;
		for (; j < ngroups; j++)
		{
			if (groups[j] == a_group) break;
		}

		if (j >= ngroups)
		{
			groups[ngroups++] = a_group;
			if (ngroups == *grpcnt) break;
		}
	}

	xdr_destroy(&inxdr);
	vm_deallocate(mach_task_self(), (vm_address_t)lookup_buf, datalen);

	*grpcnt = ngroups;
	return 0;
}

int
getgrouplist(const char *uname, int agroup, int *groups, int *grpcnt)
{
	if (_lu_running())
	{
		return lu_getgrouplist(uname, agroup, groups, grpcnt, 1);
	}

	return _old_getgrouplist(uname, agroup, groups, grpcnt);
}

static int
lu_initgroups(const char *name, int basegid)
{
	int status, ngroups, groups[NGROUPS];

	ngroups = NGROUPS;
	status = lu_getgrouplist(name, basegid, groups, &ngroups, 0);
	if (status < 0) return status;

	return setgroups(ngroups, groups);
}

static void
lu_endgrent(void)
{
	struct lu_thread_info *tdata;

	tdata = _lu_data_create_key(_lu_data_key_group, free_lu_thread_info_group);
	_lu_data_free_vm_xdr(tdata);
}

static int
lu_setgrent(void)
{
	lu_endgrent();
	return 1;
}

static struct group *
lu_getgrent()
{
	struct group *g;
	static int proc = -1;
	struct lu_thread_info *tdata;

	tdata = _lu_data_create_key(_lu_data_key_group, free_lu_thread_info_group);
	if (tdata == NULL)
	{
		tdata = (struct lu_thread_info *)calloc(1, sizeof(struct lu_thread_info));
		_lu_data_set_key(_lu_data_key_group, tdata);
	}
	
	if (tdata->lu_vm == NULL)
	{
		if (proc < 0)
		{
			if (_lookup_link(_lu_port, "getgrent", &proc) != KERN_SUCCESS)
			{
				lu_endgrent();
				return NULL;
			}
		}

		if (_lookup_all(_lu_port, proc, NULL, 0, &(tdata->lu_vm), &(tdata->lu_vm_length)) != KERN_SUCCESS)
		{
			lu_endgrent();
			return NULL;
		}

		/* mig stubs measure size in words (4 bytes) */
		tdata->lu_vm_length *= 4;

		if (tdata->lu_xdr != NULL)
		{
			xdr_destroy(tdata->lu_xdr);
			free(tdata->lu_xdr);
		}
		tdata->lu_xdr = (XDR *)calloc(1, sizeof(XDR));

		xdrmem_create(tdata->lu_xdr, tdata->lu_vm, tdata->lu_vm_length, XDR_DECODE);
		if (!xdr_int(tdata->lu_xdr, &tdata->lu_vm_cursor))
		{
			lu_endgrent();
			return NULL;
		}
	}

	if (tdata->lu_vm_cursor == 0)
	{
		lu_endgrent();
		return NULL;
	}

	g = extract_group(tdata->lu_xdr);
	if (g == NULL)
	{
		lu_endgrent();
		return NULL;
	}

	tdata->lu_vm_cursor--;
	
	return g;
}

static struct group *
getgr_internal(const char *name, gid_t gid, int source)
{
	struct group *res = NULL;
	int from_cache;

	from_cache = 0;
	res = NULL;

	switch (source)
	{
		case GR_GET_NAME:
			res = cache_getgrnam(name);
			break;
		case GR_GET_GID:
			res = cache_getgrgid(gid);
			break;
		default: res = NULL;
	}

	if (res != NULL)
	{
		from_cache = 1;
	}
	else if (_lu_running())
	{
		switch (source)
		{
			case GR_GET_NAME:
				res = lu_getgrnam(name);
				break;
			case GR_GET_GID:
				res = lu_getgrgid(gid);
				break;
			case GR_GET_ENT:
				res = lu_getgrent();
				break;
			default: res = NULL;
		}
	}
	else
	{
		pthread_mutex_lock(&_group_lock);
		switch (source)
		{
			case GR_GET_NAME:
				res = copy_group(_old_getgrnam(name));
				break;
			case GR_GET_GID:
				res = copy_group(_old_getgrgid(gid));
				break;
			case GR_GET_ENT:
				res = copy_group(_old_getgrent());
				break;
			default: res = NULL;
		}
		pthread_mutex_unlock(&_group_lock);
	}

	if (from_cache == 0) cache_group(res);

	return res;
}

static struct group *
getgr(const char *name, gid_t gid, int source)
{
	struct group *res = NULL;
	struct lu_thread_info *tdata;

	tdata = _lu_data_create_key(_lu_data_key_group, free_lu_thread_info_group);
	if (tdata == NULL)
	{
		tdata = (struct lu_thread_info *)calloc(1, sizeof(struct lu_thread_info));
		_lu_data_set_key(_lu_data_key_group, tdata);
	}

	res = getgr_internal(name, gid, source);

	recycle_group(tdata, res);
	return (struct group *)tdata->lu_entry;
}

static int
getgr_r(const char *name, gid_t gid, int source, struct group *grp, char *buffer, size_t bufsize, struct group **result)
{
	struct group *res = NULL;
	int status;

	*result = NULL;
	errno = 0;

	res = getgr_internal(name, gid, source);
	if (res == NULL) return -1;

	status = copy_group_r(res, grp, buffer, bufsize);
	free_group(res);

	if (status != 0)
	{
		errno = ERANGE;
		return -1;
	}

	*result = grp;
	return 0;
}

int
initgroups(const char *name, int basegid)
{
	int res;

	if (name == NULL) return -1;

	if (_lu_running())
	{
		if ((res = lu_initgroups(name, basegid)))
		{
			res = _old_initgroups(name, basegid);
		}
	}
	else
	{
		res = _old_initgroups(name, basegid);
	}

	return (res);
}

struct group *
getgrnam(const char *name)
{
	return getgr(name, -2, GR_GET_NAME);
}

struct group *
getgrgid(gid_t gid)
{
	return getgr(NULL, gid, GR_GET_GID);
}

struct group *
getgrent(void)
{
	return getgr(NULL, -2, GR_GET_ENT);
}

int
setgrent(void)
{
	if (_lu_running()) lu_setgrent();
	else _old_setgrent();
	return 1;
}

void
endgrent(void)
{
	if (_lu_running()) lu_endgrent();
	else _old_endgrent();
}

int
getgrnam_r(const char *name, struct group *grp, char *buffer, size_t bufsize, struct group **result)
{
	return getgr_r(name, -2, GR_GET_NAME, grp, buffer, bufsize, result);
}

int
getgrgid_r(gid_t gid, struct group *grp, char *buffer, size_t bufsize, struct group **result)
{
	return getgr_r(NULL, gid, GR_GET_GID, grp, buffer, bufsize, result);
}
