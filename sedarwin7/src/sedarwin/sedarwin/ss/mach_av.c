/*-
 * Copyright (c) 2005 SPARTA, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <mach/message.h>
#include <kern/lock.h>
#include <sedarwin/linux-compat.h>
#include <sedarwin/flask.h>
#include <sedarwin/ss/hashtab.h>
#include <sedarwin/ss/services.h>
#include <sedarwin/avc/avc.h>

static unsigned int msgid_hash(struct hashtab *h, void *key)
{
	int *p = key;

	return *p & (h->size - 1);
}

static int msgid_cmp(struct hashtab *h, void *key1, void *key2)
{
	return memcmp(key1, key2, sizeof(int));
}

struct msgid_classinfo
{
	int baseid;
	int nclasses;
	int classes[0];		/* actually larger */
};

static struct hashtab *msgid2class;

static mutex_t *migscs_load_lock;

/*
 * Read the table mapping mach message ids to security classes.
 * The permissions in those classes are expected to be relative to the
 * base message id defined for a subsystem (which is in this table).
 */
int
sebsd_load_migscs(void *tdata, size_t tsize)
{
	struct hashtab *ht, *oht;
	int error, *p, *ep;

	ht = hashtab_create(msgid_hash, msgid_cmp, 31337);
	if (ht == NULL)
		return (-1);

	printf("security class to subsystem table: %d classes\n",
	    tsize / sizeof(int));

	p = (int *)tdata;
	ep = (int *)((char *)tdata + tsize);
	while (p < ep) {
		int msgid = *p++;
		int nclasses = *p++;
		int size = *p++;
		int i;
		struct msgid_classinfo *c;

		c = sebsd_malloc(sizeof(int) * nclasses + sizeof(*c), M_SEBSD,
		    M_WAITOK);
		c->baseid = msgid;
		c->nclasses = nclasses;
		for (i = 0; i < nclasses; i++)
			c->classes[i] = *p++;
		for (i = msgid; i < msgid + size; i++) {
			int *ip = sebsd_malloc(sizeof(int), M_SEBSD, M_WAITOK);
			*ip = i;
			error = hashtab_insert(ht, ip, c);
			if (error) {
			    hashtab_destroy(ht);
			    return (-1);
			}
		}
	}

	/*
	 * Swap the old message id to class mapping with the new one
	 * and free the old.
	 * XXX - does this leak memory?
	 */
	mutex_lock(migscs_load_lock);
	oht = msgid2class;
	msgid2class = ht;
	mutex_unlock(migscs_load_lock);
	hashtab_destroy(oht);
	return (0);
}

void
sebsd_mach_av_init(void)
{
	size_t tsize;
	int   *tdata;

	migscs_load_lock = mutex_alloc(ETAP_NO_TRACE);

	if (!preload_find_data ("sebsd_migscs", &tsize, &tdata) ||
	    sebsd_load_migscs(tdata, tsize) != 0) {
		msgid2class = hashtab_create(msgid_hash, msgid_cmp, 3);
		return;
	}
}


int
sebsd_check_ipc_method1(int subj, int obj, int msgid)
{
	struct msgid_classinfo *mcl;
	u32    perms;
	int                cl;

	/*
	 * Return allowed for messages in an unknown subsystem.
	 * Instead, we probably should make a check against a
	 * new permission to be added to mach_port for this purpose.
	 */
	mcl = hashtab_search(msgid2class, &msgid); 
	if (mcl == NULL)
		return 0;

	cl = (msgid - mcl->baseid) / (8 * sizeof(u32));
	if (cl >= mcl->nclasses)
		return (1);	/* bad message, access denied */

	perms = (u32)1 <<
	    (msgid - mcl->baseid - (cl * 8 * sizeof(u32)));
	return avc_has_perm(subj, obj, mcl->classes[cl], perms, NULL);
}
