/*
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*-
 * Copyright (c) 1997 Berkeley Software Design, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Berkeley Software Design Inc's name may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BERKELEY SOFTWARE DESIGN INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BERKELEY SOFTWARE DESIGN INC BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      from BSDI nfs_lock.c,v 2.4 1998/12/14 23:49:56 jch Exp
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>		/* for hz */
#include <sys/file.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/lockf.h>		/* for hz */ /* Must come after sys/malloc.h */
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/unistd.h>
#include <sys/user.h>
#include <sys/vnode.h>

#include <kern/thread_act.h>

#include <machine/limits.h>

#include <net/if.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>
#include <nfs/nfs_lock.h>

#define OFF_MAX QUAD_MAX

uint64_t nfsadvlocks = 0;
struct timeval nfsadvlock_longest = {0, 0};
struct timeval nfsadvlocks_time = {0, 0};

/*
 * globals for managing the lockd fifo
 */
pid_t nfslockdpid = 0;
struct file *nfslockdfp = 0;
int nfslockdwaiting = 0;
int nfslockdfifowritten = 0;
int nfslockdfifolock = 0;
#define NFSLOCKDFIFOLOCK_LOCKED	1
#define NFSLOCKDFIFOLOCK_WANT	2

/*
 * pending lock request messages are kept in this queue which is
 * kept sorted by transaction ID (xid).
 */
uint64_t nfs_lockxid = 0;
LOCKD_MSG_QUEUE nfs_pendlockq;

/*
 * This structure is used to identify processes which have acquired NFS locks.
 * Knowing which processes have ever acquired locks allows us to short-circuit
 * unlock requests for processes that have never had an NFS file lock.  Thus
 * avoiding a costly and unnecessary lockd request.
 */
struct nfs_lock_pid {
	TAILQ_ENTRY(nfs_lock_pid)	lp_lru;		/* LRU list */
	LIST_ENTRY(nfs_lock_pid)	lp_hash;	/* hash chain */
	int				lp_valid;	/* valid entry? */
	int				lp_time;	/* last time seen valid */
	pid_t				lp_pid;		/* The process ID. */
	struct timeval			lp_pid_start;	/* Start time of process id */
};

#define NFS_LOCK_PID_HASH_SIZE		64	// XXX tune me
#define	NFS_LOCK_PID_HASH(pid)	\
	(&nfs_lock_pid_hash_tbl[(pid) & nfs_lock_pid_hash])
LIST_HEAD(, nfs_lock_pid) *nfs_lock_pid_hash_tbl;
TAILQ_HEAD(, nfs_lock_pid) nfs_lock_pid_lru;
u_long nfs_lock_pid_hash;
int nfs_lock_pid_lock;


/*
 * initialize global nfs lock state
 */
void
nfs_lockinit(void)
{
	TAILQ_INIT(&nfs_pendlockq);
	nfs_lock_pid_lock = 0;
	nfs_lock_pid_hash_tbl = hashinit(NFS_LOCK_PID_HASH_SIZE,
					 M_TEMP, &nfs_lock_pid_hash);
	TAILQ_INIT(&nfs_lock_pid_lru);
}

/*
 * insert a lock request message into the pending queue
 */
static inline void
nfs_lockdmsg_enqueue(LOCKD_MSG_REQUEST *msgreq)
{
	LOCKD_MSG_REQUEST *mr;

	mr = TAILQ_LAST(&nfs_pendlockq, nfs_lock_msg_queue);
	if (!mr || (msgreq->lmr_msg.lm_xid > mr->lmr_msg.lm_xid)) {
		/* fast path: empty queue or new largest xid */
		TAILQ_INSERT_TAIL(&nfs_pendlockq, msgreq, lmr_next);
		return;
	}
	/* slow path: need to walk list to find insertion point */
	while (mr && (msgreq->lmr_msg.lm_xid > mr->lmr_msg.lm_xid)) {
		mr = TAILQ_PREV(mr, nfs_lock_msg_queue, lmr_next);
	}
	if (mr) {
		TAILQ_INSERT_AFTER(&nfs_pendlockq, mr, msgreq, lmr_next);
	} else {
		TAILQ_INSERT_HEAD(&nfs_pendlockq, msgreq, lmr_next);
	}
}

/*
 * remove a lock request message from the pending queue
 */
static inline void
nfs_lockdmsg_dequeue(LOCKD_MSG_REQUEST *msgreq)
{
	TAILQ_REMOVE(&nfs_pendlockq, msgreq, lmr_next);
}

/*
 * find a pending lock request message by xid
 *
 * We search from the head of the list assuming that the message we're
 * looking for is for an older request (because we have an answer to it).
 * This assumes that lock request will be answered primarily in FIFO order.
 * However, this may not be the case if there are blocked requests.  We may
 * want to move blocked requests to a separate queue (but that'll complicate
 * duplicate xid checking).
 */
static inline LOCKD_MSG_REQUEST *
nfs_lockdmsg_find_by_xid(uint64_t lockxid)
{
	LOCKD_MSG_REQUEST *mr;

	TAILQ_FOREACH(mr, &nfs_pendlockq, lmr_next) {
		if (mr->lmr_msg.lm_xid == lockxid)
			return mr;
		if (mr->lmr_msg.lm_xid > lockxid)
			return NULL;
	}
	return mr;
}

/*
 * Because we can't depend on nlm_granted messages containing the same
 * cookie we sent with the original lock request, we need code test if
 * an nlm_granted answer matches the lock request.  We also need code
 * that can find a lockd message based solely on the nlm_granted answer.
 */

/*
 * compare lockd message to answer
 *
 * returns 0 on equality and 1 if different
 */
static inline int
nfs_lockdmsg_compare_to_answer(LOCKD_MSG_REQUEST *msgreq, struct lockd_ans *ansp)
{
	if (!(ansp->la_flags & LOCKD_ANS_LOCK_INFO))
		return 1;
	if (msgreq->lmr_msg.lm_fl.l_pid != ansp->la_pid)
		return 1;
	if (msgreq->lmr_msg.lm_fl.l_start != ansp->la_start)
		return 1;
	if (msgreq->lmr_msg.lm_fl.l_len != ansp->la_len)
		return 1;
	if (msgreq->lmr_msg.lm_fh_len != ansp->la_fh_len)
		return 1;
	if (bcmp(msgreq->lmr_msg.lm_fh, ansp->la_fh, ansp->la_fh_len))
		return 1;
	return 0;
}

/*
 * find a pending lock request message based on the lock info provided
 * in the lockd_ans/nlm_granted data.  We need this because we can't
 * depend on nlm_granted messages containing the same cookie we sent
 * with the original lock request.
 *
 * We search from the head of the list assuming that the message we're
 * looking for is for an older request (because we have an answer to it).
 * This assumes that lock request will be answered primarily in FIFO order.
 * However, this may not be the case if there are blocked requests.  We may
 * want to move blocked requests to a separate queue (but that'll complicate
 * duplicate xid checking).
 */
static inline LOCKD_MSG_REQUEST *
nfs_lockdmsg_find_by_answer(struct lockd_ans *ansp)
{
	LOCKD_MSG_REQUEST *mr;

	if (!(ansp->la_flags & LOCKD_ANS_LOCK_INFO))
		return NULL;
	TAILQ_FOREACH(mr, &nfs_pendlockq, lmr_next) {
		if (!nfs_lockdmsg_compare_to_answer(mr, ansp))
			break;
	}
	return mr;
}

/*
 * return the next unique lock request transaction ID
 */
static inline uint64_t
nfs_lockxid_get(void)
{
	LOCKD_MSG_REQUEST *mr;

	/* derive initial lock xid from system time */
	if (!nfs_lockxid) {
		/*
		 * Note: it's OK if this code inits nfs_lockxid to 0 (for example,
		 * due to a broken clock) because we immediately increment it
		 * and we guarantee to never use xid 0.  So, nfs_lockxid should only
		 * ever be 0 the first time this function is called.
		 */
		struct timeval tv;
		microtime(&tv);
		nfs_lockxid = (uint64_t)tv.tv_sec << 12;
	}

	/* make sure we get a unique xid */
	do {
		/* Skip zero xid if it should ever happen.  */
		if (++nfs_lockxid == 0)
			nfs_lockxid++;
		if (!(mr = TAILQ_LAST(&nfs_pendlockq, nfs_lock_msg_queue)) ||
		     (mr->lmr_msg.lm_xid < nfs_lockxid)) {
			/* fast path: empty queue or new largest xid */
			break;
		}
		/* check if xid is already in use */
	} while (nfs_lockdmsg_find_by_xid(nfs_lockxid));

	return nfs_lockxid;
}


/*
 * Check the nfs_lock_pid hash table for an entry and, if requested,
 * add the entry if it is not found.
 *
 * (Also, if adding, try to clean up some stale entries.)
 */
static int
nfs_lock_pid_check(struct proc *p, int addflag, struct vnode *vp)
{
	struct nfs_lock_pid *lp, *lplru, *lplru_next;
	struct proc *plru;
	int error = 0;
	struct timeval now;

	/* lock hash */
loop:
	if (nfs_lock_pid_lock) {
		while (nfs_lock_pid_lock) {
			nfs_lock_pid_lock = -1;
			tsleep(&nfs_lock_pid_lock, PCATCH, "nfslockpid", 0);
			if ((error = nfs_sigintr(VFSTONFS(vp->v_mount), NULL, p)))
				return (error);
		}
		goto loop;
	}
	nfs_lock_pid_lock = 1;

	/* Search hash chain */
	error = ENOENT;
	lp = NFS_LOCK_PID_HASH(p->p_pid)->lh_first;
	for (; lp != NULL; lp = lp->lp_hash.le_next)
		if (lp->lp_pid == p->p_pid) {
			/* found pid... */
			if (timevalcmp(&lp->lp_pid_start, &p->p_stats->p_start, ==)) {
				/* ...and it's valid */
				/* move to tail of LRU */
				TAILQ_REMOVE(&nfs_lock_pid_lru, lp, lp_lru);
				microuptime(&now);
				lp->lp_time = now.tv_sec;
				TAILQ_INSERT_TAIL(&nfs_lock_pid_lru, lp, lp_lru);
				error = 0;
				break;
			}
			/* ...but it's no longer valid */
			/* remove from hash, invalidate, and move to lru head */
			LIST_REMOVE(lp, lp_hash);
			lp->lp_valid = 0;
			TAILQ_REMOVE(&nfs_lock_pid_lru, lp, lp_lru);
			TAILQ_INSERT_HEAD(&nfs_lock_pid_lru, lp, lp_lru);
			lp = NULL;
			break;
		}

	/* if we didn't find it (valid) and we've been asked to add it */
	if ((error == ENOENT) && addflag) {
		/* scan lru list for invalid, stale entries to reuse/free */
		int lrucnt = 0;
		microuptime(&now);
		for (lplru = TAILQ_FIRST(&nfs_lock_pid_lru); lplru; lplru = lplru_next) {
			lplru_next = TAILQ_NEXT(lplru, lp_lru);
			if (lplru->lp_valid && (lplru->lp_time >= (now.tv_sec - 2))) {
				/*
				 * If the oldest LRU entry is relatively new, then don't
				 * bother scanning any further.
				 */
				break;
			}
			/* remove entry from LRU, and check if it's still in use */
			TAILQ_REMOVE(&nfs_lock_pid_lru, lplru, lp_lru);
			if (!lplru->lp_valid || !(plru = pfind(lplru->lp_pid)) ||
			    timevalcmp(&lplru->lp_pid_start, &plru->p_stats->p_start, !=)) {
				/* no longer in use */
				LIST_REMOVE(lplru, lp_hash);
				if (!lp) {
					/* we'll reuse this one */
					lp = lplru;
				} else {
					/* we can free this one */
					FREE(lplru, M_TEMP);
				}
			} else {
				/* still in use */
				lplru->lp_time = now.tv_sec;
				TAILQ_INSERT_TAIL(&nfs_lock_pid_lru, lplru, lp_lru);
			}
			/* don't check too many entries at once */
			if (++lrucnt > 8)
				break;
		}
		if (!lp) {
			/* we need to allocate a new one */
			MALLOC(lp, struct nfs_lock_pid *, sizeof(struct nfs_lock_pid),
				M_TEMP, M_WAITOK | M_ZERO);
		}
		/* (re)initialize nfs_lock_pid info */
		lp->lp_pid = p->p_pid;
		lp->lp_pid_start = p->p_stats->p_start;
		/* insert pid in hash */
		LIST_INSERT_HEAD(NFS_LOCK_PID_HASH(lp->lp_pid), lp, lp_hash);
		lp->lp_valid = 1;
		lp->lp_time = now.tv_sec;
		TAILQ_INSERT_TAIL(&nfs_lock_pid_lru, lp, lp_lru);
		error = 0;
	}

	/* unlock hash */
	if (nfs_lock_pid_lock < 0) {
		nfs_lock_pid_lock = 0;
		wakeup(&nfs_lock_pid_lock);
	} else
		nfs_lock_pid_lock = 0;

	return (error);
}


/*
 * nfs_advlock --
 *      NFS advisory byte-level locks.
 */
int
nfs_dolock(struct vop_advlock_args *ap)
/* struct vop_advlock_args {
        struct vnodeop_desc *a_desc;
        struct vnode *a_vp;
        caddr_t a_id;
        int a_op;
        struct flock *a_fl;
        int a_flags;
}; */
{
	LOCKD_MSG_REQUEST msgreq;
	LOCKD_MSG *msg;
	struct vnode *vp, *wvp;
	struct nfsnode *np;
	int error, error1;
	struct flock *fl;
	int fmode, ioflg;
	struct proc *p;
	struct nfsmount *nmp;
	struct vattr vattr;
	off_t start, end;
	struct timeval now;
	int timeo, endtime, lastmsg, wentdown = 0;
	int lockpidcheck;

	p = current_proc();

	vp = ap->a_vp;
	fl = ap->a_fl;
	np = VTONFS(vp);

	nmp = VFSTONFS(vp->v_mount);
	if (!nmp)
		return (ENXIO);
	if (nmp->nm_flag & NFSMNT_NOLOCKS)
		return (EOPNOTSUPP);

	/*
	 * The NLM protocol doesn't allow the server to return an error
	 * on ranges, so we do it.  Pre LFS (Large File Summit)
	 * standards required EINVAL for the range errors.  More recent
	 * standards use EOVERFLOW, but their EINVAL wording still
	 * encompasses these errors.
	 * Any code sensitive to this is either:
	 *  1) written pre-LFS and so can handle only EINVAL, or
	 *  2) written post-LFS and thus ought to be tolerant of pre-LFS
	 *     implementations.
	 * Since returning EOVERFLOW certainly breaks 1), we return EINVAL.
	 */
	if (fl->l_whence != SEEK_END) {
		if ((fl->l_whence != SEEK_CUR && fl->l_whence != SEEK_SET) ||
		    fl->l_start < 0 ||
		    (fl->l_len > 0 && fl->l_len - 1 > OFF_MAX - fl->l_start) ||
		    (fl->l_len < 0 && fl->l_start + fl->l_len < 0))
			return (EINVAL);
	}
	/*
	 * If daemon is running take a ref on its fifo
	 */
	if (!nfslockdfp || !(wvp = (struct vnode *)nfslockdfp->f_data)) {
		if (!nfslockdwaiting)
			return (EOPNOTSUPP);
		/*
		 * Don't wake lock daemon if it hasn't been started yet and
		 * this is an unlock request (since we couldn't possibly
		 * actually have a lock on the file).  This could be an
		 * uninformed unlock request due to closef()'s behavior of doing
		 * unlocks on all files if a process has had a lock on ANY file.
		 */
		if (!nfslockdfp && (fl->l_type == F_UNLCK))
			return (EINVAL);
		/* wake up lock daemon */
		(void)wakeup((void *)&nfslockdwaiting);
		/* wait on nfslockdfp for a while to allow daemon to start */
		tsleep((void *)&nfslockdfp, PCATCH | PUSER, "lockd", 60*hz);
		/* check for nfslockdfp and f_data */
		if (!nfslockdfp || !(wvp = (struct vnode *)nfslockdfp->f_data))
			return (EOPNOTSUPP);
	}
	VREF(wvp);

	/*
	 * Need to check if this process has successfully acquired an NFS lock before.
	 * If not, and this is an unlock request we can simply return success here.
	 */
	lockpidcheck = nfs_lock_pid_check(p, 0, vp);
	if (lockpidcheck) {
		if (lockpidcheck != ENOENT)
			return (lockpidcheck);
		if (ap->a_op == F_UNLCK) {
			vrele(wvp);
			return (0);
		}
	}

	/*
	 * The NFS Lock Manager protocol doesn't directly handle
	 * negative lengths or SEEK_END, so we need to normalize
	 * things here where we have all the info.
	 * (Note: SEEK_CUR is already adjusted for at this point)
	 */
	/* Convert the flock structure into a start and end. */
	switch (fl->l_whence) {
	case SEEK_SET:
	case SEEK_CUR:
		/*
		 * Caller is responsible for adding any necessary offset
		 * to fl->l_start when SEEK_CUR is used.
		 */
		start = fl->l_start;
		break;
	case SEEK_END:
		/* need to flush, and refetch attributes to make */
		/* sure we have the correct end of file offset   */
		if (np->n_flag & NMODIFIED) {
			np->n_xid = 0;
			error = nfs_vinvalbuf(vp, V_SAVE, p->p_ucred, p, 1);
			if (error) {
				vrele(wvp);
				return (error);
			}
		}
		np->n_xid = 0;
		error = VOP_GETATTR(vp, &vattr, p->p_ucred, p);
		if (error) {
			vrele(wvp);
			return (error);
		}
		start = np->n_size + fl->l_start;
		break;
	default:
		vrele(wvp);
		return (EINVAL);
	}
	if (fl->l_len == 0)
		end = -1;
	else if (fl->l_len > 0)
		end = start + fl->l_len - 1;
	else { /* l_len is negative */
		end = start - 1;
		start += fl->l_len;
	}
	if (start < 0) {
		vrele(wvp);
		return (EINVAL);
	}
	if (!NFS_ISV3(vp) &&
	    ((start >= 0x80000000) || (end >= 0x80000000))) {
		vrele(wvp);
		return (EINVAL);
	}

	/*
	 * Fill in the information structure.
	 */
	msgreq.lmr_answered = 0;
	msgreq.lmr_errno = 0;
	msgreq.lmr_saved_errno = 0;
	msg = &msgreq.lmr_msg;
	msg->lm_version = LOCKD_MSG_VERSION;
	msg->lm_flags = 0;

	msg->lm_fl = *fl;
	msg->lm_fl.l_start = start;
	if (end != -1)
		msg->lm_fl.l_len = end - start + 1;
	msg->lm_fl.l_pid = p->p_pid;

	if (ap->a_flags & F_WAIT)
		msg->lm_flags |= LOCKD_MSG_BLOCK;
	if (ap->a_op == F_GETLK)
		msg->lm_flags |= LOCKD_MSG_TEST;

	nmp = VFSTONFS(vp->v_mount);
	if (!nmp) {
		vrele(wvp);
		return (ENXIO);
	}

	bcopy(mtod(nmp->nm_nam, struct sockaddr *), &msg->lm_addr,
	      min(sizeof msg->lm_addr,
		  mtod(nmp->nm_nam, struct sockaddr *)->sa_len));
	msg->lm_fh_len = NFS_ISV3(vp) ? VTONFS(vp)->n_fhsize : NFSX_V2FH;
	bcopy(VTONFS(vp)->n_fhp, msg->lm_fh, msg->lm_fh_len);
	if (NFS_ISV3(vp))
		msg->lm_flags |= LOCKD_MSG_NFSV3;
	cru2x(p->p_ucred, &msg->lm_cred);

	microuptime(&now);
	lastmsg = now.tv_sec - ((nmp->nm_tprintf_delay) - (nmp->nm_tprintf_initial_delay));

	fmode = FFLAGS(O_WRONLY);
	if ((error = VOP_OPEN(wvp, fmode, kernproc->p_ucred, p))) {
		vrele(wvp);
		return (error);
	}
	++wvp->v_writecount;

	/* allocate unique xid */
	msg->lm_xid = nfs_lockxid_get();
	nfs_lockdmsg_enqueue(&msgreq);

	timeo = 2*hz;
#define IO_NOMACCHECK 0;
	ioflg = IO_UNIT | IO_NOMACCHECK;
	for (;;) {
		VOP_LEASE(wvp, p, kernproc->p_ucred, LEASE_WRITE);

		error = 0;
		while (nfslockdfifolock & NFSLOCKDFIFOLOCK_LOCKED) {
			nfslockdfifolock |= NFSLOCKDFIFOLOCK_WANT;
			error = tsleep((void *)&nfslockdfifolock,
					PCATCH | PUSER, "lockdfifo", 20*hz);
			if (error)
				break;
		}
		if (error)
			break;
		nfslockdfifolock |= NFSLOCKDFIFOLOCK_LOCKED;

		error = vn_rdwr(UIO_WRITE, wvp, (caddr_t)msg, sizeof(*msg), 0,
		    UIO_SYSSPACE, ioflg, kernproc->p_ucred, NULL, p);

		nfslockdfifowritten = 1;

		nfslockdfifolock &= ~NFSLOCKDFIFOLOCK_LOCKED;
		if (nfslockdfifolock & NFSLOCKDFIFOLOCK_WANT) {
			nfslockdfifolock &= ~NFSLOCKDFIFOLOCK_WANT;
			wakeup((void *)&nfslockdfifolock);
		}
		/* wake up lock daemon */
		if (nfslockdwaiting)
			(void)wakeup((void *)&nfslockdwaiting);

		if (error && (((ioflg & IO_NDELAY) == 0) || error != EAGAIN)) {
			break;
		}

		/*
		 * Always wait for an answer.  Not waiting for unlocks could
		 * cause a lock to be left if the unlock request gets dropped.
		 */

		/*
		 * Retry if it takes too long to get a response.
		 *
		 * The timeout numbers were picked out of thin air... they start
		 * at 2 and double each timeout with a max of 60 seconds.
		 *
		 * In order to maintain responsiveness, we pass a small timeout
		 * to tsleep and calculate the timeouts ourselves.  This allows
		 * us to pick up on mount changes quicker.
		 */
wait_for_granted:
		error = EWOULDBLOCK;
		microuptime(&now);
		if ((timeo/hz) > 0)
			endtime = now.tv_sec + timeo/hz;
		else
			endtime = now.tv_sec + 1;
		while (now.tv_sec < endtime) {
			error = tsleep((void *)&msgreq, PCATCH | PUSER, "lockd", 2*hz);
			if (msgreq.lmr_answered) {
				/*
				 * Note: it's possible to have a lock granted at
				 * essentially the same time that we get interrupted.
				 * Since the lock may be granted, we can't return an
				 * error from this request or we might not unlock the
				 * lock that's been granted.
				 */
				error = 0;
				break;
			}
			if (error != EWOULDBLOCK)
				break;
			/* check that we still have our mount... */
			/* ...and that we still support locks */
			nmp = VFSTONFS(vp->v_mount);
			if (!nmp || (nmp->nm_flag & NFSMNT_NOLOCKS))
				break;
			/*
			 * If the mount is hung and we've requested not to hang
			 * on remote filesystems, then bail now.
			 */
			if ((p != NULL) && ((p->p_flag & P_NOREMOTEHANG) != 0) &&
			    ((nmp->nm_state & (NFSSTA_TIMEO|NFSSTA_LOCKTIMEO)) != 0)) {
				if (fl->l_type == F_UNLCK)
					printf("nfs_dolock: aborting unlock request "
					    "due to timeout (noremotehang)\n");
				error = EIO;
				break;
			}
			microuptime(&now);
		}
		if (error) {
			/* check that we still have our mount... */
			nmp = VFSTONFS(vp->v_mount);
			if (!nmp) {
				if (error == EWOULDBLOCK)
					error = ENXIO;
				break;
			}
			/* ...and that we still support locks */
			if (nmp->nm_flag & NFSMNT_NOLOCKS) {
				if (error == EWOULDBLOCK)
					error = EOPNOTSUPP;
				break;
			}
			if ((error == EOPNOTSUPP) &&
			    (nmp->nm_state & NFSSTA_LOCKSWORK)) {
				/*
				 * We have evidence that locks work, yet lockd
				 * returned EOPNOTSUPP.  This is probably because
				 * it was unable to contact the server's lockd to
				 * send it the request.
				 *
				 * Because we know locks work, we'll consider
				 * this failure to be a timeout.
				 */
				error = EWOULDBLOCK;
			}
			if (error != EWOULDBLOCK) {
				/*
				 * We're going to bail on this request.
				 * If we were a blocked lock request, send a cancel.
				 */
				if ((msgreq.lmr_errno == EINPROGRESS) &&
				    !(msg->lm_flags & LOCKD_MSG_CANCEL)) {
					/* set this request up as a cancel */
					msg->lm_flags |= LOCKD_MSG_CANCEL;
					nfs_lockdmsg_dequeue(&msgreq);
					msg->lm_xid = nfs_lockxid_get();
					nfs_lockdmsg_enqueue(&msgreq);
					msgreq.lmr_saved_errno = error;
					msgreq.lmr_errno = 0;
					msgreq.lmr_answered = 0;
					/* reset timeout */
					timeo = 2*hz;
					/* send cancel request */
					continue;
				}
				break;
			}

			/*
			 * If the mount is hung and we've requested not to hang
			 * on remote filesystems, then bail now.
			 */
			if ((p != NULL) && ((p->p_flag & P_NOREMOTEHANG) != 0) &&
			    ((nmp->nm_state & (NFSSTA_TIMEO|NFSSTA_LOCKTIMEO)) != 0)) {
				if (fl->l_type == F_UNLCK)
					printf("nfs_dolock: aborting unlock request "
					    "due to timeout (noremotehang)\n");
				error = EIO;
				break;
			}
			/* warn if we're not getting any response */
			microuptime(&now);
			if ((msgreq.lmr_errno != EINPROGRESS) &&
			    (nmp->nm_tprintf_initial_delay != 0) &&
			    ((lastmsg + nmp->nm_tprintf_delay) < now.tv_sec)) {
				lastmsg = now.tv_sec;
				nfs_down(NULL, nmp, p, "lockd not responding",
					0, NFSSTA_LOCKTIMEO);
				wentdown = 1;
			}
			if (msgreq.lmr_errno == EINPROGRESS) {
				/*
				 * We've got a blocked lock request that we are
				 * going to retry.  First, we'll want to try to
				 * send a cancel for the previous request.
				 *
				 * Clear errno so if we don't get a response
				 * to the resend we'll call nfs_down().
				 * Also reset timeout because we'll expect a
				 * quick response to the cancel/resend (even if
				 * it is NLM_BLOCKED).
				 */
				msg->lm_flags |= LOCKD_MSG_CANCEL;
				nfs_lockdmsg_dequeue(&msgreq);
				msg->lm_xid = nfs_lockxid_get();
				nfs_lockdmsg_enqueue(&msgreq);
				msgreq.lmr_saved_errno = msgreq.lmr_errno;
				msgreq.lmr_errno = 0;
				msgreq.lmr_answered = 0;
				timeo = 2*hz;
				/* send cancel then resend request */
				continue;
			}
			/*
			 * We timed out, so we will rewrite the request
			 * to the fifo, but only if it isn't already full.
			 */
			ioflg |= IO_NDELAY;
			timeo *= 2;
			if (timeo > 60*hz)
				timeo = 60*hz;
			/* resend request */
			continue;
		}

		if (wentdown) {
			/* we got a reponse, so the server's lockd is OK */
			nfs_up(NULL, VFSTONFS(vp->v_mount), p, "lockd alive again",
				NFSSTA_LOCKTIMEO);
			wentdown = 0;
		}

		if (msgreq.lmr_errno == EINPROGRESS) {
			/* got NLM_BLOCKED response */
			/* need to wait for NLM_GRANTED */
			timeo = 60*hz;
			msgreq.lmr_answered = 0;
			goto wait_for_granted;
		}

		if ((msg->lm_flags & LOCKD_MSG_CANCEL) &&
		    (msgreq.lmr_saved_errno == EINPROGRESS)) {
			/*
			 * We just got a successful reply to the
			 * cancel of the previous blocked lock request.
			 * Now, go ahead and resend the request.
			 */
			msg->lm_flags &= ~LOCKD_MSG_CANCEL;
			nfs_lockdmsg_dequeue(&msgreq);
			msg->lm_xid = nfs_lockxid_get();
			nfs_lockdmsg_enqueue(&msgreq);
			msgreq.lmr_saved_errno = 0;
			msgreq.lmr_errno = 0;
			msgreq.lmr_answered = 0;
			timeo = 2*hz;
			/* resend request */
			continue;
		}

		if ((msg->lm_flags & LOCKD_MSG_TEST) && msgreq.lmr_errno == 0) {
			if (msg->lm_fl.l_type != F_UNLCK) {
				fl->l_type = msg->lm_fl.l_type;
				fl->l_pid = msg->lm_fl.l_pid;
				fl->l_start = msg->lm_fl.l_start;
				fl->l_len = msg->lm_fl.l_len;
				fl->l_whence = SEEK_SET;
			} else {
				fl->l_type = F_UNLCK;
			}
		}

		/*
		 * If the blocked lock request was cancelled.
		 * Restore the error condition from when we
		 * originally bailed on the request.
		 */
		if (msg->lm_flags & LOCKD_MSG_CANCEL) {
			msg->lm_flags &= ~LOCKD_MSG_CANCEL;
			error = msgreq.lmr_saved_errno;
		} else
			error = msgreq.lmr_errno;

		if (!error) {
			/* record that NFS file locking has worked on this mount */
			nmp = VFSTONFS(vp->v_mount);
			if (nmp && !(nmp->nm_state & NFSSTA_LOCKSWORK))
				nmp->nm_state |= NFSSTA_LOCKSWORK;
			/*
			 * If we successfully acquired a lock, make sure this pid
			 * is in the nfs_lock_pid hash table so we know we can't
			 * short-circuit unlock requests.
			 */
			if ((lockpidcheck == ENOENT) &&
			    ((ap->a_op == F_SETLK) || (ap->a_op == F_SETLKW)))
				nfs_lock_pid_check(p, 1, vp);
	
		}
		break;
	}
  
	nfs_lockdmsg_dequeue(&msgreq);

	error1 = vn_close(wvp, FWRITE, kernproc->p_ucred, p);
	/* prefer any previous 'error' to our vn_close 'error1'. */
	return (error != 0 ? error : error1);
}

/*
 * nfslockdans --
 *      NFS advisory byte-level locks answer from the lock daemon.
 */
int
nfslockdans(struct proc *p, struct lockd_ans *ansp)
{
	LOCKD_MSG_REQUEST *msgreq;
	int error;

	/*
	 * Let root, or someone who once was root (lockd generally
	 * switches to the daemon uid once it is done setting up) make
	 * this call.
	 *
	 * XXX This authorization check is probably not right.
	 */
	if ((error = suser(p->p_ucred, &p->p_acflag)) != 0 &&
	    p->p_cred->p_svuid != 0)
		return (error);

	/* the version should match, or we're out of sync */
	if (ansp->la_version != LOCKD_ANS_VERSION)
		return (EINVAL);

	/* try to find the lockd message by transaction id (cookie) */
	msgreq = nfs_lockdmsg_find_by_xid(ansp->la_xid);
	if (ansp->la_flags & LOCKD_ANS_GRANTED) {
		/*
		 * We can't depend on the granted message having our cookie,
		 * so we check the answer against the lockd message found.
		 * If no message was found or it doesn't match the answer,
		 * we look for the lockd message by the answer's lock info.
		 */
		if (!msgreq || nfs_lockdmsg_compare_to_answer(msgreq, ansp))
			msgreq = nfs_lockdmsg_find_by_answer(ansp);
		/*
		 * We need to make sure this request isn't being cancelled
		 * If it is, we don't want to accept the granted message.
		 */
		if (msgreq && (msgreq->lmr_msg.lm_flags & LOCKD_MSG_CANCEL))
			msgreq = NULL;
	}
	if (!msgreq)
		return (EPIPE);

	msgreq->lmr_errno = ansp->la_errno;
	if ((msgreq->lmr_msg.lm_flags & LOCKD_MSG_TEST) && msgreq->lmr_errno == 0) {
		if (ansp->la_flags & LOCKD_ANS_LOCK_INFO) {
			if (ansp->la_flags & LOCKD_ANS_LOCK_EXCL)
				msgreq->lmr_msg.lm_fl.l_type = F_WRLCK;
			else
				msgreq->lmr_msg.lm_fl.l_type = F_RDLCK;
			msgreq->lmr_msg.lm_fl.l_pid = ansp->la_pid;
			msgreq->lmr_msg.lm_fl.l_start = ansp->la_start;
			msgreq->lmr_msg.lm_fl.l_len = ansp->la_len;
		} else {
			msgreq->lmr_msg.lm_fl.l_type = F_UNLCK;
		}
	}

	msgreq->lmr_answered = 1;
	(void)wakeup((void *)msgreq);

	return (0);
}

/*
 * nfslockdfd --
 *      NFS advisory byte-level locks: fifo file# from the lock daemon.
 */
int
nfslockdfd(struct proc *p, int fd)
{
	int error;
	struct file *fp, *ofp;

	error = suser(p->p_ucred, &p->p_acflag);
	if (error)
		return (error);
	if (fd < 0) {
		fp = 0;
	} else {
		error = getvnode(p, fd, &fp);
		if (error)
			return (error);
		(void)fref(fp);
	}
	ofp = nfslockdfp;
	nfslockdfp = fp;
	if (ofp)
		(void)frele(ofp);
	nfslockdpid = nfslockdfp ? p->p_pid : 0;
	(void)wakeup((void *)&nfslockdfp);
	return (0);
}

/*
 * nfslockdwait --
 *      lock daemon waiting for lock request
 */
int
nfslockdwait(struct proc *p)
{
	int error;
	struct file *fp, *ofp;

	if (p->p_pid != nfslockdpid) {
		error = suser(p->p_ucred, &p->p_acflag);
		if (error)
			return (error);
	}
	if (nfslockdwaiting)
		return (EBUSY);
	if (nfslockdfifowritten) {
		nfslockdfifowritten = 0;
		return (0);
	}

	nfslockdwaiting = 1;
	tsleep((void *)&nfslockdwaiting, PCATCH | PUSER, "lockd", 0);
	nfslockdwaiting = 0;

	return (0);
}
