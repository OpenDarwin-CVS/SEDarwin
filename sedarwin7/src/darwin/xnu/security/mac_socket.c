
/*-
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001, 2002, 2003, 2004 Networks Associates Technology, Inc.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
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
 *
 */

#define MAC /* XXX */

#ifdef MAC
/* 
 * Note: When manipulating socket labels, hold the NETWORK_FUNNEL.
 * These functions are called holding the network funnel:
 *      mac_init_socket()
 *      mac_destroy_socket()
 *      mac_create_socket()
 *      mac_create_mbuf_from_socket()
 *      mac_create_socket_from_socket()
 *      mac_internalize_socket_label()
 *      mac_externalize_socket_label()
 *      mac_relabel_socket()
 *      mac_set_socket_peer_from_socket()
 *      mac_copy_socket_label()
 *      mac_check_socket_accept()
 *      mac_check_socket_bind()
 *      mac_check_socket_connect()
 *      mac_check_socket_listen()
 *      mac_check_socket_receive()
 *      mac_check_socket_relabel()
 *      mac_check_socket_send()
 *      mac_check_socket_stat()
 *      mac_check_socket_deliver()
 */

#include <security/mac_internal.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <machine/machine_routines.h>
#include <kern/kalloc.h>

extern int mac_enforce_socket;

#ifdef MAC_SOCKET

void 
mac_socket_label_free(struct label *l) 
{	
	MAC_PERFORM(destroy_socket_label, l);
	mac_labelzone_free(l);
}

static void
mac_socket_peer_label_free(struct label *l) 
{
	MAC_PERFORM(destroy_socket_peer_label, l);
	mac_labelzone_free(l);
}

struct label *
mac_socket_label_alloc(int waitok) 
{	
	int error;
	struct label *ret = mac_labelzone_alloc(waitok);
	
	if (ret == NULL)
		return(NULL);

	MAC_CHECK(init_socket_label, ret, waitok);
	if (error) {
		mac_socket_label_free(ret);
		ret = NULL;
	}
	return (ret);
}

struct label *
mac_socket_peer_label_alloc(int waitok) 
{		
	int error;
	struct label *ret = mac_labelzone_alloc(waitok);
	
	if (ret == NULL)
		return(NULL);

	MAC_CHECK(init_socket_peer_label, ret, waitok);
	if (error) {
		mac_socket_peer_label_free(ret);
		ret = NULL;
	}
	return (ret);
}

int
mac_externalize_socket_label(struct label *l, char *e, char *out, 
    size_t olen, int flags) 
{
	int error;

	if (e[0] == '*') {
		int count;
		MAC_EXTERNALIZE_REGISTERED_LABELS(socket, l, out, olen, count);
	} else
		MAC_EXTERNALIZE_LIST(socket, l, e, out, olen);

	return (error);
}

int
mac_internalize_socket_label(struct label *label, char *string) 
{
	int error;

	MAC_INTERNALIZE_LIST(socket, label, string);	
	return (error);
}

int
mac_socket_label_set(struct ucred *cred, struct socket *so, struct label *l) 
{
	int error;

	error = mac_check_socket_relabel(cred, so, l);
	if (error != 0)
		return (error);
	mac_relabel_socket(cred, so, l);	
	return (0);
}

void
mac_relabel_socket(struct ucred *cred, struct socket *so, struct label *l) 
{
	MAC_PERFORM(relabel_socket, cred, so, so->so_label, l);
}	

void
mac_copy_socket_label(struct label *src, struct label *dest)
{	
	MAC_PERFORM(copy_socket_label, src, dest);
}

int
mac_init_socket(struct socket *so, int waitok) 
{
	so->so_label = mac_socket_label_alloc(waitok);
	if (so->so_label == NULL) 
		return (ENOMEM); 

	so->so_peerlabel = mac_socket_peer_label_alloc(waitok);
	if (so->so_peerlabel == NULL) {
		mac_socket_label_free(so->so_label);
		so->so_label = NULL;
		return (ENOMEM);
	}
	return (0);
}

void
mac_destroy_socket(struct socket *so) 
{
	mac_socket_label_free(so->so_label);
	mac_socket_peer_label_free(so->so_peerlabel);

	so->so_label = NULL;
	so->so_peerlabel = NULL;
}

void
mac_create_socket(struct ucred *cred, struct socket *so) 
{
	MAC_PERFORM(create_socket, cred, so, so->so_label);
}

void 
mac_create_socket_from_socket(struct socket *oldsocket, 
    struct socket *newsocket) 
{
	MAC_PERFORM(create_socket_from_socket, oldsocket, oldsocket->so_label,
	    newsocket, newsocket->so_label);
}

void
mac_set_socket_peer_from_socket(struct socket *oldsocket,
    struct socket *newsocket) 
{
	MAC_PERFORM(set_socket_peer_from_socket, oldsocket,
	    oldsocket->so_label, newsocket, newsocket->so_peerlabel);
}

#if 0
int
mac_getsockopt_label(struct ucred *cred, struct socket *so, struct mac 
    *extmac)
{
	char *buffer, *elements;
	struct label *intlabel;
	int error;
	size_t len;

	KASSERT(thread_funnel_get() != network_flock,
	    "mac_getsockopt_label: not holding the network funnel!");

	error = mac_check_structmac_consistent(extmac);
	if (error)
		return (error);

	MALLOC(elements, char *, extmac->m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(extmac->m_string, elements, extmac->m_buflen, &len);
	if (error) {
		FREE(elements, M_MACTEMP);
		return (error);
	}

	MALLOC(buffer, char *, extmac->m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
	intlabel = mac_socket_label_alloc(M_WAITOK);
	mac_copy_socket_label(so->so_label, intlabel);
	error = mac_externalize_socket_label(intlabel, elements, buffer, 
	    extmac->m_buflen, NULL);
	mac_socket_label_free(intlabel);
	if (error == 0)
		error = copyout(buffer, extmac->m_string, strlen(buffer) + 1);

	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);

	return (error);
}
#endif
	
/* 
 * XXX: This fcn does not make sense unless the peer is connected, and
 * only through the loopback interface.  Otherwise, the peer label
 * will be a useless, possibly dangerous value, because it will be 
 * allocated, but uninitialized.  Perhaps we should initialize the peer
 * label to a special value that policies can easily check against.  One
 * more caveat: the peerlabel reflects the peer that sent the most recent
 * packet, not necessarily the peer that sent the data the application will
 * receive next.
 */
int
mac_getsockopt_peerlabel(struct ucred *cred, struct socket *so, struct
    mac *extmac) 
{
	char *elements, *buffer;
	struct label *intlabel;
	int error;
	size_t len;

	error = mac_check_structmac_consistent(extmac);
	if (error) {
		printf("mac_getsockopt_peerlabel: structmac check failed (%d)\n",
		    error);
		return (error);
	}

	MALLOC(elements, char *, extmac->m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(extmac->m_string, elements, extmac->m_buflen, &len);
	if (error) {
		printf("mac_getsockopt_peerlabel: copyinstr (%d)\n", error);
		FREE(elements, M_MACTEMP);
		return (error);
	}

	MALLOC(buffer, char *, extmac->m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
	intlabel = mac_socket_label_alloc(M_WAITOK);
	mac_copy_socket_label(so->so_peerlabel, intlabel);
	error = mac_externalize_socket_label(intlabel, elements, buffer, 
	    extmac->m_buflen, 0);
	mac_socket_label_free(intlabel);
	if (error == 0)
		error = copyout(buffer, extmac->m_string, strlen(buffer) + 1);
	else
		printf("mac_getsockopt_peerlabel: externalize failed! (%d)\n", 
		    error);

	FREE(buffer, M_MACTEMP);
	FREE(elements, M_MACTEMP);

	return (error);
}

int
mac_check_socket_accept(struct ucred *cred, struct socket *so,
    struct sockaddr *addr)
{
	int error;
	
	if (!mac_enforce_socket)
		return (0);
	MAC_CHECK(check_socket_accept, cred, so, so->so_label, addr);
	return (error);
}

int
mac_check_socket_bind(struct ucred *cred, struct socket *socket,
    struct sockaddr *addr) 
{	
	int error;
	
	if (!mac_enforce_socket)
		return (0);	
	MAC_CHECK(check_socket_bind, cred, socket, socket->so_label, addr);
	return (error);
}

int 
mac_check_socket_connect(struct ucred *cred, struct socket *so,
    struct sockaddr *addr) 
{	
	int error;

	if (!mac_enforce_socket)
		return (0);
	MAC_CHECK(check_socket_connect, cred, so, so->so_label, addr);
	return(error);
}

int 
mac_check_socket_listen(struct ucred *cred, struct socket *so) 
{	
	int error;

	if (!mac_enforce_socket)
		return (0);
	MAC_CHECK(check_socket_listen, cred, so, so->so_label);
	return (error);
}

int 
mac_check_socket_poll(struct ucred *cred, struct socket *so) 
{	
	int error;

	if (!mac_enforce_socket)
		return (0);
	MAC_CHECK(check_socket_poll, cred, so, so->so_label);
	return (error);
}

int
mac_check_socket_receive(struct ucred *cred, struct socket *so) 
{
	int error;

	if (!mac_enforce_socket)
		return (0);
	MAC_CHECK(check_socket_receive, cred, so, so->so_label);
	return(error);
}

int
mac_check_socket_relabel(struct ucred *cred, struct socket *so,
	struct label *l) 
{	
	int error;

	if (!mac_enforce_socket)
		return (0);
	MAC_CHECK(check_socket_relabel, cred, so, so->so_label, l);
	return (error);
}

int
mac_check_socket_select(struct ucred *cred, struct socket *so)
{
	int error;

	if (!mac_enforce_socket)
		return (0);
	MAC_CHECK(check_socket_select, cred, so, so->so_label);
	return (error);
}

int
mac_check_socket_send(struct ucred *cred, struct socket *so) 
{
	int error;

	if (!mac_enforce_socket)
		return (0);
	MAC_CHECK(check_socket_send, cred, so, so->so_label);
	return (error);
}

int
mac_check_socket_stat(struct ucred *cred, struct socket *so) 
{
	int error;

	if (!mac_enforce_socket)
		return (0);	
	MAC_CHECK(check_socket_stat, cred, so, so->so_label);
	return (error);
}

#else


struct label *
mac_socket_label_alloc(int flags)
{
	return (NULL);
}

void
mac_socket_label_free(struct label *l) 
{
}

int
mac_externalize_socket_label(struct label *l, char *e, char *out, 
    size_t olen, int flags) 
{
	return (0);
}

int 
mac_internalize_socket_label(struct label *l, char *string) 
{
	return (0);
}

int
mac_init_socket(struct socket *so, int waitok) 
{
	return (0);
}

void
mac_destroy_socket(struct socket *so) 
{
}

void 
mac_create_socket(struct ucred *cred, struct socket *so) 
{
}

void 
mac_create_socket_from_socket(struct socket *oldsocket, 
    struct socket *newsocket) 
{
}

void 
mac_set_socket_peer_from_socket(struct socket *oldsocket,
    struct socket *newsocket) 
{ 
}

int
mac_getsockopt_label(struct ucred *cred, struct socket *so, struct
    mac *extmac) 
{
	return (0);
}

int
mac_getsockopt_peerlabel(struct ucred *cred, struct socket *so, struct
    mac *extmac) 
{
	return (0);
}

void
mac_copy_socket_label(struct label *src, struct label *dest)
{
}

int
mac_socket_label_set(struct ucred *cred, struct socket *so, struct label *l)
{
	return (0);
}

int
mac_check_socket_accept(struct ucred *cred, struct socket *so,
    struct sockaddr *addr)
{
	return (0);
}

int 
mac_check_socket_bind(struct ucred *cred, struct socket *so,
    struct sockaddr *addr) 
{
	return (0);
}
		
int	
mac_check_socket_connect(struct ucred *cred, struct socket *so,
    struct sockaddr *addr) 
{
	return (0);
}

int	
mac_check_socket_listen(struct ucred *cred, struct socket *so) 
{
	return (0);
}

int
mac_check_socket_poll(struct ucred *cred, struct socket *so)
{
	return (0);
}

int
mac_check_socket_receive(struct ucred *cred, struct socket *so) 
{
	return (0);
}

int
mac_check_socket_select(struct ucred *cred, struct socket *so)
{
	return (0);
}

int	
mac_check_socket_send(struct ucred *cred, struct socket *so) 
{
	return (0);
}

int
mac_check_socket_stat(struct ucred *cred, struct socket *so) 
{
	return (0);
}

#endif   /* MAC_SOCKET */

#ifdef MAC_NETWORK

/* This is the label given to mbuf pkthdr's with unknown origin */
static struct label     *unknown_source;
/* This label is assigned to packets originating from the TCP itself */
static struct label     *tcp_label;
/* This is the label assigned to mbufs when mac_init_mbuf_socket() fails */
static struct label     *failed_label;

/* 
 * This list holds the list of live labels.  Used for label GC.  
 * Note: it's only accessed under a call to mac_init_mbuf_socket(),
 * which is synchronized with the network funnel.
 *
 * In this version, we use the label struct to implement the lists.
 * label->reserved1 is the mbuf the label belongs to (used for GC)
 * label->reserved2 is a pointer to the next label
 * label->reserved3 is a pointer to the previous label
 */

static struct label *deferred_head = NULL;
static struct label *live_list_head = NULL;

/* We need to remove these counters before the release */

static int deferred_mbufs;
SYSCTL_INT(_security_mac, OID_AUTO, deferred_mbufs, CTLFLAG_RD,
	&deferred_mbufs, 0, "mbufs put on the deferred list");

static int disposed_mbufs;
SYSCTL_INT(_security_mac, OID_AUTO, disposed_mbufs, CTLFLAG_RD,
	&disposed_mbufs, 0, "mbufs deleted from the deferred list");

static int live_list_size;
SYSCTL_INT(_security_mac, OID_AUTO, live_list_size, CTLFLAG_RD,
	&live_list_size, 0, "size of the GC;s live list");

static int preemption_off;
SYSCTL_INT(_security_mac, OID_AUTO, preemption_off, CTLFLAG_RD,
	&preemption_off, 0, "preemption is off during destroy op");

static int network_funnel_off;
SYSCTL_INT(_security_mac, OID_AUTO, network_funnel_off, CTLFLAG_RD,
	&network_funnel_off, 0, "network funnel isn't held on call to destroy");

static int failed_label_count;
SYSCTL_INT(_security_mac, OID_AUTO, failed_label_count, CTLFLAG_RD,
	&failed_label_count, 0, "number of mbufs assigned the failed_label");

static int gcd_mbufs;
SYSCTL_INT(_security_mac, OID_AUTO, gcd_mbufs, CTLFLAG_RD,
	&gcd_mbufs, 0, "the number of GC'd mbufs");

static int initpreemptionoff;
SYSCTL_INT(_security_mac, OID_AUTO, initpreemptionoff, CTLFLAG_RD,
	&initpreemptionoff, 0, 
	"the number of times mac_init_mbuf_socket is exec with preemption off");

/* Determines the frequency of GC scans */
#define __MAC_TIMING_INTERVAL 1000

inline struct label *
mac_get_mbuf_unknown_source(void)
{

	KASSERT((unknown_source != NULL),
	    "mac_get_mbuf_unknown_source: called before label is initialized");
	return (unknown_source);
}

inline struct label *
mac_get_tcp_label(void)
{

	KASSERT((tcp_label != NULL),
	    "mac_get_tcp_label: called before label is initialized");
	return (tcp_label);
}

inline struct label *
mac_get_mbuf_failed_label(void)
{
	return (failed_label);
}

static void
mac_init_tcp_label(void)
{

	tcp_label = mac_labelzone_alloc(MAC_WAITOK);
	if (tcp_label == NULL)
		panic("mac_init_tcp_label(): alloc failed\n");
	MAC_PERFORM(init_tcp_label, tcp_label);
}

static void
mac_init_mbuf_unknown_source_label(void) 
{

	unknown_source = mac_labelzone_alloc(MAC_WAITOK);
	if (unknown_source == NULL) 
		panic("mac_init_mbuf_unknown_source_label(): alloc failed\n");
	MAC_PERFORM(init_mbuf_unknown_source_label, unknown_source);
}

static void
mac_init_mbuf_failed_label(void)
{
	failed_label = mac_labelzone_alloc(MAC_WAITOK);
	if (unknown_source == NULL)
		panic("mac_init_mbuf_failed_label(): alloc failed\n");
	MAC_PERFORM(init_mbuf_failed_label, failed_label);
}

void
mac_init_mbuf_labeler(void)
{

	mac_init_mbuf_unknown_source_label();
	mac_init_tcp_label();
	mac_init_mbuf_failed_label();
	sysctl_register_oid(&sysctl__security_mac_deferred_mbufs);
	sysctl_register_oid(&sysctl__security_mac_live_list_size);
	sysctl_register_oid(&sysctl__security_mac_network_funnel_off);
	sysctl_register_oid(&sysctl__security_mac_preemption_off);
	sysctl_register_oid(&sysctl__security_mac_gcd_mbufs);
	sysctl_register_oid(&sysctl__security_mac_failed_label_count);
	sysctl_register_oid(&sysctl__security_mac_initpreemptionoff);
}

static inline int
check_label(struct label *l)
{
	/* 
	 * The label should have been destroyed if any of these happened:
	 *   - The mbuf has been freed
	 *   - The mbuf is no longer a pkthdr
	 *   - The mbuf is a pkthdr, but it has a different label
	 */

	struct mbuf *m;
	
	if (l == NULL)
		return (0);
	
	m = (struct mbuf *) l->reserved1;
	if (m->m_type == MT_FREE || 
	    !(m->m_flags & M_PKTHDR) ||
	    ((m->m_flags & M_PKTHDR) && m->m_pkthdr.so_label != l))
		return (1);
	else
		return (0);
}

/*
 * do_mbuf_gc() scans the list of live labels to verify that
 * the mbuf each is attached to is also live.  It calls a destroy op
 * on live labels with dead mbufs.
 */
static void
do_mbuf_gc()
{
	struct label *l, *l2, *l3;
	int error = 0;
	
	l = NULL;
	l2 = live_list_head;
	while (l2 != NULL)
		if (check_label(l2)) {
			l3 = l2->reserved2;
			MAC_PERFORM_NOBLOCK(destroy_mbuf_socket_label, l2);
			if (error)
				return;
			mac_labelzone_free(l2);
			live_list_size--;
			gcd_mbufs++;
			if (l == NULL)
				live_list_head = l3;
			else
				l->reserved2 = l3;
			l2 = l3;
		}
		else {
			l = l2;
			l2 = l2->reserved2;
		}
}

int
mac_init_mbuf_socket(struct mbuf *m)
{
	static int timer = 0;
	int preemption_enabled = 0, error = 0, check_failed = 0;
	struct label *l, *l2;

	if (get_preemption_level() == 0)
		preemption_enabled = 1;
	else
		initpreemptionoff++;

	if (preemption_enabled)
		m->m_pkthdr.so_label = mac_labelzone_alloc(MAC_WAITOK);
	else
		m->m_pkthdr.so_label = mac_labelzone_alloc(MAC_NOWAIT);
	if (m->m_pkthdr.so_label == NULL) {
		printf("WARNING: mac_init_mbuf_socket(): label alloc failed!\n");
		m->m_pkthdr.so_label = failed_label;
		failed_label_count++;
		return (ENOMEM);
	}

	if (preemption_enabled)
		MAC_CHECK(init_mbuf_socket_label, m->m_pkthdr.so_label, 
		    MAC_WAITOK);
	else
		MAC_CHECK_NOBLOCK(init_mbuf_socket_label, 
		    m->m_pkthdr.so_label, MAC_NOWAIT);
	if (check_failed || error) {
		mac_labelzone_free(m->m_pkthdr.so_label);
		m->m_pkthdr.so_label = failed_label;
		failed_label_count++;
		if (check_failed)
			return (EWOULDBLOCK);
		return (error);
	}

	l = m->m_pkthdr.so_label;
	l->reserved1 = m;

	if (preemption_enabled)
		MBUF_LOCK();
	if ((++timer % __MAC_TIMING_INTERVAL) == 0) {
		timer = 0;
		do_mbuf_gc();
	}
	if (live_list_head != NULL)
		live_list_head->reserved3 = l;
	l->reserved2 = live_list_head;
	l->reserved3 = NULL;
	live_list_head = l;
	live_list_size++;

	l = deferred_head;
	while (l != NULL) {
		l2 = l->reserved2;
		MAC_PERFORM_NOBLOCK(destroy_mbuf_socket_label, l);
		if (error < 0) {
			deferred_head = l;
			goto out;
		}
		mac_labelzone_free(l);
		disposed_mbufs++;
		l = l2;
	}
	deferred_head = NULL;
	
out:	if (preemption_enabled)
		MBUF_UNLOCK(); 
	return (0);
}

void
mac_destroy_mbuf_socket(struct mbuf *m)
{
	int locked = 0;
	struct label *l, *next, *prev;

	if (m->m_pkthdr.so_label == unknown_source ||
	    m->m_pkthdr.so_label == tcp_label ||
	    m->m_pkthdr.so_label == failed_label)
		return;

	if (thread_funnel_get() != network_flock)
		network_funnel_off++;
	if (get_preemption_level() == 0) {
		locked = 1;
		MBUF_LOCK();
		preemption_off++;
	}

	l = m->m_pkthdr.so_label;
	next = l->reserved2;
	prev = l->reserved3;
	if (l == live_list_head)
		live_list_head = next;
	if (prev != NULL)
		prev->reserved2 = next;
	if (next != NULL)
		next->reserved3 = prev;
	live_list_size--;
	l->reserved2 = deferred_head;
	deferred_head = l;
	m->m_pkthdr.so_label = unknown_source;
	deferred_mbufs++;

	if (locked)
		MBUF_UNLOCK();
} 

void
mac_copy_mbuf_socket_label(struct label *from, struct label *to) 
{

	MAC_PERFORM(copy_mbuf_socket_label, from, to);
}

void
mac_set_socket_peer_from_mbuf(struct mbuf *m, struct socket *so) 
{

	if (m->m_pkthdr.so_label == tcp_label)
		return;
	MAC_PERFORM(set_socket_peer_from_mbuf, m, m->m_pkthdr.so_label, 
	     so, so->so_peerlabel);
}

void
mac_create_mbuf_from_socket(struct socket *so, struct mbuf *m)
{

	MAC_PERFORM(create_mbuf_from_socket, so, so->so_label, m, 
	     m->m_pkthdr.so_label);
}

int 
mac_check_socket_deliver(struct socket *so, struct mbuf *m)
{
	int error;

	if (!mac_enforce_socket)
		return (0);
	MAC_CHECK(check_socket_deliver, so, so->so_label, m, m->m_pkthdr.so_label);
	return (error);
}

#else

void
mac_init_mbuf_labeler(void)
{
}

int
mac_init_mbuf_socket(struct mbuf *m)
{
}

void
mac_destroy_mbuf_socket(struct mbuf *m)
{
}

void
mac_set_socket_peer_from_mbuf(struct mbuf *m, struct socket *so)
{
}

inline struct label *
mac_get_tcp_label(void)
{
	return (NULL);
}

inline struct label *
mac_get_mbuf_unknown_source(void)
{
	return (NULL);
}

inline struct label *
mac_get_mbuf_failed_label(void)
{
	return (NULL);
}

void
mac_copy_mbuf_socket_label(struct label *from, struct label *to)
{
}

void
mac_create_mbuf_from_socket(struct socket *so, struct mbuf *m)
{
}

int
mac_check_socket_deliver(struct socket *so, struct mbuf *m)
{

	return (0);
}

#endif  /* !MAC_NETWORK */
#endif  /* MAC */
