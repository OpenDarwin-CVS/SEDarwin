/*
 * Copyright (c) 1985, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static const char sccsid[] = "@(#)res_init.c	8.1 (Berkeley) 6/7/93";
static const char rcsid[] = "$Id$";
#endif /* LIBC_SCCS and not lint */

#ifndef __APPLE__
#include "port_before.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#ifdef __APPLE__
#include <fcntl.h>
#endif

#ifndef __APPLE__
#include "port_after.h"
#endif

/* ensure that sockaddr_in6 and IN6ADDR_ANY_INIT are declared / defined */
#include <resolv.h>

#include "res_private.h"

/* Options.  Should all be left alone. */
#define RESOLVSORT
#define DEBUG

static void res_setoptions __P((res_state, const char *, const char *));

#ifdef RESOLVSORT
static const char sort_mask[] = "/&";
#define ISSORTMASK(ch) (strchr(sort_mask, ch) != NULL)
static u_int32_t net_mask __P((struct in_addr));
#endif

#if !defined(isascii)	/* XXX - could be a function */
# define isascii(c) (!(c & 0200))
#endif

/*
 * Resolver state default settings.
 */

/*
 * Set up default settings.  If the configuration file exist, the values
 * there will have precedence.  Otherwise, the server address is set to
 * INADDR_ANY and the default domain name comes from the gethostname().
 *
 * An interrim version of this code (BIND 4.9, pre-4.4BSD) used 127.0.0.1
 * rather than INADDR_ANY ("0.0.0.0") as the default name server address
 * since it was noted that INADDR_ANY actually meant ``the first interface
 * you "ifconfig"'d at boot time'' and if this was a SLIP or PPP interface,
 * it had to be "up" in order for you to reach your own name server.  It
 * was later decided that since the recommended practice is to always 
 * install local static routes through 127.0.0.1 for all your network
 * interfaces, that we could solve this problem without a code change.
 *
 * The configuration file should always be used, since it is the only way
 * to specify a default domain.  If you are running a server on your local
 * machine, you should say "nameserver 0.0.0.0" or "nameserver 127.0.0.1"
 * in the configuration file.
 *
 * Return 0 if completes successfully, -1 on error
 */
int
res_ninit(res_state statp) {
	extern int __res_vinit(res_state, int);

	return (__res_vinit(statp, 0));
}

int
res_vinit_from_file(res_state statp, int preinit, char *resconf_file)
{
	register FILE *fp;
	register char *cp, **pp;
	register int n;
	char buf[BUFSIZ];
	int nserv = 0;    /* number of nameserver records read from file */
	int haveenv = 0;
	int havesearch = 0;
	unsigned short port; /* HOST BYTE ORDER */
	unsigned int i, totaltimeout;
#ifdef RESOLVSORT
	int nsort = 0;
	char *net;
#endif
	int dots;

	port = NS_DEFAULTPORT;
	totaltimeout = 0;

	if (!preinit)
	{
		statp->retrans = RES_TIMEOUT;
		statp->retry = RES_DFLRETRY;
		statp->options = RES_DEFAULT;
		statp->id = res_randomid();
	}

	if ((statp->options & RES_INIT) != 0) res_ndestroy(statp);

#ifdef USELOOPBACK
	statp->nsaddr.sin_addr = inet_makeaddr(IN_LOOPBACKNET, 1);
#else
	statp->nsaddr.sin_addr.s_addr = INADDR_ANY;
#endif
	statp->nsaddr.sin_family = AF_INET;
	statp->nsaddr.sin_port = htons(NS_DEFAULTPORT);
#ifdef HAVE_SA_LEN
	statp->nsaddr.sin_len = sizeof(struct sockaddr_in);
#endif
	statp->nscount = 1;
	statp->ndots = 1;
	statp->pfcode = 0;
	statp->_vcsock = -1;
	statp->_flags = 0;
	statp->qhook = NULL;
	statp->rhook = NULL;
	statp->_u._ext.nscount = 0;
	statp->_u._ext.ext = malloc(sizeof(*statp->_u._ext.ext));
	statp->_u._ext.ext->search_order = 0;

	if (statp->_u._ext.ext != NULL)
	{
		memset(statp->_u._ext.ext, 0, sizeof(*statp->_u._ext.ext));
		statp->_u._ext.ext->nsaddrs[0].sin = statp->nsaddr;
		strcpy(statp->_u._ext.ext->nsuffix, "ip6.arpa");
		strcpy(statp->_u._ext.ext->nsuffix2, "ip6.int");
		strcpy(statp->_u._ext.ext->bsuffix, "ip6.arpa");
	}

#ifdef RESOLVSORT
	statp->nsort = 0;
#endif

	/* Allow user to override the local domain definition */
	cp = getenv("LOCALDOMAIN");
	if ((cp != NULL) && ((resconf_file == NULL) || (!strcmp(resconf_file, _PATH_RESCONF))))
	{
		(void)strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
		statp->defdname[sizeof(statp->defdname) - 1] = '\0';
		haveenv++;

		/*
		 * Set search list to be blank-separated strings
		 * from rest of env value.  Permits users of LOCALDOMAIN
		 * to still have a search list, and anyone to set the
		 * one that they want to use as an individual (even more
		 * important now that the rfc1535 stuff restricts searches)
		 */
		cp = statp->defdname;
		pp = statp->dnsrch;
		*pp++ = cp;
		for (n = 0; *cp && pp < statp->dnsrch + MAXDNSRCH; cp++)
		{
			if (*cp == '\n') break;
			else if (*cp == ' ' || *cp == '\t')
			{
				*cp = 0;
				n = 1;
			}
			else if (n != 0)
			{
				*pp++ = cp;
				n = 0;
				havesearch = 1;
			}
		}

		/* null terminate last domain if there are excess */
		while ((*cp != '\0') && (*cp != ' ') && (*cp != '\t') && (*cp != '\n')) cp++;
		*cp = '\0';
		*pp++ = 0;
	}

#define	MATCH(line, name) \
	(!strncmp(line, name, sizeof(name) - 1) && \
	(line[sizeof(name) - 1] == ' ' || \
	 line[sizeof(name) - 1] == '\t'))

	if (resconf_file == NULL) resconf_file = _PATH_RESCONF;

	if ((fp = fopen(resconf_file, "r")) != NULL)
	{
		/* look for port number */
		while (fgets(buf, sizeof(buf), fp) != NULL)
		{
			/* skip comments */
			if (*buf == ';' || *buf == '#') continue;

			/* read default domain name */
			if (MATCH(buf, "port"))
			{
				cp = buf + sizeof("port") - 1;
				while (*cp == ' ' || *cp == '\t') cp++;
				if ((*cp == '\0') || (*cp == '\n')) continue;
				port = atoi(cp);
				break;
			}
		}
		fclose(fp);
	}

	if ((fp = fopen(resconf_file, "r")) != NULL)
	{
	    /* read the config file */
	    while (fgets(buf, sizeof(buf), fp) != NULL)
		{
			/* skip comments */
			if ((*buf == ';') || (*buf == '#')) continue;
			
			/* read default domain name */
			if (MATCH(buf, "domain"))
			{
				/* skip if have from environ */
				if (haveenv) continue;

				cp = buf + sizeof("domain") - 1;
				while ((*cp == ' ') || (*cp == '\t')) cp++;
				if ((*cp == '\0') || (*cp == '\n')) continue;

				strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
				statp->defdname[sizeof(statp->defdname) - 1] = '\0';
				cp = strpbrk(statp->defdname, " \t\n");
				if (cp != NULL) *cp = '\0';
				havesearch = 0;
				continue;
			}

			/* set search list */
			if (MATCH(buf, "search"))
			{
				/* skip if have from environ */
			    if (haveenv) continue;

			    cp = buf + sizeof("search") - 1;
			    while ((*cp == ' ') || (*cp == '\t')) cp++;
			    if ((*cp == '\0') || (*cp == '\n')) continue;

			    strncpy(statp->defdname, cp, sizeof(statp->defdname) - 1);
			    statp->defdname[sizeof(statp->defdname) - 1] = '\0';
				cp = strchr(statp->defdname, '\n');
			    if (cp != NULL) *cp = '\0';

			    /*
			     * Set search list to be blank-separated strings
			     * on rest of line.
			     */
			    cp = statp->defdname;
			    pp = statp->dnsrch;
			    *pp++ = cp;
			    for (n = 0; *cp && pp < statp->dnsrch + MAXDNSRCH; cp++)
				{
				    if ((*cp == ' ') || (*cp == '\t'))
					{
					    *cp = 0;
					    n = 1;
				    }
					else if (n != 0)
					{
					    *pp++ = cp;
					    n = 0;
				    }
			    }

			    /* null terminate last domain if there are excess */
			    while ((*cp != '\0') && (*cp != ' ') && (*cp != '\t')) cp++;
			    *cp = '\0';
			    *pp++ = 0;
			    havesearch = 1;
			    continue;
			}

			/* read nameservers to query */
			if (MATCH(buf, "nameserver") && (nserv < MAXNS))
			{
#ifndef __APPLE__
			    struct addrinfo hints, *ai;
#endif
				int dotcount, semicount, status;
				struct in_addr addr4;
				struct sockaddr_in sin4;
				struct in6_addr addr6;
				struct sockaddr_in6 sin6;
				unsigned short aport; /* HOST BYTE ORDER */
				char *lastdot, *checkp;
			    char sbuf[NI_MAXSERV];
#ifndef __APPLE__
			    const size_t minsiz = sizeof(statp->_u._ext.ext->nsaddrs[0]);
#endif

			    cp = buf + sizeof("nameserver") - 1;
			    while ((*cp == ' ') || (*cp == '\t')) cp++;
			    cp[strcspn(cp, ";# \t\n")] = '\0';
			    if ((*cp != '\0') && (*cp != '\n'))
				{
#ifndef __APPLE__
					memset(&hints, 0, sizeof(hints));
					hints.ai_family = PF_UNSPEC;
					hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
					hints.ai_flags = AI_NUMERICHOST;
#endif
					dotcount = 0;
					semicount = 0;
					lastdot = NULL;
					aport = port;

					for (checkp = cp; *checkp != '\0'; checkp++)
					{
						if (*checkp == ':') semicount++;
						else if (*checkp == '.')
						{
							dotcount++;
							lastdot = checkp;
						}
					}

					if ((dotcount == 4) || ((semicount > 0) && (lastdot != NULL)))
					{
						aport = atoi(lastdot + 1);
						if (aport == 0) aport = port;
						*lastdot = '\0';
					}
					
					sprintf(sbuf, "%u", aport);

#ifdef __APPLE__
					memset(&addr4, 0, sizeof(struct in_addr));
					memset(&sin4, 0, sizeof(struct sockaddr_in));

					memset(&addr6, 0, sizeof(struct in6_addr));
					memset(&sin6, 0, sizeof(struct sockaddr_in6));

					status = inet_pton(AF_INET6, cp, &addr6);
					if (status == 1)
					{
						sin6.sin6_addr = addr6;
						sin6.sin6_family = AF_INET6;
						sin6.sin6_port = htons(aport);
						sin6.sin6_len = sizeof(struct sockaddr_in6);
						if (statp->_u._ext.ext != NULL)
						{
							memcpy(&statp->_u._ext.ext->nsaddrs[nserv], &sin6, sizeof(struct sockaddr_in6));
						}
						statp->nsaddr_list[nserv].sin_family = 0;
						nserv++;
					}
					else
					{
						status = inet_pton(AF_INET, cp, &addr4);
						if (status == 1)
						{
							sin4.sin_addr = addr4;
							sin4.sin_family = AF_INET;
							sin4.sin_port = htons(port);
							sin4.sin_len = sizeof(struct sockaddr_in);
							if (statp->_u._ext.ext != NULL)
							{
								memcpy(&statp->_u._ext.ext->nsaddrs[nserv], &sin4, sizeof(struct sockaddr_in));
							}
							memcpy(&statp->nsaddr_list[nserv], &sin4, sizeof(struct sockaddr_in));
							nserv++;
						}
             	   }

					
#else
					if (getaddrinfo(cp, sbuf, &hints, &ai) == 0 && ai->ai_addrlen <= minsiz)
					{
						if (statp->_u._ext.ext != NULL)
						{
							memcpy(&statp->_u._ext.ext->nsaddrs[nserv], ai->ai_addr, ai->ai_addrlen);
						}

						if (ai->ai_addrlen <= sizeof(statp->nsaddr_list[nserv]))
						{
							memcpy(&statp->nsaddr_list[nserv], ai->ai_addr, ai->ai_addrlen);
						}
						else
						{
							statp->nsaddr_list[nserv].sin_family = 0;
						}

						freeaddrinfo(ai);
						nserv++;
					}
#endif
				}

				continue;
			}

#ifdef RESOLVSORT
			if (MATCH(buf, "sortlist"))
			{
			    struct in_addr a;

			    cp = buf + sizeof("sortlist") - 1;
			    while (nsort < MAXRESOLVSORT)
				{
					while ((*cp == ' ') || (*cp == '\t')) cp++;
					if ((*cp == '\0') || (*cp == '\n') || (*cp == ';')) break;

					net = cp;
					while (*cp && !ISSORTMASK(*cp) && (*cp != ';') && isascii(*cp) && !isspace((unsigned char)*cp)) cp++;
					n = *cp;
					*cp = 0;
					if (inet_aton(net, &a))
					{
						statp->sort_list[nsort].addr = a;
						if (ISSORTMASK(n))
						{
							*cp++ = n;
							net = cp;
							while (*cp && (*cp != ';') && isascii(*cp) && !isspace((unsigned char)*cp)) cp++;
							n = *cp;
							*cp = 0;
							if (inet_aton(net, &a))
							{
								statp->sort_list[nsort].mask = a.s_addr;
							}
							else
							{
								statp->sort_list[nsort].mask = net_mask(statp->sort_list[nsort].addr);
							}
						}
						else
						{
							statp->sort_list[nsort].mask = net_mask(statp->sort_list[nsort].addr);
						}
						nsort++;
					}

					*cp = n;
				}

				continue;
			}
#endif

			if (MATCH(buf, "options"))
			{
			    res_setoptions(statp, buf + sizeof("options") - 1, "conf");
			    continue;
			}

			if (MATCH(buf, "timeout"))
			{
				cp = buf + sizeof("timeout") - 1;
				while (*cp == ' ' || *cp == '\t') cp++;
				if ((*cp == '\0') || (*cp == '\n')) continue;
				i = atoi(cp);
				if (i > RES_MAXRETRANS) i = RES_MAXRETRANS;
				totaltimeout = i;
				continue;
			}

#ifdef __APPLE__
			if (MATCH(buf, "search_order"))
			{
				cp = buf + sizeof("search_order") - 1;
				while (*cp == ' ' || *cp == '\t') cp++;
				if ((*cp == '\0') || (*cp == '\n')) continue;
				if (statp->_u._ext.ext != NULL) statp->_u._ext.ext->search_order = atoi(cp);
				continue;
			}
#endif

		}

		if (nserv > 1) statp->nscount = nserv;
#ifdef RESOLVSORT
		statp->nsort = nsort;
#endif
		fclose(fp);
	}

	/*
	 * Last chance to get a nameserver.  This should not normally
	 * be necessary
	 */
#ifdef NO_RESOLV_CONF
	if(nserv == 0) nserv = get_nameservers(statp);
#endif

	if ((resconf_file == NULL) || (!strcmp(resconf_file, _PATH_RESCONF)))
	{
		if ((statp->defdname[0] == 0) && (gethostname(buf, sizeof(statp->defdname) - 1) == 0) && ((cp = strchr(buf, '.')) != NULL))
		{
			strcpy(statp->defdname, cp + 1);
		}
	}

	/* find components of local domain that might be searched */
	if (havesearch == 0)
	{
		pp = statp->dnsrch;
		*pp++ = statp->defdname;
		*pp = NULL;

		dots = 0;
		for (cp = statp->defdname; *cp; cp++)
		{
			dots += (*cp == '.');
		}

		cp = statp->defdname;
		while (pp < statp->dnsrch + MAXDFLSRCH)
		{
			if (dots < LOCALDOMAINPARTS) break;
			cp = strchr(cp, '.') + 1;    /* we know there is one */
			*pp++ = cp;
			dots--;
		}

		*pp = NULL;
#ifdef DEBUG
		if (statp->options & RES_DEBUG)
		{
			printf(";; res_init()... default dnsrch list:\n");
			for (pp = statp->dnsrch; *pp; pp++) printf(";;\t%s\n", *pp);
			printf(";;\t..END..\n");
		}
#endif
	}

	cp = getenv("RES_OPTIONS");
	if ((cp != NULL) && ((resconf_file == NULL) || (!strcmp(resconf_file, _PATH_RESCONF))))
	{
		res_setoptions(statp, cp, "env");
	}

#ifdef __APPLE__
	/*
	 * Post processing to set the timeout value.
	 */
	if (totaltimeout != 0)
	{
		/* Timeout was set with a "timeout" line in the file */
		statp->retrans = totaltimeout;
	}
	else
	{
		/*
		 * Timeout is default, or was set with "options timeout:"
		 * This is a per-select timeout value.  Calculate total timeout
		 * and set statp->restrans which we (Apple) use to indicate
		 * total time allowed for a query to be resolved.
		 */
		totaltimeout = statp->retrans * statp->retry * statp->nscount;
		statp->retrans = totaltimeout;
	}
#endif

	statp->options |= RES_INIT;
	return (0);
}

/* This function has to be reachable by res_data.c but not publically. */
int
__res_vinit(res_state statp, int preinit)
{
	return res_vinit_from_file(statp, preinit, _PATH_RESCONF);
}

static void
res_setoptions(res_state statp, const char *options, const char *source)
{
	const char *cp = options;
	int i;
	struct __res_state_ext *ext = statp->_u._ext.ext;

#ifdef DEBUG
	if (statp->options & RES_DEBUG)
		printf(";; res_setoptions(\"%s\", \"%s\")...\n",
		       options, source);
#endif
	while (*cp) {
		/* skip leading and inner runs of spaces */
		while (*cp == ' ' || *cp == '\t')
			cp++;
		/* search for and process individual options */
		if (!strncmp(cp, "ndots:", sizeof("ndots:") - 1)) {
			i = atoi(cp + sizeof("ndots:") - 1);
			if (i <= RES_MAXNDOTS)
				statp->ndots = i;
			else
				statp->ndots = RES_MAXNDOTS;
#ifdef DEBUG
			if (statp->options & RES_DEBUG)
				printf(";;\tndots=%d\n", statp->ndots);
#endif
		} else if (!strncmp(cp, "timeout:", sizeof("timeout:") - 1)) {
			i = atoi(cp + sizeof("timeout:") - 1);
			if (i <= RES_MAXRETRANS)
				statp->retrans = i;
			else
				statp->retrans = RES_MAXRETRANS;
		} else if (!strncmp(cp, "attempts:", sizeof("attempts:") - 1)){
			i = atoi(cp + sizeof("attempts:") - 1);
			if (i <= RES_MAXRETRY)
				statp->retry = i;
			else
				statp->retry = RES_MAXRETRY;
		} else if (!strncmp(cp, "debug", sizeof("debug") - 1)) {
#ifdef DEBUG
			if (!(statp->options & RES_DEBUG)) {
				printf(";; res_setoptions(\"%s\", \"%s\")..\n",
				       options, source);
				statp->options |= RES_DEBUG;
			}
			printf(";;\tdebug\n");
#endif
		} else if (!strncmp(cp, "no_tld_query",
				    sizeof("no_tld_query") - 1) ||
			   !strncmp(cp, "no-tld-query",
				    sizeof("no-tld-query") - 1)) {
			statp->options |= RES_NOTLDQUERY;
		} else if (!strncmp(cp, "inet6", sizeof("inet6") - 1)) {
			statp->options |= RES_USE_INET6;
		} else if (!strncmp(cp, "rotate", sizeof("rotate") - 1)) {
			statp->options |= RES_ROTATE;
		} else if (!strncmp(cp, "no-check-names",
				    sizeof("no-check-names") - 1)) {
			statp->options |= RES_NOCHECKNAME;
		}
#ifdef RES_USE_EDNS0
		else if (!strncmp(cp, "edns0", sizeof("edns0") - 1)) {
			statp->options |= RES_USE_EDNS0;
		}
#endif
		else if (!strncmp(cp, "a6", sizeof("a6") - 1)) {
			statp->options |= RES_USE_A6;
		}
		else if (!strncmp(cp, "dname", sizeof("dname") - 1)) {
			statp->options |= RES_USE_DNAME;
		}
		else if (!strncmp(cp, "nibble:", sizeof("nibble:") - 1)) {
			if (ext == NULL)
				goto skip;
			cp += sizeof("nibble:") - 1;
			i = MIN(strcspn(cp, " \t"), sizeof(ext->nsuffix) - 1);
			strncpy(ext->nsuffix, cp, i);
			ext->nsuffix[i] = '\0';
		}
		else if (!strncmp(cp, "nibble2:", sizeof("nibble2:") - 1)) {
			if (ext == NULL)
				goto skip;
			cp += sizeof("nibble2:") - 1;
			i = MIN(strcspn(cp, " \t"), sizeof(ext->nsuffix2) - 1);
			strncpy(ext->nsuffix2, cp, i);
			ext->nsuffix2[i] = '\0';
		}
		else if (!strncmp(cp, "bitstring:", sizeof("bitstring:") - 1)) {
			if (ext == NULL)
				goto skip;
			cp += sizeof("bitstring:") - 1;
			i = MIN(strcspn(cp, " \t"), sizeof(ext->bsuffix) - 1);
			strncpy(ext->bsuffix, cp, i);
			ext->bsuffix[i] = '\0';
		}
		else if (!strncmp(cp, "v6revmode:", sizeof("v6revmode:") - 1)) {
			cp += sizeof("v6revmode:") - 1;
			/* "nibble" and "bitstring" used to be valid */
			if (!strncmp(cp, "single", sizeof("single") - 1)) {
				statp->options |= RES_NO_NIBBLE2;
			} else if (!strncmp(cp, "both", sizeof("both") - 1)) {
				statp->options &=
					 ~RES_NO_NIBBLE2;
			}
		}
		else {
			/* XXX - print a warning here? */
		}
   skip:
		/* skip to next run of spaces */
		while (*cp && *cp != ' ' && *cp != '\t')
			cp++;
	}
}

#ifdef RESOLVSORT
/* XXX - should really support CIDR which means explicit masks always. */
static u_int32_t
net_mask(in)		/* XXX - should really use system's version of this */
	struct in_addr in;
{
	register u_int32_t i = ntohl(in.s_addr);

	if (IN_CLASSA(i))
		return (htonl(IN_CLASSA_NET));
	else if (IN_CLASSB(i))
		return (htonl(IN_CLASSB_NET));
	return (htonl(IN_CLASSC_NET));
}
#endif

u_int
res_randomid(void) {
	struct timeval now;
#ifdef __APPLE__
	int rf;
	static u_int x = 0;

	if (x == 0)
	{
		rf = open("/dev/random", O_RDONLY, 0);
		if (rf >= 0)
		{
			read(rf, &x, sizeof(u_int));
			close(rf);
		}
		else
		{
			x = (getpid() << 10) + time(NULL);
		}

		srandom(x);
	}

	return random();
#endif

	gettimeofday(&now, NULL);
	return (0xffff & (now.tv_sec ^ now.tv_usec ^ getpid()));
}

/*
 * This routine is for closing the socket if a virtual circuit is used and
 * the program wants to close it.  This provides support for endhostent()
 * which expects to close the socket.
 *
 * This routine is not expected to be user visible.
 */
void
res_nclose(res_state statp) {
	int ns;

	if (statp->_vcsock >= 0) { 
		(void) close(statp->_vcsock);
		statp->_vcsock = -1;
		statp->_flags &= ~(RES_F_VC | RES_F_CONN);
	}
	for (ns = 0; ns < statp->_u._ext.nscount; ns++) {
		if (statp->_u._ext.nssocks[ns] != -1) {
			(void) close(statp->_u._ext.nssocks[ns]);
			statp->_u._ext.nssocks[ns] = -1;
		}
	}
}

void
res_ndestroy(res_state statp) {
	res_nclose(statp);
	if (statp->_u._ext.ext != NULL)
		free(statp->_u._ext.ext);
	statp->options &= ~RES_INIT;
	statp->_u._ext.ext = NULL;
}

const char *
res_get_nibblesuffix(res_state statp) {
	if (statp->_u._ext.ext)
		return (statp->_u._ext.ext->nsuffix);
	return ("ip6.arpa");
}

const char *
res_get_nibblesuffix2(res_state statp) {
	if (statp->_u._ext.ext)
		return (statp->_u._ext.ext->nsuffix2);
	return ("ip6.int");
}

const char *
res_get_bitstringsuffix(res_state statp) {
	if (statp->_u._ext.ext)
		return (statp->_u._ext.ext->bsuffix);
	return ("ip6.arpa");
}

void
res_setservers(res_state statp, const union res_sockaddr_union *set, int cnt) {
	int i, nserv;
	size_t size;

	/* close open servers */
	res_nclose(statp);

	/* cause rtt times to be forgotten */
	statp->_u._ext.nscount = 0;

	nserv = 0;
	for (i = 0; i < cnt && nserv < MAXNS; i++) {
		switch (set->sin.sin_family) {
		case AF_INET:
			size = sizeof(set->sin);
			if (statp->_u._ext.ext)
				memcpy(&statp->_u._ext.ext->nsaddrs[nserv],
					&set->sin, size);
			if (size <= sizeof(statp->nsaddr_list[nserv]))
				memcpy(&statp->nsaddr_list[nserv],
					&set->sin, size);
			else
				statp->nsaddr_list[nserv].sin_family = 0;
			nserv++;
			break;

		case AF_INET6:
			size = sizeof(set->sin6);
			if (statp->_u._ext.ext)
				memcpy(&statp->_u._ext.ext->nsaddrs[nserv],
					&set->sin6, size);
			if (size <= sizeof(statp->nsaddr_list[nserv]))
				memcpy(&statp->nsaddr_list[nserv],
					&set->sin6, size);
			else
				statp->nsaddr_list[nserv].sin_family = 0;
			nserv++;
			break;

		default:
			break;
		}
		set++;
	}
	statp->nscount = nserv;
	
}

int
res_getservers(res_state statp, union res_sockaddr_union *set, int cnt) {
	int i;
	size_t size;
	u_int16_t family;

	for (i = 0; i < statp->nscount && i < cnt; i++) {
		if (statp->_u._ext.ext)
			family = statp->_u._ext.ext->nsaddrs[i].sin.sin_family;
		else 
			family = statp->nsaddr_list[i].sin_family;

		switch (family) {
		case AF_INET:
			size = sizeof(set->sin);
			if (statp->_u._ext.ext)
				memcpy(&set->sin,
				       &statp->_u._ext.ext->nsaddrs[i],
				       size);
			else
				memcpy(&set->sin, &statp->nsaddr_list[i],
				       size);
			break;

		case AF_INET6:
			size = sizeof(set->sin6);
			if (statp->_u._ext.ext)
				memcpy(&set->sin6,
				       &statp->_u._ext.ext->nsaddrs[i],
				       size);
			else
				memcpy(&set->sin6, &statp->nsaddr_list[i],
				       size);
			break;

		default:
			set->sin.sin_family = 0;
			break;
		}
		set++;
	}
	return (statp->nscount);
}
