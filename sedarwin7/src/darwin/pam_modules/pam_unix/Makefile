# Copyright 1998 Juniper Networks, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#	$FreeBSD: src/lib/libpam/modules/pam_unix/Makefile,v 1.8 2001/08/26 17:41:13 markm Exp $

LIB=		pam_unix
SHLIB_NAME=	pam_unix.so
SRCS=		pam_unix.c pw_copy.c pw_yp.c pw_util.c ypxfr_misc.c ${GENSRCS}
CFLAGS=		-DYP -Dyp_error=warnx \
		-I${.OBJDIR} \
		-I${.CURDIR}/../../../../libexec/ypxfr \
		-I${.CURDIR}/../../../../usr.sbin/vipw \
		-I${.CURDIR}/../../../../usr.bin/chpass
DPADD=		${LIBUTIL} ${LIBCRYPT} ${LIBRPCSVC}
LDADD=		-lutil -lcrypt -lrpcsvc
MAN=		pam_unix.8

GENSRCS=yp.h yp_clnt.c yppasswd.h yppasswd_clnt.c \
	yppasswd_private.h yppasswd_private_clnt.c yppasswd_private_xdr.c

RPCGEN= rpcgen -C
RPCSRC= ${DESTDIR}/usr/include/rpcsvc/yp.x
RPCSRC_PW= ${DESTDIR}/usr/include/rpcsvc/yppasswd.x
RPCSRC_PRIV= ${.CURDIR}/../../../../usr.sbin/rpc.yppasswdd/yppasswd_private.x

yp.h: ${RPCSRC}
	${RPCGEN} -h -o ${.TARGET} ${RPCSRC}

yp_clnt.c: ${RPCSRC} yp.h
	${RPCGEN} -l -o ${.TARGET} ${RPCSRC}

yppasswd.h: ${RPCSRC_PW}
	${RPCGEN} -h -o ${.TARGET} ${RPCSRC_PW}

yppasswd_clnt.c: ${RPCSRC_PW}
	${RPCGEN} -l -o ${.TARGET} ${RPCSRC_PW}

yppasswd_private.h: ${RPCSRC_PRIV}
	${RPCGEN} -h -o ${.TARGET} ${RPCSRC_PRIV}

yppasswd_private_xdr.c: ${RPCSRC_PRIV}
	${RPCGEN} -c -o ${.TARGET} ${RPCSRC_PRIV}

yppasswd_private_clnt.c: ${RPCSRC_PRIV}
	${RPCGEN} -l -o ${.TARGET} ${RPCSRC_PRIV}


yppasswd_private.h: ${RPCSRC_PRIV}
	${RPCGEN} -h -o ${.TARGET} ${RPCSRC_PRIV}

CLEANFILES= ${GENSRCS}

.include <bsd.lib.mk>

.PATH:		${.CURDIR}/../../../../usr.bin/chpass
.PATH:		${.CURDIR}/../../../../usr.sbin/vipw
.PATH:		${.CURDIR}/../../../../libexec/ypxfr
