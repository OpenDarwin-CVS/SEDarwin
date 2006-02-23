# $FreeBSD$
#

LIB=	pam_sedarwin
SRCS=	pam_sedarwin.c
DPADD=	${LIBSELINUX} ${LIBMAC}
LDADD=	-lselinux -lmac
MAN=	pam_sedarwin.8

.include <bsd.lib.mk>
