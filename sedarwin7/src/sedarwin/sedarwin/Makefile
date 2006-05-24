POLICY=		sedarwin
POLICY_VER=	1.0
POLICY_COMPVER=	1.0
POLICY_DESC=	"SEDarwin (SELinux compatible TE)"
POLICY_NOMAN=	yes

POLICY_SRCS=	sebsd.c sebsd_alloc.c sebsd_syscall.c sebsd_sysctl.c
POLICY_SRCS+=	ss/avtab.c ss/conditional.c ss/ebitmap.c ss/hashtab.c \
		ss/init.c ss/mach_av.c ss/mls.c ss/policydb.c ss/services.c \
		ss/sidtab.c ss/symtab.c
POLICY_SRCS+=	avc/avc.c avc/avc_audit.c

CFLAGS+=	-DSEFOS_DEBUG -I..

include ../../Makeconfig
include $(DARWIN_ROOT)/build/PolicyKext.mk
