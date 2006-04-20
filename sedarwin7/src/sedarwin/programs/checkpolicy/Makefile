include ../../../Makeconfig

PROG= checkpolicy

OBJS = checkpolicy.o y.tab.o policy_scan.o queue.o module_compiler.o

CFLAGS+= -I$(SOURCE_ROOT)/sedarwin/libsepol/include
CFLAGS+= -I$(SOURCE_ROOT)/sedarwin/libselinux/include
LDADD+= -L$(SOURCE_ROOT)/sedarwin/libselinux/src -L$(SOURCE_ROOT)/sedarwin/libsepol/src -L$(SOURCE_ROOT)/sedarwin/libsecompat
LDADD+= -lselinux -lsepol -lsecompat -lfl

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

install: $(PROG)
	install -m 555 $(PROG) $(DESTDIR)/usr/bin

clean:
	rm -f $(OBJS) $(PROG) y.tab.* policy_scan.c

y.tab.c y.tab.h: policy_parse.y
	$(YACC) $(YFLAGS) -d policy_parse.y
