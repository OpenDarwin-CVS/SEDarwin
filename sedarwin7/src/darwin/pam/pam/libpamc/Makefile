#
# $Id$
#

# lots of debugging information goes to /tmp/pam-debug.log
#MOREFLAGS += -D"DEBUG"

include ../Make.Rules

ifeq ($(DEBUG_REL),yes)
 LIBNAME=libpamcd
else
 LIBNAME=libpamc
endif
VERSION=.$(MAJOR_REL)
MODIFICATION=.$(MINOR_REL)

CFLAGS += $(MOREFLAGS) $(DYNAMIC) $(STATIC)

# dynamic library names

LIBNAMED = $(LIBNAME).$(DYNTYPE)
LIBNAMEDNAME = $(LIBNAME)$(VERSION).$(DYNTYPE)
LIBNAMEDFULL = $(LIBNAME)$(VERSION)$(MODIFICATION).$(DYNTYPE)

# static library name

LIBNAMEDSTATIC = $(LIBNAME).a

LIBOBJECTS = pamc_client.o pamc_converse.o pamc_load.o

ifeq ($(DYNAMIC_LIBPAM),yes)
DLIBOBJECTS = $(addprefix dynamic/,$(LIBOBJECTS))
endif

ifeq ($(STATIC_LIBPAM),yes)
SLIBOBJECTS = $(addprefix static/,$(LIBOBJECTS))
endif

# ---------------------------------------------
## rules

all: dirs $(LIBNAMED) $(LIBNAMEDSTATIC)

dirs:
ifeq ($(DYNAMIC_LIBPAM),yes)
	$(MKDIR) dynamic
endif
ifeq ($(STATIC_LIBPAM),yes)
	$(MKDIR) static
endif

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

static/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

$(LIBNAMED): $(DLIBOBJECTS)
ifeq ($(GIANT_LIBPAM),yes)
	$(AR) rc $(LIBNAMEDSTATIC) $(DLIBOBJECTS)
	$(RANLIB) $(LIBNAMEDSTATIC)
else
ifeq ($(DYNAMIC_LIBPAM),yes)
    ifeq ($(USESONAME),yes)
	$(LD_L) $(SOSWITCH) /usr/lib/$(LIBNAMEDFULL) -o $@ $(DLIBOBJECTS) $(MODULES) $(LINKLIBS)
    else
	$(LD_L) -o $@ $(DLIBOBJECTS) $(MODULES)
    endif
    ifeq ($(NEEDSONAME),yes)
	rm -f $(LIBNAMEDFULL)
	ln -s $(LIBNAMED) $(LIBNAMEDFULL)
	rm -f $(LIBNAMEDNAME)
	ln -s $(LIBNAMED) $(LIBNAMEDNAME)
    endif
endif
endif

$(LIBNAMEDSTATIC): $(SLIBOBJECTS)
ifeq ($(STATIC_LIBPAM),yes)
	$(AR) rc $@ $(SLIBOBJECTS) $(MODULES)
	$(RANLIB) $@
endif

install: all
	$(MKDIR) $(FAKEROOT)$(INCLUDED)
	$(INSTALL) -m 644 include/pam/pam_client.h $(FAKEROOT)$(INCLUDED)
ifeq ($(DYNAMIC_LIBPAM),yes)
	$(MKDIR) $(FAKEROOT)$(libdir)
	$(INSTALL) -m $(SHLIBMODE) $(LIBNAMED) $(FAKEROOT)$(libdir)/$(LIBNAMEDFULL)
	$(LDCONFIG)
  ifneq ($(DYNTYPE),"sl")
	( cd $(FAKEROOT)$(libdir) ; rm -f $(LIBNAMED) ; ln -s $(LIBNAMEDNAME) $(LIBNAMED) )
  endif
endif
ifeq ($(STATIC_LIBPAM),yes)
	$(INSTALL) -m 644 $(LIBNAMEDSTATIC) $(FAKEROOT)$(libdir)
endif

remove:
	rm -f $(FAKEROOT)$(INCLUDED)/pam_client.h
	rm -f $(FAKEROOT)$(libdir)/$(LIBNAMEDFULL)
	rm -f $(FAKEROOT)$(libdir)/$(LIBNAMED)
	$(LDCONFIG)
	rm -f $(FAKEROOT)$(libdir)/$(LIBNAMEDSTATIC)

clean:
	rm -f a.out core *~ static/*.o dynamic/*.o
	rm -f *.a *.out *.o *.so ./include/pam/*~
	if [ -d dynamic ]; then rmdir dynamic ; fi
	if [ -d static ]; then rmdir static ; fi

