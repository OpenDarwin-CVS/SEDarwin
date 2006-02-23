## Probably only works with GNU make
include ../../../../Makeconfig

ifndef CFLAGS
CFLAGS = -g -Wall -pipe -fno-common
endif

GCC=gcc
LIBCFLAGS = $(CFLAGS) $(DARWIN_HDRS) -I. -dynamic
LIB_NAME=libbsm.dylib
LIBCURVERS=1.0
LIBCOMPATVERS=1.0

LIB_HDRS=libbsm.h audit_uevents.h
LIB_HDRS_DIR=/usr/include/bsm

all: $(LIB_NAME)

$(LIB_NAME): 
	$(GCC) $(LIBCFLAGS) -c bsm_audit.c 
	$(GCC) $(LIBCFLAGS) -c bsm_io.c 
	$(GCC) $(LIBCFLAGS) -c bsm_class.c 
	$(GCC) $(LIBCFLAGS) -c bsm_control.c 
	$(GCC) $(LIBCFLAGS) -c bsm_event.c 
	$(GCC) $(LIBCFLAGS) -c bsm_flags.c 
	$(GCC) $(LIBCFLAGS) -c bsm_mask.c 
	$(GCC) $(LIBCFLAGS) -c bsm_token.c 
	$(GCC) $(LIBCFLAGS) -c bsm_user.c 
	$(GCC) $(LIBCFLAGS) -c bsm_notify.c 
	$(GCC) $(LIBCFLAGS) -c lib_wrappers.c 
	$(GCC) -dynamiclib $(CFLAGS) -install_name /usr/lib/$(LIB_NAME) -compatibility_version $(LIBCOMPATVERS) -current_version $(LIBCURVERS) *.o -o $(LIB_NAME)
	install -d $(BSM_HDRS)/bsm
	install -m 0444 $(LIB_HDRS) $(BSM_HDRS)/bsm

install: $(LIB_NAME)
	install -d $(DESTDIR)/usr/lib
	install $(LIB_NAME) $(DESTDIR)/usr/lib
	/usr/bin/strip -S $(DESTDIR)/usr/lib/$(LIB_NAME)
	install -d $(DESTDIR)/$(LIB_HDRS_DIR)
	install -m 0444 $(LIB_HDRS) $(DESTDIR)/$(LIB_HDRS_DIR)

clean:
	rm -f *.o $(LIB_NAME)
