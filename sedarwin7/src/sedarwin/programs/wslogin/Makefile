include ../../../Makeconfig
LIBSELINUX= $(SOURCE_ROOT)/sedarwin/libselinux

OBJS = wslogin.o
CFLAGS+= -I$(SOURCE_ROOT)/sedarwin -I$(LIBSELINUX)/include $(DARWIN_HDRS)
INSTALL?= install

all: wslogin.dylib build/wsloginui.app

wslogin.dylib: $(OBJS)
	gcc -dynamiclib -o $@ $(OBJS) $(LIBSELINUX)/src/libselinux.a $(DARWIN_ROOT)/libmac/*.o

build/wsloginui.app: LabelChooser.m LabelChooser.h main.m
	xcodebuild

install:
	$(INSTALL) -o $(LIBOWN) -g $(LIBGRP) -m 755 \
		wslogin.dylib $(DESTDIR)/usr/lib
	(cd build ; tar -cf - wsloginui.app) | (cd \
	    $(DESTDIR)/System/Library/CoreServices ; tar -xf -)
	$(INSTALL) -o $(LIBOWN) -g $(LIBGRP) -m 755 WindowServer.sedarwin $(DESTDIR)/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/CoreGraphics.framework/Versions/A/Resources/
	$(INSTALL) -o $(BINOWN) -g $(BINGRP) -m 700 install-windowserver.sh $(DESTDIR)/private/etc/sedarwin/

clean:
	rm -f $(OBJS) wslogin.dylib
	rm -Rf build
