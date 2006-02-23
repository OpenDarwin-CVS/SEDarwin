include ../Makeconfig

DIRS=	$(DESTDIR)/private/etc \
	$(DESTDIR)/private/etc/sedarwin \
	$(DESTDIR)/bin \
	$(DESTDIR)/usr/bin \
	$(DESTDIR)/usr/lib \
	$(DESTDIR)/usr/standalone/ppc \
	$(DESTDIR)/usr/share/man/man1 \
	$(DESTDIR)/usr/share/man/man4 \
	$(DESTDIR)/usr/share/man/man8 \
	$(DESTDIR)/System/Library/Extensions \
	$(DESTDIR)/System/Library/CoreServices \
	$(DESTDIR)/usr/include/sebsd \
	$(DESTDIR)/usr/include/bsm \
	$(DESTDIR)/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/CoreGraphics.framework/Versions/A/Resources

all:
	mkdir -p $(DIRS)

install: all

dist:
	cd $(DESTDIR) && gnutar --owner root --group wheel -czf \
		$(SOURCE_ROOT)/sedarwin.tgz .

distclean:
	rm -rf $(DESTDIR) $(SOURCE_ROOT)/sedarwin.tgz

# Don't want to wipe out the system if DESTDIR=/
clean:
