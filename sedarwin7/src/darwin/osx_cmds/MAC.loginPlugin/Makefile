#
# MAC.loginPlugin
#

include ../../../Makeconfig

all:
	@xcodebuild -alltargets -buildstyle Deployment

install:
	@xcodebuild DSTROOT="$(EXPORT_ROOT)" \
		-target MAC -buildstyle Deployment install
	@chmod -R u+w $(EXPORT_ROOT)/System/Library/LoginPlugins/MAC.loginPlugin
	@install -m 444 MAClogin.conf.sample $(EXPORT_ROOT)/private/etc/
	@install -m 555 maclogin.sh $(EXPORT_ROOT)/usr/bin/maclogin

clean:
	@xcodebuild -alltargets clean

install:
