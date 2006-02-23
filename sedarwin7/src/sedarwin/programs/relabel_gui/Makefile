#
# relabel.app
#

include ../../../Makeconfig

all:
	@xcodebuild -alltargets -buildstyle Deployment

install:
	@xcodebuild DSTROOT="$(EXPORT_ROOT)" \
		-target relabel_gui -buildstyle Deployment install
	@chmod -R u+w $(EXPORT_ROOT)/Applications/relabel.app

clean:
	@xcodebuild -alltargets clean

install:
