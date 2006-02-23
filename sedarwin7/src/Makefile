include Makeconfig

all:
	cd darwin && make 
	for i in $(BUILD_MODULES); do cd $$i && make && cd ..; done
	cd darwin/osx_cmds && make
	gnumake -C darwin/pam_modules/pam_sedarwin

dist: install
	cd release && make dist

install:
	cd release && make install
	cd darwin && make install 
	for i in $(INSTALL_MODULES); do cd $$i && make install && cd ..; done
	cd darwin/osx_cmds && make install
	gnumake -C darwin/pam_modules/pam_sedarwin DSTROOT=$(DESTDIR) install

package:
	cd release && make package

dmg:
	cd release && make dmg

clean:
	rm -f *.dmg
	cd release && make distclean
	cd darwin && make clean 
	for i in $(BUILD_MODULES); do cd $$i && make clean && cd ..; done
	cd darwin/osx_cmds && make clean
	gnumake -C darwin/pam_modules/pam_sedarwin clean

Makeconfig: Makeconfig.in
	@echo "# Set this to the root of the source distribution." > $@ 
	@echo "SOURCE_ROOT = `pwd`" >> $@
	@echo "# You must set this variable to a valid user." >> $@
	@echo "EXPORT_OWNER = `id -un`" >> $@
	@cat $< >> $@
	@echo "Auto-generating Makeconfig..."

distclean:
	cd release && $(MAKE) distclean
