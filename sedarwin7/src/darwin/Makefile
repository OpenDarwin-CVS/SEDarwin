include ../Makeconfig

all:
	mkdir -p build/obj
	cd Libstreams && gnumake
	cd bootstrap_cmds && gnumake tools
	cd cctools && gnumake
	cd kext_tools && gnumake
	cd xnu && gnumake
	cd bootstrap_cmds && gnumake all
	cd BootX && gnumake
	cd libextattr && gnumake
	cd libmac && gnumake
	cd adv_cmds/ps.tproj && gnumake
	cd etc && gnumake
	cd extattr_cmds && make
	cd mac_cmds && gnumake
	cd file_cmds && gnumake
	cd mach_cmds && gnumake
	cd top && make
	cd bsm/bsm/lib && gnumake
	gnumake -C pam_modules/pam_lctx
	cd system_cmds/mach_init.tproj && gnumake
	cd netinfo/servers/notifyd && gnumake
	cd OpenSSH && gnumake

install:
	cd xnu && make install
	install -m 644 xnu/BUILD/obj/RELEASE_PPC/mach_kernel $(DESTDIR)/
	cd xnu/BUILD/dst && tar cf - usr/include | (cd $(DESTDIR); tar xf -)
	cd bootstrap_cmds && gnumake install
	cd cctools && gnumake install
	cd BootX && gnumake install
	cd libextattr && gnumake install
	cd libmac && gnumake install
	cd adv_cmds/ps.tproj && gnumake install
	cd etc && gnumake install
	cd extattr_cmds && make install
	cd mac_cmds && gnumake install
	cd file_cmds && gnumake install
	cd mach_cmds && gnumake install
	cd top && make install
	cd bsm/bsm/lib && gnumake install
	gnumake -C pam_modules/pam_lctx DSTROOT=$(DESTDIR) install
	cd system_cmds/mach_init.tproj && gnumake install
	cd netinfo/servers/notifyd && gnumake install
	cd OpenSSH && gnumake install

clean:
	rm -rf xnu/BUILD
	cd Libstreams && gnumake clean
	cd cctools && gnumake clean
	cd bootstrap_cmds && gnumake clean
	cd kext_tools && gnumake clean
	cd BootX && gnumake clean
	cd libextattr && gnumake clean
	cd libmac && gnumake clean
	cd adv_cmds/ps.tproj && gnumake clean
	cd etc && gnumake clean
	cd extattr_cmds && make clean
	cd mac_cmds && gnumake clean
	cd file_cmds && gnumake clean
	cd mach_cmds && gnumake clean
	cd top && make clean
	cd bsm/bsm/lib && gnumake clean
	gnumake -C pam_modules/pam_lctx clean
	cd system_cmds/mach_init.tproj && gnumake clean
	cd netinfo/servers/notifyd && gnumake clean
	cd OpenSSH && gnumake clean
	rm -rf build/obj
