# This Makefile replaces the NeXT Project Builder Makefile that is
# included with the Apple sources.  This Makefile only builds the
# components required for building the Darwin kernel.

include ../../Makeconfig

all:
	cd migcom.tproj && make

clean:
	cd decomment.tproj && make clean
	cd relpath.tproj && make clean
	cd migcom.tproj && make clean

clean:
	cd decomment.tproj && make clean
	cd relpath.tproj && make clean
	cd migcom.tproj && make clean

install:
	cd migcom.tproj && make install

tools:
	cd decomment.tproj && make
	cd relpath.tproj && make
