# This Makefile replaces the Makefile that is included with the Apple
# sources.  This Makefile only builds the components required for
# building the Darwin kernel.

include ../../Makeconfig

all: ../Libstreams/streams.h
	mkdir -p include/streams
	cp -f ../Libstreams/streams.h include/streams/
	cd libstuff && make
	cd libmacho && make
	cd misc && make
	cd ld && make kld_build

install:

clean:
	cd misc && make clean
	cd libstuff && make clean
	cd libmacho && make clean
	cd ld && make clean

