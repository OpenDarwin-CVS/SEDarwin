include ../../Makeconfig

SUBDIR= checkpolicy \
	loadpolicy \
	newrole \
	relabel_gui

all:
	cd checkpolicy ; gnumake
	cd loadpolicy ; gnumake
	cd newrole ; gnumake
	cd relabel_gui ; gnumake

clean:
	cd checkpolicy ; gnumake clean
	cd loadpolicy ; gnumake clean
	cd newrole ; gnumake clean
	cd relabel_gui ; gnumake clean

install:
	cd checkpolicy ; gnumake install
	cd loadpolicy ; gnumake install
	cd newrole ; gnumake install
	cd relabel_gui ; gnumake install
