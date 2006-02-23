include ../../Makeconfig

SUBDIR=	getfmac getlcmac getpmac mexec setfsmac setlcmac setpmac lcs

all:
	@for dir in $(SUBDIR); do \
		gnumake -C $$dir ; \
		if [ $$? -ne 0 ] ; then \
			exit 1 ; \
		fi ; \
	done

install:
	@for dir in $(SUBDIR); do \
		gnumake -C $$dir install ; \
		if [ $$? -ne 0 ] ; then \
			exit 1 ; \
		fi ; \
	done

clean:
	@for dir in $(SUBDIR); do \
		gnumake -C $$dir clean ; \
		if [ $$? -ne 0 ] ; then \
			exit 1 ; \
		fi ; \
	done
