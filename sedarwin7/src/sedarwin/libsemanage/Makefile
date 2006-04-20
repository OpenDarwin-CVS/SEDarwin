all: 
	$(MAKE) -C src all

pywrap: 
	$(MAKE) -C src pywrap

install: 
	$(MAKE) -C include install
	$(MAKE) -C src install
	$(MAKE) -C man install

install-pywrap: 
	$(MAKE) -C src install-pywrap

relabel:
	$(MAKE) -C src relabel

clean distclean:
	$(MAKE) -C src $@

