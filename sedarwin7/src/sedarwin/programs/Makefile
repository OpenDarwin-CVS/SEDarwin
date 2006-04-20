SUBDIR= checkpolicy \
	genhomedircon \
	load_policy \
	newrole \
	setfiles \
	setsebool \
	semodule \
	semodule_expand \
	semodule_link \
	semodule_package \
	relabel_gui \
	restorecon

.PHONY: $(SUBDIR) all install clean

all: $(SUBDIR)

$(SUBDIR):
	$(MAKE) -w -C $@

install clean:
	for dir in $(SUBDIR); do \
		$(MAKE) -w -C $$dir $@; \
	done
