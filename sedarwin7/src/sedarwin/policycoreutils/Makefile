SUBDIRS=setfiles semanage load_policy newrole run_init restorecon audit2allow audit2why scripts sestatus semodule_package semodule semodule_link semodule_expand setsebool po

all install relabel clean: 
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done

