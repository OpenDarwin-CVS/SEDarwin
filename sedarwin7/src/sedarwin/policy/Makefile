include ../../Makeconfig
include $(DARWIN_ROOT)/build/Mig.mk

POLICY= policy.16
FLASK= ../sedarwin/flask
SCRIPTS= create-extattr.sh sebsd-relabel.sh
INSTALL?= install

all: $(POLICY) sebsd_migscs

INPUTS = $(FLASK)/security_classes mig_classes initial_sids \
	$(FLASK)/access_vectors mig_access_vectors rules.m4 users \
	initial_sid_contexts fs_use devfs

policy.conf: $(INPUTS)
	cat $(INPUTS) > policy.conf

$(POLICY): policy.conf
	../programs/checkpolicy/checkpolicy -c 17 -o $(POLICY) policy.conf

rules.m4: rules
	m4 -Imacros -s rules > rules.m4

fc.out: fc
	sudo ../../darwin/mac_cmds/setfsmac/setfsmac -x -t -s fc /bin > fc.out

genfs: fc.out
	cat fc.out | sed -ne 's/^\/[a-zA-Z0-9\/\.]* *[^ ]*$$/genfscon hfs &/p' > genfs

clean:
	rm -f bininclude $(POLICY) policy.conf  policy.h rules.m4 fc.out \
	    genfs mig_access_vectors mig_classes sebsd_migscs mig_msgids

relabel: fc
	@echo This is broken

install:
	$(INSTALL) -o ${BINOWN} -g ${BINGRP} -m 644 ${POLICY} ${DESTDIR}
	$(INSTALL) -o ${BINOWN} -g ${BINGRP} -m 644 sebsd_migscs ${DESTDIR}
	$(INSTALL) -o ${BINOWN} -g ${BINGRP} -m 644 failsafe_context ${DESTDIR}/private/etc/sedarwin
	$(INSTALL) -o ${BINOWN} -g ${BINGRP} -m 700 ${SCRIPTS} ${DESTDIR}/private/etc/sedarwin
	(cd $(CURDIR)/.. && tar -X policy/excludes -cf - policy) | (cd $(DESTDIR)/private/etc/sedarwin/ && tar -xf -)
	(cd $(FLASK)/.. && tar -cf - flask) | (cd $(DESTDIR)/private/etc/sedarwin/policy && tar -xf -)
	cp -f Makefile.install $(DESTDIR)/private/etc/sedarwin/policy/Makefile

# Mig security classes and access vectors

DEFS = $(DARWIN_ROOT)/system_cmds/mach_init.tproj/bootstrap.defs $(DARWIN_ROOT)/netinfo/servers/notifyd/notify_ipc.defs $(DARWIN_ROOT)/../../examples/mig/mtest.defs

mig_msgids: $(DEFS)
	echo > $@
	for i in $(DEFS); do $(MIG) -user /dev/null -server /dev/null -header /dev/null -sheader /dev/null -flasksc `basename $$i .defs`.flask $$i; cat `basename $$i .defs`.flask >> $@; done

mig_access_vectors: mig_msgids
	cat $< | awk '{print $$1, $$2}' > $@
	echo ';' >> $@

mig_classes: mig_access_vectors
	grep '^class' $< > $@

sebsd_migscs: $(FLASK)/security_classes mig_msgids
	cat $(FLASK)/security_classes mig_msgids | perl migscs.pl
