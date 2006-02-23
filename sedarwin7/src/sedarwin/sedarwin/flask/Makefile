#
# Makefile for building the SELinux module as part of the kernel.
#

AWK = awk

FLASK_H_DEPEND = security_classes initial_sids
AV_H_DEPEND = access_vectors

FLASK_H_FILES = av_inherit.h av_perm_to_string.h av_permissions.h class_to_string.h common_perm_to_string.h initial_sid_to_string.h

all: flask.h av_permissions.h

flask.h: $(FLASK_H_DEPEND)
	/bin/sh ./mkflask.sh $(AWK) $(FLASK_H_DEPEND)

av_permissions.h: $(AV_H_DEPEND)
	/bin/sh ./mkaccess_vector.sh $(AWK) $(AV_H_DEPEND)

install: flask.h av_permissions.h
	install -C -m0644 $(FLASK_H_FILES) ../avc
	install -C -m0644 flask.h ..

clean:  
	rm -f $(FLASK_H_FILES)
	rm -f $(FLASK_IH_FILES)
