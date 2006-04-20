#
# Makefile for building the SELinux module as part of the kernel.
#

AWK = awk

FLASK_H_DEPEND = security_classes initial_sids
AV_H_DEPEND = access_vectors

FLASK_H_FILES = class_to_string.h flask.h initial_sid_to_string.h
AV_H_FILES = av_inherit.h common_perm_to_string.h av_perm_to_string.h av_permissions.h
ALL_H_FILES = $(FLASK_H_FILES) $(AV_H_FILES)

all: $(ALL_H_FILES)

$(FLASK_H_FILES): $(FLASK_H_DEPEND)
	/bin/sh ./mkflask.sh $(AWK) $(FLASK_H_DEPEND)

$(AV_H_FILES): $(AV_H_DEPEND)
	/bin/sh ./mkaccess_vector.sh $(AWK) $(AV_H_DEPEND)

install: all
	install -C -m 644 ${ALL_H_FILES: flask.h=} ../avc
	install -C -m 644 flask.h ..

clean:  
	rm -f $(FLASK_H_FILES)
	rm -f $(AV_H_FILES)
