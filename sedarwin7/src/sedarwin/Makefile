SUBDIR= sedarwin \
	libsecompat \
	libsepol \
	libselinux \
	libsemanage \
	programs \
	policy

.PHONY: $(SUBDIR) all install clean

all: $(SUBDIR)

$(SUBDIR):
	$(MAKE) -w -C $@ 

install clean:
	for dir in $(SUBDIR); do \
		$(MAKE) -w -C $$dir $@; \
	done
