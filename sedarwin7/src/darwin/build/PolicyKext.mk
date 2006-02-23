#
# Including Makefile MUST have the following variables defined:
#
#	POLICY		Name of the policy (eg: mac_foo)
#	POLICY_VER	Policy Version for Bundle
#	POLICY_COMPVER	Policy OS Compatible Version for Bundle
#	POLICY_DESC	Description of Policy
#
# The following variables MAY be defined
#
#	POLICY_SRCS	Override default sources of $(POLICY).c
#	POLICY_NOMAN	Define if policy module has no manpage.
#	POLICY_MAN
#	POLICY_LIBS	key:string specification of OSBundleLibraries
#
#	CLEANFILES	Additional build files to remove on 'make clean'
#

CFLAGS +=	-g $(DARWIN_HDRS) -nostdinc -mlong-branch -DAPPLE -DKERNEL \
		-DKERNEL_PRIVATE -DKEXT -fno-common -static -fno-builtin \
		-I$(DARWIN)/EXTERNAL_HEADERS -I$(DARWIN)/EXTERNAL_HEADERS/bsd
CFLAGS		+=	$(CWARNFLAGS)
CFLAGS		+=	-DPOLICY_VER=\"$(POLICY_VER)\" \
			-DPOLICY_DESC=\"$(POLICY_DESC)\"
POLICY_SRCS	?=	$(POLICY).c
POLICY_OBJS	=	$(POLICY_SRCS:.c=.o)

POLICY_LIBS	+=	com.apple.kernel.bsd:1.1 \
			com.apple.kernel.libkern:1.0b1

WARNS ?=	6

#CWARNFLAGS	+=	-Wsystem-headers
#CWARNFLAGS	+=	-Werror
#CWARNFLAGS	+=	-Wall -Wno-format-y2k
#CWARNFLAGS	+=	-W -Wno-unused-parameter -Wstrict-prototypes \
#			-Wmissing-prototypes -Wpointer-arith
#CWARNFLAGS	+=	-Wreturn-type -Wcast-qual -Wwrite-strings -Wswitch \
#			-Wshadow -Wcast-align
#CWARNFLAGS	+=	-Wunused-parameter
#CWARNFLAGS	+=	-Wchar-subscripts -Winline -Wnested-externs \
#			-Wredundant-decls
#CWARNFLAGS	+=	-Wno-uninitialized

ifndef POLICY_NOMAN
POLICY_MAN	?=	$(POLICY).4
else
POLICY_MAN=
endif

CLEANFILES	+=	$(POLICY_OBJS) \
			$(POLICY)-test $(POLICY).gdb $(POLICY).report \
			.gdb_history

all: mac_$(POLICY).kext.tar $(POLICY).report

clean:
	@rm -rf mac_$(POLICY).kext.tar mac_$(POLICY).kext
	@rm -f $(CLEANFILES)

install: mac_$(POLICY).kext.tar $(POLICY_MAN)
ifndef POLICY_NOMAN
	@install -m 644 $(POLICY_MAN) $(DESTDIR)/usr/share/man/man4
endif
	@tar -C $(DESTDIR)/System/Library/Extensions -xf mac_$(POLICY).kext.tar

mac_$(POLICY).kext.tar: mac_$(POLICY).kext mac_$(POLICY).kext/Contents/Info.plist $(POLICY_OBJS)
	@echo "$(POLICY): Creating KEXT tar file..."
	@touch mac_$(POLICY).kext/LoadEarly
	@tar --owner root --group wheel -cf $@ mac_$(POLICY).kext

mac_$(POLICY).kext/Contents/Info.plist: Makefile
	@echo "$(POLICY): Generating Info.plist..."
	@sh $(DARWIN_ROOT)/build/mkPolicyInfoPlist.sh \
		$(POLICY) $(POLICY_VER) $(POLICY_COMPVER) \
		$(POLICY_DESC) "$(POLICY_LIBS)" > $@

mac_$(POLICY).kext: $(POLICY_OBJS)
	@echo "$(POLICY): Creating KEXT..."
	@mkdir -p mac_$(POLICY).kext/Contents/MacOS
	@ld -r -o mac_$(POLICY).kext/Contents/MacOS/$(POLICY) $(POLICY_OBJS) -lkmod -lcc_kext -static

# Display undefined policy entrypoints.

$(POLICY)-test: $(POLICY_OBJS)
	@$(LD) -twolevel_namespace -undefined define_a_way -o $@ $(POLICY_OBJS) 2> /dev/null
	
$(POLICY).gdb: $(POLICY)-test
	@gdb -x $(DARWIN_ROOT)/build/policy-ops.gdb $< \
		| grep mac_policy_ops \
		| sed s/\;// \
		| awk '{print "p " $$4 "\nquit"}' \
		> $@

$(POLICY).report: $(POLICY).gdb $(POLICY)-test
	@echo "$(POLICY): Creating policy report..."
	@echo "Undefined $(POLICY) policy entrypoints:" > $@
	@gdb -x $(POLICY).gdb $(POLICY)-test \
		| grep ' = 0,' \
		| awk '{print "\t"$$1}' \
		| sort \
		| uniq \
		>> $@
