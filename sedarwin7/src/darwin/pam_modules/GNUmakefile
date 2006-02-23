##
# Modules Makefile
##
# Luke Howard <lukeh@padl.com>
##

# Project info
Project               = pam_modules
SubProjects           = pam_unix pam_netinfo pam_uwtmp
#SubProjects           = pam_unix pam_deny pam_permit pam_netinfo pam_rootok pam_wheel \
#			pam_tim pam_nis pam_directoryservice 

# Have we the Keychain API?
#HaveKeychain          = $(shell if test -d /System/Library/Frameworks/Security.framework/PrivateHeaders; then echo YES; fi)
#ifeq ($(HaveKeychain),YES)
#SubProjects          += pam_keychain
#endif

# Have we the SecurityServer API?
HaveSecServer          = $(shell if test -d /System/Library/Frameworks/Security.framework/Headers; then echo YES; fi)
ifeq ($(HaveSecServer),YES)
SubProjects           += pam_securityserver
endif

include $(MAKEFILEPATH)/CoreOS/ReleaseControl/Common.make

lazy_install_source:: shadow_source recurse

install:: lazy_install_source
	make recurse TARGET=install Project=$(Project) Extra_CC_Flags=-Wall
	for a in `ls -1 $(DSTROOT)/usr/lib/pam/` ; do \
		strip -S -x $(DSTROOT)/usr/lib/pam/$${a}; \
	done;
