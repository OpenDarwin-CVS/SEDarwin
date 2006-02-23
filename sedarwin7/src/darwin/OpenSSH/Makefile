##
# Makefile for OpenSSH
##
# Wilfredo Sanchez, wsanchez@apple.com
##

include ../../Makeconfig

# Project info
Project               = openssh
ProjectName           = OpenSSH
UserType              = Administrator
ToolType              = Services
Extra_CC_Flags        = -no-cpp-precomp
Extra_LD_Flags        = -L. -Lopenbsd-compat
Configure             = $(SH) $(shell pwd)/$(Project)/configure
Configure_Flags       = --prefix="$(USRDIR)" --mandir="$(MANDIR)" --infodir="$(SHAREDIR)/info" --sysconfdir="/etc" --disable-suid-ssh --with-ssl-dir=/usr/include/openssl --with-random=/dev/urandom --with-tcp-wrappers --with-pam --with-kerberos5 --without-zlib-version-check --with-4in6 CPPFLAGS="-DUSE_POSIX_THREADS"
Install_Flags         = --prefix="$(DSTROOT)$(USRDIR)" --mandir="$(DSTROOT)$(MANDIR)" --infodir="$(DSTROOT)$(SHAREDIR)/info" sysconfdir="$(DSTROOT)$(ETCDIR)" MANPAGES=""
Environment           = CFLAGS="$(CFLAGS)" CCFLAGS="$(CXXFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)" AR="$(SH) $(shell pwd)/ar.sh"

GnuAfterInstall = fixup-dstroot install-startup-item

CoreOSMakefiles = $(MAKEFILEPATH)/CoreOS
include $(CoreOSMakefiles)/Standard/Standard.make

OBJROOT = $(Project).build

Install_Flags         = DESTDIR=$(DSTROOT)

Install_Target = install-nokeys

all: build

build: configure
	@echo "Building $(Project)..."
	$(_v) $(MAKE) -C $(OBJROOT) $(Environment)

reconfigure:
	$(_v) $(RM) $(OBJROOT)/config.status
	$(_v) $(MAKE) configure

configure: $(OBJROOT)/config.status

$(OBJROOT)/config.status:
	@echo "Configuring $(Project)..."
	$(_v) $(MKDIR) $(OBJROOT)
	$(_v) cd $(OBJROOT) && $(Environment) $(Configure) $(Configure_Flags)

install:
	@echo "Installing $(Project)..."
	$(_v) umask $(Install_Mask) ; $(MAKE) -C $(OBJROOT) $(Environment) $(Install_Flags) $(Install_Target)
	$(_v) $(FIND) $(DSTROOT) $(Find_Cruft) | $(XARGS) $(RMDIR)
	$(_v) $(MAKE) $(GnuAfterInstall)

StartupItemDir = $(NSLIBRARYDIR)/StartupItems/SSH

fixup-dstroot:
	$(_v) mkdir -p $(DSTROOT)/private/etc
	$(_v) mv    $(DSTROOT)/etc/* $(DSTROOT)/private/etc
	$(_v) rmdir $(DSTROOT)/var/empty
	$(_v) rmdir $(DSTROOT)/var
	$(_v) rmdir $(DSTROOT)/etc

install-startup-item:
	$(_v) $(INSTALL_DIRECTORY) $(DSTROOT)/private/etc/xinetd.d
	$(_v) $(INSTALL_FILE)   -c ssh-via-xinetd  $(DSTROOT)/private/etc/xinetd.d/ssh
	$(_v) $(INSTALL_DIRECTORY) $(DSTROOT)/usr/libexec
	$(_v) $(INSTALL_FILE) -m 555  -c sshd-keygen-wrapper $(DSTROOT)/usr/libexec/sshd-keygen-wrapper

clean::
	@echo "Cleaning $(Project)..."
	$(_v) $(RMDIR) -f "$(OBJROOT)"
