#
# Generated by the NeXT Project Builder.
#
# NOTE: Do NOT change this file -- Project Builder maintains it.
#
# Put all of your customizations in files called Makefile.preamble
# and Makefile.postamble (both optional), and Makefile will include them.
#
NAME = ps

PROJECTVERSION = 2.8
PROJECT_TYPE = Tool

HFILES = extern.h ps.h

CFILES = fmt.c keyword.c nlist.c print.c ps.c tasks.c

OTHERSRCS = Makefile.preamble Makefile Makefile.postamble m.template\
            h.template ps.1


MAKEFILEDIR = $(MAKEFILEPATH)/pb_makefiles
CODE_GEN_STYLE = DYNAMIC
MAKEFILE = tool.make
NEXTSTEP_INSTALLDIR = /bin
WINDOWS_INSTALLDIR = /Library/Executables
PDO_UNIX_INSTALLDIR = /bin
OTHER_CFLAGS= -I$(EXPORT_HDRS)/bsd -I$(EXPORT_HDRS)/osfmk -I$(EXPORT_HDRS)
LIBS = $(LIBMAC)
DEBUG_LIBS = $(LIBS)
PROF_LIBS = $(LIBS)




NEXTSTEP_BUILD_OUTPUT_DIR =

NEXTSTEP_OBJCPLUS_COMPILER = /usr/bin/cc
WINDOWS_OBJCPLUS_COMPILER = $(DEVDIR)/gcc
PDO_UNIX_OBJCPLUS_COMPILER = $(NEXTDEV_BIN)/gcc
NEXTSTEP_JAVA_COMPILER = /usr/bin/javac
WINDOWS_JAVA_COMPILER = $(JDKBINDIR)/javac.exe
PDO_UNIX_JAVA_COMPILER = $(JDKBINDIR)/javac

include $(MAKEFILEDIR)/platform.make

-include Makefile.preamble


# NAI: We add the next three definitions to override the variables
# pulled in from the System ProjectBuilder defaults so that the program
# is built in the current directory rather than in /tmp
include ../../../Makeconfig
OBJROOT = $(SRCROOT)/$(NAME)/Build
SYMROOT = $(SRCROOT)/$(NAME)/Debug

include $(MAKEFILEDIR)/$(MAKEFILE)

-include Makefile.postamble

-include Makefile.dependencies
