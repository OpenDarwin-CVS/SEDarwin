#
# Generated by the NeXT Project Builder.
#
# NOTE: Do NOT change this file -- Project Builder maintains it.
#
# Put all of your customizations in files called Makefile.preamble
# and Makefile.postamble (both optional), and Makefile will include them.
#

NAME = pax

PROJECTVERSION = 2.8
PROJECT_TYPE = Tool

HFILES = cache.h cpio.h extern.h ftree.h options.h pat_rep.h pax.h\
         sel_subs.h tables.h tar.h

CFILES = ar_io.c ar_subs.c buf_subs.c cache.c cpio.c file_subs.c\
         ftree.c gen_subs.c getoldopt.c options.c pat_rep.c pax.c\
         sel_subs.c tables.c tar.c tty_subs.c

OTHERSRCS = Makefile Makefile.preamble Makefile.postamble pax.1 cpio.1\
            tar.1


MAKEFILEDIR = $(MAKEFILEPATH)/pb_makefiles
CODE_GEN_STYLE = DYNAMIC
MAKEFILE = tool.make
NEXTSTEP_INSTALLDIR = /bin
LIBS = 
DEBUG_LIBS = $(LIBS)
PROF_LIBS = $(LIBS)




NEXTSTEP_BUILD_OUTPUT_DIR = /tmp/$(NAME)/Build

NEXTSTEP_OBJCPLUS_COMPILER = /usr/bin/cc
WINDOWS_OBJCPLUS_COMPILER = $(DEVDIR)/gcc
PDO_UNIX_OBJCPLUS_COMPILER = $(NEXTDEV_BIN)/gcc
NEXTSTEP_JAVA_COMPILER = /usr/bin/javac
WINDOWS_JAVA_COMPILER = $(JDKBINDIR)/javac.exe
PDO_UNIX_JAVA_COMPILER = $(NEXTDEV_BIN)/javac

include $(MAKEFILEDIR)/platform.make

-include Makefile.preamble

include $(MAKEFILEDIR)/$(MAKEFILE)

-include Makefile.postamble

-include Makefile.dependencies
