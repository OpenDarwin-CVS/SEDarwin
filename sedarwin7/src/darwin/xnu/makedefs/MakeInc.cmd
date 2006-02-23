#
# Commands for the build environment
#
MIG =  $(NEXT_ROOT)/usr/bin/mig

MD=     /usr/bin/md

RM = /bin/rm -f
CP = /bin/cp
LN = /bin/ln -s
CAT = /bin/cat
MKDIR = /bin/mkdir -p

TAR = /usr/bin/gnutar
STRIP = /usr/bin/strip
LIPO = /usr/bin/lipo

BASENAME = /usr/bin/basename
export RELPATH = $(SRCROOT)/../bootstrap_cmds/relpath.tproj/relpath
TR = /usr/bin/tr
SEG_HACK = $(SRCROOT)/../cctools/misc/seg_hack.NEW

UNIFDEF   = /usr/bin/unifdef
DECOMMENT = $(SRCROOT)/../bootstrap_cmds/decomment.tproj/decomment

