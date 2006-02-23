#
# Include this makefile to use the mig that was built in our source
# tree (so that new features are available)
#

MIGBUILDDIR := $(DARWIN_ROOT)/bootstrap_cmds/migcom.tproj

MIG = sh $(MIGBUILDDIR)/mig.sh -I$(DARWIN)/BUILD/obj/EXPORT_HDRS/osfmk -migcom $(MIGBUILDDIR)/migcom

