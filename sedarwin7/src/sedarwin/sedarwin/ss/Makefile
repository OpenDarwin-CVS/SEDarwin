export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir


include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS = 
INSTINC_SUBDIRS_PPC = ${INSTINC_SUBDIRS}
INSTINC_SUBDIRS_I386 = ${INSTINC_SUBDIRS}

EXPINC_SUBDIRS = 
EXPINC_SUBDIRS_PPC = ${EXPINC_SUBDIRS} 
EXPINC_SUBDIRS_I386 = ${EXPINC_SUBDIRS} 

EXPORT_ONLY_FILES = \
	mls.h security.h services.h policydb.h global.h context.h queue.h \
        hashtab.h symtab.h avtab.h sidtab.h ebitmap.h mls_types.h constraint.h 

INSTALL_MI_LIST	= 

INSTALL_MI_DIR = sebsd/ss

EXPORT_MI_LIST = ${EXPORT_ONLY_FILES}

EXPORT_MI_DIR = sebsd/ss


include $(MakeInc_rule)
include $(MakeInc_dir)


