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
	avc.h \
        avc_ss.h \
        class_to_string.h \
        av_perm_to_string.h \
        common_perm_to_string.h \
        initial_sid_to_string.h \
	av_permissions.h

INSTALL_MI_LIST	= 

INSTALL_MI_DIR = sebsd/avc

EXPORT_MI_LIST	= ${EXPORT_ONLY_FILES}

EXPORT_MI_DIR = sebsd/avc


include $(MakeInc_rule)
include $(MakeInc_dir)


