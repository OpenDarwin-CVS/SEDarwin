##
# pam_sedarwin
##

PAMModuleName	= pam_sedarwin

Extra_CC_Flags	=-I../../pam/pam/libpam/include/pam/ \
		 -I../../xnu/BUILD/obj/EXPORT_HDRS/bsd/ \
		 -idirafter ../../xnu/BUILD/obj/EXPORT_HDRS/osfmk \
		 -I../../../sedarwin/libselinux/include

Extra_LD_Flags	=-L../../../sedarwin/libselinux/src/ -lselinux \
		 -L../../../sedarwin/libsepol/src/ -lsepol \
		 -L../../../sedarwin/libsecompat/ -lsecompat \
		 -L../../libmac/ -lmac

include ../PAMModule.defs
