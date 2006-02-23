#!/bin/sh

SETFMAC='/usr/bin/setfmac -h'

if [ ! -f /.attribute/system/sebsd ]; then
    echo "ERROR, can't find attribute backing file"
    exit;
fi

$SETFMAC sebsd/system_u:object_r:bin_t /sbin/*
$SETFMAC sebsd/system_u:object_r:bin_t /usr/sbin/*
$SETFMAC sebsd/system_u:object_r:bin_t /bin/*
$SETFMAC sebsd/system_u:object_r:bin_t /usr/bin/*
$SETFMAC sebsd/system_u:object_r:bin_t /usr/local/bin/*
$SETFMAC sebsd/system_u:object_r:shell_exec_t /bin/*sh       
$SETFMAC sebsd/system_u:object_r:login_exec_t /usr/bin/login
$SETFMAC sebsd/system_u:object_r:sshd_exec_t /usr/sbin/sshd
$SETFMAC sebsd/system_u:object_r:lookupd_exec_t /usr/sbin/lookupd
$SETFMAC sebsd/system_u:object_r:mach_init_exec_t /sbin/mach_init
$SETFMAC sebsd/system_u:object_r:init_exec_t /sbin/init
$SETFMAC -R sebsd/system_u:object_r:appl_t /Applications/*
$SETFMAC sebsd/system_u:object_r:systemstarter_exec_t /sbin/SystemStarter
$SETFMAC sebsd/system_u:object_r:systemstarter_exec_t /usr/sbin/xinetd
$SETFMAC sebsd/system_u:object_r:coreservices_exec_t /System/Library/CoreServices/coreservicesd
$SETFMAC sebsd/system_u:object_r:loginwindow_exec_t /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow	
$SETFMAC sebsd/system_u:object_r:notifyd_exec_t /usr/sbin/notifyd
$SETFMAC sebsd/system_u:object_r:diskarbitrationd_exec_t /usr/sbin/diskarbitrationd
$SETFMAC sebsd/system_u:object_r:pbs_exec_t /System/Library/CoreServices/pbs
$SETFMAC sebsd/system_u:object_r:windowserver_exec_t /System/Library/Frameworks/ApplicationServices.framework/Frameworks/CoreGraphics.framework/Resources/WindowServer*
$SETFMAC sebsd/system_u:object_r:securityserver_exec_t /System/Library/CoreServices/SecurityServer
$SETFMAC sebsd/system_u:object_r:coreservices_exec_t /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CarbonCore.framework/Versions/A/Support/coreservicesd
