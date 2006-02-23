MLS MACpolicyPlugin
===================

The MLS policy module provides labels that are inherited on fork().  The
initial system processes are labeled mls/equal(low-high), which is
unsuitable for processes belonging to the user.  Previously, mach_init was
modified to lower user privilige but this was not viewed as a good
solution. 

This plugin allows the user enter an MLS label and will relabel the
current process with the supplied label.  The user will not be allowed to
continue unless a valid (per mac_mls_internalize_label()) label is
entered. 

The Kernel MLS policy module relies on the process/cred label for the
loginwindow.app and copies it to processes the MAC LoginPlugin adopts
session processes, and resets the label when the processes are orphaned. 

See mac_mls/mac_mls.c:mac_mls_check_proc_setlcid() for more information.
