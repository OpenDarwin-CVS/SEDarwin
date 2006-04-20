# This file was created automatically by SWIG.
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.

import _selinux

def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "this"):
        if isinstance(value, class_type):
            self.__dict__[name] = value.this
            if hasattr(value,"thisown"): self.__dict__["thisown"] = value.thisown
            del value.thisown
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static) or hasattr(self,name) or (name == "thisown"):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0
del types



is_selinux_enabled = _selinux.is_selinux_enabled

is_selinux_mls_enabled = _selinux.is_selinux_mls_enabled

getcon = _selinux.getcon

setcon = _selinux.setcon

getpidcon = _selinux.getpidcon

getprevcon = _selinux.getprevcon

getexeccon = _selinux.getexeccon

setexeccon = _selinux.setexeccon

getfscreatecon = _selinux.getfscreatecon

setfscreatecon = _selinux.setfscreatecon

getfilecon = _selinux.getfilecon

lgetfilecon = _selinux.lgetfilecon

fgetfilecon = _selinux.fgetfilecon

setfilecon = _selinux.setfilecon

lsetfilecon = _selinux.lsetfilecon

fsetfilecon = _selinux.fsetfilecon

getpeercon = _selinux.getpeercon

selinux_mkload_policy = _selinux.selinux_mkload_policy

selinux_init_load_policy = _selinux.selinux_init_load_policy

security_set_boolean_list = _selinux.security_set_boolean_list

security_load_booleans = _selinux.security_load_booleans

security_check_context = _selinux.security_check_context

security_canonicalize_context = _selinux.security_canonicalize_context

security_getenforce = _selinux.security_getenforce

security_setenforce = _selinux.security_setenforce

security_policyvers = _selinux.security_policyvers

security_get_boolean_names = _selinux.security_get_boolean_names

security_get_boolean_pending = _selinux.security_get_boolean_pending

security_get_boolean_active = _selinux.security_get_boolean_active

security_set_boolean = _selinux.security_set_boolean

security_commit_booleans = _selinux.security_commit_booleans
MATCHPATHCON_BASEONLY = _selinux.MATCHPATHCON_BASEONLY
MATCHPATHCON_NOTRANS = _selinux.MATCHPATHCON_NOTRANS

set_matchpathcon_flags = _selinux.set_matchpathcon_flags

matchpathcon_init = _selinux.matchpathcon_init

matchpathcon = _selinux.matchpathcon

matchmediacon = _selinux.matchmediacon

selinux_getenforcemode = _selinux.selinux_getenforcemode

selinux_policy_root = _selinux.selinux_policy_root

selinux_binary_policy_path = _selinux.selinux_binary_policy_path

selinux_failsafe_context_path = _selinux.selinux_failsafe_context_path

selinux_removable_context_path = _selinux.selinux_removable_context_path

selinux_default_context_path = _selinux.selinux_default_context_path

selinux_user_contexts_path = _selinux.selinux_user_contexts_path

selinux_file_context_path = _selinux.selinux_file_context_path

selinux_homedir_context_path = _selinux.selinux_homedir_context_path

selinux_media_context_path = _selinux.selinux_media_context_path

selinux_contexts_path = _selinux.selinux_contexts_path

selinux_booleans_path = _selinux.selinux_booleans_path

selinux_customizable_types_path = _selinux.selinux_customizable_types_path

selinux_users_path = _selinux.selinux_users_path

selinux_usersconf_path = _selinux.selinux_usersconf_path

selinux_translations_path = _selinux.selinux_translations_path

selinux_path = _selinux.selinux_path

selinux_check_passwd_access = _selinux.selinux_check_passwd_access

checkPasswdAccess = _selinux.checkPasswdAccess

rpm_execcon = _selinux.rpm_execcon

is_context_customizable = _selinux.is_context_customizable

selinux_trans_to_raw_context = _selinux.selinux_trans_to_raw_context

selinux_raw_to_trans_context = _selinux.selinux_raw_to_trans_context

getseuserbyname = _selinux.getseuserbyname

