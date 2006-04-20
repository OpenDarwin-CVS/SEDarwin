# This file was created automatically by SWIG.
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.

import _semanage

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


SEMANAGE_MSG_ERR = _semanage.SEMANAGE_MSG_ERR
SEMANAGE_MSG_WARN = _semanage.SEMANAGE_MSG_WARN
SEMANAGE_MSG_INFO = _semanage.SEMANAGE_MSG_INFO

semanage_msg_get_level = _semanage.semanage_msg_get_level

semanage_msg_get_channel = _semanage.semanage_msg_get_channel

semanage_msg_get_fname = _semanage.semanage_msg_get_fname

semanage_msg_set_callback = _semanage.semanage_msg_set_callback

semanage_handle_create = _semanage.semanage_handle_create

semanage_handle_destroy = _semanage.semanage_handle_destroy
SEMANAGE_CON_INVALID = _semanage.SEMANAGE_CON_INVALID
SEMANAGE_CON_DIRECT = _semanage.SEMANAGE_CON_DIRECT
SEMANAGE_CON_POLSERV_LOCAL = _semanage.SEMANAGE_CON_POLSERV_LOCAL
SEMANAGE_CON_POLSERV_REMOTE = _semanage.SEMANAGE_CON_POLSERV_REMOTE

semanage_select_store = _semanage.semanage_select_store

semanage_reload_policy = _semanage.semanage_reload_policy

semanage_set_reload = _semanage.semanage_set_reload

semanage_set_rebuild = _semanage.semanage_set_rebuild

semanage_set_create_store = _semanage.semanage_set_create_store

semanage_is_managed = _semanage.semanage_is_managed

semanage_connect = _semanage.semanage_connect

semanage_disconnect = _semanage.semanage_disconnect

semanage_begin_transaction = _semanage.semanage_begin_transaction

semanage_commit = _semanage.semanage_commit
SEMANAGE_CAN_READ = _semanage.SEMANAGE_CAN_READ
SEMANAGE_CAN_WRITE = _semanage.SEMANAGE_CAN_WRITE

semanage_access_check = _semanage.semanage_access_check

semanage_is_connected = _semanage.semanage_is_connected

semanage_module_install = _semanage.semanage_module_install

semanage_module_upgrade = _semanage.semanage_module_upgrade

semanage_module_install_base = _semanage.semanage_module_install_base

semanage_module_remove = _semanage.semanage_module_remove

semanage_module_list = _semanage.semanage_module_list

semanage_module_info_datum_destroy = _semanage.semanage_module_info_datum_destroy

semanage_module_list_nth = _semanage.semanage_module_list_nth

semanage_module_get_name = _semanage.semanage_module_get_name

semanage_module_get_version = _semanage.semanage_module_get_version

semanage_context_get_user = _semanage.semanage_context_get_user

semanage_context_set_user = _semanage.semanage_context_set_user

semanage_context_get_role = _semanage.semanage_context_get_role

semanage_context_set_role = _semanage.semanage_context_set_role

semanage_context_get_type = _semanage.semanage_context_get_type

semanage_context_set_type = _semanage.semanage_context_set_type

semanage_context_get_mls = _semanage.semanage_context_get_mls

semanage_context_set_mls = _semanage.semanage_context_set_mls

semanage_context_create = _semanage.semanage_context_create

semanage_context_clone = _semanage.semanage_context_clone

semanage_context_free = _semanage.semanage_context_free

semanage_context_from_string = _semanage.semanage_context_from_string

semanage_context_to_string = _semanage.semanage_context_to_string

semanage_bool_key_create = _semanage.semanage_bool_key_create

semanage_bool_key_extract = _semanage.semanage_bool_key_extract

semanage_bool_key_free = _semanage.semanage_bool_key_free

semanage_bool_compare = _semanage.semanage_bool_compare

semanage_bool_compare2 = _semanage.semanage_bool_compare2

semanage_bool_get_name = _semanage.semanage_bool_get_name

semanage_bool_set_name = _semanage.semanage_bool_set_name

semanage_bool_get_value = _semanage.semanage_bool_get_value

semanage_bool_set_value = _semanage.semanage_bool_set_value

semanage_bool_create = _semanage.semanage_bool_create

semanage_bool_clone = _semanage.semanage_bool_clone

semanage_bool_free = _semanage.semanage_bool_free

semanage_bool_query = _semanage.semanage_bool_query

semanage_bool_exists = _semanage.semanage_bool_exists

semanage_bool_count = _semanage.semanage_bool_count

semanage_bool_iterate = _semanage.semanage_bool_iterate

semanage_bool_list = _semanage.semanage_bool_list

semanage_bool_modify_local = _semanage.semanage_bool_modify_local

semanage_bool_del_local = _semanage.semanage_bool_del_local

semanage_bool_query_local = _semanage.semanage_bool_query_local

semanage_bool_exists_local = _semanage.semanage_bool_exists_local

semanage_bool_count_local = _semanage.semanage_bool_count_local

semanage_bool_iterate_local = _semanage.semanage_bool_iterate_local

semanage_bool_list_local = _semanage.semanage_bool_list_local

semanage_bool_set_active = _semanage.semanage_bool_set_active

semanage_bool_query_active = _semanage.semanage_bool_query_active

semanage_bool_exists_active = _semanage.semanage_bool_exists_active

semanage_bool_count_active = _semanage.semanage_bool_count_active

semanage_bool_iterate_active = _semanage.semanage_bool_iterate_active

semanage_bool_list_active = _semanage.semanage_bool_list_active

semanage_iface_compare = _semanage.semanage_iface_compare

semanage_iface_compare2 = _semanage.semanage_iface_compare2

semanage_iface_key_create = _semanage.semanage_iface_key_create

semanage_iface_key_extract = _semanage.semanage_iface_key_extract

semanage_iface_key_free = _semanage.semanage_iface_key_free

semanage_iface_get_name = _semanage.semanage_iface_get_name

semanage_iface_set_name = _semanage.semanage_iface_set_name

semanage_iface_get_ifcon = _semanage.semanage_iface_get_ifcon

semanage_iface_set_ifcon = _semanage.semanage_iface_set_ifcon

semanage_iface_get_msgcon = _semanage.semanage_iface_get_msgcon

semanage_iface_set_msgcon = _semanage.semanage_iface_set_msgcon

semanage_iface_create = _semanage.semanage_iface_create

semanage_iface_clone = _semanage.semanage_iface_clone

semanage_iface_free = _semanage.semanage_iface_free

semanage_iface_modify_local = _semanage.semanage_iface_modify_local

semanage_iface_del_local = _semanage.semanage_iface_del_local

semanage_iface_query_local = _semanage.semanage_iface_query_local

semanage_iface_exists_local = _semanage.semanage_iface_exists_local

semanage_iface_count_local = _semanage.semanage_iface_count_local

semanage_iface_iterate_local = _semanage.semanage_iface_iterate_local

semanage_iface_list_local = _semanage.semanage_iface_list_local

semanage_iface_query = _semanage.semanage_iface_query

semanage_iface_exists = _semanage.semanage_iface_exists

semanage_iface_count = _semanage.semanage_iface_count

semanage_iface_iterate = _semanage.semanage_iface_iterate

semanage_iface_list = _semanage.semanage_iface_list

semanage_user_key_create = _semanage.semanage_user_key_create

semanage_user_key_extract = _semanage.semanage_user_key_extract

semanage_user_key_free = _semanage.semanage_user_key_free

semanage_user_compare = _semanage.semanage_user_compare

semanage_user_compare2 = _semanage.semanage_user_compare2

semanage_user_get_name = _semanage.semanage_user_get_name

semanage_user_set_name = _semanage.semanage_user_set_name

semanage_user_get_prefix = _semanage.semanage_user_get_prefix

semanage_user_set_prefix = _semanage.semanage_user_set_prefix

semanage_user_get_mlslevel = _semanage.semanage_user_get_mlslevel

semanage_user_set_mlslevel = _semanage.semanage_user_set_mlslevel

semanage_user_get_mlsrange = _semanage.semanage_user_get_mlsrange

semanage_user_set_mlsrange = _semanage.semanage_user_set_mlsrange

semanage_user_get_num_roles = _semanage.semanage_user_get_num_roles

semanage_user_add_role = _semanage.semanage_user_add_role

semanage_user_del_role = _semanage.semanage_user_del_role

semanage_user_has_role = _semanage.semanage_user_has_role

semanage_user_get_roles = _semanage.semanage_user_get_roles

semanage_user_set_roles = _semanage.semanage_user_set_roles

semanage_user_create = _semanage.semanage_user_create

semanage_user_clone = _semanage.semanage_user_clone

semanage_user_free = _semanage.semanage_user_free

semanage_user_modify_local = _semanage.semanage_user_modify_local

semanage_user_del_local = _semanage.semanage_user_del_local

semanage_user_query_local = _semanage.semanage_user_query_local

semanage_user_exists_local = _semanage.semanage_user_exists_local

semanage_user_count_local = _semanage.semanage_user_count_local

semanage_user_iterate_local = _semanage.semanage_user_iterate_local

semanage_user_list_local = _semanage.semanage_user_list_local

semanage_user_query = _semanage.semanage_user_query

semanage_user_exists = _semanage.semanage_user_exists

semanage_user_count = _semanage.semanage_user_count

semanage_user_iterate = _semanage.semanage_user_iterate

semanage_user_list = _semanage.semanage_user_list
SEMANAGE_PROTO_UDP = _semanage.SEMANAGE_PROTO_UDP
SEMANAGE_PROTO_TCP = _semanage.SEMANAGE_PROTO_TCP

semanage_port_compare = _semanage.semanage_port_compare

semanage_port_compare2 = _semanage.semanage_port_compare2

semanage_port_key_create = _semanage.semanage_port_key_create

semanage_port_key_extract = _semanage.semanage_port_key_extract

semanage_port_key_free = _semanage.semanage_port_key_free

semanage_port_get_proto = _semanage.semanage_port_get_proto

semanage_port_set_proto = _semanage.semanage_port_set_proto

semanage_port_get_proto_str = _semanage.semanage_port_get_proto_str

semanage_port_get_low = _semanage.semanage_port_get_low

semanage_port_get_high = _semanage.semanage_port_get_high

semanage_port_set_port = _semanage.semanage_port_set_port

semanage_port_set_range = _semanage.semanage_port_set_range

semanage_port_get_con = _semanage.semanage_port_get_con

semanage_port_set_con = _semanage.semanage_port_set_con

semanage_port_create = _semanage.semanage_port_create

semanage_port_clone = _semanage.semanage_port_clone

semanage_port_free = _semanage.semanage_port_free

semanage_port_modify_local = _semanage.semanage_port_modify_local

semanage_port_del_local = _semanage.semanage_port_del_local

semanage_port_query_local = _semanage.semanage_port_query_local

semanage_port_exists_local = _semanage.semanage_port_exists_local

semanage_port_count_local = _semanage.semanage_port_count_local

semanage_port_iterate_local = _semanage.semanage_port_iterate_local

semanage_port_list_local = _semanage.semanage_port_list_local

semanage_port_query = _semanage.semanage_port_query

semanage_port_exists = _semanage.semanage_port_exists

semanage_port_count = _semanage.semanage_port_count

semanage_port_iterate = _semanage.semanage_port_iterate

semanage_port_list = _semanage.semanage_port_list

semanage_fcontext_compare = _semanage.semanage_fcontext_compare

semanage_fcontext_compare2 = _semanage.semanage_fcontext_compare2

semanage_fcontext_key_create = _semanage.semanage_fcontext_key_create

semanage_fcontext_key_extract = _semanage.semanage_fcontext_key_extract

semanage_fcontext_key_free = _semanage.semanage_fcontext_key_free

semanage_fcontext_get_expr = _semanage.semanage_fcontext_get_expr

semanage_fcontext_set_expr = _semanage.semanage_fcontext_set_expr
SEMANAGE_FCONTEXT_ALL = _semanage.SEMANAGE_FCONTEXT_ALL
SEMANAGE_FCONTEXT_REG = _semanage.SEMANAGE_FCONTEXT_REG
SEMANAGE_FCONTEXT_DIR = _semanage.SEMANAGE_FCONTEXT_DIR
SEMANAGE_FCONTEXT_CHAR = _semanage.SEMANAGE_FCONTEXT_CHAR
SEMANAGE_FCONTEXT_BLOCK = _semanage.SEMANAGE_FCONTEXT_BLOCK
SEMANAGE_FCONTEXT_SOCK = _semanage.SEMANAGE_FCONTEXT_SOCK
SEMANAGE_FCONTEXT_LINK = _semanage.SEMANAGE_FCONTEXT_LINK
SEMANAGE_FCONTEXT_PIPE = _semanage.SEMANAGE_FCONTEXT_PIPE

semanage_fcontext_get_type = _semanage.semanage_fcontext_get_type

semanage_fcontext_get_type_str = _semanage.semanage_fcontext_get_type_str

semanage_fcontext_set_type = _semanage.semanage_fcontext_set_type

semanage_fcontext_get_con = _semanage.semanage_fcontext_get_con

semanage_fcontext_set_con = _semanage.semanage_fcontext_set_con

semanage_fcontext_create = _semanage.semanage_fcontext_create

semanage_fcontext_clone = _semanage.semanage_fcontext_clone

semanage_fcontext_free = _semanage.semanage_fcontext_free

semanage_fcontext_modify_local = _semanage.semanage_fcontext_modify_local

semanage_fcontext_del_local = _semanage.semanage_fcontext_del_local

semanage_fcontext_query_local = _semanage.semanage_fcontext_query_local

semanage_fcontext_exists_local = _semanage.semanage_fcontext_exists_local

semanage_fcontext_count_local = _semanage.semanage_fcontext_count_local

semanage_fcontext_iterate_local = _semanage.semanage_fcontext_iterate_local

semanage_fcontext_list_local = _semanage.semanage_fcontext_list_local

semanage_fcontext_query = _semanage.semanage_fcontext_query

semanage_fcontext_exists = _semanage.semanage_fcontext_exists

semanage_fcontext_count = _semanage.semanage_fcontext_count

semanage_fcontext_iterate = _semanage.semanage_fcontext_iterate

semanage_fcontext_list = _semanage.semanage_fcontext_list

semanage_seuser_key_create = _semanage.semanage_seuser_key_create

semanage_seuser_key_extract = _semanage.semanage_seuser_key_extract

semanage_seuser_key_free = _semanage.semanage_seuser_key_free

semanage_seuser_compare = _semanage.semanage_seuser_compare

semanage_seuser_compare2 = _semanage.semanage_seuser_compare2

semanage_seuser_get_name = _semanage.semanage_seuser_get_name

semanage_seuser_set_name = _semanage.semanage_seuser_set_name

semanage_seuser_get_sename = _semanage.semanage_seuser_get_sename

semanage_seuser_set_sename = _semanage.semanage_seuser_set_sename

semanage_seuser_get_mlsrange = _semanage.semanage_seuser_get_mlsrange

semanage_seuser_set_mlsrange = _semanage.semanage_seuser_set_mlsrange

semanage_seuser_create = _semanage.semanage_seuser_create

semanage_seuser_clone = _semanage.semanage_seuser_clone

semanage_seuser_free = _semanage.semanage_seuser_free

semanage_seuser_modify_local = _semanage.semanage_seuser_modify_local

semanage_seuser_del_local = _semanage.semanage_seuser_del_local

semanage_seuser_query_local = _semanage.semanage_seuser_query_local

semanage_seuser_exists_local = _semanage.semanage_seuser_exists_local

semanage_seuser_count_local = _semanage.semanage_seuser_count_local

semanage_seuser_iterate_local = _semanage.semanage_seuser_iterate_local

semanage_seuser_list_local = _semanage.semanage_seuser_list_local

semanage_seuser_query = _semanage.semanage_seuser_query

semanage_seuser_exists = _semanage.semanage_seuser_exists

semanage_seuser_count = _semanage.semanage_seuser_count

semanage_seuser_iterate = _semanage.semanage_seuser_iterate

semanage_seuser_list = _semanage.semanage_seuser_list
SEMANAGE_PROTO_IP4 = _semanage.SEMANAGE_PROTO_IP4
SEMANAGE_PROTO_IP6 = _semanage.SEMANAGE_PROTO_IP6

semanage_node_compare = _semanage.semanage_node_compare

semanage_node_compare2 = _semanage.semanage_node_compare2

semanage_node_key_create = _semanage.semanage_node_key_create

semanage_node_key_extract = _semanage.semanage_node_key_extract

semanage_node_key_free = _semanage.semanage_node_key_free

semanage_node_get_addr = _semanage.semanage_node_get_addr

semanage_node_get_addr_bytes = _semanage.semanage_node_get_addr_bytes

semanage_node_set_addr = _semanage.semanage_node_set_addr

semanage_node_set_addr_bytes = _semanage.semanage_node_set_addr_bytes

semanage_node_get_mask = _semanage.semanage_node_get_mask

semanage_node_get_mask_bytes = _semanage.semanage_node_get_mask_bytes

semanage_node_set_mask = _semanage.semanage_node_set_mask

semanage_node_set_mask_bytes = _semanage.semanage_node_set_mask_bytes

semanage_node_get_proto = _semanage.semanage_node_get_proto

semanage_node_set_proto = _semanage.semanage_node_set_proto

semanage_node_get_proto_str = _semanage.semanage_node_get_proto_str

semanage_node_get_con = _semanage.semanage_node_get_con

semanage_node_set_con = _semanage.semanage_node_set_con

semanage_node_create = _semanage.semanage_node_create

semanage_node_clone = _semanage.semanage_node_clone

semanage_node_free = _semanage.semanage_node_free

semanage_node_modify_local = _semanage.semanage_node_modify_local

semanage_node_del_local = _semanage.semanage_node_del_local

semanage_node_query_local = _semanage.semanage_node_query_local

semanage_node_exists_local = _semanage.semanage_node_exists_local

semanage_node_count_local = _semanage.semanage_node_count_local

semanage_node_iterate_local = _semanage.semanage_node_iterate_local

semanage_node_list_local = _semanage.semanage_node_list_local

semanage_node_query = _semanage.semanage_node_query

semanage_node_exists = _semanage.semanage_node_exists

semanage_node_count = _semanage.semanage_node_count

semanage_node_iterate = _semanage.semanage_node_iterate

semanage_node_list = _semanage.semanage_node_list

