#! /usr/bin/env python
# Copyright (C) 2005 Red Hat 
# see file 'COPYING' for use and warranty information
#
# semanage is a tool for managing SELinux configuration files
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 2 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA     
#                                        02111-1307  USA
#
#  

import pwd, string, selinux, tempfile, os, re, sys
from semanage import *;

is_mls_enabled=selinux.is_selinux_mls_enabled()
import syslog
try:
	import audit
	class logger:
		def __init__(self):
			self.audit_fd=audit.audit_open()

		def log(self, success, msg, name="", sename="", serole="", serange="", old_sename="", old_serole="", old_serange=""):
			audit.audit_log_semanage_message(self.audit_fd, audit.AUDIT_USER_ROLE_CHANGE, sys.argv[0],msg, name, 0, sename, serole, serange, old_sename, old_serole, old_serange, "", "", "", success);
except:
	class logger:
		def log(self, success, msg, name="", sename="", serole="", serange="", old_sename="", old_serole="", old_serange=""):
			if success == 1:
				message = "Successful: "
			else:
				message = "Failed: "
			message += " %s name=%s" % (msg,name)
			if sename != "":
				message += " sename=" + sename
			if old_sename != "":
				message += " old_sename=" + old_sename
			if serole != "":
				message += " role=" + serole
			if old_serole != "":
				message += " old_role=" + old_serole
			if serange != "":
				message += " MLSRange=" + serange
			if old_serange != "":
				message += " old_MLSRange=" + old_serange
			syslog.syslog(message);
			
mylog=logger()		

def validate_level(raw):
	sensitivity="s([0-9]|1[0-5])"
	category="c(1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])"
	cat_range=category + "(\." + category +")?"
	categories = cat_range + "(\," + cat_range + ")*"
	reg = sensitivity + "(-" + sensitivity + ")?" + "(:" + categories + ")?"
	return re.search("^" + reg +"$",raw)

def translate(raw, prepend=1):
	if prepend == 1:
		context="a:b:c:%s" % raw
	else:
		context=raw
	(rc, trans)=selinux.selinux_raw_to_trans_context(context)
	if rc != 0:
		return raw
	if prepend:
		trans = trans.strip("a:b:c")
	if trans == "":
		return raw
	else:
		return trans
	
def untranslate(trans, prepend=1):
 	if prepend == 1:
		context="a:b:c:%s" % trans
	else:
		context = trans

	(rc, raw)=selinux.selinux_trans_to_raw_context(context)
	if rc != 0:
		return trans
	if prepend:
		raw = raw.strip("a:b:c")	
	if raw == "":
		return trans
	else:
		return raw
	
class setransRecords:
	def __init__(self):
		self.filename=selinux.selinux_translations_path()
		fd=open(self.filename, "r")
		translations=fd.read().split('\n')
		fd.close()
		self.ddict={}
		self.comments=[]
		for r in translations:
			if len(r) == 0:
				continue
			i=r.strip()
			if i== "" or i[0] == "#":
				self.comments.append(r)
				continue
			i=i.split("=")
			if len(i) != 2:
				self.comments.append(r)
				continue
			self.ddict[i[0]] = i[1]

	def get_all(self):
		return self.ddict

	def out(self):
		rec=""
		for c in self.comments:
			rec+=c +"\n"
		keys=self.ddict.keys()
		keys.sort()
		for k in keys:
			rec += "%s=%s\n" %  (k, self.ddict[k])
		return rec
	
	def list(self,heading=1):
		if heading:
			print "\n%-25s %s\n" % ("Level", "Translation")
		keys=self.ddict.keys()
		keys.sort()
		for k in keys:
			print "%-25s %s" % (k, self.ddict[k])
		
	def add(self, raw, trans):
		if trans.find(" ") >= 0:
			raise ValueError("Translations can not contain spaces '%s' " % trans)

		if validate_level(raw)  == None:
			raise ValueError("Invalid Level '%s' " % raw)
		
		if self.ddict.has_key(raw):
			raise ValueError("%s already defined in translations" % raw)
		else:
			self.ddict[raw]=trans
		self.save()
	
	def modify(self, raw, trans):
		if trans.find(" ") >= 0:

			raise ValueError("Translations can not contain spaces '%s' " % trans)
		if self.ddict.has_key(raw):
			self.ddict[raw]=trans
		else:
			raise ValueError("%s not defined in translations" % raw)
		self.save()
		
	def delete(self, raw):
		self.ddict.pop(raw)
		self.save()

	def save(self):
		newfilename = tempfile.mktemp('', self.filename)
		fd=open(newfilename, "w")
		fd.write(self.out())
		fd.close()
		os.rename(newfilename, self.filename)

class semanageRecords:
	def __init__(self):
		self.sh = semanage_handle_create()
		self.semanaged = semanage_is_managed(self.sh)

		if not self.semanaged:
			semanage_handle_destroy(self.sh)
			raise ValueError("SELinux policy is not managed or store cannot be accessed.")

		rc = semanage_access_check(self.sh)
		if rc < SEMANAGE_CAN_READ:
			semanage_handle_destroy(self.sh)
			raise ValueError("Cannot read policy store.")

		rc = semanage_connect(self.sh)
		if rc < 0:
			semanage_handle_destroy(self.sh)
			raise ValueError("Could not establish semanage connection")

class loginRecords(semanageRecords):
	def __init__(self):
		semanageRecords.__init__(self)

	def add(self, name, sename, serange):
		if is_mls_enabled == 1:
			if serange == "":
				serange = "s0"
			else:
				serange = untranslate(serange)
			
		if sename == "":
			sename = "user_u"
			
		try:
			(rc,k) = semanage_seuser_key_create(self.sh, name)
			if rc < 0:
				raise ValueError("Could not create a key for %s" % name)

			(rc,exists) = semanage_seuser_exists(self.sh, k)
			if rc < 0:
				raise ValueError("Could not check if login mapping for %s is defined" % name)
			if exists:
				raise ValueError("Login mapping for %s is already defined" % name)
			try:
				pwd.getpwnam(name)
			except:
				raise ValueError("Linux User %s does not exist" % name)

			(rc,u) = semanage_seuser_create(self.sh)
			if rc < 0:
				raise ValueError("Could not create login mapping for %s" % name)

			rc = semanage_seuser_set_name(self.sh, u, name)
			if rc < 0:
				raise ValueError("Could not set name for %s" % name)

			if serange != "":
				rc = semanage_seuser_set_mlsrange(self.sh, u, serange)
				if rc < 0:
					raise ValueError("Could not set MLS range for %s" % name)

			rc = semanage_seuser_set_sename(self.sh, u, sename)
			if rc < 0:
				raise ValueError("Could not set SELinux user for %s" % name)

			rc = semanage_begin_transaction(self.sh)
			if rc < 0:
				raise ValueError("Could not start semanage transaction")

			rc = semanage_seuser_modify_local(self.sh, k, u)
			if rc < 0:
				raise ValueError("Could not add login mapping for %s" % name)

			rc = semanage_commit(self.sh) 
			if rc < 0:
				raise ValueError("Could not add login mapping for %s" % name)

		except ValueError, error:
			mylog.log(0, "add SELinux user mapping", name, sename, "", serange);
			raise error
		
		mylog.log(1, "add SELinux user mapping", name, sename, "", serange);
		semanage_seuser_key_free(k)
		semanage_seuser_free(u)

	def modify(self, name, sename = "", serange = ""):
		oldsename=""
		oldserange=""
		try:
			if sename == "" and serange == "":
				raise ValueError("Requires seuser or serange")

			(rc,k) = semanage_seuser_key_create(self.sh, name)
			if rc < 0:
				raise ValueError("Could not create a key for %s" % name)

			(rc,exists) = semanage_seuser_exists(self.sh, k)
			if rc < 0:
				raise ValueError("Could not check if login mapping for %s is defined" % name)
			if not exists:
				raise ValueError("Login mapping for %s is not defined" % name)

			(rc,u) = semanage_seuser_query(self.sh, k)
			if rc < 0:
				raise ValueError("Could not query seuser for %s" % name)

			oldserange=semanage_seuser_get_mlsrange(u)
			oldsename=semanage_seuser_get_sename(u)
			if serange != "":
				semanage_seuser_set_mlsrange(self.sh, u, untranslate(serange))
			else:
				serange=oldserange
			if sename != "":
				semanage_seuser_set_sename(self.sh, u, sename)
			else:
				sename=oldsename

			rc = semanage_begin_transaction(self.sh)
			if rc < 0:
				raise ValueError("Could not srart semanage transaction")

			rc = semanage_seuser_modify_local(self.sh, k, u)
			if rc < 0:
				raise ValueError("Could not modify login mapping for %s" % name)

			rc = semanage_commit(self.sh)
			if rc < 0:
				raise ValueError("Could not modify login mapping for %s" % name)

		except ValueError, error:
			mylog.log(0,"modify selinux user mapping", name, sename,"", serange, oldsename, "", oldserange);
			raise error
		
		mylog.log(1,"modify selinux user mapping", name, sename, "", serange, oldsename, "", oldserange);
		semanage_seuser_key_free(k)
		semanage_seuser_free(u)

	def delete(self, name):
		try:
			(rc,k) = semanage_seuser_key_create(self.sh, name)
			if rc < 0:
				raise ValueError("Could not create a key for %s" % name)

			(rc,exists) = semanage_seuser_exists(self.sh, k)
			if rc < 0:
				raise ValueError("Could not check if login mapping for %s is defined" % name)
			if not exists:
				raise ValueError("Login mapping for %s is not defined" % name)

			(rc,exists) = semanage_seuser_exists_local(self.sh, k)
			if rc < 0:
				raise ValueError("Could not check if login mapping for %s is defined" % name)
			if not exists:
				raise ValueError("Login mapping for %s is defined in policy, cannot be deleted" % name)

			rc = semanage_begin_transaction(self.sh)
			if rc < 0:
				raise ValueError("Could not start semanage transaction")

			rc = semanage_seuser_del_local(self.sh, k)

			if rc < 0:
				raise ValueError("Could not delete login mapping for %s" % name)

			rc = semanage_commit(self.sh)
			if rc < 0:
				raise ValueError("Could not delete login mapping for %s" % name)

		except ValueError, error:
			mylog.log(0,"delete SELinux user mapping", name);
			raise error
		
		mylog.log(1,"delete SELinux user mapping", name);
		semanage_seuser_key_free(k)

		
	def get_all(self):
		ddict={}
		(rc, self.ulist) = semanage_seuser_list(self.sh)
		if rc < 0:
			raise ValueError("Could not list login mappings")

		for u in self.ulist:
			name = semanage_seuser_get_name(u)
			ddict[name]=(semanage_seuser_get_sename(u), semanage_seuser_get_mlsrange(u))
		return ddict

	def list(self,heading=1):
		ddict=self.get_all()
		keys=ddict.keys()
		keys.sort()
		if is_mls_enabled == 1:
			if heading:
				print "\n%-25s %-25s %-25s\n" % ("Login Name", "SELinux User", "MLS/MCS Range")
			for k in keys:
				print "%-25s %-25s %-25s" % (k, ddict[k][0], translate(ddict[k][1]))
		else:
			if heading:
				print "\n%-25s %-25s\n" % ("Login Name", "SELinux User")
			for k in keys:
				print "%-25s %-25s" % (k, ddict[k][0])

class seluserRecords(semanageRecords):
	def __init__(self):
		semanageRecords.__init__(self)

	def add(self, name, roles, selevel, serange):
		if is_mls_enabled == 1:
			if serange == "":
				serange = "s0"
			else:
				serange = untranslate(serange)
			
			if selevel == "":
				selevel = "s0"
			else:
				selevel = untranslate(selevel)
			
		seroles=" ".join(roles)
		try:
			(rc,k) = semanage_user_key_create(self.sh, name)
			if rc < 0:
				raise ValueError("Could not create a key for %s" % name)

			(rc,exists) = semanage_user_exists(self.sh, k)
			if rc < 0:
				raise ValueError("Could not check if SELinux user %s is defined" % name)
			if exists:
				raise ValueError("SELinux user %s is already defined" % name)

			(rc,u) = semanage_user_create(self.sh)
			if rc < 0:
				raise ValueError("Could not create SELinux user for %s" % name)

			rc = semanage_user_set_name(self.sh, u, name)
			if rc < 0:
				raise ValueError("Could not set name for %s" % name)

			for r in roles:
				rc = semanage_user_add_role(self.sh, u, r)
				if rc < 0:
					raise ValueError("Could not add role %s for %s" % (r, name))

			if is_mls_enabled == 1:
				rc = semanage_user_set_mlsrange(self.sh, u, serange)
				if rc < 0:
					raise ValueError("Could not set MLS range for %s" % name)

				rc = semanage_user_set_mlslevel(self.sh, u, selevel)
				if rc < 0:
					raise ValueError("Could not set MLS level for %s" % name)

			(rc,key) = semanage_user_key_extract(self.sh,u)
			if rc < 0:
				raise ValueError("Could not extract key for %s" % name)

			rc = semanage_begin_transaction(self.sh)
			if rc < 0:
				raise ValueError("Could not start semanage transaction")

			rc = semanage_user_modify_local(self.sh, k, u)
			if rc < 0:
				raise ValueError("Could not add SELinux user %s" % name)

			rc = semanage_commit(self.sh)
			if rc < 0:
				raise ValueError("Could not add SELinux user %s" % name)

		except ValueError, error:
			mylog.log(0,"add SELinux user record", name, name, seroles, serange)
			raise error
		
		mylog.log(1,"add SELinux user record", name, name, seroles, serange)
		semanage_user_key_free(k)
		semanage_user_free(u)

	def modify(self, name, roles = [], selevel = "", serange = ""):
		try:
			if len(roles) == 0  and serange == "" and selevel == "":
				if is_mls_enabled == 1:
					raise ValueError("Requires roles, level or range")
				else:
					raise ValueError("Requires roles")

			(rc,k) = semanage_user_key_create(self.sh, name)
			if rc < 0:
				raise ValueError("Could not create a key for %s" % name)

			(rc,exists) = semanage_user_exists(self.sh, k)
			if rc < 0:
				raise ValueError("Could not check if SELinux user %s is defined" % name)
			if not exists:
				raise ValueError("SELinux user %s is not defined" % name)

			(rc,u) = semanage_user_query(self.sh, k)
			if rc < 0:
				raise ValueError("Could not query user for %s" % name)

			if serange != "":
				semanage_user_set_mlsrange(self.sh, u, untranslate(serange))
			if selevel != "":
				semanage_user_set_mlslevel(self.sh, u, untranslate(selevel))

			if len(roles) != 0:
				for r in roles:
					semanage_user_add_role(self.sh, u, r)

			rc = semanage_begin_transaction(self.sh)
			if rc < 0:
				raise ValueError("Could not start semanage transaction")

			rc = semanage_user_modify_local(self.sh, k, u)
			if rc < 0:
				raise ValueError("Could not modify SELinux user %s" % name)

			rc = semanage_commit(self.sh)
			if rc < 0:
				raise ValueError("Could not modify SELinux user %s" % name)

		except ValueError, error:
			mylog.log(0,"modify SELinux user record", name, seuser, seroles, serange, oldseuser, oldseroles, olrserange)
			raise error
		
		mylog.log(1,"modify SELinux user record", name, seuser, seroles, serange, oldseuser, oldseroles, olrserange)
		semanage_user_key_free(k)
		semanage_user_free(u)

	def delete(self, name):
		try:
			(rc,k) = semanage_user_key_create(self.sh, name)
			if rc < 0:
				raise ValueError("Could not create a key for %s" % name)
			
			(rc,exists) = semanage_user_exists(self.sh, k)
			if rc < 0:
				raise ValueError("Could not check if SELinux user %s is defined" % name)		
			if not exists:
				raise ValueError("SELinux user %s is not defined" % name)

			(rc,exists) = semanage_user_exists_local(self.sh, k)
			if rc < 0:
				raise ValueError("Could not check if SELinux user %s is defined" % name)
			if not exists:
				raise ValueError("SELinux user %s is defined in policy, cannot be deleted" % name)
			
			rc = semanage_begin_transaction(self.sh)
			if rc < 0:
				raise ValueError("Could not start semanage transaction")

			rc = semanage_user_del_local(self.sh, k)
			if rc < 0:
				raise ValueError("Could not delete SELinux user %s" % name)

			rc = semanage_commit(self.sh)
			if rc < 0:
				raise ValueError("Could not delete SELinux user %s" % name)
		except ValueError, error:
			mylog.log(0,"delete SELinux user record", name)
			raise error
		
		mylog.log(1,"delete SELinux user record", name)
		semanage_user_key_free(k)		

	def get_all(self):
		ddict={}
		(rc, self.ulist) = semanage_user_list(self.sh)
		if rc < 0:
			raise ValueError("Could not list SELinux users")

		for u in self.ulist:
			name = semanage_user_get_name(u)
			(rc, rlist) = semanage_user_get_roles(self.sh, u)
			if rc < 0:
				raise ValueError("Could not list roles for user %s" % name)

			roles = string.join(rlist, ' ');
			ddict[semanage_user_get_name(u)] = (semanage_user_get_mlslevel(u), semanage_user_get_mlsrange(u), roles)

		return ddict

	def list(self, heading=1):
		ddict=self.get_all()
		keys=ddict.keys()
		keys.sort()
		if is_mls_enabled == 1:
			if heading:
				print "\n%-15s %-10s %-30s" % ("", "MLS/", "MLS/")
				print "%-15s %-10s %-30s %s\n" % ("SELinux User", "MCS Level", "MCS Range", "SELinux Roles")
			for k in keys:
				print "%-15s %-10s %-30s %s" % (k, translate(ddict[k][0]), translate(ddict[k][1]), ddict[k][2])
		else:
			if heading:
				print "%-15s %s\n" % ("SELinux User", "SELinux Roles")
			for k in keys:
				print "%-15s %s" % (k, ddict[k][2])

class portRecords(semanageRecords):
	def __init__(self):
		semanageRecords.__init__(self)

	def __genkey(self, port, proto):
		if proto == "tcp":
			proto_d=SEMANAGE_PROTO_TCP
		else:
			if proto == "udp":
				proto_d=SEMANAGE_PROTO_UDP
			else:
				raise ValueError("Protocol udp or tcp is required")
		if port == "":
			raise ValueError("Port is required")
			
		ports=port.split("-")
		if len(ports) == 1:
			low=string.atoi(ports[0])
			high=string.atoi(ports[0])
		else:
			low=string.atoi(ports[0])
			high=string.atoi(ports[1])

		(rc,k) = semanage_port_key_create(self.sh, low, high, proto_d)
		if rc < 0:
			raise ValueError("Could not create a key for %s/%s" % (proto, port))
		return ( k, proto_d, low, high )

	def add(self, port, proto, serange, type):
		if is_mls_enabled == 1:
			if serange == "":
				serange="s0"
			else:
				serange=untranslate(serange)
			
		if type == "":
			raise ValueError("Type is required")

		( k, proto_d, low, high ) = self.__genkey(port, proto)			

		(rc,exists) = semanage_port_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if port %s/%s is defined" % (proto, port))
		if exists:
			raise ValueError("Port %s/%s already defined" % (proto, port))

		(rc,p) = semanage_port_create(self.sh)
		if rc < 0:
			raise ValueError("Could not create port for %s/%s" % (proto, port))
		
		semanage_port_set_proto(p, proto_d)
		semanage_port_set_range(p, low, high)
		(rc, con) = semanage_context_create(self.sh)
		if rc < 0:
			raise ValueError("Could not create context for %s/%s" % (proto, port))

		rc = semanage_context_set_user(self.sh, con, "system_u")
		if rc < 0:
			raise ValueError("Could not set user in port context for %s/%s" % (proto, port))

		rc = semanage_context_set_role(self.sh, con, "object_r")
		if rc < 0:
			raise ValueError("Could not set role in port context for %s/%s" % (proto, port))

		rc = semanage_context_set_type(self.sh, con, type)
		if rc < 0:
			raise ValueError("Could not set type in port context for %s/%s" % (proto, port))

		rc = semanage_context_set_mls(self.sh, con, serange)
		if rc < 0:
			raise ValueError("Could not set mls fields in port context for %s/%s" % (proto, port))

		rc = semanage_port_set_con(self.sh, p, con)
		if rc < 0:
			raise ValueError("Could not set port context for %s/%s" % (proto, port))

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_port_modify_local(self.sh, k, p)
		if rc < 0:
			raise ValueError("Could not add port %s/%s" % (proto, port))
	
		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not add port %s/%s" % (proto, port))

		semanage_context_free(con)
		semanage_port_key_free(k)
		semanage_port_free(p)

	def modify(self, port, proto, serange, setype):
		if serange == "" and setype == "":
			if is_mls_enabled == 1:
				raise ValueError("Requires setype or serange")
			else:
				raise ValueError("Requires setype")

		( k, proto_d, low, high ) = self.__genkey(port, proto)

		(rc,exists) = semanage_port_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if port %s/%s is defined" % (proto, port))
		if not exists:
			raise ValueError("Port %s/%s is not defined" % (proto,port))
	
		(rc,p) = semanage_port_query(self.sh, k)
		if rc < 0:
			raise ValueError("Could not query port %s/%s" % (proto, port))

		con = semanage_port_get_con(p)
			
		if serange != "":
			semanage_context_set_mls(self.sh, con, untranslate(serange))
		if setype != "":
			semanage_context_set_type(self.sh, con, setype)

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_port_modify_local(self.sh, k, p)
		if rc < 0:
			raise ValueError("Could not modify port %s/%s" % (proto, port))

		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not modify port %s/%s" % (proto, port))
		
		semanage_port_key_free(k)
		semanage_port_free(p)

	def delete(self, port, proto):
		( k, proto_d, low, high ) = self.__genkey(port, proto)
		(rc,exists) = semanage_port_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if port %s/%s is defined" % (proto, port))
		if not exists:
			raise ValueError("Port %s/%s is not defined" % (proto, port))
		
		(rc,exists) = semanage_port_exists_local(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if port %s/%s is defined" % (proto, port))
		if not exists:
			raise ValueError("Port %s/%s is defined in policy, cannot be deleted" % (proto, port))

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_port_del_local(self.sh, k)
		if rc < 0:
			raise ValueError("Could not delete port %s/%s" % (proto, port))

		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not delete port %s/%s" % (proto, port))
		
		semanage_port_key_free(k)

	def get_all(self):
		ddict={}
		(rc, self.plist) = semanage_port_list(self.sh)
		if rc < 0:
			raise ValueError("Could not list ports")

		for port in self.plist:
			con = semanage_port_get_con(port)
			ctype = semanage_context_get_type(con)
			if ctype == "reserved_port_t":
				continue
			level = semanage_context_get_mls(con)
			proto = semanage_port_get_proto(port)
			proto_str = semanage_port_get_proto_str(proto)
			low = semanage_port_get_low(port)
			high = semanage_port_get_high(port)
			ddict[(low, high)]=(ctype, proto_str, level)
		return ddict

	def get_all_by_type(self):
		ddict={}
		(rc, self.plist) = semanage_port_list(self.sh)
		if rc < 0:
			raise ValueError("Could not list ports")

		for port in self.plist:
			con = semanage_port_get_con(port)
			ctype = semanage_context_get_type(con)
			if ctype == "reserved_port_t":
				continue
			proto = semanage_port_get_proto(port)
			proto_str = semanage_port_get_proto_str(proto)
			low = semanage_port_get_low(port)
			high = semanage_port_get_high(port)
			if (ctype, proto_str) not in ddict.keys():
				ddict[(ctype,proto_str)]=[]
			if low == high:
				ddict[(ctype,proto_str)].append("%d" % low)
			else:
				ddict[(ctype,proto_str)].append("%d-%d" % (low, high))
		return ddict

	def list(self, heading=1):
		if heading:
			print "%-30s %-8s %s\n" % ("SELinux Port Type", "Proto", "Port Number")
		ddict=self.get_all_by_type()
		keys=ddict.keys()
		keys.sort()
		for i in keys:
			rec = "%-30s %-8s " % i
			rec += "%s" % ddict[i][0]
			for p in ddict[i][1:]:
				rec += ", %s" % p
			print rec

class interfaceRecords(semanageRecords):
	def __init__(self):
		semanageRecords.__init__(self)

	def add(self, interface, serange, ctype):
		if is_mls_enabled == 1:
			if serange == "":
				serange="s0"
			else:
				serange=untranslate(serange)
			
		if ctype == "":
			raise ValueError("SELinux Type is required")

		(rc,k) = semanage_iface_key_create(self.sh, interface)
		if rc < 0:
			raise ValueError("Could not create key for %s" % interface)

		(rc,exists) = semanage_iface_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if interface %s is defined" % interface)
		if exists:
			raise ValueError("Interface %s already defined" % interface)

		(rc,iface) = semanage_iface_create(self.sh)
		if rc < 0:
			raise ValueError("Could not create interface for %s" % interface)
		
		rc = semanage_iface_set_name(self.sh, iface, interface)
		(rc, con) = semanage_context_create(self.sh)
		if rc < 0:
			raise ValueError("Could not create context for %s" % interface)

		rc = semanage_context_set_user(self.sh, con, "system_u")
		if rc < 0:
			raise ValueError("Could not set user in interface context for %s" % interface)

		rc = semanage_context_set_role(self.sh, con, "object_r")
		if rc < 0:
			raise ValueError("Could not set role in interface context for %s" % interface)

		rc = semanage_context_set_type(self.sh, con, ctype)
		if rc < 0:
			raise ValueError("Could not set type in interface context for %s" % interface)

		rc = semanage_context_set_mls(self.sh, con, serange)
		if rc < 0:
			raise ValueError("Could not set mls fields in interface context for %s" % interface)

		rc = semanage_iface_set_ifcon(self.sh, iface, con)
		if rc < 0:
			raise ValueError("Could not set interface context for %s" % interface)

		rc = semanage_iface_set_msgcon(self.sh, iface, con)
		if rc < 0:
			raise ValueError("Could not set message context for %s" % interface)

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_iface_modify_local(self.sh, k, iface)
		if rc < 0:
			raise ValueError("Could not add interface %s" % interface)

		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not add interface %s" % interface)

		semanage_context_free(con)
		semanage_iface_key_free(k)
		semanage_iface_free(iface)

	def modify(self, interface, serange, setype):
		if serange == "" and setype == "":
			raise ValueError("Requires setype or serange")

		(rc,k) = semanage_iface_key_create(self.sh, interface)
		if rc < 0:
			raise ValueError("Could not create key for %s" % interface)

		(rc,exists) = semanage_iface_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if interface %s is defined" % interface)
		if not exists:
			raise ValueError("Interface %s is not defined" % interface)
	
		(rc,iface) = semanage_iface_query(self.sh, k)
		if rc < 0:
			raise ValueError("Could not query interface %s" % interface)

		con = semanage_iface_get_ifcon(iface)
			
		if serange != "":
			semanage_context_set_mls(self.sh, con, untranslate(serange))
		if setype != "":
			semanage_context_set_type(self.sh, con, setype)

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_iface_modify_local(self.sh, k, iface)
		if rc < 0:
			raise ValueError("Could not modify interface %s" % interface)
		
		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not modify interface %s" % interface)

		semanage_iface_key_free(k)
		semanage_iface_free(iface)

	def delete(self, interface):
		(rc,k) = semanage_iface_key_create(self.sh, interface)
		if rc < 0:
			raise ValueError("Could not create key for %s" % interface)

		(rc,exists) = semanage_iface_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if interface %s is defined" % interface)
		if not exists:
			raise ValueError("Interface %s is not defined" % interface)

		(rc,exists) = semanage_iface_exists_local(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if interface %s is defined" % interface)
		if not exists:
			raise ValueError("Interface %s is defined in policy, cannot be deleted" % interface)

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_iface_del_local(self.sh, k)
		if rc < 0:
			raise ValueError("Could not delete interface %s" % interface)

		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not delete interface %s" % interface)
		
		semanage_iface_key_free(k)

	def get_all(self):
		ddict={}
		(rc, self.ilist) = semanage_iface_list(self.sh)
		if rc < 0:
			raise ValueError("Could not list interfaces")

		for interface in self.ilist:
			con = semanage_iface_get_ifcon(interface)
			ddict[semanage_iface_get_name(interface)]=(semanage_context_get_user(con), semanage_context_get_role(con), semanage_context_get_type(con), semanage_context_get_mls(con))

		return ddict
			
	def list(self, heading=1):
		if heading:
			print "%-30s %s\n" % ("SELinux Interface", "Context")
		ddict=self.get_all()
		keys=ddict.keys()
		keys.sort()
		for k in keys:
			print "%-30s %s:%s:%s:%s " % (k,ddict[k][0], ddict[k][1],ddict[k][2], translate(ddict[k][3], False))
			
class fcontextRecords(semanageRecords):
	def __init__(self):
		semanageRecords.__init__(self)
		self.file_types={}
		self.file_types[""]   = SEMANAGE_FCONTEXT_ALL;
		self.file_types["all files"] = SEMANAGE_FCONTEXT_ALL;
		self.file_types["--"] = SEMANAGE_FCONTEXT_REG;
		self.file_types["regular file"] = SEMANAGE_FCONTEXT_REG;
		self.file_types["-d"] = SEMANAGE_FCONTEXT_DIR;
		self.file_types["directory"] = SEMANAGE_FCONTEXT_DIR;
		self.file_types["-c"] = SEMANAGE_FCONTEXT_CHAR;
		self.file_types["character device"] = SEMANAGE_FCONTEXT_CHAR;
		self.file_types["-b"] = SEMANAGE_FCONTEXT_BLOCK;
		self.file_types["block device"] = SEMANAGE_FCONTEXT_BLOCK;
		self.file_types["-s"] = SEMANAGE_FCONTEXT_SOCK;
		self.file_types["socket"] = SEMANAGE_FCONTEXT_SOCK;
		self.file_types["-l"] = SEMANAGE_FCONTEXT_LINK;
		self.file_types["symbolic link"] = SEMANAGE_FCONTEXT_LINK;
		self.file_types["-p"] = SEMANAGE_FCONTEXT_PIPE;
		self.file_types["named pipe"] = SEMANAGE_FCONTEXT_PIPE;
		
		
	def add(self, target, type, ftype="", serange="", seuser="system_u"):
		if seuser == "":
			seuser="system_u"
		if is_mls_enabled == 1:
			if serange == "":
				serange="s0"
			else:
				serange=untranslate(serange)
			
		if type == "":
			raise ValueError("SELinux Type is required")

		(rc,k) = semanage_fcontext_key_create(self.sh, target, self.file_types[ftype])
		if rc < 0:
			raise ValueError("Could not create key for %s" % target)

		(rc,exists) = semanage_fcontext_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if file context for %s is defined" % target)
		if exists:
			raise ValueError("File context for %s already defined" % target)

		(rc,fcontext) = semanage_fcontext_create(self.sh)
		if rc < 0:
			raise ValueError("Could not create file context for %s" % target)
		
		rc = semanage_fcontext_set_expr(self.sh, fcontext, target)
		(rc, con) = semanage_context_create(self.sh)
		if rc < 0:
			raise ValueError("Could not create context for %s" % target)

		rc = semanage_context_set_user(self.sh, con, seuser)
		if rc < 0:
			raise ValueError("Could not set user in file context for %s" % target)
		
		rc = semanage_context_set_role(self.sh, con, "object_r")
		if rc < 0:
			raise ValueError("Could not set role in file context for %s" % target)

		rc = semanage_context_set_type(self.sh, con, type)
		if rc < 0:
			raise ValueError("Could not set type in file context for %s" % target)

		rc = semanage_context_set_mls(self.sh, con, serange)
		if rc < 0:
			raise ValueError("Could not set mls fields in file context for %s" % target)

		semanage_fcontext_set_type(fcontext, self.file_types[ftype])

		rc = semanage_fcontext_set_con(self.sh, fcontext, con)
		if rc < 0:
			raise ValueError("Could not set file context for %s" % target)

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_fcontext_modify_local(self.sh, k, fcontext)
		if rc < 0:
			raise ValueError("Could not add file context for %s" % target)

		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not add file context for %s" % target)

		semanage_context_free(con)
		semanage_fcontext_key_free(k)
		semanage_fcontext_free(fcontext)

	def modify(self, target, setype, ftype, serange, seuser):
		if serange == "" and setype == "" and seuser == "":
			raise ValueError("Requires setype, serange or seuser")

		(rc,k) = semanage_fcontext_key_create(self.sh, target, self.file_types[ftype])
		if rc < 0:
			raise ValueError("Could not create a key for %s" % target)

		(rc,exists) = semanage_fcontext_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if file context for %s is defined" % target)
		if not exists:
			raise ValueError("File context for %s is not defined" % target)
		
		(rc,fcontext) = semanage_fcontext_query(self.sh, k)
		if rc < 0:
			raise ValueError("Could not query file context for %s" % target)

		con = semanage_fcontext_get_con(fcontext)
			
		if serange != "":
			semanage_context_set_mls(self.sh, con, untranslate(serange))
		if seuser != "":
			semanage_context_set_user(self.sh, con, seuser)	
		if setype != "":
			semanage_context_set_type(self.sh, con, setype)

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_fcontext_modify_local(self.sh, k, fcontext)
		if rc < 0:
			raise ValueError("Could not modify file context for %s" % target)

		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not modify file context for %s" % target)
		
		semanage_fcontext_key_free(k)
		semanage_fcontext_free(fcontext)

	def delete(self, target, ftype):
		(rc,k) = semanage_fcontext_key_create(self.sh, target, self.file_types[ftype])
		if rc < 0:
			raise ValueError("Could not create a key for %s" % target)

		(rc,exists) = semanage_fcontext_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if file context for %s is defined" % target)
		if not exists:
			raise ValueError("File context for %s is not defined" % target)
		
		(rc,exists) = semanage_fcontext_exists_local(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if file context for %s is defined" % target)
		if not exists:
			raise ValueError("File context for %s is defined in policy, cannot be deleted" % target)

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_fcontext_del_local(self.sh, k)
		if rc < 0:
			raise ValueError("Could not delete file context for %s" % target)

		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not delete file context for %s" % target)
		
		semanage_fcontext_key_free(k)		

	def get_all(self):
		ddict={}
		(rc, self.flist) = semanage_fcontext_list(self.sh)
		if rc < 0:
			raise ValueError("Could not list file contexts")

		for fcontext in self.flist:
			expr = semanage_fcontext_get_expr(fcontext)
			ftype = semanage_fcontext_get_type(fcontext)
			ftype_str = semanage_fcontext_get_type_str(ftype)
			con = semanage_fcontext_get_con(fcontext)
			if con:
				ddict[expr, ftype_str] = (semanage_context_get_user(con), semanage_context_get_role(con), semanage_context_get_type(con), semanage_context_get_mls(con))
			else:
				ddict[expr, ftype_str] = con

		return ddict
			
	def list(self, heading=1):
		if heading:
			print "%-50s %-18s %s\n" % ("SELinux fcontext", "type", "Context")
		ddict=self.get_all()
		keys=ddict.keys()
		for k in keys:
			if ddict[k]:
				print "%-50s %-18s %s:%s:%s:%s " % (k[0], k[1], ddict[k][0], ddict[k][1],ddict[k][2], translate(ddict[k][3],False))
			else:
				print "%-50s %-18s <<None>>" % (k[0], k[1])
				
class booleanRecords(semanageRecords):
	def __init__(self):
		semanageRecords.__init__(self)
		
	def modify(self, name, value = ""):
		if value == "":
			raise ValueError("Requires value")

		(rc,k) = semanage_bool_key_create(self.sh, name)
		if rc < 0:
			raise ValueError("Could not create a key for %s" % name)

		(rc,exists) = semanage_bool_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if boolean %s is defined" % name)
		if not exists:
			raise ValueError("Boolean %s is not defined" % name)	

		(rc,b) = semanage_bool_query(self.sh, k)
		if rc < 0:
			raise ValueError("Could not query file context %s" % name)

		if value != "":
			nvalue = string.atoi(value)
			semanage_bool_set_value(b, nvalue)

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_bool_modify_local(self.sh, k, b)
		if rc < 0:
			raise ValueError("Could not modify boolean %s" % name)

		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not modify boolean %s" % name)
		
		semanage_bool_key_free(k)
		semanage_bool_free(b)

	def delete(self, name):
		(rc,k) = semanage_bool_key_create(self.sh, name)
		if rc < 0:
			raise ValueError("Could not create a key for %s" % name)

		(rc,exists) = semanage_bool_exists(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if boolean %s is defined" % name)
		if not exists:
			raise ValueError("Boolean %s is not defined" % name)
	
		(rc,exists) = semanage_bool_exists_local(self.sh, k)
		if rc < 0:
			raise ValueError("Could not check if boolean %s is defined" % name)
		if not exists:
			raise ValueError("Boolean %s is defined in policy, cannot be deleted" % name)

		rc = semanage_begin_transaction(self.sh)
		if rc < 0:
			raise ValueError("Could not start semanage transaction")

		rc = semanage_fcontext_del_local(self.sh, k)
		if rc < 0:
			raise ValueError("Could not delete boolean %s" % name)
	
		rc = semanage_commit(self.sh)
		if rc < 0:
			raise ValueError("Could not delete boolean %s" % name)
		
		semanage_bool_key_free(k)

	def get_all(self):
		ddict={}
		(rc, self.blist) = semanage_bool_list(self.sh)
		if rc < 0:
			raise ValueError("Could not list booleans")

		for boolean in self.blist:
			name = semanage_bool_get_name(boolean)
			value = semanage_bool_get_value(boolean)
			ddict[name] = value

		return ddict
			
	def list(self, heading=1):
		if heading:
			print "%-50s %-18s\n" % ("SELinux boolean", "value")
		ddict=self.get_all()
		keys=ddict.keys()
		for k in keys:
			if ddict[k]:
				print "%-50s %-18s " % (k[0], ddict[k][0])
