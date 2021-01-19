#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Univention AD Connector
#  Basic class for the UCS connector part
#
# Copyright 2004-2021 Univention GmbH
#
# https://www.univention.de/
#
# All rights reserved.
#
# The source code of this program is made available
# under the terms of the GNU Affero General Public License version 3
# (GNU AGPL V3) as published by the Free Software Foundation.
#
# Binary versions of this program provided by Univention to you as
# well as other copyrighted, protected or trademarked materials like
# Logos, graphics, fonts, specific documentations and configurations,
# cryptographic keys etc. are subject to a license agreement between
# you and Univention and not subject to the GNU AGPL V3.
#
# In the case you use this program under the terms of the GNU AGPL V3,
# the program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <https://www.gnu.org/licenses/>.

from __future__ import print_function
import sys
from six.moves import cPickle as pickle
import os
import types
import collections
import random
import traceback
import copy
import time
import ldap
import univention.uldap
import univention.admin.uldap
import univention.admin.modules
import univention.admin.objects
from univention.connector.adcache import ADCache
import univention.debug2 as ud
from samba.ndr import ndr_unpack
from samba.dcerpc import misc
from signal import signal, SIGTERM, SIG_DFL

import sqlite3 as lite

term_signal_caught = False

univention.admin.modules.update()

# update choices-lists which are defined in LDAP
univention.admin.syntax.update_choices()

try:
	univention.admin.handlers.disable_ad_restrictions(disable=False)
except AttributeError:
	ud.debug(ud.LDAP, ud.INFO, 'univention.admin.handlers.disable_ad_restrictions is not available')


# util functions defined during mapping

def make_lower(mlValue):
	'''
	lower string cases for mlValue which can be string or a list of values which can be given to mlValue
	'''
	if hasattr(mlValue, 'lower'):
		return mlValue.lower()
	if isinstance(mlValue, type([])):
		return [make_lower(x) for x in mlValue]
	return mlValue


password_charsets = [
	'abcdefghijklmnopqrstuvwxyz',
	'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
	'0123456789',
	'^!\$%&/()=?{[]}+~#-_.:,;<>|\\',
]


def generate_strong_password(length=24):
	pwd = []
	charset = random.choice(password_charsets)
	while len(pwd) < length:
		pwd.append(random.choice(charset))
		charset = random.choice(list(set(password_charsets) - set([charset])))
	return "".join(pwd)


def set_ucs_passwd_user(connector, key, ucs_object):
	'''
	set random password to fulfill required values
	'''
	ucs_object['password'] = generate_strong_password()


def check_ucs_lastname_user(connector, key, ucs_object):
	'''
	check if required values for lastname are set
	'''
	if 'lastname' not in ucs_object or not ucs_object['lastname']:
		ucs_object['lastname'] = ucs_object.get('username')


def set_primary_group_user(connector, key, ucs_object):
	'''
	check if correct primary group is set
	'''
	connector.set_primary_group_to_ucs_user(key, ucs_object)

# compare functions

# helper


def dictonary_lowercase(dict):
	if isinstance(dict, type({})):
		ndict = {}
		for key in dict.keys():
			ndict[key] = []
			for val in dict[key]:
				ndict[key].append(val.lower())
		return ndict
	elif isinstance(dict, type([])):
		nlist = []
		for d in dict:
			nlist.append(d.lower())
		return nlist
	else:
		try:  # should be string
			return dict.lower()
		except (ldap.SERVER_DOWN, SystemExit):
			raise
		except:  # FIXME: which exception is to be caught?
			pass


def compare_lowercase(val1, val2):
	try:  # TODO: fails if conversion to ascii-str raises exception
		if dictonary_lowercase(val1) == dictonary_lowercase(val2):
			return True
		else:
			return False
	except Exception:  # FIXME: which exception is to be caught?
		return False

# helper classes


class configdb:

	def __init__(self, filename):
		self.filename = filename
		self._dbcon = lite.connect(self.filename)

	def get(self, section, option):
		for i in [1, 2]:
			try:
				cur = self._dbcon.cursor()
				cur.execute("SELECT value FROM '%s' WHERE key=?" % section, (option,))
				rows = cur.fetchall()
				cur.close()
				if rows:
					return rows[0][0]
				return ''
			except lite.Error:
				if self._dbcon:
					self._dbcon.close()
				self._dbcon = lite.connect(self.filename)

	def set(self, section, option, value):
		for i in [1, 2]:
			try:
				cur = self._dbcon.cursor()
				cur.execute("""
		INSERT OR REPLACE INTO '%s' (key,value)
			VALUES (  ?, ?
		);""" % section, [option, value])
				self._dbcon.commit()
				cur.close()
				return
			except lite.Error as e:
				ud.debug(ud.LDAP, ud.WARN, "sqlite: %s" % e)
				if self._dbcon:
					self._dbcon.close()
				self._dbcon = lite.connect(self.filename)

	def items(self, section):
		for i in [1, 2]:
			try:
				cur = self._dbcon.cursor()
				cur.execute("SELECT * FROM '%s'" % (section))
				rows = cur.fetchall()
				cur.close()
				return rows
			except lite.Error as e:
				ud.debug(ud.LDAP, ud.WARN, "sqlite: %s" % e)
				if self._dbcon:
					self._dbcon.close()
				self._dbcon = lite.connect(self.filename)

	def remove_option(self, section, option):
		for i in [1, 2]:
			try:
				cur = self._dbcon.cursor()
				cur.execute("DELETE FROM '%s' WHERE key=?" % section, (option,))
				self._dbcon.commit()
				cur.close()
				return
			except lite.Error as e:
				ud.debug(ud.LDAP, ud.WARN, "sqlite: %s" % e)
				if self._dbcon:
					self._dbcon.close()
				self._dbcon = lite.connect(self.filename)

	def has_section(self, section):
		for i in [1, 2]:
			try:
				cur = self._dbcon.cursor()
				cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='%s';" % section)
				self._dbcon.commit()
				rows = cur.fetchone()
				cur.close()
				if rows:
					return True
				else:
					return False
			except lite.Error as e:
				ud.debug(ud.LDAP, ud.WARN, "sqlite: %s" % e)
				if self._dbcon:
					self._dbcon.close()
				self._dbcon = lite.connect(self.filename)

	def add_section(self, section):
		for i in [1, 2]:
			try:
				cur = self._dbcon.cursor()
				cur.execute("CREATE TABLE IF NOT EXISTS '%s'(Key TEXT PRIMARY KEY, Value TEXT)" % section)
				self._dbcon.commit()
				cur.close()
				return
			except lite.Error as e:
				ud.debug(ud.LDAP, ud.WARN, "sqlite: %s" % e)
				if self._dbcon:
					self._dbcon.close()
				self._dbcon = lite.connect(self.filename)

	def has_option(self, section, option):
		for i in [1, 2]:
			try:
				cur = self._dbcon.cursor()
				cur.execute("SELECT value FROM '%s' WHERE key=?" % section, (option,))
				rows = cur.fetchall()
				cur.close()
				if rows:
					return True
				else:
					return False
			except lite.Error as e:
				ud.debug(ud.LDAP, ud.WARN, "sqlite: %s" % e)
				if self._dbcon:
					self._dbcon.close()
				self._dbcon = lite.connect(self.filename)












class attribute:

	def __init__(self, ucs_attribute='', ldap_attribute='', con_attribute='', con_other_attribute='', required=0, single_value=False, compare_function='', con_value_merge_function='', mapping=(), reverse_attribute_check=False, sync_mode='sync', con_depends=''):
		self.ucs_attribute = ucs_attribute
		self.ldap_attribute = ldap_attribute
		self.con_attribute = con_attribute
		self.con_other_attribute = con_other_attribute
		self.con_depends = con_depends
		self.required = required
		self.compare_function = compare_function
		self.con_value_merge_function = con_value_merge_function
		if mapping:
			self.mapping = mapping
		# Make a reverse check of this mapping. This is necassary if the attribute is
		# available in UCS and in AD but the mapping is not 1:1.
		# For example the homeDirectory attribute is in UCS and in AD, but the mapping is
		# from homeDirectory in AD to sambaHomePath in UCS. The homeDirectory in UCS is not
		# considered.
		# Seee https://forge.univention.org/bugzilla/show_bug.cgi?id=25823
		self.reverse_attribute_check = reverse_attribute_check
		self.sync_mode = sync_mode
		self.single_value = single_value


class property:

	def __init__(
		self,
		ucs_default_dn='',
		con_default_dn='',
		ucs_module='',
		ucs_module_others=[],
		sync_mode='',
		scope='',
		con_search_filter='',
		ignore_filter=None,
		match_filter=None,
		ignore_subtree=[],
		con_create_objectclass=[],
		con_create_attributes=[],
		dn_mapping_function=[],
		attributes=None,
		ucs_create_functions=[],
		post_con_create_functions=[],
		post_con_modify_functions=[],
		post_ucs_modify_functions=[],
		post_attributes=None,
		mapping_table=None,
		position_mapping=[]):

		self.ucs_default_dn = ucs_default_dn

		self.con_default_dn = con_default_dn

		self.ucs_module = ucs_module
		self.ucs_module_others = ucs_module_others
		self.sync_mode = sync_mode

		self.scope = scope

		self.con_search_filter = con_search_filter
		self.ignore_filter = ignore_filter
		self.match_filter = match_filter
		self.ignore_subtree = ignore_subtree

		self.con_create_objectclass = con_create_objectclass
		self.con_create_attributes = con_create_attributes
		self.dn_mapping_function = dn_mapping_function
		self.attributes = attributes

		self.ucs_create_functions = ucs_create_functions

		self.post_con_create_functions = post_con_create_functions
		self.post_con_modify_functions = post_con_modify_functions
		self.post_ucs_modify_functions = post_ucs_modify_functions

		self.post_attributes = post_attributes
		self.mapping_table = mapping_table
		self.position_mapping = position_mapping




class ucs(object):

	def __init__(self, CONFIGBASENAME, _property, configRegistry, listener_dir, logfilename, debug_level):

		self.CONFIGBASENAME = CONFIGBASENAME

		self.configRegistry = configRegistry
		self.property = _property  # this is the mapping!

		self.init_debug()

		self.listener_dir = listener_dir

		configdbfile = '/etc/univention/%s/internal.sqlite' % self.CONFIGBASENAME
		self.config = configdb(configdbfile)


		adcachedbfile='/etc/univention/%s/adcache.sqlite' % self.CONFIGBASENAME
		self.adcache = ADCache(adcachedbfile)


		self.open_ucs()

		for section in ['DN Mapping UCS', 'DN Mapping CON', 'UCS rejected', 'UCS deleted']:
			if not self.config.has_section(section):
				self.config.add_section(section)

		irrelevant_attributes = self.configRegistry.get('%s/ad/mapping/attributes/irrelevant' % (self.CONFIGBASENAME,), '')
		self.irrelevant_attributes = set(irrelevant_attributes.split(','))

		ud.debug(ud.LDAP, ud.INFO, "init finished")

	def __del__(self):
		self.close_debug()

	def dn_mapped_to_base(self, dn, base):
		if dn.endswith(base):
			return dn
		elif dn.lower().endswith(base.lower()):
			return ''.join((dn[:-len(base)], base))
		else:
			return dn

	def open_ucs(self):
		bindpw_file = self.configRegistry.get('%s/ldap/bindpw' % self.CONFIGBASENAME, '/etc/ldap.secret')
		binddn = self.configRegistry.get('%s/ldap/binddn' % self.CONFIGBASENAME, 'cn=admin,' + self.configRegistry['ldap/base'])
		with open(bindpw_file) as fd:
			bindpw = fd.read().rstrip()

		host = self.configRegistry.get('%s/ldap/server' % self.CONFIGBASENAME, self.configRegistry.get('ldap/master'))

		try:
			port = int(self.configRegistry.get('%s/ldap/port' % self.CONFIGBASENAME, self.configRegistry.get('ldap/master/port', 7389)))
		except ValueError:
			port = 7389

		self.lo = univention.admin.uldap.access(host=host, port=port, base=self.configRegistry['ldap/base'], binddn=binddn, bindpw=bindpw, start_tls=2, follow_referral=True)

	def search_ucs(self, filter='(objectClass=*)', base='', scope='sub', attr=[], unique=0, required=0, timeout=-1, sizelimit=0):
		try:
			result = self.lo.search(filter=filter, base=base, scope=scope, attr=attr, unique=unique, required=required, timeout=timeout, sizelimit=sizelimit)
			return result
		except univention.admin.uexceptions.ldapError as search_exception:
			ud.debug(ud.LDAP, ud.INFO, 'Lost connection to the LDAP server. Trying to reconnect ...')
			try:
				self.open_ucs()
			except ldap.SERVER_DOWN:
				ud.debug(ud.LDAP, ud.INFO, 'LDAP-Server seems to be down')
				raise search_exception

	def init_debug(self):
		if '%s/debug/function' % self.CONFIGBASENAME in self.baseConfig:
			try:
				function_level = int(self.baseConfig['%s/debug/function' % self.CONFIGBASENAME])
			except (ldap.SERVER_DOWN, SystemExit):
				raise
			except:  # FIXME: which exception is to be caught?
				function_level = 0
		else:
			function_level = 0
		ud.init('/var/log/univention/%s.log' % self.CONFIGBASENAME, 1, function_level)
		if '%s/debug/level' % self.CONFIGBASENAME in self.baseConfig:
			debug_level = self.baseConfig['%s/debug/level' % self.CONFIGBASENAME]
		else:
			debug_level = 2
		ud.set_level(ud.LDAP, int(debug_level))

	def close_debug(self):
		ud.debug(ud.LDAP, ud.INFO, "close debug")

	def _get_config_option(self, section, option):
		return self.config.get(section, option)

	def _set_config_option(self, section, option, value):
		self.config.set(section, option, value)

	def _remove_config_option(self, section, option):
		self.config.remove_option(section, option)

	def _get_config_items(self, section):
		return self.config.items(section)

	def _save_rejected_ucs(self, filename, dn):
		self._set_config_option('UCS rejected', filename, dn)

	def _remove_rejected_ucs(self, filename):
		self._remove_config_option('UCS rejected', filename)

	def _list_rejected_ucs(self):
		result = []
		for i in self._get_config_items('UCS rejected'):
			result.append(i)
		return result

	def _list_rejected_filenames_ucs(self):
		result = []
		for filename, dn in self._get_config_items('UCS rejected'):
			result.append(filename)
		return result

	def list_rejected_ucs(self):
		return self._get_config_items('UCS rejected')

	def _encode_dn_as_config_option(self, dn):
		return dn

	def _decode_dn_from_config_option(self, dn):
		if dn:
			return dn
		return ''

	def _set_dn_mapping(self, dn_ucs, dn_con):
		self._set_config_option('DN Mapping UCS', self._encode_dn_as_config_option(dn_ucs.lower()), self._encode_dn_as_config_option(dn_con.lower()))
		self._set_config_option('DN Mapping CON', self._encode_dn_as_config_option(dn_con.lower()), self._encode_dn_as_config_option(dn_ucs.lower()))

	def _remove_dn_mapping(self, dn_ucs, dn_con):
		# delete all if mapping failed in the past
		dn_con_mapped = self._get_dn_by_ucs(dn_ucs.lower())
		dn_ucs_mapped = self._get_dn_by_con(dn_con.lower())
		dn_con_re_mapped = self._get_dn_by_ucs(dn_ucs_mapped.lower())
		dn_ucs_re_mapped = self._get_dn_by_con(dn_con_mapped.lower())

		for ucs, con in [(dn_ucs, dn_con), (dn_ucs_mapped, dn_con_mapped), (dn_ucs_re_mapped, dn_con_re_mapped)]:
			if con:
				self._remove_config_option('DN Mapping CON', self._encode_dn_as_config_option(con.lower()))
			if ucs:
				self._remove_config_option('DN Mapping UCS', self._encode_dn_as_config_option(ucs.lower()))

	def _get_dn_by_ucs(self, dn_ucs):
		return self._decode_dn_from_config_option(self._get_config_option('DN Mapping UCS', self._encode_dn_as_config_option(dn_ucs.lower())))

	def get_dn_by_ucs(self, dn_ucs):
		if not dn_ucs:
			return dn_ucs
		dn = self._get_dn_by_ucs(dn_ucs)
		return self.dn_mapped_to_base(dn, self.lo_ad.base)

	def _get_dn_by_con(self, dn_con):
		if not dn_con:
			return dn_con
		return self._decode_dn_from_config_option(self._get_config_option('DN Mapping CON', self._encode_dn_as_config_option(dn_con.lower())))

	def get_dn_by_con(self, dn_con):
		dn = self._get_dn_by_con(dn_con)
		return self.dn_mapped_to_base(dn, self.lo.base)

	def _check_dn_mapping(self, dn_ucs, dn_con):
		dn_con_mapped = self._get_dn_by_ucs(dn_ucs.lower())
		dn_ucs_mapped = self._get_dn_by_con(dn_con.lower())
		if dn_con_mapped != dn_con.lower() or dn_ucs_mapped != dn_ucs.lower():
			self._remove_dn_mapping(dn_ucs.lower(), dn_con_mapped.lower())
			self._remove_dn_mapping(dn_ucs_mapped.lower(), dn_con.lower())
			self._set_dn_mapping(dn_ucs.lower(), dn_con.lower())

	def _list_dn_mappings(self, config_space):
		ret = []
		for d1, d2 in self._get_config_items(config_space):
			return_update = False
			count = 0
			while not return_update and count < 3:
				try:
					ret.append((self._decode_dn_from_config_option(d1), self._decode_dn_from_config_option(self._get_config_option(config_space, d1))))
					return_update = True
				except (ldap.SERVER_DOWN, SystemExit):
					raise
				except:  # FIXME: which exception is to be caught?
					count = count + 1
					d1 = d1 + " ="
			ret.append(("failed", self._decode_dn_from_config_option(d1)))
		return ret

	def list_dn_mappings_by_con(self):
		return self._list_dn_mappings('DN Mapping CON')

	def list_dn_mappings_by_ucs(self):
		return self._list_dn_mappings('DN Mapping UCS')

	def _debug_traceback(self, level, text):
		'''
		print traceback with ud.debug, level is i.e. ud.INFO
		'''
		ud.debug(ud.LDAP, level, text)
		ud.debug(ud.LDAP, level, traceback.format_exc())

	def __sync_file_from_ucs(self, filename, append_error='', traceback_level=ud.WARN):
		'''
		sync changes from UCS stored in given file
		'''

		try:
			with open(filename, 'rb') as fob:
				(dn, new, old, old_dn) = pickle.load(fob, encoding='bytes')
				# With the Python 2 listener pickle files we got bytes here, otherwise already string
				if isinstance(dn, bytes):
					dn = dn.decode('utf-8')
				if isinstance(old_dn, bytes):
					old_dn = old_dn.decode('utf-8')
		except IOError:
			return True  # file not found so there's nothing to sync
		except (pickle.UnpicklingError, EOFError) as e:
			message = 'file emtpy' if isinstance(e, EOFError) else e.message
			ud.debug(ud.LDAP, ud.ERROR, '__sync_file_from_ucs: invalid pickle file {}: {}'.format(filename, message))
			# ignore corrupted pickle file, but save as rejected to not try again
			self._save_rejected_ucs(filename, 'unknown', resync=False, reason='broken file')
			return False

		if dn == 'cn=Subschema':
			return True

		def recode_attribs(attribs):
			return dict((key.decode('UTF-8') if isinstance(key, bytes) else key, value) for key, value in attribs.items())

		new = recode_attribs(new)
		old = recode_attribs(old)

		key = None

		# if the object was moved into a ignored tree
		# we should delete this object
		ignore_subtree_match = False

		_attr = new or old
		for k in self.property.keys():
			if self.modules[k].identify(unicode(dn, 'utf8'), _attr):
				key = k
				break

		if not new:
			change_type = "delete"
			ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: object was deleted")
		else:
			entryUUID = new.get('entryUUID', [None])[0]
			if entryUUID:
				if self.was_entryUUID_deleted(entryUUID):
					if self._get_entryUUID(dn) == entryUUID:
						ud.debug(ud.LDAP, ud.PROCESS, "__sync_file_from_ucs: Object with entryUUID %s has been removed before but became visible again." % entryUUID)
					else:
						ud.debug(ud.LDAP, ud.PROCESS, "__sync_file_from_ucs: Object with entryUUID %s has been removed before. Don't re-create." % entryUUID)
						return True
			else:
				ud.debug(ud.LDAP, ud.ERROR, "__sync_file_from_ucs: Object without entryUUID: %s" % (dn,))
				return False

			# ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: old: %s" % old)
			# ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: new: %s" % new)
			if old and new:
				change_type = "modify"
				ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: object was modified")
				if old_dn and not old_dn == dn:
					ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: object was moved")
					# object was moved
					new_object = {'dn': dn, 'modtype': change_type, 'attributes': new}
					old_object = {'dn': old_dn, 'modtype': change_type, 'attributes': old}
					if self._ignore_object(key, new_object):
						# moved into ignored subtree, delete:
						ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: moved object is now ignored, will delete it")
						change_type = 'delete'
						ignore_subtree_match = True

					if self._ignore_object(key, old_object):
						# moved from ignored subtree, add:
						ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: moved object was ignored, will add it")
						change_type = 'add'

			else:
				object = {'dn': dn, 'modtype': 'modify', 'attributes': new}
				try:
					if self._ignore_object(key, object):
						ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: new object is ignored, nothing to do")
						change_type = 'modify'
						ignore_subtree_match = True
						return True
					else:
						if old_dn and not old_dn == dn:
							change_type = "modify"
							ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: object was moved")
						else:
							change_type = "add"
							old_dn = ''  # there may be an old_dn if object was moved from ignored container
							ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: object was added: %s" % dn)
				except (ldap.SERVER_DOWN, SystemExit):
					raise
				except Exception:  # FIXME: which exception is to be caught?
					# the ignore_object method might throw an exception if the subschema will be synced
					change_type = "add"
					old_dn = ''  # there may be an old_dn if object was moved from ignored container
					ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: object was added: %s" % dn)

		if key:
			if change_type == 'delete':
				if old_dn:
					object = {'dn': old_dn, 'modtype': change_type, 'attributes': old}
				else:
					object = {'dn': dn, 'modtype': change_type, 'attributes': old}
			else:
				object = {'dn': dn, 'modtype': change_type, 'attributes': new}

			if change_type == 'modify' and old_dn:
				object['olddn'] = old_dn  # needed for correct samaccount-mapping

			if not self._ignore_object(key, object) or ignore_subtree_match:
				premapped_ucs_dn = object['dn']
				object = self._object_mapping(key, object, 'ucs')
				if not self._ignore_object(key, object) or ignore_subtree_match:
					ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: finished mapping")

					if change_type == 'modify':
						# to be able to compare mapped values we need to map the old state of the object too
						if old_dn:
							object_old = {'dn': object['olddn'], 'modtype': change_type, 'attributes': old}
						else:
							object_old = {'dn': object['dn'], 'modtype': change_type, 'attributes': old}
						object_old = self._object_mapping(key, object_old, 'ucs')
					else:
						object_old = {'dn': object['dn'], 'modtype': change_type, 'attributes': {}}  # Dummy

					try:
						if ((old_dn and not self.sync_from_ucs(key, object, premapped_ucs_dn, unicode(old_dn, 'utf8'), object_old))
							or (not old_dn and not self.sync_from_ucs(key, object, premapped_ucs_dn, old_dn, object_old))):
							self._save_rejected_ucs(filename, dn)
							return False
						else:
							return True
					except ldap.SERVER_DOWN:
						raise
					except ldap.NO_SUCH_OBJECT:
						self._save_rejected_ucs(filename, dn)
						if traceback_level == ud.INFO:
							self._debug_traceback(traceback_level, "The sync failed. This could be because the parent object does not exist. This object will be synced in next sync step.")
						else:
							self._debug_traceback(traceback_level, "sync failed, saved as rejected\n\t%s" % (filename,))
						return False
					except Exception:
						self._save_rejected_ucs(filename, dn)
						self._debug_traceback(traceback_level, "sync failed, saved as rejected\n\t%s" % (filename,))
						return False
				else:
					return True
			else:
				return True
		else:
			ud.debug(ud.LDAP, ud.INFO, "__sync_file_from_ucs: No mapping was found for dn: %s" % dn)
			return True

	def get_ucs_ldap_object(self, dn):

		if isinstance(dn, type(u'')):
			searchdn = dn
		else:
			searchdn = unicode(dn)
		try:
			return self.lo.get(searchdn, required=1)
		except ldap.NO_SUCH_OBJECT:
			return None
		except ldap.INVALID_SYNTAX:
			return None

	def get_ucs_object(self, property_type, dn):
		ucs_object = None
		if isinstance(dn, unicode):
			searchdn = dn
		else:
			searchdn = unicode(dn)
		try:
			attr = self.get_ucs_ldap_object(searchdn)
			if not attr:
				ud.debug(ud.LDAP, ud.INFO, "get_ucs_object: object not found: %s" % searchdn)
				return None
			module = self.modules[property_type]  # default, determined by mapping filter
			if not module.identify(searchdn, attr):
				for m in self.modules_others.get(property_type, []):
					if m and m.identify(searchdn, attr):
						module = m
						break
				else:
					ud.debug(ud.LDAP, ud.ERROR, "get_ucs_object: could not identify UDM object type: %s" % searchdn)
					ud.debug(ud.LDAP, ud.PROCESS, "get_ucs_object: using default: %s" % module.module)

			ucs_object = univention.admin.objects.get(module, co=None, lo=self.lo, position='', dn=searchdn)
			ud.debug(ud.LDAP, ud.INFO, "get_ucs_object: object found: %s" % searchdn)
		except ldap.SERVER_DOWN:
			raise
		except Exception:  # FIXME: which exception is to be caught?
			ud.debug(ud.LDAP, ud.INFO, "get_ucs_object: object search failed: %s" % searchdn)
			self._debug_traceback(ud.WARN, "get_ucs_object: failure was: \n\t")
			return None

		return ucs_object

	def initialize_ucs(self):
		print("--------------------------------------")
		print("Initialize sync from UCS")
		sys.stdout.flush()

		# load UCS Modules
		self.modules = {}
		self.modules_others = {}
		position = univention.admin.uldap.position(self.lo.base)
		for key in self.property.keys():
			if self.property[key].ucs_module:
				self.modules[key] = univention.admin.modules.get(self.property[key].ucs_module)
				if hasattr(self.property[key], 'identify'):
					ud.debug(ud.LDAP, ud.INFO, "Override identify function for %s" % key)
					self.modules[key].identify = self.property[key].identify
			else:
				self.modules[key] = None
			univention.admin.modules.init(self.lo, position, self.modules[key])

			self.modules_others[key] = []
			if self.property[key].ucs_module_others:
				for m in self.property[key].ucs_module_others:
					if m:
						self.modules_others[key].append(univention.admin.modules.get(m))
				for m in self.modules_others[key]:
					if m:
						univention.admin.modules.init(self.lo, position, m)

		# try to resync rejected changes
		self.resync_rejected_ucs()
		# call poll_ucs to sync
		self.poll_ucs()
		print("--------------------------------------")
		sys.stdout.flush()

	def initialize(self):
		# dummy
		pass

	def resync_rejected_ucs(self):
		'''
		tries to resync rejected changes from UCS
		'''
		rejected = self._list_rejected_ucs()
		change_counter = 0
		print("--------------------------------------")
		print("Sync %s rejected changes from UCS" % len(rejected))
		sys.stdout.flush()

		if rejected:
			for filename, dn in rejected:
				ud.debug(ud.LDAP, ud.PROCESS, 'sync from ucs:   Resync rejected file: %s' % (filename))
				try:
					if self.__sync_file_from_ucs(filename, append_error=' rejected'):
						try:
							os.remove(os.path.join(filename))
						except OSError:  # file not found
							pass
						self._remove_rejected_ucs(filename)
						change_counter += 1
				except ldap.SERVER_DOWN:
					raise
				except Exception:  # FIXME: which exception is to be caught?
					self._save_rejected_ucs(filename, dn)
					self._debug_traceback(ud.WARN, "sync failed, saved as rejected \n\t%s" % filename)

		print("restored %s rejected changes" % change_counter)
		print("--------------------------------------")
		sys.stdout.flush()

	def resync_rejected(self):
		# dummy
		pass

	def poll_ucs(self):
		'''
		poll changes from UCS: iterates over files exported by directory-listener module
		'''
		# check for changes from ucs ldap directory

		change_counter = 0

		self.rejected_files = self._list_rejected_filenames_ucs()

		files = os.listdir(self.listener_dir)
		num_changes = len(files) - 1
		if self.profiling and num_changes:
			ud.debug(ud.LDAP, ud.PROCESS, "POLL FROM UCS: Incomming %s" % (num_changes,))


		print("--------------------------------------")
		print("try to sync %s changes from UCS" % (num_changes,))
		print("done:", end=' ')
		sys.stdout.flush()
		done_counter = 0
		files = sorted(files)

		# We may dropped the parent object, so don't show the traceback in any case
		traceback_level = ud.WARN

		for listener_file in files:
			sync_successfull = False
			filename = os.path.join(self.listener_dir, listener_file)
			if os.path.isfile(filename):
				if filename not in self.rejected_files:
					try:
						with open(filename, 'rb') as fob:
							(dn, new, old, old_dn) = pickle.load(fob, encoding='bytes')
							if isinstance(dn, bytes):
								dn = dn.decode('utf-8')
							if isinstance(old_dn, bytes):
								old_dn = old_dn.decode('utf-8')
					except IOError:
						continue  # file not found so there's nothing to sync
					except (pickle.UnpicklingError, EOFError) as e:
						message = 'file emtpy' if isinstance(e, EOFError) else e.message
						ud.debug(ud.LDAP, ud.ERROR, 'poll_ucs: invalid pickle file {}: {}'.format(filename, message))
						# ignore corrupted pickle file, but save as rejected to not try again
						self._save_rejected_ucs(filename, 'unknown', resync=False, reason='broken file')
						continue


					# If the list contains more than one file, the DN will be synced later
					# but if the object was added or removed, the synchonization is required
					for i in [0, 1]:  # do it twice if the LDAP connection was closed
						try:
							sync_successfull = self.__sync_file_from_ucs(filename, traceback_level=traceback_level)
						except (ldap.SERVER_DOWN, SystemExit):
							# once again, ldap idletimeout ...
							if i == 0:
								self.open_ucs()
								continue
							raise
						except Exception:
							self._save_rejected_ucs(filename, dn)
							# We may dropped the parent object, so don't show this warning
							self._debug_traceback(traceback_level, "sync failed, saved as rejected \n\t%s" % filename)
						if sync_successfull:
							os.remove(os.path.join(self.listener_dir, listener_file))
							change_counter += 1
						break

				done_counter += 1
				print("%s" % done_counter, end=' ')
				sys.stdout.flush()

		print("")

		self.rejected_files = self._list_rejected_filenames_ucs()

		if self.rejected_files:
			print("Changes from UCS: %s (%s saved rejected)" % (change_counter, len(self.rejected_files)))
		else:
			print("Changes from UCS: %s (%s saved rejected)" % (change_counter, '0'))
		print("--------------------------------------")
		sys.stdout.flush()

		if self.profiling and change_counter:
			ud.debug(ud.LDAP, ud.PROCESS, "POLL FROM UCS: Processed %s" % (change_counter,))
		return change_counter

	def poll(self, show_deleted=True):
		# dummy
		pass

	def __set_values(self, property_type, object, ucs_object, modtype='modify'):
		if not modtype == 'add':
			ucs_object.open()

		ud.debug(ud.LDAP, ud.INFO, '__set_values: object: %s' % object)

		def set_values(attributes):
			if attributes.ldap_attribute in object['attributes']:
				ucs_key = attributes.ucs_attribute
				if ucs_key:
					value = object['attributes'][attributes.ldap_attribute]
					ud.debug(ud.LDAP, ud.INFO, '__set_values: set attribute, ucs_key: %s - value: %s' % (ucs_key, value))

					if isinstance(value, type(types.ListType())) and len(value) == 1:
						value = value[0]
					equal = False

					# set encoding
					compare = [ucs_object[ucs_key], value]
					for i in [0, 1]:
						if isinstance(compare[i], type([])):
							compare[i] = univention.connector.ad.compatible_list(compare[i])
						else:
							compare[i] = univention.connector.ad.compatible_modstring(compare[i])

					if attributes.compare_function != '':
						equal = attributes.compare_function(compare[0], compare[1])
					else:
						equal = compare[0] == compare[1]
					if not equal:
						# This is deduplication of LDAP attribute values for S4 -> UCS.
						# It preserves ordering of the attribute values which is
						# important for the handling of `con_other_attribute`.
						if isinstance(value, list):
							ucs_object[ucs_key] = list(collections.OrderedDict.fromkeys(value))
						else:
							ucs_object[ucs_key] = value

						ud.debug(ud.LDAP, ud.INFO, "set key in ucs-object: %s" % ucs_key)
				else:
					ud.debug(ud.LDAP, ud.INFO, '__set_values: no ucs_attribute found in %s' % attributes)
			else:
				# the value isn't set in the AD directory, but it could be set in UCS, so we should delete it on UCS side

				# prevent value resets of mandatory attributes
				mandatory_attrs = ['lastname']

				ucs_key = attributes.ucs_attribute
				if ucs_key in ucs_object:
					# Special handling for con other attributes, see Bug #20599
					if attributes.con_other_attribute:
						if object['attributes'].get(attributes.con_other_attribute):
							ucs_object[ucs_key] = object['attributes'].get(attributes.con_other_attribute)
							ud.debug(ud.LDAP, ud.INFO, '__set_values: no ldap_attribute defined in %r, we set the key %r in the ucs-object to con_other_attribute %r' % (object['dn'], ucs_key, attributes.con_other_attribute))
						elif ucs_key not in mandatory_attrs:
							ucs_object[ucs_key] = []
							ud.debug(ud.LDAP, ud.INFO, '__set_values: no ldap_attribute defined in %r, we unset the key %r in the ucs-object' % (object['dn'], ucs_key))
						else:
							ud.debug(ud.LDAP, ud.WARN, '__set_values: The attributes for %s have not been removed as it represents a mandatory attribute' % ucs_key)
					else:
						ud.debug(ud.LDAP, ud.INFO, '__set_values: no ldap_attribute defined in %r, we unset the key %r in the ucs-object' % (object['dn'], ucs_key))

						if ucs_key not in mandatory_attrs:
							ucs_object[ucs_key] = []
						else:
							ud.debug(ud.LDAP, ud.WARN, '__set_values: The attributes for %s have not been removed as it represents a mandatory attribute' % ucs_key)

		for attribute in self.property[property_type].attributes.values():
			if attribute.sync_mode in ['read', 'sync']:
				changed_attributes = object.get('changed_attributes', [])
				changed = not changed_attributes or \
					attribute.con_attribute in changed_attributes or \
					attribute.con_other_attribute in changed_attributes or \
					attribute.con_depends in changed_attributes

				if changed or modtype == 'add':
					ud.debug(ud.LDAP, ud.INFO,
						'__set_values: Set: %s' % attribute.con_attribute)
					set_values(attribute)
				else:
					ud.debug(ud.LDAP, ud.INFO,
						'__set_values: Skip: %s' % attribute.con_attribute)

		# post-values
		if not self.property[property_type].post_attributes:
			return
		for attribute in self.property[property_type].post_attributes.values():
			if attribute.sync_mode in ['read', 'sync']:
				ud.debug(ud.LDAP, ud.INFO,
					'__set_values: mapping for attribute: %s' % attribute)
				changed_attributes = object.get('changed_attributes', [])
				changed = not changed_attributes or \
					attribute.con_attribute in changed_attributes or \
					attribute.con_other_attribute in changed_attributes or \
					attribute.con_depends in changed_attributes

				if changed or modtype == 'add':
					ud.debug(ud.LDAP, ud.INFO,
						'__set_values: Set: %s' % attribute.con_attribute)
					if attribute.reverse_attribute_check:
						if object['attributes'].get(attribute.ldap_attribute):
							set_values(attribute)
						else:
							ucs_object[attribute.ucs_attribute] = ''
					else:
						set_values(attribute)
				else:
					ud.debug(ud.LDAP, ud.INFO,
						'__set_values: Skip: %s' % attribute.con_attribute)

	def add_in_ucs(self, property_type, object, module, position):
		ucs_object = module.object(None, self.lo, position=position)
		if property_type == 'group':
			ucs_object.open()
			ud.debug(ud.LDAP, ud.INFO, "sync_to_ucs: remove %s from ucs group cache" % object['dn'])
			self.group_members_cache_ucs[object['dn'].lower()] = set()
		else:
			ucs_object.open()
		self.__set_values(property_type, object, ucs_object, modtype='add')
		for ucs_create_function in self.property[property_type].ucs_create_functions:
			ud.debug(ud.LDAP, ud.INFO, "Call ucs_create_functions: %s" % ucs_create_function)
			ucs_create_function(self, property_type, ucs_object)
		return bool(ucs_object.create())

	def modify_in_ucs(self, property_type, object, module, position):

		ucs_object_dn = object.get('olddn', object['dn'])
		ucs_object = univention.admin.objects.get(module, None, self.lo, dn=ucs_object_dn, position='')
		self.__set_values(property_type, object, ucs_object)

		return bool(ucs_object.modify())

	def move_in_ucs(self, property_type, object, module, position):
		try:
			if object['olddn'].lower() == object['dn'].lower():
				ud.debug(ud.LDAP, ud.WARN, "move_in_ucs: cancel move, old and new dn are the same ( %s to %s)" % (object['olddn'], object['dn']))
				return True
			else:
				ud.debug(ud.LDAP, ud.INFO, "move_in_ucs: move object from %s to %s" % (object['olddn'], object['dn']))
		except (ldap.SERVER_DOWN, SystemExit):
			raise
		except:  # FIXME: which exception is to be caught?
			ud.debug(ud.LDAP, ud.INFO, "move_in_ucs: move object in UCS")
		ucs_object = univention.admin.objects.get(module, None, self.lo, dn=object['olddn'], position='')
		ucs_object.open()
		ucs_object.move(object['dn'])
		return True

	def _get_entryUUID(self, dn):
		try:
			result = self.search_ucs(base=dn, scope='base', attr=['entryUUID'], unique=True)
		except univention.admin.uexceptions.noObject:
			return None

		if result:
			(_dn, attributes) = result[0]
			return attributes.get('entryUUID')[0]
		return None

	def update_deleted_cache_after_removal(self, entryUUID, objectGUID):
		if entryUUID:
			if objectGUID:
				objectGUID_str = str(ndr_unpack(misc.GUID, objectGUID))
			else:
				# use a dummy value
				objectGUID_str = 'objectGUID'
			ud.debug(ud.LDAP, ud.INFO, ("update_deleted_cache_after_removal: Save entryUUID %s as deleted to UCS deleted cache. ObjectGUUID: %s") % (entryUUID, objectGUID_str))
			self._set_config_option('UCS deleted', entryUUID, objectGUID_str)

	def was_entryUUID_deleted(self, entryUUID):
		objectGUID = self.config.get('UCS deleted', entryUUID)
		if objectGUID:
			return True
		return False

	def delete_in_ucs(self, property_type, object, module, position):
		ucs_object = univention.admin.objects.get(module, None, self.lo, dn=object['dn'], position='')

		if object['attributes'].get('objectGUID'):
			objectGUID = object['attributes'].get('objectGUID')[0]
		else:
			objectGUID = None
		entryUUID = self._get_entryUUID(object['dn'])
		try:
			ucs_object.open()
			ucs_object.remove()
			self.update_deleted_cache_after_removal(entryUUID, objectGUID)
			return True
		except Exception as e:
			ud.debug(ud.LDAP, ud.INFO, "delete object exception: %s" % e)
			if str(e) == "Operation not allowed on non-leaf":  # need to delete subtree
				ud.debug(ud.LDAP, ud.INFO, "remove object from UCS failed, need to delete subtree")
				for result in self.search_ucs(base=object['dn']):
					if compare_lowercase(result[0], object['dn']):
						continue
					ud.debug(ud.LDAP, ud.INFO, "delete: %s" % result[0])
					subobject = {'dn': result[0], 'modtype': 'delete', 'attributes': result[1]}
					key = None
					for k in self.property.keys():
						if self.modules[k].identify(result[0], result[1]):
							key = k
							break
					object_mapping = self._object_mapping(key, subobject, 'ucs')
					ud.debug(ud.LDAP, ud.WARN, "delete subobject: %s" % object_mapping['dn'])
					if not self._ignore_object(key, object_mapping):
						if not self.sync_to_ucs(key, subobject, object_mapping['dn'], object):
							try:
								ud.debug(ud.LDAP, ud.WARN, "delete of subobject failed: %s" % result[0])
							except (ldap.SERVER_DOWN, SystemExit):
								raise
							except:  # FIXME: which exception is to be caught?
								ud.debug(ud.LDAP, ud.WARN, "delete of subobject failed")
							return False

				return delete_in_ucs(property_type, object, module, position)
			elif str(e) == "noObject":  # already deleted #TODO: check if it's really match
				return True
			else:
				raise

	def sync_to_ucs(self, property_type, object, premapped_ad_dn, original_object, retry=True):
		# this function gets an object from the ad class, which should be converted into a ucs modul

		# if sync is write (sync to AD) or none, there is nothing to do
		if self.property[property_type].sync_mode in ['write', 'none']:
			ud.debug(ud.LDAP, ud.INFO, "sync_to_ucs ignored, sync_mode is %s" % self.property[property_type].sync_mode)
			return True

		if object['dn'].find('\\0ACNF:') > 0:
			ud.debug(ud.LDAP, ud.PROCESS, 'Ignore conflicted object: %s' % object['dn'])
			return True

		try:
			guid_blob = original_object.get('attributes').get('objectGUID')[0]
			guid = str(ndr_unpack(misc.GUID, guid_blob))

			object['changed_attributes'] = []
			if object['modtype'] == 'modify' and original_object:
				old_ad_object = self.adcache.get_entry(guid)
				ud.debug(ud.LDAP, ud.INFO, "sync_to_ucs: old_ad_object: %s" % old_ad_object)
				ud.debug(ud.LDAP, ud.INFO, "sync_to_ucs: new_ad_object: %s" % original_object['attributes'])
				original_attributes = original_object['attributes']
				if old_ad_object:
					for attr in original_object['attributes']:
						if old_ad_object.get(attr) != original_attributes.get(attr):
							object['changed_attributes'].append(attr)
					for attr in old_ad_object:
						if old_ad_object.get(attr) != original_attributes.get(attr):
							if attr not in object['changed_attributes']:
								object['changed_attributes'].append(attr)
					if not (set(object['changed_attributes']) - self.irrelevant_attributes):
						ud.debug(ud.LDAP, ud.INFO, "sync_to_ucs: ignore %r" % (original_object['dn'],))
						ud.debug(ud.LDAP, ud.ALL, "sync_to_ucs: changed_attributes=%s" % (object['changed_attributes'],))
						return True
				else:
					object['changed_attributes'] = original_attributes.keys()
			ud.debug(ud.LDAP, ud.INFO, "The following attributes have been changed: %s" % object['changed_attributes'])

			result = False

			# Check if the object on UCS side should be synchronized
			#  https://forge.univention.org/bugzilla/show_bug.cgi?id=37351
			old_ucs_ldap_object = {}
			old_ucs_ldap_object['dn'] = object.get('olddn', object['dn'])
			old_ucs_ldap_object['attributes'] = self.get_ucs_ldap_object(old_ucs_ldap_object['dn'])

			if old_ucs_ldap_object['attributes'] and self._ignore_object(property_type, old_ucs_ldap_object):
				ud.debug(ud.LDAP, ud.PROCESS, 'The object %r will be ignored because a valid match filter for this object was not found.' % (old_ucs_ldap_object['dn'],))
				return True

			old_object = self.get_ucs_object(property_type, object.get('olddn', object['dn']))

			if old_object and object['modtype'] == 'add':
				object['modtype'] = 'modify'
			if not old_object and object['modtype'] == 'modify':
				object['modtype'] = 'add'
			if not old_object and object['modtype'] == 'move':
				object['modtype'] = 'add'

			if self.group_mapping_cache_ucs.get(object['dn'].lower()) and object['modtype'] != 'delete':
				self.group_mapping_cache_ucs[object['dn'].lower()] = None

			ud.debug(ud.LDAP, ud.PROCESS, 'sync to ucs:   [%14s] [%10s] %s' % (property_type, object['modtype'], object['dn']))
			position = univention.admin.uldap.position(self.configRegistry['ldap/base'])

			parent_dn = self.lo.parentDn(object['dn'])
			ud.debug(ud.LDAP, ud.INFO, 'sync_to_ucs: set position to %s' % parent_dn)
			position.setDn(parent_dn)

			module = self.modules[property_type]  # default, determined by mapping filter
			if old_object:
				ud.debug(ud.LDAP, ud.INFO, "sync_to_ucs: using existing target object type: %s" % (old_object.module,))
				module = univention.admin.modules.get(old_object.module)

			if object['modtype'] == 'add':
				result = self.add_in_ucs(property_type, object, module, position)
				self._check_dn_mapping(object['dn'], premapped_ad_dn)
				self.adcache.add_entry(guid, original_object.get('attributes'))
			if object['modtype'] == 'delete':
				if not old_object:
					ud.debug(ud.LDAP, ud.WARN, "Object to delete doesn't exists, ignore (%r)" % object['dn'])
					result = True
				else:
					result = self.delete_in_ucs(property_type, object, module, position)
				self._remove_dn_mapping(object['dn'], premapped_ad_dn)
				self.adcache.remove_entry(guid)
			if object['modtype'] == 'move':
				result = self.move_in_ucs(property_type, object, module, position)
				self._remove_dn_mapping(object['olddn'], '')  # we don't know the old ad-dn here anymore, will be checked by remove_dn_mapping
				self._check_dn_mapping(object['dn'], premapped_ad_dn)

			if object['modtype'] == 'modify':
				result = self.modify_in_ucs(property_type, object, module, position)
				self._check_dn_mapping(object['dn'], premapped_ad_dn)
				self.adcache.add_entry(guid, original_object.get('attributes'))

			if not result:
				ud.debug(ud.LDAP, ud.WARN, "Failed to get Result for DN (%r)" % (object['dn'],))
				return False

			if object['modtype'] in ['add', 'modify']:
				for post_ucs_modify_function in self.property[property_type].post_ucs_modify_functions:
					ud.debug(ud.LDAP, ud.INFO, "Call post_ucs_modify_functions: %s" % post_ucs_modify_function)
					post_ucs_modify_function(self, property_type, object)
					ud.debug(ud.LDAP, ud.INFO, "Call post_ucs_modify_functions: %s (done)" % post_ucs_modify_function)

			ud.debug(ud.LDAP, ud.INFO, "Return  result for DN (%s)" % object['dn'])
			return result

		except univention.admin.uexceptions.valueInvalidSyntax as msg:
			ud.debug(ud.LDAP, ud.ERROR, "InvalidSyntax: %s (%r)" % (msg, object['dn']))
			return False
		except univention.admin.uexceptions.valueMayNotChange as msg:
			ud.debug(ud.LDAP, ud.ERROR, "Value may not change: %s (%r)" % (msg, object['dn']))
			return False
		except ldap.SERVER_DOWN:
			raise
		except Exception:  # FIXME: which exception is to be caught?
			self._debug_traceback(ud.ERROR, "Unknown Exception during sync_to_ucs")
			return False

	def sync_from_ucs(self, property_type, object, pre_mapped_ucs_dn, old_dn=None, object_old=None):
		# dummy
		return False

	# internal functions

	def _subtree_match(self, dn, subtree):
		if len(subtree) > len(dn):
			return False
		if subtree.lower() == dn[len(dn) - len(subtree):].lower():
			return True
		return False

	def _subtree_replace(self, dn, subtree, subtreereplace):  # FIXME: may raise an exception if called with umlauts
		if len(subtree) > len(dn):
			return dn
		if subtree.lower() == dn[len(dn) - len(subtree):].lower():
			return dn[:len(dn) - len(subtree)] + subtreereplace
		return dn

	# attributes ist ein dictionary von LDAP-Attributen und den zugeordneten Werten
	def _filter_match(self, filter, attributes):
		'''
		versucht eine liste von attributen auf einen LDAP-Filter zu matchen
		Besonderheiten des Filters:
		- immer case-sensitive
		- nur * als Wildcard
		- geht "lachser" mit Verschachtelten Klammern um
		'''

		filter_connectors = ['!', '&', '|']

		def list_lower(elements):
			if isinstance(elements, type([])):
				retlist = []
				for l in elements:
					retlist.append(l.lower())
				return retlist
			else:
				return elements

		def dict_lower(dict):
			if isinstance(dict, type({})):
				retdict = {}
				for key in dict:
					retdict[key.lower()] = dict[key]
				return retdict
			else:
				return dict

		def attribute_filter(filter, attributes):
			attributes = dict_lower(attributes)

			pos = filter.find('=')
			if pos < 0:
				raise ValueError('missing "=" in filter: %s' % filter)
			attribute = filter[:pos].lower()
			if not attribute:
				raise ValueError('missing attribute in filter: %s' % filter)
			value = filter[pos + 1:]

			if attribute.endswith(':1.2.840.113556.1.4.803:'):
				# bitwise filter
				attribute_name = attribute.replace(':1.2.840.113556.1.4.803:', '')
				attribute_value = attributes.get(attribute_name)
				if attribute_value:
					try:
						if isinstance(attribute_value, type([])):
							attribute_value = int(attribute_value[0])
						int_value = int(value)
						if ((attribute_value & int_value) == int_value):
							return True
						else:
							return False
					except ldap.SERVER_DOWN:
						raise
					except Exception:
						ud.debug(ud.LDAP, ud.WARN, "attribute_filter: Failed to convert attributes for bitwise filter")
						return False

			if value == '*':
				return attribute in list_lower(attributes.keys())
			elif attribute in attributes:
				return value.lower() in list_lower(attributes[attribute])
			else:
				return False

		def connecting_filter(filter, attributes):

			def walk(filter, attributes):

				def split(filter):
					opened = []
					closed = []
					pos = 0
					level = 0
					for char in filter:
						if char == '(':
							if level == 0:
								opened.append(pos)
							level += 1
						elif char == ')':
							if level == 1:
								closed.append(pos)
							level -= 1
						if level < 0:
							raise ValueError("too many ')' in filter: %s" % filter)
						pos += 1

					if len(opened) != len(closed):
						raise ValueError("'(' and ')' don't match in filter: %s" % filter)
					filters = []
					for i in range(len(opened)):
						filters.append(filter[opened[i] + 1:closed[i]])
					return filters

				if filter[0] == '(':
					if not filter[-1] == ')':
						raise ValueError("matching ) missing in filter: %s" % filter)
					else:
						filters = split(filter)
						results = []
						for filter in filters:
							results.append(subfilter(filter, attributes))
						return results
				else:
					return [subfilter(filter, attributes)]

			if filter[0] == '!':
				return not subfilter(filter[1:], attributes)
			elif filter[0] == '|':
				return 1 in walk(filter[1:], attributes)
			elif filter[0] == '&':
				return 0 not in walk(filter[1:], attributes)

		def subfilter(filter, attributes):

			if filter[0] == '(':
				if not filter[-1] == ')':
					raise ValueError("matching ) missing in filter: %s" % filter)
				else:
					return subfilter(filter[1:-1], attributes)

			elif filter[0] in filter_connectors:
				return connecting_filter(filter, attributes)

			else:
				return attribute_filter(filter, attributes)

		return subfilter(filter, attributes)

	def _ignore_object(self, key, object):
		'''
		parse if object should be ignored because of ignore_subtree or ignore_filter
		'''
		if 'dn' not in object:
			ud.debug(ud.LDAP, ud.INFO, "_ignore_object: ignore object without DN (key: {})".format(key))
			return True  # ignore not existing object
		for subtree in self.property[key].ignore_subtree:
			if self._subtree_match(object['dn'], subtree):
				ud.debug(ud.LDAP, ud.INFO, "_ignore_object: ignore object because of subtree match: [%r:%r]" % (key, object['dn']))
				return True

		if self.property[key].ignore_filter and self._filter_match(self.property[key].ignore_filter, object['attributes']):
			ud.debug(ud.LDAP, ud.INFO, "_ignore_object: ignore object because of ignore_filter: [%r:%r]" % (key, object['dn']))
			return True

		if self.property[key].match_filter and not self._filter_match(self.property[key].match_filter, object['attributes']):
			ud.debug(ud.LDAP, ud.INFO, "_ignore_object: ignore object because of match_filter: [%r:%r]" % (key, object['dn']))
			return True

		ud.debug(ud.LDAP, ud.INFO, "_ignore_object: Do not ignore %r:%r" % (key, object['dn']))

		return False

	def _object_mapping(self, key, old_object, object_type='con'):
		ud.debug(ud.LDAP, ud.INFO, "_object_mapping: map with key %s and type %s" % (key, object_type))
		object = copy.deepcopy(old_object)
		# Eingehendes Format object:
		#	'dn': dn
		#	'modtype': 'add', 'delete', 'modify', 'move'
		#	'attributes': { attr: [values] }
		#       'olddn' : dn (nur bei move)
		# Ausgehendes Format object_out:
		#	'dn': dn
		#	'modtype':  'add', 'delete', 'modify', 'move'
		#	'attributes': { attr: [values] }
		#       'olddn' : dn (nur bei move)

		# sync mode
		# dn mapping
		# ignore_filter
		# attributes
		# post_attributes
		object_out = {}
		object_out['attributes'] = {}
		if object and 'modtype' in object:
			object_out['modtype'] = object['modtype']
		else:
			object_out['modtype'] = ''

		# DN mapping

		dn_mapping_stored = []
		for dntype in ['dn', 'olddn']:  # check if all available dn's are already mapped
			if dntype in object:
				ud.debug(ud.LDAP, ud.INFO, "_dn_type %s" % (object_type))  # don't send str(object) to debug, may lead to segfaults

				if (object_type == 'ucs' and self._get_dn_by_ucs(object[dntype]) != ''):
					object[dntype] = self._get_dn_by_ucs(object[dntype])
					object[dntype] = self.dn_mapped_to_base(object[dntype], self.lo_ad.base)
					dn_mapping_stored.append(dntype)
				if (object_type != 'ucs' and self._get_dn_by_con(object[dntype]) != ''):
					object[dntype] = self._get_dn_by_con(object[dntype])
					object[dntype] = self.dn_mapped_to_base(object[dntype], self.lo.base)
					dn_mapping_stored.append(dntype)

		if key in self.property:
			if hasattr(self.property[key], 'dn_mapping_function'):
				# DN mapping functions
				for function in self.property[key].dn_mapping_function:
					object = function(self, object, dn_mapping_stored, isUCSobject=(object_type == 'ucs'))

		if object_type == 'ucs':
			if key in self.property:
				if hasattr(self.property[key], 'position_mapping'):
					for dntype in ['dn', 'olddn']:
						if dntype in object and dntype not in dn_mapping_stored:
							# save the old rdn with the correct upper and lower case
							rdn_store = self._get_rdn(object[dntype])
							for mapping in self.property[key].position_mapping:
								object[dntype] = self._subtree_replace(object[dntype].lower(), mapping[0].lower(), mapping[1])

							if self.lo_ad.base == object[dntype][len(object[dntype]) - len(self.lo_ad.base):] and len(self.lo_ad.base) > len(self.lo.base):
								ud.debug(ud.LDAP, ud.INFO, "The dn %s is already converted to the AD base, don't do this again." % object[dntype])
							else:
								object[dntype] = self._subtree_replace(object[dntype].lower(), self.lo.base.lower(), self.lo_ad.base)  # FIXME: lo_ad may change with other connectors
							# write the correct upper and lower case back to the DN
							object[dntype] = object[dntype].replace(object[dntype][0:len(rdn_store)], rdn_store, 1)
		else:
			if key in self.property:
				if hasattr(self.property[key], 'position_mapping'):
					for dntype in ['dn', 'olddn']:
						if dntype in object and dntype not in dn_mapping_stored:
							# save the old rdn with the correct upper and lower case
							rdn_store = self._get_rdn(object[dntype])
							for mapping in self.property[key].position_mapping:
								object[dntype] = self._subtree_replace(object[dntype].lower(), mapping[1].lower(), mapping[0])

							if self.lo.base == object[dntype][len(object[dntype]) - len(self.lo.base):] and len(self.lo.base) > len(self.lo_ad.base):
								ud.debug(ud.LDAP, ud.INFO, "The dn %s is already converted to the UCS base, don't do this again." % object[dntype])
							else:
								object[dntype] = self._subtree_replace(object[dntype].lower(), self.lo_ad.base.lower(), self.lo.base)  # FIXME: lo_ad may change with other connectors
							# write the correct upper and lower case back to the DN
							object[dntype] = object[dntype].replace(object[dntype][0:len(rdn_store)], rdn_store, 1)

		object_out = object

		# other mapping
		if object_type == 'ucs':
			for attribute, values in object['attributes'].items():
				for attr_key in self.property[key].attributes.keys():
					if attribute == self.property[key].attributes[attr_key].ldap_attribute:
						# mapping function
						if hasattr(self.property[key].attributes[attr_key], 'mapping'):
							# direct mapping
							if self.property[key].attributes[attr_key].mapping[0]:
								object_out['attributes'][self.property[key].attributes[attr_key].con_attribute] = self.property[key].attributes[attr_key].mapping[0](self, key, object)
						else:
							if self.property[key].attributes[attr_key].con_other_attribute:
								object_out['attributes'][self.property[key].attributes[attr_key].con_attribute] = [values[0]]
								object_out['attributes'][self.property[key].attributes[attr_key].con_other_attribute] = values[1:]
							else:
								object_out['attributes'][self.property[key].attributes[attr_key].con_attribute] = values

						# mapping_table
						if self.property[key].mapping_table and attr_key in self.property[key].mapping_table.keys():
							for ucsval, conval in self.property[key].mapping_table[attr_key]:
								if isinstance(object_out['attributes'][self.property[key].attributes[attr_key].con_attribute], type([])):

									ucsval_lower = make_lower(ucsval)
									objectval_lower = make_lower(object_out['attributes'][self.property[key].attributes[attr_key].con_attribute])

									if ucsval_lower in objectval_lower:
										object_out['attributes'][self.property[key].attributes[attr_key].con_attribute][objectval_lower.index(ucsval_lower)] = conval
									elif ucsval_lower == objectval_lower:
										object_out['attributes'][self.property[key].attributes[attr_key].con_attribute] = conval

				if hasattr(self.property[key], 'post_attributes') and self.property[key].post_attributes is not None:
					for attr_key in self.property[key].post_attributes.keys():
						if attribute == self.property[key].post_attributes[attr_key].ldap_attribute:
							if hasattr(self.property[key].post_attributes[attr_key], 'mapping'):
								if self.property[key].post_attributes[attr_key].mapping[0]:
									object_out['attributes'][self.property[key].post_attributes[attr_key].con_attribute] = self.property[key].post_attributes[attr_key].mapping[0](self, key, object)
							else:
								if self.property[key].post_attributes[attr_key].con_other_attribute:
									object_out['attributes'][self.property[key].post_attributes[attr_key].con_attribute] = [values[0]]
									object_out['attributes'][self.property[key].post_attributes[attr_key].con_other_attribute] = values[1:]
								else:
									object_out['attributes'][self.property[key].post_attributes[attr_key].con_attribute] = values

		else:
			# Filter out Configuration objects w/o DN
			if object['dn'] is not None:
				for attribute, values in object['attributes'].items():
					for attr_key in self.property[key].attributes.keys():
						if attribute == self.property[key].attributes[attr_key].con_attribute:
							# mapping function
							if hasattr(self.property[key].attributes[attr_key], 'mapping'):
								# direct mapping
								if self.property[key].attributes[attr_key].mapping[1]:
									object_out['attributes'][self.property[key].attributes[attr_key].ldap_attribute] = self.property[key].attributes[attr_key].mapping[1](self, key, object)
							else:
								if self.property[key].attributes[attr_key].con_other_attribute and object['attributes'].get(self.property[key].attributes[attr_key].con_other_attribute):
									object_out['attributes'][self.property[key].attributes[attr_key].ldap_attribute] = values + object['attributes'].get(self.property[key].attributes[attr_key].con_other_attribute)
								else:
									object_out['attributes'][self.property[key].attributes[attr_key].ldap_attribute] = values

							# mapping_table
							if self.property[key].mapping_table and attr_key in self.property[key].mapping_table.keys():
								for ucsval, conval in self.property[key].mapping_table[attr_key]:
									if isinstance(object_out['attributes'][self.property[key].attributes[attr_key].con_attribute], type([])):

										conval_lower = make_lower(conval)
										objectval_lower = make_lower(object_out['attributes'][self.property[key].attributes[attr_key].ldap_attribute])

										if conval_lower in objectval_lower:
											object_out['attributes'][self.property[key].attributes[attr_key].ldap_attribute][objectval_lower.index(conval_lower)] = ucsval
										elif conval_lower == objectval_lower:
											object_out['attributes'][self.property[key].attributes[attr_key].ldap_attribute] = ucsval

					if hasattr(self.property[key], 'post_attributes') and self.property[key].post_attributes is not None:
						for attr_key in self.property[key].post_attributes.keys():
							if attribute == self.property[key].post_attributes[attr_key].con_attribute:
								if hasattr(self.property[key].post_attributes[attr_key], 'mapping'):
									if self.property[key].post_attributes[attr_key].mapping[1]:
										object_out['attributes'][self.property[key].post_attributes[attr_key].ldap_attribute] = self.property[key].post_attributes[attr_key].mapping[1](self, key, object)
								else:
									if self.property[key].post_attributes[attr_key].con_other_attribute and object['attributes'].get(self.property[key].post_attributes[attr_key].con_other_attribute):
										object_out['attributes'][self.property[key].post_attributes[attr_key].ldap_attribute] = values + object['attributes'].get(self.property[key].post_attributes[attr_key].con_other_attribute)
									else:
										object_out['attributes'][self.property[key].post_attributes[attr_key].ldap_attribute] = values

		return object_out
