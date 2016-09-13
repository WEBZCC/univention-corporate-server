#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
#
# Univention Configuration Registry
#  build UMC module
#
# Copyright 2011-2016 Univention GmbH
#
# http://www.univention.de/
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
# <http://www.gnu.org/licenses/>.

import re
import os
import sys
import copy
import json
from email.utils import formatdate

import polib
import xml.etree.ElementTree as ET

import univention.debhelper as dh_ucs

MODULE = 'Module'
PYTHON = 'Python'
DEFINITION = 'Definition'
JAVASCRIPT = 'Javascript'
CATEGORY = 'Category'
ICONS = 'Icons'

LANGUAGES = ('de', )

PO_HEADER = 'This file is auto-generated by the dh-umc tools and should not be edited!'
PO_METADATA = {
	'Project-Id-Version': '',
	'Report-Msgid-Bugs-To': 'packages@univention.de',
	'POT-Creation-Date': '',
	'PO-Revision-Date': '',
	'Last-Translator': 'Univention GmbH <packages@univention.de>',
	'Language-Team': 'Univention GmbH <packages@univention.de>',
	'Language': '',
	'MIME-Version': '1.0',
	'Content-Type': 'text/plain; charset=UTF-8',
	'Content-Transfer-Encoding': '8bit'
}

"""Each module definition contains the following entries:

 Module: The internal name of the module
 Python: A directory containing the python module. There must be a subdirectory named like the internal name of the module.
 Definition: The XML definition of the module
 Javascript: The directory of the javascript code. In this directory must be a a file called <Module>.js
 Category: The XML definition of additional categories
 Icons: A directory containing the icons used by the module. The
   directory structure must follow the following pattern
   <weight>x<height>/<icon>.(png|gif)

The entry Category is optional.

Example:
 Module: ucr
 Python: umc/module
 Definition: umc/ucr.xml
 Javascript: umc/js
 Category: umc/categories/ucr.xml
 Icons: umc/icons
"""


class Error(SystemExit):
	pass


class UMC_Module(dict):

	def __init__(self, *args):
		dict.__init__(self, *args)
		for key in (MODULE, PYTHON, JAVASCRIPT, DEFINITION, CATEGORY, ICONS):
			if key in self and self[key]:
				self[key] = self[key][0]

	@property
	def package(self):
		return self.get('package')

	@property
	def python_path(self):
		return '%(Python)s/%(Module)s/' % self

	@property
	def js_path(self):
		return '%(Javascript)s/' % self

	@property
	def js_module_file(self):
		return '%(Javascript)s/%(Module)s.js' % self

	def iter_files(self, suffix):
		for dirname, dirs, files in os.walk(self.js_path):
			# ignore .svn directories
			if '.svn' in dirs:
				dirs.remove('.svn')
			# we are only interested in .js files
			for ifile in files:
				if ifile.endswith(suffix):
					yield os.path.join(dirname, ifile)

	@property
	def js_files(self):
		return self.iter_files('.js')
		# for dirname, dirs, files in os.walk( self.js_path ):
		# ignore .svn directories
		# 	if '.svn' in dirs:
		# 		dirs.remove( '.svn' )
		# we are only interested in .js files
		# 	for ifile in files:
		# 		if ifile.endswith('.js'):
		# 			yield os.path.join(dirname, ifile)

	@property
	def html_files(self):
		return self.iter_files('.html')
		# for dirname, dirs, files in os.walk( self.js_path ):
		# ignore .svn directories
		# 	if '.svn' in dirs:
		# 		dirs.remove( '.svn' )
		# we are only interested in .js files
		# 	for ifile in files:
		# 		if ifile.endswith('.html'):
		# 			yield os.path.join(dirname, ifile)

	@property
	def module_name(self):
		return self.__getitem__(MODULE)

	@property
	def xml_definition(self):
		return self.get(DEFINITION)

	@property
	def xml_categories(self):
		if CATEGORY in self:
			return self.get(CATEGORY, '')

	@property
	def python_files(self):
		for (path, dirs, filenames) in os.walk(self.python_path):
			for filename in filenames:
				if not filename.endswith('.py'):
					continue
				yield os.path.join(path, filename)

	@property
	def python_po_files(self):
		path = '%(Python)s/%(Module)s/' % self
		for lang in LANGUAGES:
			yield os.path.join(path, '%s.po' % lang)

	@property
	def js_po_files(self):
		for lang in LANGUAGES:
			yield os.path.join(self.__getitem__(JAVASCRIPT), '%s.po' % lang)

	@property
	def xml_po_files(self):
		if self.xml_definition is None:
			return
		dirpath = os.path.dirname(self.xml_definition)
		for lang in LANGUAGES:
			yield (lang, os.path.join(dirpath, '%s.po' % lang))

	@property
	def icons(self):
		return self.get(ICONS)


def read_modules(package, core=False):
	modules = []

	file_umc_module = os.path.join('debian/', package + '.umc-modules')

	if not os.path.isfile(file_umc_module):
		return modules

	f_umc_module = open(file_umc_module, 'r')

	for item in dh_ucs.parseRfc822(f_umc_module.read()):
		# required fields
		if not core:
			for required in (MODULE, PYTHON, DEFINITION, JAVASCRIPT):
				if not required in item or not item[required]:
					raise AttributeError('UMC module definition incomplete. key %s missing' % required)

		# single values
		item['package'] = package
		module = UMC_Module(item)
		if core:
			if module.module_name != 'umc-core' or not module.xml_categories:
				raise ValueError('Module definition does not match core module')
		modules.append(module)

	return modules


def _appendPoEntry(poFile, xmlEntry):
	"""Helper function to access text property of XML elements and to find the
	corresponding po-entry."""
	if xmlEntry is not None and xmlEntry.text is not None:  # important to use "xmlEntry is non None"!
		entry = polib.POEntry(msgid=xmlEntry.text, msgstr='')
		try:
			poFile.append(entry)
		except ValueError as exc:  # Entry "..." already exists
			print >> sys.stderr, 'Warning: Appending %r to po file failed: %s' % (xmlEntry.text, exc)


def module_xml2po(module, po_file, language):
	"""Create a PO file the XML definition of an UMC module"""
	message_po = '%s/messages.po' % (os.path.dirname(po_file) or '.')

	po = polib.POFile(check_for_duplicates=True)
	po.header = PO_HEADER
	po.metadata = copy.copy(PO_METADATA)
	po.metadata['Project-Id-Version'] = module.package
	po.metadata['POT-Creation-Date'] = formatdate(localtime=True)
	po.metadata['Language'] = language

	if module.xml_definition and os.path.isfile(module.xml_definition):
		tree = ET.ElementTree(file=module.xml_definition)
		_appendPoEntry(po, tree.find('module/name'))
		_appendPoEntry(po, tree.find('module/description'))
		for flavor in tree.findall('module/flavor'):
			_appendPoEntry(po, flavor.find('name'))
			_appendPoEntry(po, flavor.find('description'))
		_appendPoEntry(po, tree.find('link/name'))
		_appendPoEntry(po, tree.find('link/description'))
		_appendPoEntry(po, tree.find('link/url'))

	if module.xml_categories and os.path.isfile(module.xml_categories):
		tree = ET.ElementTree(file=module.xml_categories)
		for cat in tree.findall('categories/category'):
			_appendPoEntry(po, cat.find('name'))

	po.save(message_po)
	if os.path.isfile(po_file):
		try:
			if dh_ucs.doIt('msgmerge', '--update', '--sort-output', po_file, message_po):
				raise Error('Failed to merge module translations into %s.' % (po_file,))
		finally:
			if os.path.isfile(message_po):
				os.unlink(message_po)
	else:
		dh_ucs.doIt('mv', message_po, po_file)


def create_po_file(po_file, package, files, language='python'):
	"""Create a PO file for a defined set of files"""
	message_po = '%s/messages.po' % (os.path.dirname(po_file) or '.')

	if os.path.isfile(message_po):
		os.unlink(message_po)
	if isinstance(files, basestring):
		files = [files]
	if dh_ucs.doIt('xgettext', '--force-po', '--add-comments=i18n', '--from-code=UTF-8', '--sort-output', '--package-name=%s' % package, '--msgid-bugs-address=packages@univention.de', '--copyright-holder=Univention GmbH', '--language', language, '-o', message_po, *files):
		raise Error('xgettext failed for the files: %r' % (files,))
	po = polib.pofile(message_po)
	po.header = PO_HEADER
	po.metadata['Content-Type'] = 'text/plain; charset=UTF-8'
	if po.metadata_is_fuzzy:  # xgettext always creates fuzzy metadata
		try:
			po.metadata_is_fuzzy.remove('fuzzy')
		except ValueError:
			pass
	po.save()
	if os.path.isfile(po_file):
		try:
			if dh_ucs.doIt('msgmerge', '--update', '--sort-output', po_file, message_po):
				raise Error('Failed to merge translations into %s.' % (po_file,))
		finally:
			if os.path.isfile(message_po):
				os.unlink(message_po)
	else:
		dh_ucs.doIt('mv', message_po, po_file)


def create_mo_file(po_file):
	if dh_ucs.doIt('msgfmt', '--check', '--output-file', po_file.replace('.po', '.mo'), po_file):
		raise Error('Failed to compile translation file from %s.' % (po_file,))


def create_json_file(po_file):
	json_file = po_file.replace('.po', '.json')
	json_fd = open(json_file, 'w')
	pofile = polib.pofile(po_file)
	data = {}
	
	has_plurals = False
	for meta_entry in pofile.ordered_metadata():
		if meta_entry[0] == "Plural-Forms":
			has_plurals = True
			plural_rules = meta_entry[1]
			break

	# The rules get parsed from the pofile and put into the json file as
	# entries, if there are any. Parsing happens with regular expressions.
	if has_plurals:
		p = re.compile("nplurals\s*=\s*")
		pos_start = re.search(p, plural_rules).end()
		p = re.compile("[\d]+")
		pos_end = p.match(plural_rules, pos_start).end()
		data["$nplurals$"] = plural_rules[pos_start:pos_end]
		
		# The $plural$ string contains everything from "plural=" to the last
		# ';'. This is a useful, since it would include illegal code, which
		# can then be found later and generate an error.
		p = re.compile("plural\s*=\s*")
		pos_start = re.search(p, plural_rules).end()
		pos_end = list(re.finditer(';', plural_rules))[-1].start()
		data["$plural$"] = plural_rules[pos_start:pos_end]
		
		# The expression in data["$plural$"] will be evalueted via eval() in
		# javascript. To avoid malicious code injection a simple check is
		# performed here.
		p = re.compile("^[\s\dn=?!&|%:()<>]+$")
		if not p.match(data["$plural$"]):
			raise ValueError(('There are illegal characters in the "plural" '
			'expression in the .po file\'s header entry "Plural-Forms"'))

	for entry in pofile:
		if entry.msgstr:
			data[entry.msgid] = entry.msgstr
		elif entry.msgstr_plural and not has_plurals:
			raise LookupError(("There are plural forms in the .po file, but no rules for them in the .po file's header"))
		elif entry.msgstr_plural:
			data[entry.msgid] = list(entry.msgstr_plural.values())

	json_fd.write(json.dumps(data))
	json_fd.close()
