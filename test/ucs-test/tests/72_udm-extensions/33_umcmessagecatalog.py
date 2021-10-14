#!/usr/share/ucs-test/runner pytest-3
## desc: Register UMCMessageCatalog via joinscript
## tags: [udm-extensions,apptest]
## roles: [domaincontroller_master,domaincontroller_backup,domaincontroller_slave,memberserver]
## exposure: dangerous
## packages:
##   - univention-config
##   - univention-directory-manager-tools
##   - shell-univention-lib

from __future__ import print_function
import os
import base64

from univention.testing.debian_package import DebianPackage
from univention.testing.utils import fail, wait_for_replication, verify_ldap_object
from univention.testing.strings import random_ucs_version
import pytest
from univention.testing.udm_extensions import (
	get_package_name, get_package_version, get_extension_name, get_extension_filename, get_extension_buffer,
	get_unjoin_script_buffer, get_join_script_buffer, call_join_script, get_dn_of_extension_by_name,
	remove_extension_by_name, call_unjoin_script, get_absolute_extension_filename
)

mo_file = base64.b64decode('''
3hIElQAAAAAFAAAAHAAAAEQAAAAHAAAAbAAAAAAAAACIAAAADwAAAIkAAAAaAAAAmQAAAB0AAAC0AAAARQAAANIAAA
A7AQAAGAEAAA8AAABUAgAAGAAAAGQCAAAfAAAAfQIAAEUAAACdAgAAAQAAAAAAAAAEAAAAAwAAAAAAAAACAAAABQAA
AABLb3Bhbm8gQ29udGFjdHMAS29wYW5vIE5vbi1BY3RpdmUgQWNjb3VudHMATWFuYWdlbWVudCBvZiBLb3Bhbm8gQ2
9udGFjdHMATWFuYWdlbWVudCBvZiBLb3Bhbm8gbm9uLWFjdGl2ZSBhY2NvdW50cywgcmVzb3VyY2VzIGFuZCBzaGFy
ZWQgc3RvcmVzAFByb2plY3QtSWQtVmVyc2lvbjoga29wYW5vNHVjcwpSZXBvcnQtTXNnaWQtQnVncy1UbzogClBPVC
1DcmVhdGlvbi1EYXRlOiAyMDE0LTAzLTI4IDE0OjExKzAxMDAKUE8tUmV2aXNpb24tRGF0ZTogMjAxMi0wMy0yOSAx
MTo1MSswMjAwCkxhc3QtVHJhbnNsYXRvcjogcGFja2FnZXNAdW5pdmVudGlvbi5kZQpMYW5ndWFnZS1UZWFtOiBHZX
JtYW4gPGRlQGxpLm9yZz4KTGFuZ3VhZ2U6IGRlCk1JTUUtVmVyc2lvbjogMS4wCkNvbnRlbnQtVHlwZTogdGV4dC9w
bGFpbjsgY2hhcnNldD1VVEYtOApDb250ZW50LVRyYW5zZmVyLUVuY29kaW5nOiB1bmljb2RlCgBLb3Bhbm8gS29udG
FrdGUAS29wYW5vIE5vbi1BY3RpdmUgS29udGVuAFZlcndhbHR1bmcgdm9uIEtvcGFubyBLb250YWt0ZW4AVmVyd2Fs
dHVuZyB2b24gS29wYW5vIG5vbi1hY3RpdmUgS29udGVuLCBSZXNzb3VyY2VuIHVuZCBTaGFyZWQgU3RvcmVzAA==''')

TEST_DATA = (
	('umcregistration', '32_file_integrity_udm_module.xml', '/usr/share/univention-management-console/modules/udm-%s.xml'),
	('umcmessagecatalog', 'de-ucs-test.mo', '/usr/share/univention-management-console/i18n/de/ucs-test.mo'),
	('umcmessagecatalog', 'fr-ucs-test.mo', '/usr/share/univention-management-console/i18n/fr/ucs-test.mo'),
)


@pytest.mark.tags('udm-extensions', 'apptest')
@pytest.mark.roles('domaincontroller_master', 'domaincontroller_backup', 'domaincontroller_slave', 'memberserver')
@pytest.mark.exposure('dangerous')
def test_33_umcmessagecatalog():
	extension_type = 'module'
	package_name = get_package_name()
	package_version = get_package_version()
	extension_name = get_extension_name(extension_type)
	extension_filename = get_extension_filename(extension_type, extension_name)

	options = {}
	buffers = {}
	for option_type, filename, target_filename in TEST_DATA:
		buffers[filename] = open('/usr/share/ucs-test/72_udm-extensions/%s' % filename, 'rb').read()
		options.setdefault(option_type, []).append('/usr/share/%s/%s' % (package_name, filename))
	joinscript_buffer = get_join_script_buffer(
		extension_type,
		'/usr/share/%s/%s' % (package_name, extension_filename),
		options=options,
		joinscript_version=1,
		version_start=random_ucs_version(max_major=2),
		version_end=random_ucs_version(min_major=5)
	)
	unjoinscript_buffer = get_unjoin_script_buffer(extension_type, extension_name, package_name)
	extension_buffer = get_extension_buffer(extension_type, extension_name)

	package = DebianPackage(name=package_name, version=package_version)
	try:
		# create package and install it
		package.create_join_script_from_buffer('66%s.inst' % package_name, joinscript_buffer)
		package.create_unjoin_script_from_buffer('66%s-uninstall.uinst' % package_name, unjoinscript_buffer)
		package.create_usr_share_file_from_buffer(extension_filename, extension_buffer)
		for fn, data in buffers.items():
			package.create_usr_share_file_from_buffer(fn, data, 'wb')
		package.build()
		package.install()

		call_join_script('66%s.inst' % package_name)

		# wait until removed object has been handled by the listener
		wait_for_replication()

		dnlist = get_dn_of_extension_by_name(extension_type, extension_name)
		if not dnlist:
			fail('ERROR: cannot find UDM extension object with cn=%s in LDAP' % extension_name)

		# check if registered file has been replicated to local system
		target_fn = get_absolute_extension_filename(extension_type, extension_filename)
		if os.path.exists(target_fn):
			print('FILE REPLICATED: %r' % target_fn)
		else:
			fail('ERROR: target file %s does not exist' % target_fn)

		for option_type, src_fn, filename in TEST_DATA:
			if option_type == 'umcmessagecatalog' and not os.path.exists(filename):
				fail('ERROR: file %r of type %r does not exist' % (filename, option_type))
		dnlist = get_dn_of_extension_by_name(extension_type, extension_name)

		verify_ldap_object(dnlist[0], {
			'cn': [extension_name],
			'univentionUMCMessageCatalog;entry-de-ucs-test': [mo_file],
			'univentionUMCMessageCatalog;entry-fr-ucs-test': [mo_file],
		})

		call_unjoin_script('66%s-uninstall.uinst' % package_name)

	finally:
		print('Removing UDM extension from LDAP')
		remove_extension_by_name(extension_type, extension_name, fail_on_error=False)

		print('Uninstalling binary package %r' % package_name)
		package.uninstall()

		print('Removing source package')
		package.remove()
