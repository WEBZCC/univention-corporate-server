#!/usr/share/ucs-test/runner pytest-3
## desc: Register and verify all UDM extension in one step
## tags: [udm-extensions,apptest]
## roles: [domaincontroller_master,domaincontroller_backup,domaincontroller_slave,memberserver]
## exposure: dangerous
## packages:
##   - univention-config
##   - univention-directory-manager-tools
##   - shell-univention-lib

from __future__ import print_function
from univention.testing.debian_package import DebianPackage
from univention.testing.utils import wait_for_replication, verify_ldap_object
from univention.testing.udm_extensions import (
	get_package_name,
	get_package_version,
	get_extension_name,
	get_extension_filename,
	get_extension_buffer,
	VALID_EXTENSION_TYPES,
	get_dn_of_extension_by_name,
	remove_extension_by_name,
	call_join_script
)
from univention.testing.strings import random_name
import pytest
import bz2


@pytest.mark.tags('udm-extensions', 'apptest')
@pytest.mark.roles('domaincontroller_master', 'domaincontroller_backup', 'domaincontroller_slave', 'memberserver')
@pytest.mark.exposure('dangerous')
def test_register_with_special_name_and_verify_all():
	"""Register and verify all UDM extension in one step"""
	objectname = "/".join([random_name(), random_name()])  # slash reqired for 'module'
	package_name = get_package_name()
	package_version = get_package_version()
	extension_name = {}
	extension_objectname = {}
	extension_buffer = {}
	extension_filename = {}
	for extension_type in VALID_EXTENSION_TYPES:
		extension_name[extension_type] = get_extension_name(extension_type)
		extension_objectname[extension_type] = objectname
		extension_buffer[extension_type] = get_extension_buffer(extension_type, extension_name[extension_type])
		extension_filename[extension_type] = get_extension_filename(extension_type, extension_name[extension_type])

	data = {'package': package_name, 'objectname': objectname}
	data.update(extension_filename)
	joinscript_buffer = '''#!/bin/sh
VERSION=1
set -e
. /usr/share/univention-join/joinscripthelper.lib
joinscript_init
. /usr/share/univention-lib/ldap.sh
ucs_registerLDAPExtension "$@" --name "%(objectname)s" --ucsversionstart 5.0-0 --udm_hook /usr/share/%(package)s/%(hook)s --udm_syntax /usr/share/%(package)s/%(syntax)s --udm_module /usr/share/%(package)s/%(module)s
joinscript_save_current_version
exit 0
''' % data

	package = DebianPackage(name=package_name, version=package_version)
	try:
		# create package and install it
		package.create_join_script_from_buffer('66%s.inst' % package_name, joinscript_buffer)
		for extension_type in VALID_EXTENSION_TYPES:
			package.create_usr_share_file_from_buffer(extension_filename[extension_type], extension_buffer[extension_type])
		package.build()
		package.install()

		call_join_script('66%s.inst' % package_name)

		# wait until removed object has been handled by the listener
		wait_for_replication()

		for extension_type in VALID_EXTENSION_TYPES:
			dnlist = get_dn_of_extension_by_name(extension_type, extension_objectname[extension_type])
			assert dnlist, 'Cannot find UDM %s extension with name %s in LDAP' % (extension_type, extension_objectname[extension_type])
			verify_ldap_object(dnlist[0], {
				'cn': [extension_objectname[extension_type]],
				'univentionUDM%sFilename' % extension_type.capitalize(): [extension_filename[extension_type]],
				'univentionOwnedByPackage': [package_name],
				'univentionObjectType': ['settings/udm_%s' % extension_type],
				'univentionOwnedByPackageVersion': [package_version],
				'univentionUDM%sData' % extension_type.capitalize(): [bz2.compress(extension_buffer[extension_type])],
			})

	finally:
		for extension_type in VALID_EXTENSION_TYPES:
			remove_extension_by_name(extension_type, extension_objectname[extension_type], fail_on_error=False)
		package.uninstall()
		package.remove()
