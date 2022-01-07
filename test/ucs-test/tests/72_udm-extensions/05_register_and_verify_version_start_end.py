#!/usr/share/ucs-test/runner pytest-3
## desc: Check setting of a version range for UDM extensions
## tags: [udm-extensions,apptest]
## roles: [domaincontroller_master,domaincontroller_backup,domaincontroller_slave,memberserver]
## exposure: dangerous
## packages:
##   - univention-config
##   - univention-directory-manager-tools
##   - shell-univention-lib

from __future__ import print_function
from test_udm_extensions import temp_deb_pkg
from univention.testing.utils import wait_for_replication, verify_ldap_object
from univention.testing.strings import random_name, random_version, random_ucs_version
from univention.testing.udm_extensions import (
	get_package_name,
	get_package_version,
	get_extension_name,
	get_extension_filename,
	get_join_script_buffer,
	get_extension_buffer,
	call_join_script,
	get_dn_of_extension_by_name,
	VALID_EXTENSION_TYPES
)
import pytest
import bz2


@pytest.mark.tags('udm-extensions', 'apptest')
@pytest.mark.roles('domaincontroller_master', 'domaincontroller_backup', 'domaincontroller_slave', 'memberserver')
@pytest.mark.exposure('dangerous')
@pytest.mark.parametrize('extension_type', VALID_EXTENSION_TYPES)
def test_register_and_verify_version_start_end(extension_type):
	"""Check setting of a version range for UDM extensions"""
	package_name = get_package_name()
	package_version = get_package_version()
	extension_name = get_extension_name(extension_type)
	extension_filename = get_extension_filename(extension_type, extension_name)
	version_start = random_ucs_version(max_major=2)
	version_end = random_ucs_version(min_major=5)
	app_id = '%s-%s' % (random_name(), random_version())
	joinscript_buffer = get_join_script_buffer(
		extension_type,
		'/usr/share/%s/%s' % (package_name, extension_filename),
		app_id=app_id, version_start=version_start, version_end=version_end
	)
	extension_buffer = get_extension_buffer(extension_type, extension_name)
	print(joinscript_buffer)

	with temp_deb_pkg(package_name, package_version, extension_type, extension_name) as package:
		# create package and install it
		package.create_join_script_from_buffer('66%s.inst' % package_name, joinscript_buffer)
		package.create_usr_share_file_from_buffer(extension_filename, extension_buffer)
		package.build()
		package.install()

		call_join_script('66%s.inst' % package_name)

		# wait until removed object has been handled by the listener
		wait_for_replication()

		dnlist = get_dn_of_extension_by_name(extension_type, extension_name)
		assert dnlist, 'Cannot find UDM %s extension with name %s in LDAP' % (extension_type, extension_name)
		verify_ldap_object(dnlist[0], {
			'cn': [extension_name],
			'univentionUDM%sFilename' % extension_type.capitalize(): [extension_filename],
			'univentionOwnedByPackage': [package_name],
			'univentionObjectType': ['settings/udm_%s' % extension_type],
			'univentionOwnedByPackageVersion': [package_version],
			'univentionUDM%sData' % extension_type.capitalize(): [bz2.compress(extension_buffer)],
			'univentionUCSVersionStart': [version_start],
			'univentionUCSVersionEnd': [version_end],
		})
