#!/usr/share/ucs-test/runner pytest-3
## desc: Test extension update with correct version order
## tags: [udm-extensions,apptest]
## roles: [domaincontroller_master,domaincontroller_backup,domaincontroller_slave,memberserver]
## exposure: dangerous
## packages:
##   - univention-config
##   - univention-directory-manager-tools
##   - shell-univention-lib

from __future__ import print_function
import random

import pytest

from univention.testing.debian_package import DebianPackage
from univention.testing.utils import wait_for_replication, fail, verify_ldap_object
from univention.testing.strings import random_name, random_version, random_ucs_version
from univention.testing.udm_extensions import (
	get_package_name,
	get_extension_name,
	get_extension_filename,
	get_extension_buffer,
	get_join_script_buffer,
	VALID_EXTENSION_TYPES,
	get_dn_of_extension_by_name,
	get_absolute_extension_filename,
	remove_extension_by_name,
	call_join_script
)


class Test_UDMExtension(object):
	@pytest.mark.parametrize('extension_type',VALID_EXTENSION_TYPES)
	@pytest.mark.tags('udm-extensions', 'apptest')
	@pytest.mark.roles('domaincontroller_master', 'domaincontroller_backup', 'domaincontroller_slave', 'memberserver')
	@pytest.mark.exposure('dangerous')
	def update_extension_via_package(self, extension_type):
		package_name = get_package_name()
		version = random_version()
		package_version_LOW = '%s.%d' % (version, random.randint(0, 4))
		package_version_HIGH = '%s.%d' % (version, random.randint(5, 9))
		extension_name = get_extension_name(extension_type)
		extension_filename = get_extension_filename(extension_type, extension_name)
		app_id = '%s-%s' % (random_name(), random_version())
		joinscript_version = 1

		packages = []
		try:
			for package_version in (package_version_LOW, package_version_HIGH):

				version_start = random_ucs_version(max_major=2)
				version_end = random_ucs_version(min_major=5)

				# create unique extension identifier
				extension_identifier = '%s_%s' % (extension_name, package_version.replace('.', '_'))
				extension_buffer = get_extension_buffer(extension_type, extension_name, extension_identifier)
				joinscript_buffer = get_join_script_buffer(
					extension_type,
					'/usr/share/%s/%s' % (package_name, extension_filename),
					app_id=app_id,
					joinscript_version=joinscript_version,
					version_start=version_start,
					version_end=version_end
				)
				joinscript_version += 1

				# create package and install it
				package = DebianPackage(name=package_name, version=package_version)
				packages.append(package)
				package.create_join_script_from_buffer('66%s.inst' % package_name, joinscript_buffer)
				package.create_usr_share_file_from_buffer(extension_filename, extension_buffer)
				package.build()
				package.install()

				call_join_script('66%s.inst' % package_name)

				# wait until removed object has been handled by the listener
				wait_for_replication()

				dnlist = get_dn_of_extension_by_name(extension_type, extension_name)
				if not dnlist:
					fail('Cannot find UDM %s extension with name %s in LDAP' % (extension_type, extension_name))
				verify_ldap_object(dnlist[0], {
					'cn': [extension_name],
					'univentionUCSVersionStart': [version_start],
					'univentionUCSVersionEnd': [version_end],
				})

				content = open(get_absolute_extension_filename(extension_type, extension_filename)).read()
				if extension_identifier not in content:
					fail('ERROR: UDM extension of package %d has not been written to disk (%s)' % (len(packages), extension_filename,))

		finally:
			print('Removing UDM extension from LDAP')
			remove_extension_by_name(extension_type, extension_name, fail_on_error=False)

			for package in packages:
				print('Uninstalling binary package %r' % package.get_package_name())
				package.uninstall()

			print('Removing source package')
			for package in packages:
				package.remove()
