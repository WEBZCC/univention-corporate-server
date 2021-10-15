#!/usr/share/ucs-test/runner pytest-3
## desc: Create Py2-only UDM module extension object, expect it to get removed
## tags: [udm-ldapextensions,apptest]
## roles: [domaincontroller_master,domaincontroller_backup,domaincontroller_slave,memberserver]
## exposure: dangerous
## packages:
##   - univention-directory-manager-tools

import bz2
import base64
import os

import pytest

from univention.config_registry import ConfigRegistry
import univention.testing.udm as udm_test
from univention.testing.utils import verify_ldap_object, wait_for_replication
from univention.testing.strings import random_name, random_version, random_ucs_version
from univention.testing.udm_extensions import (
	get_extension_name,
	get_extension_filename,
	get_extension_buffer,
	get_package_name,
	get_package_version
)

class Test_UDMExtension(object):
	@pytest.mark.tags('udm-ldapextensions', 'apptest')
	@pytest.mark.roles('domaincontroller_master', 'domaincontroller_backup', 'domaincontroller_slave', 'memberserver')
	@pytest.mark.exposure('dangerous')
	def keep_but_dont_activate_py2_only_udm_module(self, udm, ucr):
		"""Create Py2-only UDM module extension object, expect it to get removed"""
		extension_type = 'module'
		extension_name = get_extension_name(extension_type)
		extension_filename = get_extension_filename(extension_type, extension_name)
		extension_buffer = get_extension_buffer(extension_type, extension_name)
		object_name = random_name()

		package_name = get_package_name()
		package_version = get_package_version()
		app_id = '%s-%s' % (random_name(), random_version())
		version_start = random_ucs_version(max_major=4)
		version_end = '4.4-99'

		dn = udm.create_object(
			'settings/udm_%s' % extension_type,
			name=extension_name,
			data=base64.b64encode(bz2.compress(extension_buffer)),
			filename=extension_filename,
			packageversion=package_version,
			appidentifier=app_id,
			package=package_name,
			ucsversionstart=version_start,
			ucsversionend=version_end,
			active='FALSE',
			position='cn=udm_%s,cn=univention,%s' % (extension_type, ucr['ldap/base'])
		)

		wait_for_replication()

		verify_ldap_object(dn, {
			'cn': [extension_name],
			'univentionUDM%sFilename' % extension_type.capitalize(): [extension_filename],
			'univentionOwnedByPackage': [package_name],
			'univentionObjectType': ['settings/udm_%s' % extension_type],
			'univentionOwnedByPackageVersion': [package_version],
			'univentionUDM%sData' % extension_type.capitalize(): [bz2.compress(extension_buffer)],
			'univentionUDM%sActive' % extension_type.capitalize(): ['FALSE'],
		})

		assert(not os.path.exists('/usr/lib/python2.7/dist-packages/univention/admin/handlers/%s' % (extension_filename,)))

		wait_for_replication()
		udm.stop_cli_server()
