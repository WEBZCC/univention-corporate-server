#!/usr/share/ucs-test/runner pytest-3
## desc: Create UDM module extension object and test it via CLI
## tags: [udm-ldapextensions,apptest]
## roles: [domaincontroller_master,domaincontroller_backup,domaincontroller_slave,memberserver]
## exposure: dangerous
## packages:
##   - univention-directory-manager-tools

import subprocess
import bz2
import base64

import pytest

from univention.config_registry import ConfigRegistry
import univention.testing.udm as udm_test
from univention.testing.utils import verify_ldap_object, wait_for_replication, fail
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
	def test_py2_and_3_udm_module(self, udm, ucr):
		"""Create UDM module extension object and test it via CLI"""
		with udm_test.UCSTestUDM() as udm:
			extension_type = 'module'
			extension_name = get_extension_name(extension_type)
			extension_filename = get_extension_filename(extension_type, extension_name)
			extension_buffer = get_extension_buffer(extension_type, extension_name)
			object_name = random_name()

			package_name = get_package_name()
			package_version = get_package_version()
			app_id = '%s-%s' % (random_name(), random_version())
			version_start = random_ucs_version(max_major=2)
			version_end = random_ucs_version(min_major=5)

			udm.create_object(
				'container/cn',
				name='udm_%s' % (extension_type,),
				position='cn=univention,%s' % (ucr['ldap/base'],),
				ignore_exists=True
			)

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
			udm.stop_cli_server()

			verify_ldap_object(dn, {
				'cn': [extension_name],
				'univentionUDM%sFilename' % extension_type.capitalize(): [extension_filename],
				'univentionOwnedByPackage': [package_name],
				'univentionObjectType': ['settings/udm_%s' % extension_type],
				'univentionOwnedByPackageVersion': [package_version],
				'univentionUDM%sData' % extension_type.capitalize(): [bz2.compress(extension_buffer)],
				'univentionUDM%sActive' % extension_type.capitalize(): ['TRUE'],

			})

			output, stderr = subprocess.Popen(['udm', 'modules'], stdout=subprocess.PIPE).communicate()
			if extension_name not in output:
				fail('ERROR: udm cli server has not been reloaded yet or module registration failed')

			extension_dn = udm.create_object(extension_name, position=ucr.get('ldap/base'), name=object_name)
			udm.remove_object(extension_name, dn=extension_dn)

		wait_for_replication()
		udm.stop_cli_server()

		with udm_test.UCSTestUDM() as udm:
			# test if user/user module is still ok after removing UDM module extension
			udm.create_user()
