#!/usr/share/ucs-test/runner pytest-3
## desc: Register and deregister UDM extension via joinscript
## tags: [udm-extensions,apptest]
## roles: [domaincontroller_master,domaincontroller_backup,domaincontroller_slave,memberserver]
## exposure: dangerous
## packages:
##   - univention-config
##   - univention-directory-manager-tools
##   - shell-univention-lib

from __future__ import print_function
from test_udm_extensions import temp_deb_pkg
from univention.testing.utils import wait_for_replication
from univention.testing.udm_extensions import (
	get_package_name,
	get_package_version,
	get_extension_name,
	get_extension_filename,
	get_extension_buffer,
	get_absolute_extension_filename,
	get_join_script_buffer,
	get_unjoin_script_buffer,
	get_dn_of_extension_by_name,
	VALID_EXTENSION_TYPES,
	call_join_script,
	call_unjoin_script
)
import stat
import os
import grp
import pytest
import hashlib


@pytest.mark.tags('udm-extensions', 'apptest')
@pytest.mark.roles('domaincontroller_master', 'domaincontroller_backup', 'domaincontroller_slave', 'memberserver')
@pytest.mark.exposure('dangerous')
@pytest.mark.parametrize('extension_type', VALID_EXTENSION_TYPES)
def test_register_deregister_via_joinscript(extension_type):
	"""Register and deregister UDM extension via joinscript"""
	package_name = get_package_name()
	package_version = get_package_version()
	extension_name = get_extension_name(extension_type)
	extension_filename = get_extension_filename(extension_type, extension_name)
	joinscript_buffer = get_join_script_buffer(extension_type, '/usr/share/%s/%s' % (package_name, extension_filename), version_start='5.0-0')
	unjoinscript_buffer = get_unjoin_script_buffer(extension_type, extension_name, package_name)
	extension_buffer = get_extension_buffer(extension_type, extension_name)

	with temp_deb_pkg(package_name, package_version, extension_type, extension_name) as package:
		# create package and install it
		package.create_join_script_from_buffer('66%s.inst' % package_name, joinscript_buffer)
		package.create_unjoin_script_from_buffer('66%s-uninstall.uinst' % package_name, unjoinscript_buffer)
		package.create_usr_share_file_from_buffer(extension_filename, extension_buffer)
		package.build()
		package.install()

		call_join_script('66%s.inst' % package_name)

		# wait until removed object has been handled by the listener
		wait_for_replication()

		dnlist = get_dn_of_extension_by_name(extension_type, extension_name)
		assert dnlist, 'ERROR: cannot find UDM extension object with cn=%s in LDAP' % extension_name

		# check if registered file has been replicated to local system
		target_fn = get_absolute_extension_filename(extension_type, extension_filename)
		assert os.path.exists(target_fn), 'ERROR: target file %s does not exist' % target_fn

		# check replicated file has correct file mode
		current_mode = oct(os.stat(target_fn).st_mode & (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO))
		expected_mode = '0644'
		assert current_mode == expected_mode, 'ERROR: permissions of target file %s are not ok (current=%s  expected=%s)' % (target_fn, current_mode, expected_mode)

		# check replicated file is own by root:nobody
		expected_groups = (0, grp.getgrnam('nogroup').gr_gid)
		expected_uid = 0
		current_uid = os.stat(target_fn).st_uid
		current_group = os.stat(target_fn).st_gid
		assert current_uid == expected_uid and current_group in expected_groups, 'ERROR: owner/group of target file %s is not ok (current=%s:%s  expected_uid=%s expected_gid=%s)' % (target_fn, current_uid, current_group, expected_uid, expected_groups)

		# check if sha1(buffer) == sha1(file)
		hash_buffer = hashlib.sha1(extension_buffer).hexdigest()
		hash_file = hashlib.sha1(open(target_fn).read()).hexdigest()
		print('HASH BUFFER: %r' % hash_buffer)
		print('HASH FILE: %r' % hash_file)
		assert hash_buffer == hash_file, 'ERROR: sha1 sums of file and buffer differ (fn=%s ; file=%s ; buffer=%s)' % (target_fn, hash_file, hash_buffer)

		call_unjoin_script('66%s-uninstall.uinst' % package_name)

		# wait until removed object has been handled by the listener
		wait_for_replication()

		dnlist = get_dn_of_extension_by_name(extension_type, extension_name)
		assert not dnlist, 'ERROR: UDM extension object with cn=%s is still present in LDAP' % extension_name

		# check if registered file has been removed from local system
		assert not os.path.exists(target_fn), 'ERROR: target file %s is still present' % target_fn
