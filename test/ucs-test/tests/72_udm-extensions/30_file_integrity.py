#!/usr/share/ucs-test/runner pytest-3
## desc: Check permissions of distributed extension file
## tags: [udm-ldapextensions,apptest]
## roles: [domaincontroller_master,domaincontroller_backup,domaincontroller_slave,memberserver]
## exposure: dangerous
## packages:
##   - univention-directory-manager-tools

from __future__ import print_function
from univention.testing.utils import wait_for_replication
from univention.testing.strings import random_name, random_version, random_ucs_version
from univention.testing.udm_extensions import (
	get_package_name,
	get_package_version,
	get_extension_name,
	get_extension_filename,
	get_extension_buffer,
	VALID_EXTENSION_TYPES,
	get_absolute_extension_filename,
)
import os
import bz2
import base64
import hashlib
import stat
import pytest
import grp


@pytest.mark.tags('udm-ldapextensions', 'apptest')
@pytest.mark.roles('domaincontroller_master', 'domaincontroller_backup', 'domaincontroller_slave', 'memberserver')
@pytest.mark.exposure('dangerous')
@pytest.mark.parametrize('extension_type', VALID_EXTENSION_TYPES)
def test_file_integrity(udm, ucr, extension_type):
	"""Check permissions of distributed extension file"""
	# wait for replicate before test starts
	wait_for_replication()

	package_name = get_package_name()
	package_version = get_package_version()
	app_id = '%s-%s' % (random_name(), random_version())
	version_start = random_ucs_version(max_major=2)
	version_end = random_ucs_version(min_major=5)

	extension_name = get_extension_name(extension_type)
	extension_filename = get_extension_filename(extension_type, extension_name)
	extension_buffer = get_extension_buffer(extension_type, extension_name)

	udm.create_object(
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
		position='cn=custom attributes,cn=univention,%s' % ucr.get('ldap/base')
	)

	# wait for replication before local filesystem is checked
	wait_for_replication()

	# check if registered file has been replicated to local system
	target_fn = get_absolute_extension_filename(extension_type, extension_filename)
	assert os.path.exists(target_fn), 'ERROR: expected UDM extension does not exist in filesystem (%s)' % (target_fn, )

	# check if sha1(buffer) == sha1(file)
	hash_buffer = hashlib.sha1(extension_buffer).hexdigest()
	hash_file = hashlib.sha1(open(target_fn).read()).hexdigest()
	assert hash_buffer == hash_file, 'ERROR: sha1 sums of file and buffer differ (fn=%s ; file=%s ; buffer=%s)' % (target_fn, hash_file, hash_buffer)

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

	udm.cleanup()

	# wait for replication before local filesystem is checked
	wait_for_replication()
	assert not os.path.exists(target_fn), 'ERROR: file %s should not exist' % target_fn  # TODO fails
