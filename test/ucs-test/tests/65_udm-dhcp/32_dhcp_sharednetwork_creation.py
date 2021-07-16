#!/usr/share/ucs-test/runner pytest-3
## desc: Create dhcp/shared
## tags: [udm]
## roles: [domaincontroller_master]
## exposure: careful
## packages:
##   - univention-config
##   - univention-directory-manager-tools


import pytest
import univention.testing.utils as utils
import univention.testing.strings as uts


class Test_DHCPSharednetwork(object):
	@pytest.mark.tags('udm')
	@pytest.mark.roles('domaincontroller_master')
	@pytest.mark.exposure('careful')
	def test_dhcp_sharednetwork_creation(self, udm):
		dhcp_service = udm.create_object('dhcp/service', service=uts.random_name())

		dhcp_shared_network = udm.create_object('dhcp/shared', name=uts.random_name(), superordinate=dhcp_service)
		utils.verify_ldap_object(dhcp_shared_network)
