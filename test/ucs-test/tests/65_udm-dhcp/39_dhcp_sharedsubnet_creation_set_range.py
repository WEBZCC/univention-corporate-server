#!/usr/share/ucs-test/runner pytest-3
## desc: Set range during dhcp/sharedsubnet creation
## tags: [udm]
## roles: [domaincontroller_master]
## exposure: careful
## packages:
##   - univention-config
##   - univention-directory-manager-tools


import pytest
import univention.testing.utils as utils
import univention.testing.strings as uts


class Test_DHCPSharedsubnet(object):
	@pytest.mark.tags('udm')
	@pytest.mark.roles('domaincontroller_master')
	@pytest.mark.exposure('careful')
	def test_dhcp_sharedsubnet_creation_set_range(self, udm):
		"""Set range during dhcp/sharedsubnet creation"""
		dhcp_service = udm.create_object('dhcp/service', service=uts.random_name())
		dhcp_shared_network = udm.create_object('dhcp/shared', name=uts.random_name(), superordinate=dhcp_service)

		range = '10.20.30.1 10.20.30.5'
		dhcp_shared_subnet = udm.create_object('dhcp/sharedsubnet', subnet='10.20.30.0', subnetmask='24', range=range, superordinate=dhcp_shared_network)
		utils.verify_ldap_object(dhcp_shared_subnet, {'dhcpRange': [range]})
