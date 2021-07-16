#!/usr/share/ucs-test/runner pytest-3
## desc: test UDM-CLI code for --policies={1,2}
## tags: [udm]
## roles: [domaincontroller_master]
## exposure: careful
## packages:
##   - univention-config
##   - univention-directory-manager-tools

import pprint
import pytest
import univention.testing.udm as udm_test
import univention.testing.strings as uts

@pytest.mark.tags('udm')
@pytest.mark.roles('domaincontroller_master')
@pytest.mark.exposure('careful')
def test_udm_cli_policies_output(udm):
	"""test UDM-CLI code for --policies={1,2}"""
	dhcp_service = udm.create_object('dhcp/service', service=uts.random_name())

	subnet_mask = '24'
	subnet = '10.20.30.0'
	dhcp_subnet = udm.create_object('dhcp/subnet', superordinate=dhcp_service, subnet=subnet, subnetmask=subnet_mask)

	dhcp_host = udm.create_object('dhcp/host', superordinate=dhcp_subnet, host=uts.random_name(), hwaddress='ethernet 01:ff:78:38:ab:24', fixedaddress='10.20.30.123')

	host = udm.list_objects('dhcp/host', position=dhcp_host, policies=1)[0][1]
	pprint.pprint(host)
	required = {'Policy-based Settings', 'Subnet-based Settings', 'Merged Settings'}
	assert set(host) & required == required

	host = udm.list_objects('dhcp/host', position=dhcp_host, policies=2)[0][1]
	pprint.pprint(host)
	required = {'univentionPWLength', 'univentionPWHistoryLen'}
	assert set(host['Policy-based Settings']) & required == required
	assert set(host['Subnet-based Settings']) & required == required
	assert set(host['Merged Settings']) & required == required
