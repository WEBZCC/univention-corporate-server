# -*- coding: utf-8 -*-
#
# Univention Admin Modules
#  admin policy for the share userquota
#
# Copyright 2004-2011 Univention GmbH
#
# http://www.univention.de/
#
# All rights reserved.
#
# The source code of this program is made available
# under the terms of the GNU Affero General Public License version 3
# (GNU AGPL V3) as published by the Free Software Foundation.
#
# Binary versions of this program provided by Univention to you as
# well as other copyrighted, protected or trademarked materials like
# Logos, graphics, fonts, specific documentations and configurations,
# cryptographic keys etc. are subject to a license agreement between
# you and Univention and not subject to the GNU AGPL V3.
#
# In the case you use this program under the terms of the GNU AGPL V3,
# the program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <http://www.gnu.org/licenses/>.

from univention.admin.layout import Tab, Group
import univention.admin.syntax
import univention.admin.filter
import univention.admin.handlers
import univention.admin.localization

import univention.debug

translation=univention.admin.localization.translation('univention.admin.handlers.policies')
_=translation.translate

class shareUserQuotaFixedAttributes(univention.admin.syntax.select):
	name='shareUserQuotaFixedAttributes'
	choices=[
		('univentionQuotaSoftLimitSpace',_('Soft limit (Bytes)')),
		('univentionQuotaHardLimitSpace',_('Hard limit (Bytes)')),
		('univentionQuotaSoftLimitInodes',_('Soft limit (Files)')),
		('univentionQuotaHardLimitInodes',_('Hard limit (Files)'))
		]

module='policies/share_userquota'
operations=['add','edit','remove','search']

policy_oc='univentionPolicyShareUserQuota'
policy_apply_to=["shares/share"]
policy_position_dn_prefix="cn=userquota,cn=shares"

childs=0
short_description=_('Policy: User quota')
policy_short_description=_('User quota')
long_description=_('Default quota for each user on a share')
options={
}
property_descriptions={
	'name': univention.admin.property(
			short_description=_('Name'),
			long_description='',
			syntax=univention.admin.syntax.string,
			multivalue=0,
			options=[],
			required=1,
			may_change=0,
			identifies=1,
		),
	'softLimitSpace': univention.admin.property(
			short_description=_('Soft limit (Bytes)'),
			long_description=_('Soft limit. If exceeded users can be warned.'),
			syntax=univention.admin.syntax.filesize,
			multivalue=0,
			options=[],
			required=0,
			may_change=1,
			identifies=0
		),
	'hardLimitSpace': univention.admin.property(
			short_description=_('Hard limit (Bytes)'),
			long_description=_('Hard limit. Can not be exceeded.'),
			syntax=univention.admin.syntax.filesize,
			multivalue=0,
			options=[],
			required=0,
			may_change=1,
			identifies=0
		),
	'softLimitInodes': univention.admin.property(
			short_description=_('Soft limit (Files)'),
			long_description=_('Soft limit. If exceeded users can be warned.'),
			syntax=univention.admin.syntax.integer,
			multivalue=0,
			options=[],
			required=0,
			may_change=1,
			identifies=0
		),
	'hardLimitInodes': univention.admin.property(
			short_description=_('Hard limit (Files)'),
			long_description=_('Hard limit. Can not be exceeded.'),
			syntax=univention.admin.syntax.integer,
			multivalue=0,
			options=[],
			required=0,
			may_change=1,
			identifies=0
		),
	'requiredObjectClasses': univention.admin.property(
			short_description=_('Required object classes'),
			long_description='',
			syntax=univention.admin.syntax.string,
			multivalue=1,
			options=[],
			required=0,
			may_change=1,
			identifies=0
		),
	'prohibitedObjectClasses': univention.admin.property(
			short_description=_('Excluded object classes'),
			long_description='',
			syntax=univention.admin.syntax.string,
			multivalue=1,
			options=[],
			required=0,
			may_change=1,
			identifies=0
		),
	'fixedAttributes': univention.admin.property(
			short_description=_('Fixed attributes'),
			long_description='',
			syntax=shareUserQuotaFixedAttributes,
			multivalue=1,
			options=[],
			required=0,
			may_change=1,
			identifies=0
		),
	'emptyAttributes': univention.admin.property(
			short_description=_('Empty attributes'),
			long_description='',
			syntax=shareUserQuotaFixedAttributes,
			multivalue=1,
			options=[],
			required=0,
			may_change=1,
			identifies=0
		),
}

layout = [
	Tab(_('General'),_('Quota'), layout = [
		Group( _( 'General' ), layout = [
			'name',
			[ 'softLimitSpace', 'hardLimitSpace' ],
			[ 'softLimitInodes', 'hardLimitInodes' ]
		] ),
	] ),
	Tab(_('Object'),_('Object'), advanced = True, layout = [
		[ 'requiredObjectClasses' , 'prohibitedObjectClasses' ],
		[ 'fixedAttributes', 'emptyAttributes' ]
	] ),
]

mapping=univention.admin.mapping.mapping()
mapping.register('name', 'cn', None, univention.admin.mapping.ListToString)
mapping.register('hardLimitSpace', 'univentionQuotaHardLimitSpace', None, univention.admin.mapping.ListToString)
mapping.register('softLimitSpace', 'univentionQuotaSoftLimitSpace', None, univention.admin.mapping.ListToString)
mapping.register('hardLimitInodes', 'univentionQuotaHardLimitInodes', None, univention.admin.mapping.ListToString)
mapping.register('softLimitInodes', 'univentionQuotaSoftLimitInodes', None, univention.admin.mapping.ListToString)
mapping.register('requiredObjectClasses', 'requiredObjectClasses')
mapping.register('prohibitedObjectClasses', 'prohibitedObjectClasses')
mapping.register('fixedAttributes', 'fixedAttributes')
mapping.register('emptyAttributes', 'emptyAttributes')

class object(univention.admin.handlers.simplePolicy):
	module=module

	def __init__(self, co, lo, position, dn='', superordinate=None, attributes = [] ):
		global mapping
		global property_descriptions

		self.mapping=mapping
		self.descriptions=property_descriptions

		univention.admin.handlers.simplePolicy.__init__(self, co, lo, position, dn, superordinate, attributes )

	def _ldap_pre_create(self):
		self.dn='%s=%s,%s' % (mapping.mapName('name'), mapping.mapValue('name', self.info['name']), self.position.getDn())

	def _ldap_addlist(self):
		return [ ('objectClass', ['top', 'univentionPolicy', 'univentionPolicyShareUserQuota']) ]

def lookup(co, lo, filter_s, base='', superordinate=None, scope='sub', unique=0, required=0, timeout=-1, sizelimit=0):

	filter=univention.admin.filter.conjunction('&', [
		univention.admin.filter.expression('objectClass', 'univentionPolicyShareUserQuota')
		])

	if filter_s:
		filter_p=univention.admin.filter.parse(filter_s)
		univention.admin.filter.walk(filter_p, univention.admin.mapping.mapRewrite, arg=mapping)
		filter.expressions.append(filter_p)

	res=[]
	try:
		for dn, attrs in lo.search(unicode(filter), base, scope, [], unique, required, timeout, sizelimit):
			res.append( object( co, lo, None, dn, attributes = attrs ) )
	except:
		pass
	return res

def identify(dn, attr, canonical=0):
	return 'univentionPolicyShareUserQuota' in attr.get('objectClass', [])
