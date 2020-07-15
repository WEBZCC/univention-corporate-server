# -*- coding: utf-8 -*-
#
# Univention Directory Manager
"""listener script for UDM REST API reloading of extended attributes."""
#
# Copyright 2020 Univention GmbH
#
# https://www.univention.de/
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
# <https://www.gnu.org/licenses/>.

from __future__ import absolute_import

import subprocess

import listener

name = 'udm_rest_reload'
description = 'Handle UDM module reloading in UDM REST API'
filter = '(|(objectClass=univentionUDMProperty)(objectClass=univentionUDMOption)(objectClass=univentionUDMSyntax)(objectClass=univentionUDMModule)(objectClass=univentionUDMHook))'
attributes = []


def handler(dn, new, old):
	"""Handle UDM extended attribute reloading"""
	listener.setuid(0)
	try:
		subprocess.call(['systemctl', 'reload', 'univention-directory-manager-rest'])
	finally:
		listener.unsetuid()
