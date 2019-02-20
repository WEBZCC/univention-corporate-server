#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
#
# Copyright 2019 Univention GmbH
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

class DiaryEvent(object):
	_all_events = {}

	@classmethod
	def get(cls, name):
		return cls._all_events.get(name)

	@classmethod
	def names(cls):
		return sorted(cls._all_events.keys())

	def __init__(self, name, message, args=None, tags=None, icon=None):
		self.name = name
		self.message = message
		self.args = args or {}
		self.tags = tags or []
		self.icon = icon
		self._all_events[self.name] = self

USER_CREATED = DiaryEvent('USER_CREATED', {'en': 'User {username} created', 'de': 'Benutzer {username} angelegt'}, args=['username'], icon='users')

APP_INSTALL_START = DiaryEvent('APP_INSTALL_START', {'en': 'Installation of {name} {version} started', 'de': 'Installation von {name} {version} wurde gestartet'}, args=['name', 'version'], icon='software')
APP_INSTALL_SUCCESS = DiaryEvent('APP_INSTALL_SUCCESS', {'en': 'Installation of {name} {version} was successful', 'de': 'Die Installation von {name} {version} war erfolgreich'}, args=['name', 'version'], icon='software')
APP_INSTALL_FAILURE = DiaryEvent('APP_INSTALL_FAILURE', {'en': 'Installation of {name} {version} failed. Error {error_code}', 'de': 'Installation von {name} {version} schlug fehl. Fehler {error_code}'}, args=['name', 'version', 'error_code'], tags=['error'], icon='software')

SERVER_PASSWORD_CHANGED = DiaryEvent('SERVER_PASSWORD_CHANGED', {'en': 'Machine account password changed successfully', 'de': 'Maschinenpasswort erfolgreich geändert'}, icon='devices')
SERVER_PASSWORD_CHANGED_FAILED = DiaryEvent('SERVER_PASSWORD_CHANGED_FAILED', {'en': 'Machine account password change failed', 'de': 'Änderung des Maschinenpassworts fehlgeschlagen'}, tags=['error'], icon='devices')

UPDATE_STARTED = DiaryEvent('UPDATE_STARTED', {'en': 'Started to update {hostname}', 'de': 'Aktualisierung von {hostname} begonnen'}, args=['hostname'], icon='software')
UPDATE_FINISHED_SUCCESS = DiaryEvent('UPDATE_FINISHED_SUCCESS', {'en': 'Successfully updated {hostname} to {version}', 'de': 'Aktualisierung von {hostname} auf {version} erfolgreich abgeschlossen'}, args=['hostname', 'version'], icon='software')
UPDATE_FINISHED_FAILURE = DiaryEvent('UPDATE_FINISHED_FAILURE', {'en': 'Failed to update {hostname}', 'de': 'Aktualisierung von {hostname} fehlgeschlagen'}, args=['hostname'], tags=['error'], icon='software')

JOIN_STARTED = DiaryEvent('JOIN_STARTED', {'en': 'Started to join {hostname} into the domain', 'de': 'Domänenbeitritt von {hostname} begonnen'}, args=['hostname'], icon='domain')
JOIN_FINISHED_SUCCESS = DiaryEvent('JOIN_FINISHED_SUCCESS', {'en': 'Successfully joined {hostname}', 'de': '{hostname} erfolgreich der Domäne beigetreten'}, args=['hostname'], icon='domain')
JOIN_FINISHED_FAILURE = DiaryEvent('JOIN_FINISHED_FAILURE', {'en': 'Failed to join {hostname}', 'de': 'Domänenbeitritt von {hostname} fehlgeschlagen'}, args=['hostname'], tags=['error'], icon='domain')
JOIN_SCRIPT_FAILED = DiaryEvent('JOIN_SCRIPT_FAILED', {'en': 'Running Joinscript {joinscript} failed', 'de': 'Ausführung des Joinscripts {joinscript} fehlgeschlagen'}, tags=['error'], icon='domain')
