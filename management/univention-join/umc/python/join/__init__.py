#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Univention Management Console
#  module: system usage statistics
#
# Copyright 2011-2021 Univention GmbH
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

import traceback
import subprocess
import os
import tempfile
import socket
import glob
import re
import dns.resolver
import dns.exception

import notifier.threads
import apt_pkg

import univention.management.console as umc
from univention.management.console.log import MODULE
from univention.management.console.modules import Base, UMC_Error
from univention.management.console.config import ucr
from univention.management.console.modules.decorators import simple_response, sanitize
from univention.management.console.modules.sanitizers import StringSanitizer, ListSanitizer, BooleanSanitizer


from typing import Any, Callable, Dict, List, Union  # noqa F401


_ = umc.Translation('univention-management-console-module-join').translate

CMD_ENABLE_EXEC = ['/usr/share/univention-updater/enable-apache2-umc', '--no-restart']
CMD_DISABLE_EXEC = ['/usr/share/univention-updater/disable-apache2-umc', '--exclude-apache']
RE_HOSTNAME = re.compile(r'^[a-z]([a-z0-9-]*[a-z0-9])*(\.([a-z0-9]([a-z0-9-]*[a-z0-9])*[.])*[a-z0-9]([a-z0-9-]*[a-z0-9])*)?$')


def get_master_dns_lookup() -> Dict:
	# DNS lookup for the Primary Directory Node entry
	msg = None
	fqdn = None
	try:
		domainname = ucr.get('domainname')
		query = f'_domaincontroller_master._tcp.{domainname}.'
		resolver = dns.resolver.Resolver()
		resolver.lifetime = 3.0  # max. 3 seconds
		result = resolver.query(query, 'SRV')
		if result:
			fqdn = result[0].target.canonicalize().split(1)[0].to_text()
	except dns.resolver.NXDOMAIN:
		MODULE.error(f'No record found for {query}.')
		msg = _('No DNS record for the Primary Directory Node was found. This might be a problem with the configured DNS server. Please make sure the DNS settings are correct.')
	except dns.resolver.Timeout:
		MODULE.error(f'Timeout when looking up {query}.')
		msg = _('The lookup of the Primary Directory Node record timed out. There might be a problem with the configured DNS server. Make sure the DNS server is up and running or check the DNS settings.')
	except dns.resolver.NoAnswer:
		MODULE.error(f'Non-Authoritative answer during lookup of {query}.')
	except dns.exception.DNSException as exc:
		MODULE.error(f'Error during Primary Directory Node lookup: {traceback.format_exc()}')
		msg = f'Error during Primary Directory Node lookup: {exc}.'
	return {'master': fqdn, 'error_message': msg}


class HostSanitizer(StringSanitizer):

	def _sanitize(self, value: str, name: str, further_args: List[str]) -> str:
		value = super(HostSanitizer, self)._sanitize(value, name, further_args)
		try:
			return socket.getfqdn(value)
		except socket.gaierror:
			# invalid FQDN
			self.raise_validation_error(_('The entered FQDN is not a valid value'))


class Progress(object):

	def __init__(self, max_steps=100):
		self.reset(max_steps)

	def reset(self, max_steps: int = 100) -> None:
		self.max_steps = max_steps
		self.finished = False
		self.steps = 0
		self.component = _('Initializing')
		self.info = ''
		self.errors = []
		self.critical = False

	def poll(self) -> Dict:
		return dict(
			finished=self.finished,
			steps=100 * float(self.steps) / self.max_steps,
			component=self.component,
			info=self.info,
			errors=self.errors,
			critical=self.critical,
		)

	def finish(self) -> None:
		self.finished = True

	def info_handler(self, info: str) -> None:
		MODULE.process(info)
		self.info = info

	def error_handler(self, err: str) -> None:
		MODULE.warn(err)
		self.errors.append(err)

	def component_handler(self, component: str) -> None:
		self.component = component

	def critical_handler(self, critical: bool) -> None:
		self.critical = critical

	def step_handler(self, steps: int) -> None:
		self.steps = steps

	def add_steps(self, steps: int = 1) -> None:
		self.steps += steps


def _dummyFunc(*args: List) -> None:
	"""dummy function that does nothing"""
	pass


def system_join(
	hostname: str, username: str, password: str, info_handler: Callable = _dummyFunc,
	error_handler: Callable = _dummyFunc, critical_handler: Callable = _dummyFunc,
	step_handler: Callable = _dummyFunc, component_handler: Callable = _dummyFunc) -> bool:
	# get the number of join scripts
	nJoinScripts = len(glob.glob(f'{INSTDIR}/*.inst'))
	stepsPerScript = 100.0 / (nJoinScripts + 1)

	with tempfile.NamedTemporaryFile() as passwordFile:
		passwordFile.write(password.encode('UTF-8'))
		passwordFile.flush()

		MODULE.process('Performing system join...')
		cmd = ['/usr/sbin/univention-join', '-dcname', hostname, '-dcaccount', username, '-dcpwd', passwordFile.name]

		return run(cmd, stepsPerScript, info_handler, error_handler, critical_handler, step_handler, component_handler)


def run_join_scripts(
	scripts: List, force: bool, username: str, password: str, info_handler: Callable = _dummyFunc,
	error_handler: Callable = _dummyFunc, critical_handler: Callable = _dummyFunc,
	step_handler: Callable = _dummyFunc, component_handler: Callable = _dummyFunc) -> bool:
	with tempfile.NamedTemporaryFile() as passwordFile:
		cmd = ['/usr/sbin/univention-run-join-scripts']
		if username and password:
			# credentials are provided
			passwordFile.write(password.encode('UTF-8'))
			passwordFile.flush()
			cmd += ['-dcaccount', username, '-dcpwd', passwordFile.name]

		if force:
			cmd += ['--force']

		if scripts:
			# if scripts are provided only execute them instead of running all join scripts
			cmd += ['--run-scripts'] + scripts
		else:
			# we need the number of join scripts for the progressbar
			scripts = os.listdir(INSTDIR)
		stepsPerScript = 100.0 / (len(scripts) + 1)

		MODULE.process('Executing join scripts ...')
		return run(cmd, stepsPerScript, info_handler, error_handler, critical_handler, step_handler, component_handler)


def run(
	cmd: List, stepsPerScript: float, info_handler: Callable = _dummyFunc, error_handler: Callable = _dummyFunc,
	critical_handler: Callable = _dummyFunc, step_handler: Callable = _dummyFunc, component_handler: Callable = _dummyFunc) -> bool:
	# disable restart of UMC server/web-server
	MODULE.info('disabling restart of UMC server/web-server')
	subprocess.call(CMD_DISABLE_EXEC)

	try:
		# regular expressions for output parsing
		regError = re.compile(r'^\* Message:\s*(?P<message>.*)\s*$')
		regJoinScript = re.compile(r'(Configure|Running)\s+(?P<script>.*)\.inst.*$')
		regInfo = re.compile(r'^(?P<message>.*?)\s*:?\s*\x1b.*$')

		# call to univention-join
		MODULE.info('calling "%s"' % ' '.join(cmd))
		process = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		failedJoinScripts = []
		while True:
			# get the next line
			line = process.stdout.readline()
			if not line:
				# no more text from stdout
				break
			line = line.decode('utf-8', errors='replace')
			MODULE.process(line.strip())

			# parse output... first check for errors
			matches = regError.match(line)
			if matches:
				message = matches.groupdict().get('message')
				error_handler(_("The system join process could not be completed:<br/><br/><i>%s</i><br/><br/> More details can be found in the log file <i>/var/log/univention/join.log</i>.<br/>Please retry after resolving any conflicting issues.") % message)
				if message.startswith('ssh-login for') or message.startswith('binddn for'):
					# invalid credentials or non existent user
					# do a critical error, the script will stop here
					critical_handler(True)

				continue

			# check for currently called join script
			matches = regJoinScript.match(line)
			if matches:
				component_handler(_('Executing join scripts'))
				info_handler(_('Executing join script %s') % matches.groupdict().get('script'))
				step_handler(stepsPerScript)
				if 'failed' in line:
					failedJoinScripts.append(matches.groupdict().get('script'))
				continue

			# check for other information
			matches = regInfo.match(line)
			if matches:
				info_handler(matches.groupdict().get('message'))
				step_handler(stepsPerScript / 10)
				continue

		# get all remaining output
		stdout, stderr = process.communicate()
		if stderr:
			# write stderr into the log file
			MODULE.warn(f'stderr: {stderr.decode("UTF-8", "replace")}')

		success = True
		# check for errors
		if process.returncode != 0:
			# error case
			MODULE.warn(f'Could not perform system join: {stdout.decode("UTF-8", "replace")}{stderr.decode("UTF-8", "replace")}')
			success = False
		elif failedJoinScripts:
			MODULE.warn(f'The following join scripts could not be executed: {failedJoinScripts}')
			error_handler(_('Some join scripts could not be executed. More details can be found in the log file <i>/var/log/univention/join.log</i>.<br/>Please retry to execute the join scripts after resolving any conflicting issues.'))

			success = False
		return success
	finally:
		# make sure that UMC servers and apache can be restarted again
		MODULE.info('enabling UMC and apache server restart')
		subprocess.call(CMD_ENABLE_EXEC)


INSTDIR = '/usr/lib/univention-install'
LOGFILE = '/var/log/univention/join.log'
LOCKFILE = '/var/lock/univention_umc_join.lock'
RE_JOINFILE = re.compile(r'^(?P<script>(?P<prio>\d\d)(?P<name>.+))\.(inst|uinst)$')
RE_NOT_CONFIGURED = re.compile(r"^Warning: '([^']+)' is not configured.$")
RE_ERROR = re.compile(r'^Error: (.*?)$')


class Instance(Base):

	def init(self) -> None:
		self.progress_state = Progress()

	@simple_response
	def dpkg_locked(self) -> bool:
		"""Do not execute join scripts when dpkg is running (e.g. via
		App Center)
		"""
		return self._dpkg_locked()

	def _dpkg_locked(self) -> bool:
		fd = apt_pkg.get_lock('/var/lib/dpkg/lock')
		if fd == -1:
			return True
		else:
			os.close(fd)
			return False

	@simple_response
	def query(self) -> List[str]:
		"""collects status about join scripts"""

		# unjoined system?
		if not self._joined:
			return []

		# List all join scripts
		files = {}
		for fname in os.listdir(INSTDIR):
			match = RE_JOINFILE.match(fname)
			if match:
				entry = match.groupdict()
				entry['configured'] = True
				entry['status'] = f'1:{entry["prio"]}'
				files[entry['name']] = entry

		# check for unconfigured scripts
		process = subprocess.Popen(['/usr/sbin/univention-check-join-status'], shell=False, stdout=subprocess.PIPE)
		stdout, stderr = process.communicate()
		if process.returncode == 0:
			return list(files.values())

		for line in stdout.decode('UTF-8', 'replace').splitlines():
			# is there a general error?
			match = RE_ERROR.match(line)
			if match and not line.startswith('Error: Not all install files configured'):
				raise UMC_Error(_('Error: %s') % match.groups()[0])

			# unconfigured script
			match = RE_NOT_CONFIGURED.match(line)
			if match:
				name = match.groups()[0]
				if name not in files:
					# The joinscripts does not exists in the filesystem or has a invalid name
					MODULE.error('not existing join script or join script with invalid name mentioned in status file: %r' % (name,))
					continue
				files[name]['configured'] = False
				files[name]['status'] = f'0:{files[name]["prio"]}'

		return list(files.values())

	@simple_response
	def joined(self) -> bool:
		return self._joined

	@simple_response
	def progress(self) -> Dict:
		return self.progress_state.poll()

	@simple_response
	def running(self) -> bool:
		""" returns true if a join script is running. """
		return self._running

	@simple_response
	def master(self) -> str:
		""" returns the hostname of the Primary Directory Node as fqdn """
		return get_master_dns_lookup()

	@property
	def _joined(self) -> bool:
		return os.path.exists('/var/univention-join/joined')

	@property
	def _running(self) -> bool:
		return os.path.exists(LOCKFILE)

	def _lock(self) -> None:
		try:
			open(LOCKFILE, 'a').close()
		except (IOError, OSError) as ex:
			MODULE.warn(f'_lock: {ex}')

	def _unlock(self) -> None:
		try:
			if self._running:
				os.unlink(LOCKFILE)
		except (IOError, OSError) as ex:
			MODULE.warn(f'_unlock: {ex}')

	def __del__(self) -> None:
		self._unlock()

	# TODO __finalize__?

	@simple_response
	def logview(self) -> List[str]:
		"""Returns the last 2MB of the join.log file"""
		with open(LOGFILE, 'rb') as fd:
			size = 2097152
			try:
				fd.seek(max(os.stat(fd.name).st_size - size, 0))
			except IOError:
				pass
			return fd.read(size).decode('utf-8', 'replace')

	@sanitize(
		username=StringSanitizer(required=True, minimum=1),
		password=StringSanitizer(required=True, minimum=1),
		hostname=HostSanitizer(required=True, regex_pattern=RE_HOSTNAME),
	)
	def join(self, request) -> bool:
		username, password, hostname = (request.options['username'], request.options['password'], request.options['hostname'])

		# Check if already a join process is running
		if self._running:
			raise UMC_Error(_('A join process is already running.'))

		# check for valid server role
		if ucr.get('server/role') == 'domaincontroller_master':
			raise UMC_Error(_('Invalid server role! A Primary Directory Node cannot be joined.'))

		# check for dpkg lock
		if self._dpkg_locked():
			raise UMC_Error(_('Currently, software is being installed or uninstalled. Join scripts should not be run right now.'))

		def _thread():
			self.progress_state.reset()
			self.progress_state.component = _('Domain join')
			self._lock()
			return system_join(
				hostname, username, password,
				info_handler=self.progress_state.info_handler,
				step_handler=self.progress_state.add_steps,
				error_handler=self.progress_state.error_handler,
				component_handler=self.progress_state.component_handler,
				critical_handler=self.progress_state.critical_handler,
			)

		def _finished(thread, result: Union[None, BaseException]) -> None:
			MODULE.info('Finished joining')
			self._unlock()
			self.progress_state.info = _('finished...')
			self.progress_state.finish()
			if isinstance(result, BaseException):
				msg = ''.join(thread.trace + traceback.format_exception_only(*thread.exc_info[:2]))
				MODULE.warn(f'Exception during domain join: {msg}')
				self.progress_state.error_handler(_('An unexpected error occurred: %s') % result)

		# launch thread
		thread = notifier.threads.Simple('join', _thread, _finished)
		thread.run()

		self.finished(request.id, True, status=202)

	@sanitize(
		username=StringSanitizer(required=False, minimum=1),
		password=StringSanitizer(required=False, minimum=1),
		scripts=ListSanitizer(required=True, min_elements=1),
		force=BooleanSanitizer(default=False)
	)
	def run(self, request) -> None:
		"""runs the given join scripts"""

		# Check if already a join process is running
		if self._running:
			raise UMC_Error(_('A join process is already running.'))

		# check for dpkg lock
		if self._dpkg_locked():
			raise UMC_Error(_('Currently, software is being installed or uninstalled. Join scripts should not be run right now.'))

		scripts, username, password, force = (request.options['scripts'], request.options.get('username'), request.options.get('password'), request.options.get('force', False))

		# sort scripts
		scripts.sort(key=lambda i: int(re.match(r'^(\d+)', i).group()))

		def _thread() -> bool:
			# reset progress state and lock against other join processes
			self.progress_state.reset()
			self.progress_state.component = _('Authentication')
			self._lock()
			return run_join_scripts(
				scripts, force, username, password,
				info_handler=self.progress_state.info_handler,
				step_handler=self.progress_state.add_steps,
				error_handler=self.progress_state.error_handler,
				component_handler=self.progress_state.component_handler,
				critical_handler=self.progress_state.critical_handler,
			)

		def _finished(thread, result: Union[None, BaseException]) -> None:
			MODULE.info('Finished running join scripts')
			self._unlock()
			self.progress_state.info = _('finished...')
			self.progress_state.finish()
			if isinstance(result, BaseException):
				msg = ''.join(thread.trace + traceback.format_exception_only(*thread.exc_info[:2]))
				MODULE.warn(f'Exception during running join scripts: {msg}')
				self.progress_state.error_handler(_('An unexpected error occurred: %s') % result)

		# launch thread
		thread = notifier.threads.Simple('join', _thread, _finished)
		thread.run()

		self.finished(request.id, True, status=202)
