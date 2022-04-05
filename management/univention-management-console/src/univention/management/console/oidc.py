#!/usr/bin/python3
#
# Univention Management Console
#  OpenID Connect implementation for the UMC
#
# Copyright 2022 Univention GmbH
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

import json

import jwt
from jwt.algorithms import RSAAlgorithm
from six.moves.urllib_parse import urlencode
from tornado import escape, gen
from tornado.auth import OAuth2Mixin
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest

from univention.management.console.resource import Resource
from univention.management.console.log import CORE
from univention.management.console.error import BadRequest, NotFound, Unauthorized, ServerError


class OIDCUser(object):

	def __init__(self, claims):
		self.claims = claims
		self.username = claims['uid']


class OIDCResource(OAuth2Mixin, Resource):
	"""Base class for all OIDC resources."""

	OP = None

	def prepare(self):
		super(OIDCResource, self).prepare()
		self.op = self.get_query_argument('state', self.get_query_argument('op', self.get_cookie('oidc-op', self.application.settings['oidc_default_op'])))
		try:
			settings = self.application.settings['oidc'][self.op]
		except KeyError:
			raise NotFound('OP not available')
		self.cookie_name_token = settings['oidc_cookie_token']
		self.cookie_name_user = settings['oidc_cookie_user']
		# self.cookie_name_refresh_token = settings['oidc_cookie_refresh_token']
		# oidc_server = settings['oidc_server']
		# oidc_client_realm = settings['oidc_client_realm']
		self.oidc_client_id = settings['oidc_client_id']
		self.oidc_secret = settings['oidc_secret']
		self._OAUTH_AUTHORIZE_URL = settings["oidc_authorize_url"]
		self._OAUTH_ACCESS_TOKEN_URL = settings["oidc_access_token_url"]
		self._OAUTH_LOGOUT_URL = settings["oidc_logout_url"]
		self._OAUTH_USERINFO_URL = settings["oidc_userinfo_url"]
		self._OAUTH_CERT_URL = settings["oidc_cert_url"]
		self.extra_parameters = [x.strip() for x in settings.get('extra_parameters', '').split(',') if x.strip()]

	def reverse_abs_url(self, name):
		return self.request.protocol + "://" + self.request.host + self.reverse_url(name, *self.path_args)


class OIDCLogin(OIDCResource):

	sessions = {}

	@gen.coroutine
	def get_authenticated_user(self, redirect_uri, code):
		http = self.get_auth_http_client()
		body = urlencode({
			"redirect_uri": redirect_uri,
			"code": code,
			"client_id": self.oidc_client_id,
			"client_secret": self.oidc_secret,
			"grant_type": "authorization_code",
		})
		response = yield http.fetch(
			self._OAUTH_ACCESS_TOKEN_URL,
			method="POST",
			headers={"Content-Type": "application/x-www-form-urlencoded"},
			body=body,
		)
		raise gen.Return(escape.json_decode(response.body))

	@gen.coroutine
	def get(self):
		code = self.get_argument('code', False)
		if code:
			try:
				access = yield self.get_authenticated_user(
					redirect_uri=self.reverse_abs_url('oidc-login'),
					code=self.get_argument('code'),
				)
			except HTTPClientError as exc:
				raise BadRequest('Could not authenticate user: %s' % (json.loads(exc.response.body),))

			access_token = access['access_token']
			if not access_token:
				raise BadRequest("Could not receive access token")

			# refresh_token = access['refresh_token']

			user_info_req = HTTPRequest(
				self._OAUTH_USERINFO_URL,
				method="GET",
				headers={
					"Accept": "application/json",
					"Authorization": "Bearer {}".format(access_token)
				},
			)
			http_client = self.get_auth_http_client()
			user_info_res = yield http_client.fetch(user_info_req)
			user_info_res_json = json.loads(user_info_res.body.decode('utf-8'))
			self.set_secure_cookie(self.cookie_name_user, user_info_res_json['preferred_username'])
			self.set_secure_cookie(self.cookie_name_token, access_token)
			# self.set_secure_cookie(self.cookie_name_refresh_token, refresh_token)
			CORE.info('OIDC-Login: User-Info: %r' % (user_info_res_json,))
			self.sessions[access_token.encode('ASCII')] = user_info_res_json
			# currently not required, all infos are in the first userinfo self
			# user = yield self.oauth2_request(
			# 	url=self._OAUTH_USERINFO_URL,
			# 	access_token=access['access_token'],
			# 	post_args={},
			# )
			self.redirect(self.reverse_abs_url('index'))
		else:
			self.redirect = self.redirect
			extra_parameters = {'approval_prompt': 'auto'}
			for extra_parameter in self.extra_parameters:
				value = self.get_query_argument(extra_parameter, None)
				if value:
					extra_parameters[extra_parameter] = value
			extra_parameters['state'] = self.op

			self.authorize_redirect(
				redirect_uri=self.reverse_abs_url('oidc-login'),
				client_id=self.oidc_client_id,
				scope=['profile', 'email'],
				response_type='code',
				extra_params=extra_parameters,
			)

	def get_user(self):
		user = self.sessions.get(self.get_secure_cookie(self.cookie_name_token))
		# user = yield self.get_current_user(self)
		if user:
			return OIDCUser(user)

	@gen.coroutine
	def get_current_user(self):
		# user = self.get_secure_cookie(self.cookie_name_user)
		bearer = self.get_secure_cookie(self.cookie_name_token)
		self = HTTPRequest(self._OAUTH_CERT_URL, method='GET')
		http_client = AsyncHTTPClient()

		response = yield http_client.fetch(self, raise_error=False)

		if response.code != 200:
			CORE.warning("Fetching certificate failed")
			raise ServerError("Fetching certificate failed")

		jwk = json.loads(response.body.decode('utf-8'))
		try:
			public_key = RSAAlgorithm.from_jwk(json.dumps(jwk['keys'][0]))
			payload = jwt.decode(bearer, public_key, algorithms='RS256', options={'verify_aud': False})
		except jwt.ExpiredSignatureError:
			CORE.warning("Signature expired")
			raise Unauthorized("Signature expired")
		except jwt.InvalidSignatureError:
			CORE.error("Invalid signature")
			raise Unauthorized("Invalid signature")

		CORE.info('OIDC JWK-Payload: %r' % (payload,))
		raise gen.Return(payload)


class OIDCLogout(OIDCResource):

	def get(self):
		access_token = self.get_secure_cookie(self.cookie_name_token)
		if not access_token:
			raise BadRequest("Not logged in")
		access_token = access_token.decode('UTF-8')

		self.sessions.pop(access_token.encode('ASCII'), None)
		self.clear_cookie('oidc-op')
		self.clear_cookie(self.cookie_name_user)
		self.clear_cookie(self.cookie_name_token)
		# self.clear_cookie(self.cookie_name_refresh_token)
		logout_url = '%s?%s' % (self._OAUTH_LOGOUT_URL, urlencode({'redirect_uri': self.reverse_abs_url('index')}))
		self.redirect(logout_url)
