#!/usr/share/ucs-test/runner pytest-3 -svvv
## desc: SSO Login at UMC as Service Provider
## tags: [saml]
## join: true
## exposure: safe
## tags:
##  - skip_admember

import univention.testing.utils as utils

import samltest


def __get_samlSession():
	account = utils.UCSTestDomainAdminCredentials()
	return samltest.SamlTest(account.username, account.bindpw)


def __test_umc_sp(samlSession, test_function):
	samlSession.login_with_new_session_at_IdP()
	test_function()
	samlSession.logout_at_IdP()
	samlSession.test_logout_at_IdP()
	samlSession.test_logout()


def test_umc_web_server():
	samlSession = __get_samlSession()
	__test_umc_sp(samlSession, samlSession.test_login)
