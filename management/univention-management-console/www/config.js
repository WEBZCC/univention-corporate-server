/*
 * Copyright 2017 Univention GmbH
 *
 * http://www.univention.de/
 *
 * All rights reserved.
 *
 * The source code of this program is made available
 * under the terms of the GNU Affero General Public License version 3
 * (GNU AGPL V3) as published by the Free Software Foundation.
 *
 * Binary versions of this program provided by Univention to you as
 * well as other copyrighted, protected or trademarked materials like
 * Logos, graphics, fonts, specific documentations and configurations,
 * cryptographic keys etc. are subject to a license agreement between
 * you and Univention and not subject to the GNU AGPL V3.
 *
 * In the case you use this program under the terms of the GNU AGPL V3,
 * the program is provided in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License with the Debian GNU/Linux or Univention distribution in file
 * /usr/share/common-licenses/AGPL-3; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/*global require*/
function getQuery(/*String*/ param, /*mixed*/ defaultVal) {
	// parse the URI query string
	var query = window.location.search.substring(1);
	var vars = query.split('&');
	for (var i = 0; i < vars.length; i++) {
		// parse the tuple
		var tuple = vars[i].split('=');

		// check whether we found the particular parameter we are interested in
		if (2 === tuple.length && param === tuple[0]) {
			return tuple[1];
		}
	}

	// otherwise return the specified default value
	return defaultVal;
}

function getCookie(/*String*/ param, /*mixed*/ defaultVal) {
	// find the given parameter in the cookie string
	var reg = new RegExp(param + '=([a-zA-Z_-]*)');
	var m = reg.exec(document.cookie);
	if (m && m[1]) {
		return m[1];
	}

	// in case the parameter does not exist, return the default value
	return defaultVal;
}

var _fillUsernameField = function(username) {
	require('dojo/dom').byId('umcLoginUsername').value = username;
	require('dojo/dom').byId('umcLoginPassword').focus();
	//fire change event manually for internet explorer
	require(['dojo/dom', 'dojo/has'], function(dom, has) {
		if (has('ie') < 10) {
			var event = document.createEvent("HTMLEvents");
			event.initEvent("change", true, false);
			dom.byId('umcLoginUsername').dispatchEvent(event);
		}
	});
};

var _showLoginTooltip = function(evt) {
	require(["dojo/on", "dojo/_base/event", "dijit/Tooltip",  "umc/i18n!umc/app"], function(on, dojoEvent, Tooltip, _) {
		var node = evt.target;
		var helpText = _('Please login with a valid username and password.') + ' ';
		if (getQuery('username') === 'root') {
			helpText += _('Use the %s user for the initial system configuration.', '<b><a href="javascript:void();" onclick="_fillUsernameField(\'root\')">root</a></b>');
		} else {
			helpText += _('The default username to manage the domain is %s.', '<b><a href="javascript:void();" onclick="_fillUsernameField(\'Administrator\')">Administrator</a></b>');
		}
		Tooltip.show(helpText, node);
		if (evt) {
			dojoEvent.stop(evt);
		}
		on.once(dojo.body(), 'click', function(evt) {
			Tooltip.hide(node);
			dojoEvent.stop(evt);
		});
	});
};

var getLocale = function() {
	var locale = getQuery('lang') || getCookie('UMCLang');
	if (locale) {
		locale = locale.replace('_', '-');
	}
	return locale;
};
