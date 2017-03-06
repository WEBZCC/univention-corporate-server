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
/*global define*/

define([
	"dojo/_base/declare",
	"dojo/_base/lang",
	"dojo/_base/array",
	"dojo/_base/kernel",
	"dojo/dom",
	"dojo/dom-class",
	"dojo/store/Memory",
	"dojo/store/Observable",
	"dijit/registry",
	"dojox/html/entities",
	"login",
	"umc/tools",
	"umc/menu",
	"umc/i18n!server-overview"
], function(declare, lang, array, kernel, dom, domClass, Memory, Observable, registry, entities, login, tools, menu, _) {

	return {
		standby: function(standby) {
			domClass.toggle(window.document.body, 'standby', standby);
		},

		start: function() {
			this.initLabels();
			login.start().then(lang.hitch(this, 'init'));
		},

		init: function() {
			this.initGallery();
			this.initLiveSearch();
		},

		initLabels: function() {
			var title = entities.encode(_('%s - Server overview', tools.status('domainname')));
			window.document.title = title;

			title = entities.encode(_('Server overview for domain %s', tools.status('domainname')));
			dom.byId('title').innerHTML = title;

			this.liveSearch = registry.byId('liveSearch');
			this.liveSearch._searchTextBox.set('inlineLabel', _('Search servers'));

			menu.addEntry({
				label: _('Back to portal'),
				priority: 0,
				onClick: function() {
					window.location.pathname = '/univention/';
				}
			});

		},

		initLiveSearch: function() {
			this.liveSearch.on('search', lang.hitch(this, function(pattern) {
				this.gallery.updateQuery(this.liveSearch.get('value'));
			}));
		},

		initGallery: function() {
			this.gallery = registry.byId('gallery');
			this.gallery.useFqdn = !tools.isIPAddress(window.location.hostname);
			tools.umcpCommand('serveroverview/query').then(lang.hitch(this, function(data) {
				var store = new Observable(new Memory({
					data: data.result,
					idProperty: 'dn'
				}));
				this.gallery.set('store', store);
				this.standby(false);
			}));
		}
	};
});
