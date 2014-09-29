/*
 * Copyright 2011-2014 Univention GmbH
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
/*global define console*/

define([
	"dojo/_base/declare",
	"dojo/_base/lang",
	"dojo/dom-class",
	"dijit/form/Button"
], function(declare, lang, domClass, Button) {
	return declare("umc.widgets.Button", [ Button ], {
		// defaultButton: Boolean
		//		If set to 'true', button will be rendered as default, i.e., submit button.
		defaultButton: false,

		// callback: Function
		//		Convenience property for onClick callback handler.
		callback: null,

		visible: true,

		type: 'button',

		constructor: function(props) {
			lang.mixin(this, props);
			if (this.defaultButton) {
				this['class'] = 'dijitDefaultButton';
			}
		},

		buildRendering: function() {
			this.inherited(arguments);

			this.set('iconClass', this.iconClass);
		},

		postCreate: function() {
			this.inherited(arguments);

			if (typeof this.callback == "function") {
				this.on('click', lang.hitch(this, 'callback'));
			}
		},

		show: function() {
			this.set( 'visible', true );
		},

		hide: function() {
			this.set( 'visible', false );
		},

		_setVisibleAttr: function(newVal) {
			this._set('visible', newVal);
			domClass.toggle(this.domNode, 'dijitHidden', !newVal);
		}
	});
});


