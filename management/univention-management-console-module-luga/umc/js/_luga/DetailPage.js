/*
 * Copyright 2012 Univention GmbH
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
/*global console MyError dojo dojox dijit umc */

dojo.provide("umc.modules._luga.DetailPage");

dojo.require("umc.dialog");
dojo.require("umc.i18n");
dojo.require("umc.tools");
dojo.require("umc.widgets.Form");
dojo.require("umc.widgets.Page");
dojo.require("umc.widgets.StandbyMixin");

dojo.declare("umc.modules._luga.DetailPage", [ umc.widgets.Page, umc.widgets.StandbyMixin, umc.i18n.Mixin ], {
	// summary:
	//		This class represents the detail view of our dummy module.

	// reference to the module's store object
	moduleStore: null,

	// use i18n information from umc.modules.luga
	i18nClass: 'umc.modules.luga',

	// internal reference to the formular containing all form widgets of an UDM object
	_form: null,

	postMixInProperties: function() {
		// is called after all inherited properties/methods have been mixed
		// into the object (originates from dijit._Widget)

		// it is important to call the parent's postMixInProperties() method
		this.inherited(arguments);

		// Set the opacity for the standby animation to 100% in order to mask
		// GUI changes when the module is opened. Call this.standby(true|false)
		// to enabled/disable the animation.
		this.standbyOpacity = 1;

		// set the page header
		if (this.moduleFlavor === 'luga/users') {
			this.headerText = this._('Properties for user %s', '');
			this.helpText = this._('Create or modify an local user.');
		} else if (this.moduleFlavor === 'luga/groups') {
			this.headerText = this._('Object properties');
			this.helpText = this._('This page demonstrates how object properties can be viewed for editing.');
		}

		// configure buttons for the footer of the detail page
		this.footerButtons = [{
			name: 'submit',
			label: this._('Save'),
			callback: dojo.hitch(this, function() {
				this._save(this._form.gatherFormValues());
			})
		}, {
			name: 'back',
			label: this._('Back to overview'),
			callback: dojo.hitch(this, 'confirmClose')
		}];
	},

	buildRendering: function() {
		// is called after all DOM nodes have been setup
		// (originates from dijit._Widget)

		// it is important to call the parent's postMixInProperties() method
		this.inherited(arguments);

		this.renderDetailPage();
	},

	renderDetailPage: function() {
		// render the form containing all detail information that may be edited
		var widgets;
		var layout;
		if (this.moduleFlavor === 'luga/users') {
			// specify all widgets
			widgets = [{
				type: 'TextBox',
				name: 'username',
				label: this._('Username')
			}, {
				type: 'TextBox',
				name: 'password',
				label: this._('Password')
			}, {
				type: 'TextBox',
				name: 'uid',
				label: this._('User ID')
			}, {
				type: 'ComboBox',
				name: 'group',
				label: this._('primary group'),
				dynamicValues: 'luga/groups/get_groups'
			}, {
				type: 'TextBox',
				name: 'homedir',
				label: this._('Unix home directory')
			}, {
				type: 'TextBox',
				name: 'shell',
				label: this._('Login shell')
			}, {
				type: 'TextBox',
				name: 'fullname',
				label: this._('Full name')
			}, {
				type: 'TextBox',
				name: 'roomnumber',
				label: this._('Room number')
			}, {
				type: 'TextBox',
				name: 'tel_business',
				label: this._('Telephone (business)')
			}, {
				type: 'TextBox',
				name: 'tel_private',
				label: this._('Telephone (private)')
			}, {
				type: 'TextBox',
				name: 'miscellaneous',
				label: this._('Miscellaneous')
			}, {
				type: 'MultiSelect',
				name: 'groups',
				label: this._('Additional Groups'),
				dynamicValues: 'luga/groups/get_groups'
			}, {
				type: 'CheckBox',
				name: 'locked',
				label: this._('Disable login')
			}, {
				type: 'CheckBox',
				name: 'expired',
				label: this._('expired')
			}, {
				type: 'CheckBox',
				name: 'empty_password',
				label: this._('empty password')
			}, {
				type: 'TextBox',
				disabled: true,
				name: 'days_since_epoch_of_last_pw_change',
				label: this._('days since Jan 1, 1970 that password was last changed')
			}, {
				type: 'TextBox',
				disabled: true,
				name: 'days_until_change_allowed',
				label: this._('days before password may be changed')
			}, {
				type: 'TextBox',
				disabled: true,
				name: 'days_before_change_required',
				label: this._('days after which password must be changed')
			}, {
				type: 'TextBox',
				disabled: true,
				name: 'days_warning_for_expiration',
				label: this._('days before password is to expire that user is warned')
			}, {
				type: 'TextBox',
				disabled: true,
				name: 'days_before_account_inactive',
				label: this._('days after password expires that account is disabled')
			}, {
				type: 'TextBox',
				disabled: true,
				name: 'days_since_epoch_when_account_expires',
				label: this._('days since Jan 1, 1970 that account is disabled')
			}];

			// specify the layout... additional dicts are used to group form elements
			// together into title panes
			layout = [{
				label: this._('General'),
				layout: [ [ 'uid', 'groups' ], 'username', 'password', 'group']
			}, {
				label: this._('User information'),
				layout: [ ['homedir', 'shell' ], ['fullname', 'roomnumber'], ['tel_business', 'tel_private'], 'miscellaneous' ]
			}, {
				label: this._('Options and Passwords'),
				layout: [ 'locked', 'expired', 'empty_password', 'days_since_epoch_of_last_pw_change', 'days_until_change_allowed', 'days_before_change_required', 'days_warning_for_expiration', 'days_before_account_inactive', 'days_since_epoch_when_account_expires' ]
			}];
		} else if (this.moduleFlavor === 'luga/groups') {
			widgets = [{
				type: 'TextBox',
				name: 'groupname',
				label: this._('Groupname')
			}, {
				type: 'TextBox',
				name: 'password',
				label: this._('Password')
			}, {
				type: 'CheckBox',
				name: 'remove_password',
				label: this._('Remove password')
			}, {
				type: 'TextBox',
				name: 'gid',
				label: this._('Group ID')
			}, {
				type: 'MultiSelect',
				name: 'users',
				label: this._('Users'),
				dynamicValues: 'luga/users/get_users'
			}];
			layout = [];
		}

		// create the form
		this._form = new umc.widgets.Form({
			widgets: widgets,
			layout: layout,
			moduleStore: this.moduleStore,
			// alows the form to be scrollable when the window size is not large enough
			scrollable: true
		});

		// add form to page... the page extends a BorderContainer, by default
		// an element gets added to the center region
		this.addChild(this._form);

		// hook to onSubmit event of the form
		this.connect(this._form, 'onSubmit', '_save');
	},

	getAlteredValues: function() {
		
	},

	_save: function(values) {
		// summary:
		//		Save the user changes for the edited object.

		return;

		// TODO: compare old values with new ones
		// only send new values

		values = this.getAlteredValues();

		var deferred = null;
		if (this._multiEdit) {
			// save the changes for each object once
			var transaction = this.moduleStore.transaction();
			deferred = transaction.commit();
		}
		else if (this.newObjectOptions) {
			deferred = this.moduleStore.add(values, this.newObjectOptions);
		}
		else {
			deferred = this.moduleStore.put(values);
		}
		deferred.then(dojo.hitch(this, function(result) {
			// see whether saving was successfull
			this.standby(false);
			var success = true;
			var msg = '';
			if (false === result) {
				msg += 'error';
			}
			else {
				success = result.success;
				if (!result.success) {
					msg = this._('error TODO', result);
				}
			}

			if (success) {
				// everything ok, close page
				this.onCloseTab();
			}
			else {
				// print error message to user
				umc.dialog.alert(msg);
			}
		}), dojo.hitch(this, function() {
			this.standby(false);
		}));
	},

	load: function(id) {
		// during loading show the standby animation
		this.standby(true);

		// load the object into the form... the load method returns a
		// dojo.Deferred object in order to handel asynchronity
		this._form.load(id).then(dojo.hitch(this, function() {
			// done, switch of the standby animation
			this.standby(false);
		}), dojo.hitch(this, function() {
			// error handler: switch of the standby animation
			// error messages will be displayed automatically
			this.standby(false);
		}));
	},

	confirmClose: function() {
		this.onClose();
	},

	onClose: function() {
		// event stub 
	}
});




