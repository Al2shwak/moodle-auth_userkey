<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Admin settings and defaults
 *
 * @package auth_userkey
 * @copyright  2017 Stephen Bourget
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

if ($ADMIN->fulltree) {
    $yesno = [get_string('no'), get_string('yes')];
    $authmethods = get_auth_plugin('userkey')->get_selectable_auth_methods();

    $settings->add(new admin_setting_configselect(
        'auth_userkey/registrationmode',
        get_string('registrationmode', 'auth_userkey'),
        get_string('registrationmode_desc', 'auth_userkey'),
        'email',
        [
            'email' => get_string('registrationmode_email', 'auth_userkey'),
            'emailadmin' => get_string('registrationmode_emailadmin', 'auth_userkey'),
            'manual' => get_string('registrationmode_manual', 'auth_userkey'),
        ]
    ));

    $settings->add(new admin_setting_configmultiselect(
        'auth_userkey/allowedauthmethods',
        get_string('allowedauthmethods', 'auth_userkey'),
        get_string('allowedauthmethods_desc', 'auth_userkey'),
        ['manual', 'email'],
        $authmethods
    ));

    $settings->add(new admin_setting_configtext(
        'auth_userkey/keylifetime',
        get_string('keylifetime', 'auth_userkey'),
        get_string('keylifetime_desc', 'auth_userkey', 'auth'),
        '60',
        PARAM_INT
    ));

    $settings->add(new admin_setting_configselect(
        'auth_userkey/iprestriction',
        new lang_string('iprestriction', 'auth_userkey'),
        new lang_string('iprestriction_desc', 'auth_userkey'),
        0,
        $yesno
    ));

    $settings->add(new admin_setting_configtext(
        'auth_userkey/ipwhitelist',
        get_string('ipwhitelist', 'auth_userkey'),
        get_string('ipwhitelist_desc', 'auth_userkey', 'auth'),
        '',
        PARAM_TEXT
    ));

    $settings->add(new admin_setting_configtext(
        'auth_userkey/redirecturl',
        get_string('redirecturl', 'auth_userkey'),
        get_string('redirecturl_desc', 'auth_userkey', 'auth'),
        '',
        PARAM_URL
    ));

    $settings->add(new admin_setting_configtext(
        'auth_userkey/allowedredirecthosts',
        get_string('allowedredirecthosts', 'auth_userkey'),
        get_string('allowedredirecthosts_desc', 'auth_userkey'),
        '',
        PARAM_TEXT
    ));

    $settings->add(new admin_setting_configtext(
        'auth_userkey/ssourl',
        get_string('ssourl', 'auth_userkey'),
        get_string('ssourl_desc', 'auth_userkey', 'auth'),
        '',
        PARAM_URL
    ));
}
