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
 * Web services for auth_userkey.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

$functions = [
    'auth_userkey_request_login_url' => [
        'classname'   => 'auth_userkey\\external\\request_login_url',
        'description' => 'Return one time key based login URL',
        'type'        => 'write',
        'capabilities'  => 'auth/userkey:generatekey',
    ],
    'auth_userkey_provision_user_login' => [
        'classname'   => 'auth_userkey\\external\\provision_user_login',
        'description' => 'Create a user and return a one-time login URL',
        'type'        => 'write',
        'capabilities' => 'auth/userkey:createuser,auth/userkey:generatekey',
    ],
];

$services = [
    'User key authentication web service' => [
        'functions' => [
            'auth_userkey_request_login_url',
            'auth_userkey_provision_user_login',
            'core_webservice_get_site_info',
        ],
        'shortname' => 'auth_userkey',
        'restrictedusers' => 1,
        'enabled' => 1,
    ],
];
