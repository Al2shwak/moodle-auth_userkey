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
    'auth_userkey_get_registration_fields' => [
        'classname' => 'auth_userkey\\external\\get_registration_fields',
        'description' => 'Return Moodle registration requirements',
        'type' => 'read',
        'capabilities' => 'auth/userkey:registeruser',
    ],
    'auth_userkey_register_user' => [
        'classname' => 'auth_userkey\\external\\register_user',
        'description' => 'Create an unconfirmed user using the configured registration and confirmation method',
        'type' => 'write',
        'capabilities' => 'auth/userkey:registeruser',
    ],
    'auth_userkey_authenticate_user' => [
        'classname' => 'auth_userkey\\external\\authenticate_user',
        'description' => 'Validate credentials and resend confirmation for eligible pending accounts',
        'type' => 'write',
        'capabilities' => 'auth/userkey:authenticate',
    ],
    'auth_userkey_request_password_reset' => [
        'classname' => 'auth_userkey\\external\\request_password_reset',
        'description' => 'Request Moodle native password-reset email without disclosing account state',
        'type' => 'write',
        'capabilities' => 'auth/userkey:resetpassword',
    ],
    'auth_userkey_request_login_url' => [
        'classname'   => 'auth_userkey\\external\\request_login_url',
        'description' => 'Return one time key based login URL',
        'type'        => 'write',
        'capabilities'  => 'auth/userkey:generatekey',
    ],
];

$services = [
    'User key authentication web service' => [
        'functions' => [
            'auth_userkey_get_registration_fields',
            'auth_userkey_register_user',
            'auth_userkey_authenticate_user',
            'auth_userkey_request_password_reset',
            'auth_userkey_request_login_url',
            'core_cohort_get_cohorts',
            'core_cohort_add_cohort_members',
            'core_cohort_delete_cohort_members',
            'core_webservice_get_site_info',
        ],
        'shortname' => 'auth_userkey',
        'restrictedusers' => 1,
        'enabled' => 1,
    ],
];
