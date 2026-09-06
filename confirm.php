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
 * Confirm a service-created email-authentication account.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php'); // phpcs:ignore moodle.Files.RequireLogin.Missing

$data = required_param('data', PARAM_RAW);
$manager = new \auth_userkey\registration_manager();

if (!$manager->confirm_user($data)) {
    throw new moodle_exception('invalidconfirmdata', 'error');
}

redirect($manager->get_confirmation_redirect_url());
