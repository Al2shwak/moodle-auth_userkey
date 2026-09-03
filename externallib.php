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
 * Webservices for auth_userkey.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die(); // phpcs:ignore moodle.Files.MoodleInternal.MoodleInternalNotNeeded

/**
 * Backwards-compatible wrapper for the legacy external class name.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class auth_userkey_external extends \auth_userkey\external\request_login_url {
    /**
     * Describe the legacy external function parameters.
     *
     * @return \core_external\external_function_parameters
     */
    public static function request_login_url_parameters() {
        return parent::execute_parameters();
    }

    /**
     * Return login url array.
     *
     * @param array $user
     *
     * @return array
     * @throws \dml_exception
     * @throws \moodle_exception
     * @throws \required_capability_exception
     */
    public static function request_login_url($user) {
        return parent::execute($user);
    }

    /**
     * Describe request_login_url webservice return structure.
     *
     * @return \core_external\external_single_structure
     */
    public static function request_login_url_returns() {
        return parent::execute_returns();
    }
}
