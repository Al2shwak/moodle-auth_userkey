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

namespace auth_userkey\external;

use core_external\external_api;
use core_external\external_function_parameters;
use core_external\external_single_structure;
use core_external\external_value;

/**
 * External function for validating a student's Moodle credentials.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class authenticate_user extends external_api {
    /**
     * Describe credential parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters(): external_function_parameters {
        return new external_function_parameters([
            'identifier' => new external_value(PARAM_RAW_TRIMMED, 'Moodle username or email address'),
            'password' => new external_value(PARAM_RAW, 'Plain text password sent only over HTTPS'),
        ]);
    }

    /**
     * Validate credentials without creating a Moodle browser session.
     *
     * @param string $identifier Username or email address.
     * @param string $password Plain text password.
     * @return array
     */
    public static function execute(string $identifier, string $password): array {
        if (!is_enabled_auth('userkey')) {
            throw new \moodle_exception('pluginisdisabled', 'auth_userkey');
        }

        $params = self::validate_parameters(self::execute_parameters(), [
            'identifier' => $identifier,
            'password' => $password,
        ]);
        $context = \context_system::instance();
        self::validate_context($context);
        require_capability('auth/userkey:authenticate', $context);

        return get_auth_plugin('userkey')->authenticate_user($params['identifier'], $params['password']);
    }

    /**
     * Describe the authenticated identity.
     *
     * @return external_single_structure
     */
    public static function execute_returns(): external_single_structure {
        return new external_single_structure([
            'userid' => new external_value(PARAM_INT, 'Immutable Moodle user ID'),
            'username' => new external_value(PARAM_USERNAME, 'Moodle username'),
        ]);
    }
}
