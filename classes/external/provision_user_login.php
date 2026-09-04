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
 * External function for creating a user and requesting their first one-time login URL.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class provision_user_login extends external_api {
    /**
     * Describe the request parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters(): external_function_parameters {
        return new external_function_parameters([
            'user' => new external_single_structure(
                get_auth_plugin('userkey')->get_provision_user_login_parameters()
            ),
        ]);
    }

    /**
     * Create a new user and generate a one-time login URL.
     *
     * @param array $user New user data.
     * @return array Login URL.
     */
    public static function execute(array $user): array {
        if (!is_enabled_auth('userkey')) {
            throw new \moodle_exception('pluginisdisabled', 'auth_userkey');
        }

        $params = self::validate_parameters(self::execute_parameters(), ['user' => $user]);

        $context = \context_system::instance();
        self::validate_context($context);
        require_capability('auth/userkey:generatekey', $context);
        require_capability('auth/userkey:createuser', $context);

        return [
            'loginurl' => get_auth_plugin('userkey')->provision_user_login($params['user']),
        ];
    }

    /**
     * Describe the return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns(): external_single_structure {
        return new external_single_structure([
            'loginurl' => new external_value(PARAM_RAW, 'One-time login URL for the newly created user'),
        ]);
    }
}
