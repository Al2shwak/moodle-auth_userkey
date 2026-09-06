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

use auth_userkey\registration_manager;
use core_external\external_api;
use core_external\external_function_parameters;
use core_external\external_multiple_structure;
use core_external\external_single_structure;
use core_external\external_value;

/**
 * External function for registering a Moodle-owned user pending email confirmation.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class register_user extends external_api {
    /**
     * Describe registration parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters(): external_function_parameters {
        return new external_function_parameters([
            'user' => new external_single_structure([
                'email' => new external_value(PARAM_EMAIL, 'Email address; also used as the username'),
                'password' => new external_value(PARAM_RAW, 'Plain text password sent only over HTTPS'),
                'firstname' => new external_value(PARAM_NOTAGS, 'The first name(s) of the user'),
                'lastname' => new external_value(PARAM_NOTAGS, 'The family name of the user'),
                'city' => new external_value(PARAM_NOTAGS, 'Home city', VALUE_OPTIONAL),
                'country' => new external_value(PARAM_ALPHA, 'Two-letter country code', VALUE_OPTIONAL),
                'customfields' => new external_multiple_structure(
                    new external_single_structure([
                        'type' => new external_value(PARAM_ALPHANUMEXT, 'Custom profile field shortname'),
                        'value' => new external_value(PARAM_RAW, 'Custom profile field value'),
                    ]),
                    'Signup-visible custom profile fields',
                    VALUE_OPTIONAL
                ),
            ]),
        ]);
    }

    /**
     * Register a user and send Moodle's confirmation email.
     *
     * @param array $user Registration data.
     * @return array
     */
    public static function execute(array $user): array {
        if (!is_enabled_auth('userkey')) {
            throw new \moodle_exception('pluginisdisabled', 'auth_userkey');
        }

        $params = self::validate_parameters(self::execute_parameters(), ['user' => $user]);
        $context = \context_system::instance();
        self::validate_context($context);
        require_capability('auth/userkey:registeruser', $context);

        return (new registration_manager())->register_user($params['user']);
    }

    /**
     * Describe registration result.
     *
     * @return external_single_structure
     */
    public static function execute_returns(): external_single_structure {
        return new external_single_structure([
            'userid' => new external_value(PARAM_INT, 'Immutable Moodle user ID'),
            'username' => new external_value(PARAM_USERNAME, 'Normalized username'),
            'confirmationrequired' => new external_value(PARAM_BOOL, 'Whether account confirmation is required'),
            'authmethod' => new external_value(PARAM_PLUGIN, 'Authentication method assigned to the Moodle account'),
            'confirmationmethod' => new external_value(PARAM_ALPHA, 'Either email or admin'),
        ]);
    }
}
