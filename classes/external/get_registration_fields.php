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
 * External function exposing the Moodle registration requirements.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_registration_fields extends external_api {
    /**
     * Describe parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters(): external_function_parameters {
        return new external_function_parameters([]);
    }

    /**
     * Return registration metadata.
     *
     * @return array
     */
    public static function execute(): array {
        if (!is_enabled_auth('userkey')) {
            throw new \moodle_exception('pluginisdisabled', 'auth_userkey');
        }

        self::validate_parameters(self::execute_parameters(), []);
        $context = \context_system::instance();
        self::validate_context($context);
        require_capability('auth/userkey:registeruser', $context);

        return (new registration_manager())->get_registration_fields();
    }

    /**
     * Describe registration metadata.
     *
     * @return external_single_structure
     */
    public static function execute_returns(): external_single_structure {
        return new external_single_structure([
            'passwordpolicy' => new external_value(PARAM_RAW, 'Current Moodle password policy'),
            'customfields' => new external_multiple_structure(
                new external_single_structure([
                    'type' => new external_value(PARAM_ALPHANUMEXT, 'Custom profile field shortname'),
                    'name' => new external_value(PARAM_RAW, 'Display name'),
                    'datatype' => new external_value(PARAM_ALPHANUMEXT, 'Moodle profile field datatype'),
                    'required' => new external_value(PARAM_BOOL, 'Whether the field is required'),
                    'locked' => new external_value(PARAM_BOOL, 'Whether the field is locked'),
                    'forceunique' => new external_value(PARAM_BOOL, 'Whether values must be unique'),
                    'defaultvalue' => new external_value(PARAM_RAW, 'Default value'),
                    'settings' => new external_multiple_structure(
                        new external_single_structure([
                            'name' => new external_value(PARAM_ALPHANUMEXT, 'Moodle field setting name'),
                            'value' => new external_value(PARAM_RAW, 'Moodle field setting value'),
                        ])
                    ),
                ])
            ),
        ]);
    }
}
