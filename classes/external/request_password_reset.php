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
 * External function for requesting Moodle's native password-reset email.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class request_password_reset extends external_api {
    /**
     * Describe the request parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters(): external_function_parameters {
        return new external_function_parameters([
            'email' => new external_value(PARAM_EMAIL, 'Moodle account email address'),
        ]);
    }

    /**
     * Ask Moodle to send its normal password-reset email.
     *
     * The response is deliberately identical for every valid email input so callers cannot determine whether an
     * account exists, is confirmed, is suspended, or supports password resets.
     *
     * @param string $email Moodle account email address.
     * @return array
     */
    public static function execute(string $email): array {
        global $CFG, $PAGE;

        if (!is_enabled_auth('userkey')) {
            throw new \moodle_exception('pluginisdisabled', 'auth_userkey');
        }

        $params = self::validate_parameters(self::execute_parameters(), ['email' => $email]);
        $context = \context_system::instance();
        self::validate_context($context);
        require_capability('auth/userkey:resetpassword', $context);
        $PAGE->set_context($context);

        require_once($CFG->dirroot . '/login/lib.php');
        $response = [
            'accepted' => true,
            'message' => get_string('passwordresetrequestaccepted', 'auth_userkey'),
        ];

        // Honour Moodle's alternate forgotten-password configuration instead of bypassing it.
        if (empty($CFG->forgottenpasswordurl)) {
            $email = \core_text::strtolower($params['email']);
            try {
                $user = get_complete_user_data('email', $email, null, true);
            } catch (\dml_exception $exception) {
                $user = false;
            }

            // Moodle's default resend link depends on public self-registration being enabled. Use this plugin's
            // confirmation endpoint for its user-confirmed accounts, and never bypass administrator confirmation.
            if ($user && empty($user->confirmed)) {
                $confirmationmethod = get_user_preferences(
                    'auth_userkey_confirmationmethod',
                    'email',
                    $user
                );
                if ($confirmationmethod === 'email' && in_array($user->auth, ['email', 'manual'], true)) {
                    send_confirmation_email($user, new \moodle_url('/auth/userkey/confirm.php'));
                }
                return $response;
            }

            try {
                $data = [
                    'username' => '',
                    'email' => $email,
                ];
                $errors = core_login_validate_forgot_password_data($data);
                if (empty($errors)) {
                    core_login_process_password_reset('', $data['email']);
                }
            } catch (\moodle_exception $exception) {
                // Do not expose account state or mail delivery details through the integration response.
                return $response;
            }
        }

        return $response;
    }

    /**
     * Describe the generic response.
     *
     * @return external_single_structure
     */
    public static function execute_returns(): external_single_structure {
        return new external_single_structure([
            'accepted' => new external_value(PARAM_BOOL, 'Whether the request was accepted for processing'),
            'message' => new external_value(PARAM_TEXT, 'Generic response that does not disclose account state'),
        ]);
    }
}
