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

namespace auth_userkey;

/**
 * Creates and confirms Moodle-owned accounts for the WordPress bridge.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class registration_manager {
    /** User confirms an email-auth account through the emailed link. */
    public const MODE_EMAIL = 'email';

    /** A Moodle administrator confirms an email-auth account. */
    public const MODE_EMAIL_ADMIN = 'emailadmin';

    /** User confirms a manual-auth account through the emailed link. */
    public const MODE_MANUAL = 'manual';

    /** Per-user record of whether confirmation belongs to the user or an administrator. */
    private const CONFIRMATION_PREFERENCE = 'auth_userkey_confirmationmethod';

    /** Confirmation is completed through a link sent to the user. */
    private const CONFIRMATION_EMAIL = 'email';

    /** Confirmation is completed by a Moodle administrator. */
    private const CONFIRMATION_ADMIN = 'admin';

    /** @var object|null Email authentication plugin override used by tests. */
    private $emailauth;

    /**
     * Constructor.
     *
     * @param object|null $emailauth Email authentication plugin override.
     */
    public function __construct($emailauth = null) {
        $this->emailauth = $emailauth;
    }

    /**
     * Return the password policy and custom fields available during registration.
     *
     * @return array
     */
    public function get_registration_fields(): array {
        global $CFG;

        require_once($CFG->libdir . '/authlib.php');
        require_once($CFG->dirroot . '/user/profile/lib.php');

        $customfields = [];
        foreach (profile_get_signup_fields() as $field) {
            $config = $field->object->get_field_config_for_external();
            $customfields[] = [
                'type' => $config['shortname'],
                'name' => format_string($config['name']),
                'datatype' => $config['datatype'],
                'required' => !empty($config['required']),
                'locked' => !empty($config['locked']),
                'forceunique' => !empty($config['forceunique']),
                'defaultvalue' => $config['defaultdata'] ?? '',
                'settings' => $this->get_field_settings($config),
            ];
        }

        return [
            'passwordpolicy' => !empty($CFG->passwordpolicy) ? print_password_policy() : '',
            'customfields' => $customfields,
        ];
    }

    /**
     * Register an unconfirmed user using the configured registration mode.
     *
     * @param array $data Validated external-function data.
     * @return array The new immutable user identity.
     */
    public function register_user(array $data): array {
        global $CFG, $DB;

        require_once($CFG->libdir . '/authlib.php');
        require_once($CFG->dirroot . '/user/editlib.php');
        require_once($CFG->dirroot . '/user/profile/lib.php');

        [$authmethod, $confirmationmethod] = $this->get_registration_mode();
        if (!is_enabled_auth($authmethod)) {
            if ($authmethod === 'email') {
                throw new \moodle_exception('emailauthdisabled', 'auth_userkey');
            }
            throw new \moodle_exception('registrationauthdisabled', 'auth_userkey', '', $authmethod);
        }

        $email = \core_text::strtolower(trim($data['email']));
        $username = $email;
        $this->validate_identity($username, $email);

        $user = (object) [
            'username' => $username,
            'password' => $data['password'],
            'firstname' => trim($data['firstname']),
            'lastname' => trim($data['lastname']),
            'email' => $email,
            'city' => $data['city'] ?? '',
            'country' => $data['country'] ?? '',
        ];

        if ($user->firstname === '' || $user->lastname === '') {
            throw new \invalid_parameter_exception(get_string('invalidregistrationdata', 'auth_userkey'));
        }

        $user->id = 0;
        $passworderror = '';
        if (!check_password_policy($user->password, $passworderror, $user)) {
            throw new \invalid_parameter_exception($passworderror);
        }

        $this->apply_and_validate_custom_fields($user, $data['customfields'] ?? []);

        $user = signup_setup_new_user($user);
        $user->auth = $authmethod;

        $transaction = $DB->start_delegated_transaction();
        try {
            if ($confirmationmethod === self::CONFIRMATION_ADMIN) {
                $this->create_user_without_confirmation_email($user);
            } else {
                $emailauth = $this->emailauth ?? get_auth_plugin('email');
                $emailauth->user_signup_with_confirmation(
                    $user,
                    false,
                    new \moodle_url('/auth/userkey/confirm.php')
                );
            }
            set_user_preference(self::CONFIRMATION_PREFERENCE, $confirmationmethod, $user);
            $transaction->allow_commit();
        } catch (\Throwable $exception) {
            $transaction->rollback($exception);
        }

        return [
            'userid' => (int) $user->id,
            'username' => $user->username,
            'confirmationrequired' => true,
            'authmethod' => $authmethod,
            'confirmationmethod' => $confirmationmethod,
        ];
    }

    /**
     * Confirm a user from the opaque data placed in Moodle's confirmation email.
     *
     * @param string $data Confirmation data in secret/username format.
     * @return bool
     */
    public function confirm_user(string $data): bool {
        $parts = explode('/', $data, 2);
        if (count($parts) !== 2) {
            return false;
        }

        [$secret, $username] = $parts;
        if (clean_param($secret, PARAM_ALPHANUM) !== $secret || $username === '') {
            return false;
        }

        $user = get_complete_user_data('username', $username);
        if (
                !$user
                || !empty($user->deleted)
                || !in_array($user->auth, ['email', 'manual'], true)
                || !is_enabled_auth($user->auth)
                || get_user_preferences(self::CONFIRMATION_PREFERENCE, self::CONFIRMATION_EMAIL, $user)
                    !== self::CONFIRMATION_EMAIL
                || !hash_equals((string) $user->secret, $secret)
        ) {
            return false;
        }

        $authplugin = $user->auth === 'email' && $this->emailauth
            ? $this->emailauth
            : get_auth_plugin($user->auth);
        $result = $authplugin->user_confirm($username, $secret);
        if ($result === AUTH_CONFIRM_OK || $result === AUTH_CONFIRM_ALREADY) {
            unset_user_preference(self::CONFIRMATION_PREFERENCE, $user);
            return true;
        }

        return false;
    }

    /**
     * Return the account auth method and confirmation method for new registrations.
     *
     * @return array{0: string, 1: string}
     */
    private function get_registration_mode(): array {
        $mode = get_config('auth_userkey', 'registrationmode');
        if ($mode === false || $mode === '') {
            $mode = self::MODE_EMAIL;
        }

        switch ($mode) {
            case self::MODE_EMAIL:
                return ['email', self::CONFIRMATION_EMAIL];
            case self::MODE_EMAIL_ADMIN:
                return ['email', self::CONFIRMATION_ADMIN];
            case self::MODE_MANUAL:
                return ['manual', self::CONFIRMATION_EMAIL];
            default:
                throw new \moodle_exception('invalidregistrationmode', 'auth_userkey');
        }
    }

    /**
     * Create an unconfirmed account without sending a user confirmation email.
     *
     * This follows Moodle's email-auth signup sequence while deliberately omitting only the email-delivery step.
     *
     * @param \stdClass $user Prepared user record containing a plaintext password.
     */
    private function create_user_without_confirmation_email(\stdClass $user): void {
        global $CFG;

        require_once($CFG->dirroot . '/user/lib.php');

        $plainpassword = $user->password;
        $user->id = user_create_user($user, true, false);
        user_add_password_history($user->id, $plainpassword);
        profile_save_data($user);
        \core\event\user_created::create_from_userid($user->id)->trigger();
    }

    /**
     * Return the configured post-confirmation destination without creating a Moodle session.
     *
     * @return \moodle_url
     */
    public function get_confirmation_redirect_url(): \moodle_url {
        $config = get_config('auth_userkey');
        $redirecturl = empty($config->ssourl) ? new \moodle_url('/') : new \moodle_url($config->ssourl);
        $redirecturl->param('emailconfirmed', 1);
        return $redirecturl;
    }

    /**
     * Return field-type-specific settings for future WordPress form renderers.
     *
     * @param array $config Moodle custom profile field configuration.
     * @return array
     */
    private function get_field_settings(array $config): array {
        $settings = [];
        foreach (['param1', 'param2', 'param3', 'param4', 'param5'] as $name) {
            $settings[] = [
                'name' => $name,
                'value' => (string) ($config[$name] ?? ''),
            ];
        }
        return $settings;
    }

    /**
     * Validate that the normalized email can safely be used as a unique username.
     *
     * @param string $username Normalized username.
     * @param string $email Normalized email.
     */
    protected function validate_identity(string $username, string $email): void {
        global $CFG, $DB;

        if (!validate_email($email) || email_is_not_allowed($email)) {
            throw new \invalid_parameter_exception(get_string('invalidemail'));
        }
        if ($username !== \core_user::clean_field($username, 'username')) {
            throw new \invalid_parameter_exception(get_string('invalidusername'));
        }
        if ($DB->record_exists('user', ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id])) {
            throw new \moodle_exception('accountalreadyexists', 'auth_userkey');
        }

        $select = $DB->sql_equal('email', ':email', false, true) . ' AND mnethostid = :mnethostid';
        if (
            $DB->record_exists_select('user', $select, [
                'email' => $email,
                'mnethostid' => $CFG->mnet_localhost_id,
            ])
        ) {
            throw new \moodle_exception('accountalreadyexists', 'auth_userkey');
        }
    }

    /**
     * Apply supplied signup-visible custom profile fields and validate all required fields.
     *
     * @param \stdClass $user Registration data.
     * @param array $customfields Custom field shortnames and values.
     */
    protected function apply_and_validate_custom_fields(\stdClass $user, array $customfields): void {
        $allowedfields = [];
        foreach (profile_get_signup_fields() as $field) {
            $config = $field->object->get_field_config_for_external();
            $allowedfields[$config['shortname']] = [
                'inputname' => $field->object->inputname,
                'required' => !empty($config['required']),
                'properties' => $field->object->get_field_properties(),
            ];
        }

        $seen = [];
        foreach ($customfields as $customfield) {
            $shortname = $customfield['type'];
            if (!isset($allowedfields[$shortname]) || isset($seen[$shortname])) {
                throw new \invalid_parameter_exception(get_string('invalidcustomfield', 'auth_userkey'));
            }
            $seen[$shortname] = true;

            $value = $customfield['value'];
            [$type, $allownull] = $allowedfields[$shortname]['properties'];
            $value = validate_param($value, $type, $allownull);
            $decoded = json_decode($value, true);
            $inputname = $allowedfields[$shortname]['inputname'];
            $user->{$inputname} = is_array($decoded) && json_last_error() === JSON_ERROR_NONE
                ? $decoded
                : $value;
        }

        foreach ($allowedfields as $shortname => $field) {
            if ($field['required'] && !isset($seen[$shortname])) {
                throw new \invalid_parameter_exception(get_string('missingcustomfield', 'auth_userkey', $shortname));
            }
        }

        $user->id = 0;
        $errors = profile_validation($user, []);
        unset($user->id);
        if (!empty($errors)) {
            throw new \invalid_parameter_exception(implode(' ', array_values($errors)));
        }
    }
}
