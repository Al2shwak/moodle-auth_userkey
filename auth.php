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
 * User key auth method.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

use auth_userkey\core_userkey_manager;
use auth_userkey\userkey_manager_interface;
use core_external\external_value;

require_once($CFG->libdir . '/authlib.php');
require_once($CFG->dirroot . '/user/lib.php');

/**
 * User key authentication plugin.
 */
class auth_plugin_userkey extends auth_plugin_base {
    /**
     * User key manager.
     *
     * @var userkey_manager_interface
     */
    protected $userkeymanager;

    /**
     * Defaults for config form.
     *
     * @var array
     */
    protected $defaults = [
        'keylifetime' => 60,
        'iprestriction' => 0,
        'ipwhitelist' => '',
        'allowedauthmethods' => 'manual,email',
        'registrationmode' => 'email',
        'redirecturl' => '',
        'allowedredirecthosts' => '',
        'ssourl' => '',
    ];

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'userkey';
        $this->config = get_config('auth_userkey');
        $this->userkeymanager = new core_userkey_manager($this->config);
    }

    /**
     * All the checking happens before the login page in this hook.
     *
     * It redirects a user if required or return true.
     */
    public function pre_loginpage_hook() {
        global $SESSION;

        // If we previously tried to skip SSO on, but then navigated
        // away, and come in from another deep link while SSO only is
        // on, then reset the previous session memory of forcing SSO.
        if (isset($SESSION->enrolkey_skipsso)) {
            unset($SESSION->enrolkey_skipsso);
        }

        return $this->loginpage_hook();
    }

    /**
     * All the checking happens before the login page in this hook.
     *
     * It redirects a user if required or return true.
     */
    public function loginpage_hook() {
        if ($this->should_login_redirect()) {
            $this->redirect($this->config->ssourl);
        }

        return true;
    }

    /**
     * Redirects the user to provided URL.
     *
     * @param string $url URL to redirect to.
     *
     * @throws \moodle_exception If gets running via CLI or AJAX call.
     */
    protected function redirect($url) {
        if (CLI_SCRIPT || AJAX_SCRIPT) {
            throw new moodle_exception('redirecterrordetected', 'auth_userkey', '', $url);
        }

        redirect($url);
    }

    /**
     * Don't allow login using login form.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     *
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password) {
        return false;
    }

    /**
     * Logs a user in using userkey and redirects after.
     *
     * @throws \moodle_exception If something went wrong.
     */
    public function user_login_userkey() {
        global $SESSION, $USER;

        $keyvalue = required_param('key', PARAM_ALPHANUM);
        $wantsurl = optional_param('wantsurl', '', PARAM_URL);
        $redirecturl = $this->get_redirect_url($wantsurl);

        $key = $this->userkeymanager->validate_key($keyvalue);

        if (isloggedin()) {
            if ($USER->id != $key->userid) {
                // A bearer link must not be able to terminate or replace an active user's session.
                throw new moodle_exception('differentuserloggedin', 'auth_userkey');
            } else {
                // Don't process further if the user is already logged in.
                $this->userkeymanager->delete_keys($key->userid);
                $this->redirect($redirecturl);
            }
        }

        $this->userkeymanager->delete_keys($key->userid);

        $user = get_complete_user_data('id', $key->userid);
        if (!$user || !empty($user->deleted) || !\core_user::is_real_user($user->id)) {
            throw new moodle_exception('invalidkey');
        }

        if (is_siteadmin($user)) {
            \core\event\user_login_failed::create([
                'userid' => $user->id,
                'other' => [
                    'username' => $user->username,
                    'reason' => AUTH_LOGIN_UNAUTHORISED,
                ],
            ])->trigger();
            throw new moodle_exception('siteadminnotallowed', 'auth_userkey');
        }

        if (
                empty($user->confirmed)
                || !empty($user->suspended)
                || !$this->is_auth_method_allowed($user->auth)
        ) {
            $reason = empty($user->confirmed) ? AUTH_LOGIN_UNAUTHORISED : AUTH_LOGIN_SUSPENDED;
            \core\event\user_login_failed::create([
                'userid' => $user->id,
                'other' => [
                    'username' => $user->username,
                    'reason' => $reason,
                ],
            ])->trigger();
            throw new moodle_exception('loginnotallowed', 'auth_userkey');
        }

        complete_user_login($user);

        // Identify this session as using user key auth method.
        $SESSION->userkey = true;

        $this->redirect($redirecturl);
    }

    /**
     * Don't store local passwords.
     *
     * @return bool True.
     */
    public function prevent_local_passwords() {
        return true;
    }

    /**
     * Returns true if this authentication plugin is external.
     *
     * @return bool False.
     */
    public function is_internal() {
        return false;
    }

    /**
     * The plugin can't change the user's password.
     *
     * @return bool False.
     */
    public function can_change_password() {
        return false;
    }

    /**
     * Set userkey manager.
     *
     * This function is the only way to inject dependency, because of the way auth plugins work.
     *
     * @param \auth_userkey\userkey_manager_interface $keymanager
     */
    public function set_userkey_manager(userkey_manager_interface $keymanager) {
        $this->userkeymanager = $keymanager;
    }

    /**
     * Return enabled authentication methods that implement password authentication.
     *
     * Authentication methods that must never be bridged are excluded even when enabled.
     *
     * @return array Method name to display name.
     */
    public function get_selectable_auth_methods(): array {
        $blockedmethods = ['userkey', 'nologin', 'webservice', 'none'];
        $methods = [];

        foreach (get_enabled_auth_plugins() as $method) {
            if (in_array($method, $blockedmethods, true)) {
                continue;
            }

            $authplugin = get_auth_plugin($method);
            $loginmethod = new \ReflectionMethod($authplugin, 'user_login');
            if ($loginmethod->getDeclaringClass()->getName() === auth_plugin_base::class) {
                continue;
            }

            $methods[$method] = $authplugin->get_title();
        }

        return $methods;
    }

    /**
     * Return the configured authentication allowlist, restricted to selectable enabled methods.
     *
     * @return array Authentication method names.
     */
    public function get_allowed_auth_methods(): array {
        if (!property_exists($this->config, 'allowedauthmethods')) {
            $configured = explode(',', $this->defaults['allowedauthmethods']);
        } else if (is_array($this->config->allowedauthmethods)) {
            $configured = $this->config->allowedauthmethods;
        } else if ($this->config->allowedauthmethods === '') {
            $configured = [];
        } else {
            $configured = explode(',', $this->config->allowedauthmethods);
        }

        $configured = array_unique(array_filter(array_map(static function ($method) {
            return clean_param(trim((string) $method), PARAM_PLUGIN);
        }, $configured)));

        return array_values(array_intersect($configured, array_keys($this->get_selectable_auth_methods())));
    }

    /**
     * Check whether an account authentication method may use this bridge.
     *
     * @param string $method Authentication method name.
     * @return bool
     */
    protected function is_auth_method_allowed(string $method): bool {
        return in_array($method, $this->get_allowed_auth_methods(), true);
    }

    /**
     * Check if restriction by IP is enabled.
     *
     * @return bool
     */
    protected function is_ip_restriction_enabled() {
        if (isset($this->config->iprestriction) && $this->config->iprestriction == true) {
            return true;
        }

        return false;
    }

    /**
     * Validate user data from web service.
     *
     * @param mixed $data User data from web service.
     *
     * @return array
     *
     * @throws \invalid_parameter_exception If provided data is invalid.
     */
    protected function validate_user_data($data) {
        $data = (array)$data;

        if (empty($data['id'])) {
            throw new invalid_parameter_exception('Required field "id" is not set or empty.');
        }

        if ($this->is_ip_restriction_enabled()) {
            if (empty($data['ip'])) {
                throw new invalid_parameter_exception('Required parameter "ip" is not set.');
            }
            if (!\core\ip_utils::is_ip_address($data['ip'])) {
                throw new invalid_parameter_exception('IP address is invalid.');
            }
        }

        return $data;
    }

    /**
     * Return user object.
     *
     * @param array $data Validated user data.
     *
     * @return object A user object.
     *
     * @throws \invalid_parameter_exception If user is not exist and we don't need to create a new.
     */
    protected function get_user(array $data) {
        global $DB, $CFG;

        $user = $DB->get_record('user', [
            'id' => $data['id'],
            'mnethostid' => $CFG->mnet_localhost_id,
            'deleted' => 0,
        ]);

        if (empty($user)) {
            throw new invalid_parameter_exception('User is not exist');
        } else if (!\core_user::is_real_user($user->id) || empty($user->confirmed)) {
            throw new invalid_parameter_exception('User is not active');
        } else if (!empty($user->suspended) || $user->auth === 'nologin') {
            throw new invalid_parameter_exception('User is suspended');
        } else if (!$this->is_auth_method_allowed($user->auth)) {
            throw new invalid_parameter_exception(get_string('authmethodnotallowed', 'auth_userkey'));
        } else if (is_siteadmin($user)) {
            throw new invalid_parameter_exception(get_string('siteadminnotallowed', 'auth_userkey'));
        }

        return $user;
    }

    /**
     * Return allowed IPs from user data.
     *
     * @param array $data Validated user data.
     *
     * @return null|string Allowed IPs or null.
     */
    protected function get_allowed_ips(array $data) {
        if (isset($data['ip']) && !empty($data['ip'])) {
            return $data['ip'];
        }

        return null;
    }

    /**
     * Generate login user key.
     *
     * @param array $data Validated user data.
     *
     * @return string
     * @throws \invalid_parameter_exception
     */
    protected function generate_user_key(array $data) {
        $user = $this->get_user($data);
        $ips = $this->get_allowed_ips($data);

        return $this->userkeymanager->create_key($user->id, $ips);
    }

    /**
     * Return login URL.
     *
     * @param array|stdClass $data User data from web service.
     *
     * @return string Login URL.
     *
     * @throws \invalid_parameter_exception
     */
    public function get_login_url($data) {
        global $CFG;

        $userdata = $this->validate_user_data($data);
        $userkey  = $this->generate_user_key($userdata);

        return $CFG->wwwroot . '/auth/userkey/login.php?key=' . $userkey;
    }

    /**
     * Validate Moodle-owned credentials without creating a browser session.
     *
     * The user is resolved before calling authenticate_user_login() so that enabled external
     * authentication plugins cannot provision a new account as a side effect of a failed lookup.
     *
     * @param string $identifier Moodle username or email address.
     * @param string $password Plain text password supplied over HTTPS.
     * @return array Immutable Moodle identity.
     * @throws \moodle_exception When the credentials or account are not eligible for SSO.
     */
    public function authenticate_user(string $identifier, string $password): array {
        global $CFG, $DB;

        $identifier = trim($identifier);
        $user = false;

        if (validate_email($identifier)) {
            $select = $DB->sql_equal('email', ':email', false, true)
                . ' AND mnethostid = :mnethostid AND deleted = 0';
            $users = $DB->get_records_select(
                'user',
                $select,
                ['email' => $identifier, 'mnethostid' => $CFG->mnet_localhost_id],
                'id ASC',
                'id, username, auth, confirmed, suspended, deleted',
                0,
                2
            );
            if (count($users) === 1) {
                $user = reset($users);
            }
        } else {
            $username = \core_text::strtolower($identifier);
            if ($username !== '' && $username === \core_user::clean_field($username, 'username')) {
                $user = $DB->get_record('user', [
                    'username' => $username,
                    'mnethostid' => $CFG->mnet_localhost_id,
                    'deleted' => 0,
                ], 'id, username, auth, confirmed, suspended, deleted');
            }
        }

        if (
            !$user
            || !$this->is_auth_method_allowed($user->auth)
            || !\core_user::is_real_user($user->id)
            || !empty($user->deleted)
            || empty($user->confirmed)
            || !empty($user->suspended)
            || is_siteadmin($user)
        ) {
            throw new moodle_exception('invalidauthentication', 'auth_userkey');
        }

        $failurereason = null;
        $authenticated = authenticate_user_login($user->username, $password, false, $failurereason);
        if (
            !$authenticated
            || !\core_user::is_real_user($authenticated->id)
            || !empty($authenticated->deleted)
            || empty($authenticated->confirmed)
            || !empty($authenticated->suspended)
            || !$this->is_auth_method_allowed($authenticated->auth)
            || is_siteadmin($authenticated)
        ) {
            throw new moodle_exception('invalidauthentication', 'auth_userkey');
        }

        return [
            'userid' => (int) $authenticated->id,
            'username' => $authenticated->username,
        ];
    }

    /**
     * Return parameters for request_login_url_parameters().
     *
     * @return array
     */
    public function get_request_login_url_user_parameters() {
        $parameters = [
            'id' => new external_value(PARAM_INT, 'Database ID of the user'),
        ];

        if ($this->is_ip_restriction_enabled()) {
            $parameters['ip'] = new external_value(
                PARAM_RAW_TRIMMED,
                'User IP address'
            );
        }

        return $parameters;
    }

    /**
     * Check if we should redirect a user as part of login.
     *
     * @return bool
     */
    protected function should_login_redirect() {
        global $SESSION;

        $skipsso = optional_param('enrolkey_skipsso', 0, PARAM_BOOL);

        // Check whether we've skipped SSO already.
        // This is here because loginpage_hook is called again during form
        // submission (all of login.php is processed) and ?skipsso=on is not
        // preserved forcing us to the SSO.
        if ((isset($SESSION->enrolkey_skipsso) && $SESSION->enrolkey_skipsso == 1)) {
            return false;
        }

        $SESSION->enrolkey_skipsso = $skipsso;

        // If SSO only is set and user is not passing the skip param
        // or has it already set in their session then redirect to the SSO URL.
        if (isset($this->config->ssourl) && $this->config->ssourl != '' && !$skipsso) {
            return true;
        }
    }

    /**
     * Check if we should redirect a user after logout.
     *
     * @return bool
     */
    protected function should_logout_redirect() {
        global $SESSION;

        if (!isset($SESSION->userkey)) {
            return false;
        }

        if (!isset($this->config->redirecturl)) {
            return false;
        }

        if (empty($this->config->redirecturl)) {
            return false;
        }

        return true;
    }


    /**
     * Logout page hook.
     *
     * Override redirect URL after logout.
     *
     * @see auth_plugin_base::logoutpage_hook()
     */
    public function logoutpage_hook() {
        global $redirect;

        if ($this->should_logout_redirect()) {
            $redirect = $this->config->redirecturl;
        }
    }

    /**
     * Log out user and redirect.
     */
    public function user_logout_userkey() {
        global $CFG, $SESSION;

        $redirect = required_param('return', PARAM_LOCALURL);
        if ($redirect === '' || preg_match('~^[\\\\/]{2}~', $redirect)) {
            $redirect = $CFG->wwwroot;
        }

        // If the session has already expired, there is no state-changing action to protect.
        if (!isloggedin()) {
            $this->redirect($redirect);
        }

        // Only sessions established through this plugin may use its logout endpoint.
        if (empty($SESSION->userkey)) {
            throw new moodle_exception('incorrectlogout', 'auth_userkey', $CFG->wwwroot);
        }

        require_sesskey();
        require_logout();
        $this->redirect($redirect);
    }

    /**
     * Return a safe post-login redirect URL.
     *
     * Local Moodle URLs are always accepted. An external HTTP(S) URL is accepted only when its
     * host is explicitly configured in the allowed redirect hosts setting.
     *
     * @param string $wantsurl Requested redirect URL.
     * @return string Safe redirect URL.
     */
    protected function get_redirect_url(string $wantsurl): string {
        global $CFG;

        if ($wantsurl === '') {
            return $CFG->wwwroot;
        }

        // Browsers interpret a double slash as a protocol-relative external URL, while
        // PARAM_LOCALURL accepts any value beginning with a slash as root-relative.
        if (preg_match('~^[\\\\/]{2}~', $wantsurl)) {
            return $CFG->wwwroot;
        }

        $localurl = clean_param($wantsurl, PARAM_LOCALURL);
        if ($localurl !== '') {
            return $localurl;
        }

        $parts = parse_url($wantsurl);
        if (
            $parts === false
            || empty($parts['host'])
            || empty($parts['scheme'])
            || !in_array(core_text::strtolower($parts['scheme']), ['http', 'https'], true)
            || isset($parts['user'])
            || isset($parts['pass'])
            || empty($this->config->allowedredirecthosts)
        ) {
            return $CFG->wwwroot;
        }

        $redirecthost = core_text::strtolower(rtrim($parts['host'], '.'));
        $allowedhosts = preg_split('/[;,\r\n]+/', $this->config->allowedredirecthosts);

        foreach ($allowedhosts as $allowedhost) {
            $allowedhost = core_text::strtolower(rtrim(trim($allowedhost), '.'));
            if ($allowedhost !== '' && $redirecthost === $allowedhost) {
                return $wantsurl;
            }
        }

        return $CFG->wwwroot;
    }
}
