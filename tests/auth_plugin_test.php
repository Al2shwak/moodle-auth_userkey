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

use advanced_testcase;
use auth_plugin_userkey;
use invalid_parameter_exception;
use moodle_exception;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Tests for the UserKey authentication plugin.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(\auth_plugin_userkey::class)]
final class auth_plugin_test extends advanced_testcase {
    /** @var auth_plugin_userkey Plugin instance. */
    private $auth;

    /**
     * Reset state and enable relevant authentication methods.
     */
    protected function setUp(): void {
        global $CFG;

        parent::setUp();
        $this->resetAfterTest();
        require_once($CFG->dirroot . '/auth/userkey/tests/fake_userkey_manager.php');
        require_once($CFG->dirroot . '/auth/userkey/auth.php');
        $CFG->auth = 'manual,email,userkey,nologin';
        $_SERVER['HTTP_USER_AGENT'] = 'phpunit';
        $this->auth = new auth_plugin_userkey();
    }

    /**
     * The auth plugin itself never accepts passwords or owns them.
     */
    public function test_userkey_auth_properties(): void {
        $this->assertFalse($this->auth->user_login('someone', 'Password1!'));
        $this->assertTrue($this->auth->prevent_local_passwords());
        $this->assertFalse($this->auth->is_internal());
        $this->assertFalse($this->auth->can_change_password());
    }

    /**
     * Login URL requests use an immutable user ID and leave account data unchanged.
     */
    public function test_login_url_by_id_does_not_mutate_user(): void {
        global $CFG, $DB;

        $user = self::getDataGenerator()->create_user([
            'username' => 'fixedidentity',
            'email' => 'fixed@example.com',
            'auth' => 'manual',
        ]);
        $this->auth->set_userkey_manager(new fake_userkey_manager());

        $url = $this->auth->get_login_url([
            'id' => $user->id,
            'username' => 'ignored',
            'email' => 'ignored@example.com',
            'auth' => 'userkey',
        ]);

        $this->assertSame($CFG->wwwroot . '/auth/userkey/login.php?key=FaKeKeyFoRtEsTiNg', $url);
        $stored = $DB->get_record('user', ['id' => $user->id], '*', MUST_EXIST);
        $this->assertSame('fixedidentity', $stored->username);
        $this->assertSame('fixed@example.com', $stored->email);
        $this->assertSame('manual', $stored->auth);
    }

    /**
     * Missing IDs are rejected.
     */
    public function test_login_url_requires_id(): void {
        $this->expectException(invalid_parameter_exception::class);
        $this->auth->get_login_url([]);
    }

    /**
     * Ineligible accounts cannot receive keys.
     *
     */
    public function test_login_url_rejects_ineligible_accounts(): void {
        $cases = [
            'unconfirmed' => [['confirmed' => 0], false],
            'suspended' => [['suspended' => 1], false],
            'nologin' => [['auth' => 'nologin'], false],
            'administrator' => [[], true],
        ];

        foreach ($cases as [$properties, $admin]) {
            $user = self::getDataGenerator()->create_user($properties);
            if ($admin) {
                set_config('siteadmins', (string) $user->id);
            }
            $this->auth = new auth_plugin_userkey();

            try {
                $this->auth->get_login_url(['id' => $user->id]);
                $this->fail('Expected an ineligible account to be rejected.');
            } catch (invalid_parameter_exception $exception) {
                $this->assertNotEmpty($exception->getMessage());
            }
        }
    }

    /**
     * IP restriction requires a valid address.
     */
    public function test_login_url_validates_ip(): void {
        $user = self::getDataGenerator()->create_user();
        set_config('iprestriction', true, 'auth_userkey');
        $this->auth = new auth_plugin_userkey();

        $this->expectException(invalid_parameter_exception::class);
        $this->auth->get_login_url(['id' => $user->id, 'ip' => 'example.com']);
    }

    /**
     * Only enabled password implementations are selectable and unsafe methods remain excluded.
     */
    public function test_selectable_auth_methods_exclude_unsafe_methods(): void {
        $methods = $this->auth->get_selectable_auth_methods();

        $this->assertArrayHasKey('manual', $methods);
        $this->assertArrayHasKey('email', $methods);
        $this->assertArrayNotHasKey('userkey', $methods);
        $this->assertArrayNotHasKey('nologin', $methods);
        $this->assertArrayNotHasKey('webservice', $methods);
        $this->assertArrayNotHasKey('none', $methods);
    }

    /**
     * The default allowlist contains manual and email authentication.
     */
    public function test_default_allowed_auth_methods(): void {
        $this->assertSame(['manual', 'email'], $this->auth->get_allowed_auth_methods());
    }

    /**
     * One configured allowlist controls both credential validation and login URL generation.
     */
    public function test_configured_auth_allowlist_applies_to_both_endpoints(): void {
        $emailuser = self::getDataGenerator()->create_user([
            'username' => 'disallowedemail@example.com',
            'email' => 'disallowedemail@example.com',
            'password' => 'Password1!',
            'auth' => 'email',
            'confirmed' => 1,
        ]);
        set_config('allowedauthmethods', 'manual', 'auth_userkey');
        $this->auth = new auth_plugin_userkey();

        try {
            $this->auth->authenticate_user($emailuser->username, 'Password1!');
            $this->fail('Expected credential validation to enforce the allowlist.');
        } catch (moodle_exception $exception) {
            $this->assertSame('invalidauthentication', $exception->errorcode);
        }

        try {
            $this->auth->get_login_url(['id' => $emailuser->id]);
            $this->fail('Expected login URL generation to enforce the allowlist.');
        } catch (invalid_parameter_exception $exception) {
            $this->assertStringContainsString('not allowed for SSO', $exception->getMessage());
        }
    }

    /**
     * An explicitly empty allowlist fails closed.
     */
    public function test_empty_auth_allowlist_denies_all_accounts(): void {
        $user = self::getDataGenerator()->create_user(['auth' => 'manual']);
        set_config('allowedauthmethods', '', 'auth_userkey');
        $this->auth = new auth_plugin_userkey();

        $this->assertSame([], $this->auth->get_allowed_auth_methods());
        $this->expectException(invalid_parameter_exception::class);
        $this->auth->get_login_url(['id' => $user->id]);
    }

    /**
     * Manual users can authenticate using username or case-insensitive email.
     */
    public function test_authenticate_manual_user_by_username_and_email(): void {
        $user = self::getDataGenerator()->create_user([
            'username' => 'credentialuser',
            'email' => 'Credential.User@example.com',
            'password' => 'Password1!',
            'auth' => 'manual',
        ]);

        $byusername = $this->auth->authenticate_user('credentialuser', 'Password1!');
        $byemail = $this->auth->authenticate_user('CREDENTIAL.USER@EXAMPLE.COM', 'Password1!');

        $this->assertSame((int) $user->id, $byusername['userid']);
        $this->assertSame((int) $user->id, $byemail['userid']);
        $this->assertSame('credentialuser', $byemail['username']);
    }

    /**
     * Confirmed email-auth users can authenticate.
     */
    public function test_authenticate_confirmed_email_user(): void {
        $user = self::getDataGenerator()->create_user([
            'username' => 'emailuser@example.com',
            'email' => 'emailuser@example.com',
            'password' => 'Password1!',
            'auth' => 'email',
            'confirmed' => 1,
        ]);

        $result = $this->auth->authenticate_user($user->email, 'Password1!');
        $this->assertSame((int) $user->id, $result['userid']);
    }

    /**
     * A correct password resends Moodle's confirmation email for user-confirmed registration modes.
     */
    public function test_authenticate_unconfirmed_user_resends_confirmation_email(): void {
        $olderrorlevel = error_reporting();
        error_reporting($olderrorlevel & ~E_DEPRECATED);
        $sink = $this->redirectEmails();
        $manager = new registration_manager();
        $modes = [registration_manager::MODE_EMAIL, registration_manager::MODE_MANUAL];

        try {
            foreach ($modes as $index => $mode) {
                set_config('registrationmode', $mode, 'auth_userkey');
                $result = $manager->register_user([
                    'email' => 'pending' . $index . '@example.com',
                    'password' => 'Password1!',
                    'firstname' => 'Pending',
                    'lastname' => 'User',
                ]);

                try {
                    $this->auth->authenticate_user($result['username'], 'Password1!');
                    $this->fail('Expected an unconfirmed account to require confirmation.');
                } catch (moodle_exception $exception) {
                    $this->assertSame('confirmationrequired', $exception->errorcode);
                }
            }

            $this->assertCount(4, $sink->get_messages());
            foreach ($sink->get_messages() as $message) {
                $this->assertStringContainsString('/auth/userkey/confirm.php?data=', $message->body);
            }
        } finally {
            $sink->close();
            error_reporting($olderrorlevel);
        }
    }

    /**
     * An incorrect password never triggers another confirmation email.
     */
    public function test_authenticate_unconfirmed_user_requires_valid_password_before_resend(): void {
        $sink = $this->redirectEmails();
        $manager = new registration_manager();
        $result = $manager->register_user([
            'email' => 'pendingwrongpassword@example.com',
            'password' => 'Password1!',
            'firstname' => 'Pending',
            'lastname' => 'Password',
        ]);

        try {
            $this->auth->authenticate_user($result['username'], 'WrongPassword1!');
            $this->fail('Expected invalid credentials to be rejected.');
        } catch (moodle_exception $exception) {
            $this->assertSame('invalidauthentication', $exception->errorcode);
        }

        $this->assertCount(1, $sink->get_messages());
        $sink->close();
    }

    /**
     * Administrator-confirmed accounts never receive an email from the login flow.
     */
    public function test_authenticate_does_not_resend_for_admin_confirmation(): void {
        set_config('registrationmode', registration_manager::MODE_EMAIL_ADMIN, 'auth_userkey');
        $sink = $this->redirectEmails();
        $manager = new registration_manager();
        $result = $manager->register_user([
            'email' => 'pendingadmin@example.com',
            'password' => 'Password1!',
            'firstname' => 'Pending',
            'lastname' => 'Admin',
        ]);

        try {
            $this->auth->authenticate_user($result['username'], 'Password1!');
            $this->fail('Expected administrator confirmation to remain pending.');
        } catch (moodle_exception $exception) {
            $this->assertSame('invalidauthentication', $exception->errorcode);
        }

        $this->assertCount(0, $sink->get_messages());
        $sink->close();
    }

    /**
     * A mail delivery failure is distinguishable after successful credential validation.
     */
    public function test_authenticate_reports_confirmation_email_failure(): void {
        $sink = $this->redirectEmails();
        $manager = new registration_manager();
        $result = $manager->register_user([
            'email' => 'pendingmailfailure@example.com',
            'password' => 'Password1!',
            'firstname' => 'Pending',
            'lastname' => 'Failure',
        ]);
        $this->auth = new class extends auth_plugin_userkey {
            /**
             * Simulate an email transport failure.
             *
             * @param \stdClass $user Unconfirmed user.
             * @return bool
             */
            protected function resend_confirmation_email(\stdClass $user): bool {
                return false;
            }
        };

        try {
            $this->auth->authenticate_user($result['username'], 'Password1!');
            $this->fail('Expected confirmation email delivery to fail.');
        } catch (moodle_exception $exception) {
            $this->assertSame('confirmationemailfailed', $exception->errorcode);
        }

        $this->assertCount(1, $sink->get_messages());
        $sink->close();
    }

    /**
     * The bridge honours Moodle's account lockout state.
     */
    public function test_authenticate_honours_lockout(): void {
        $olderrorlevel = error_reporting();
        error_reporting($olderrorlevel & ~E_DEPRECATED);
        $user = self::getDataGenerator()->create_user([
            'username' => 'lockoutuser',
            'password' => 'Password1!',
            'auth' => 'manual',
        ]);
        set_config('lockoutthreshold', 2);
        set_config('lockoutwindow', 1200);
        set_config('lockoutduration', 1800);
        $sink = $this->redirectEmails();

        for ($attempt = 0; $attempt < 2; $attempt++) {
            try {
                $this->auth->authenticate_user($user->username, 'WrongPassword1!');
            } catch (moodle_exception $exception) {
                $this->assertSame('invalidauthentication', $exception->errorcode);
            }
        }

        $this->assertTrue(login_is_lockedout($user));
        try {
            $this->auth->authenticate_user($user->username, 'Password1!');
            $this->fail('Expected a locked account to be rejected.');
        } catch (moodle_exception $exception) {
            $this->assertSame('invalidauthentication', $exception->errorcode);
        } finally {
            $sink->close();
            error_reporting($olderrorlevel);
        }
    }

    /**
     * Deleted and guest users receive the same generic authentication error.
     */
    public function test_authenticate_rejects_deleted_and_guest_users(): void {
        $deleted = self::getDataGenerator()->create_user([
            'username' => 'deletedcredential',
            'password' => 'Password1!',
        ]);
        delete_user($deleted);

        foreach (['deletedcredential', 'guest'] as $identifier) {
            try {
                $this->auth->authenticate_user($identifier, 'Password1!');
                $this->fail('Expected an ineligible account to be rejected.');
            } catch (moodle_exception $exception) {
                $this->assertSame('invalidauthentication', $exception->errorcode);
            }
        }
    }

    /**
     * Every invalid credential/account case returns one generic error.
     *
     */
    public function test_authenticate_rejects_with_generic_error(): void {
        $cases = [
            'wrong password' => [[], 'WrongPassword1!', false],
            'suspended' => [['suspended' => 1], 'Password1!', false],
            'nologin' => [['auth' => 'nologin'], 'Password1!', false],
            'administrator' => [[], 'Password1!', true],
        ];

        $index = 0;
        foreach ($cases as [$properties, $password, $admin]) {
            $index++;
            $properties += [
                'username' => 'blockeduser' . $index,
                'email' => 'blocked' . $index . '@example.com',
                'password' => 'Password1!',
                'auth' => 'manual',
            ];
            $user = self::getDataGenerator()->create_user($properties);
            if ($admin) {
                set_config('siteadmins', (string) $user->id);
            }

            try {
                $this->auth->authenticate_user($user->username, $password);
                $this->fail('Expected generic authentication failure.');
            } catch (moodle_exception $exception) {
                $this->assertSame('invalidauthentication', $exception->errorcode);
                $this->assertSame('Invalid login.', $exception->getMessage());
            }
        }
    }

    /**
     * Unknown and duplicate-email identifiers are not authenticated.
     */
    public function test_authenticate_rejects_unknown_and_ambiguous_email(): void {
        global $CFG;

        try {
            $this->auth->authenticate_user('unknown@example.com', 'Password1!');
            $this->fail('Expected unknown user to fail.');
        } catch (moodle_exception $exception) {
            $this->assertSame('invalidauthentication', $exception->errorcode);
        }

        $CFG->allowaccountssameemail = true;
        self::getDataGenerator()->create_user(['email' => 'shared@example.com']);
        self::getDataGenerator()->create_user(['email' => 'shared@example.com']);

        $this->expectException(moodle_exception::class);
        $this->expectExceptionMessage('Invalid login.');
        $this->auth->authenticate_user('SHARED@example.com', 'Password1!');
    }

    /**
     * Logout redirects are limited to sessions created through UserKey.
     */
    public function test_logout_hook_only_redirects_userkey_session(): void {
        global $redirect, $SESSION;

        $redirect = '';
        set_config('redirecturl', 'https://wordpress.example/logout-complete', 'auth_userkey');
        $this->auth = new auth_plugin_userkey();
        $this->auth->logoutpage_hook();
        $this->assertSame('', $redirect);

        $SESSION->userkey = true;
        $this->auth->logoutpage_hook();
        $this->assertSame('https://wordpress.example/logout-complete', $redirect);
    }
}
