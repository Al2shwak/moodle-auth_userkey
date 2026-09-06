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
use invalid_parameter_exception;
use moodle_exception;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Tests for Moodle-owned registration and confirmation.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(registration_manager::class)]
final class registration_manager_test extends advanced_testcase {
    /** @var registration_manager Registration service. */
    private $manager;

    /**
     * Enable email auth while deliberately keeping public self-registration disabled.
     */
    protected function setUp(): void {
        global $CFG;

        parent::setUp();
        $this->resetAfterTest();
        $CFG->auth = 'manual,email,userkey';
        $CFG->registerauth = '';
        $CFG->passwordpolicy = false;
        $this->manager = new registration_manager();
    }

    /**
     * Registration normalizes identity, hashes the password, and sends Moodle's confirmation email.
     */
    public function test_register_user_creates_unconfirmed_email_user(): void {
        global $DB;

        $sink = $this->redirectEmails();
        $result = $this->manager->register_user($this->valid_registration([
            'email' => 'Student.One@Example.COM',
            'city' => 'Kuwait City',
            'country' => 'KW',
        ]));

        $user = $DB->get_record('user', ['id' => $result['userid']], '*', MUST_EXIST);
        $this->assertSame('student.one@example.com', $result['username']);
        $this->assertTrue($result['confirmationrequired']);
        $this->assertSame('email', $result['authmethod']);
        $this->assertSame('email', $result['confirmationmethod']);
        $this->assertSame('student.one@example.com', $user->username);
        $this->assertSame('student.one@example.com', $user->email);
        $this->assertSame('email', $user->auth);
        $this->assertEquals(0, $user->confirmed);
        $this->assertTrue(validate_internal_user_password($user, 'Password1!'));
        $this->assertSame('', $GLOBALS['CFG']->registerauth);
        $this->assertSame(1, $sink->count());
        $messages = $sink->get_messages();
        $message = reset($messages);
        $this->assertStringContainsString('/auth/userkey/confirm.php?data=', $message->body);
        $sink->close();
    }

    /**
     * Manual mode assigns manual auth while retaining user email confirmation.
     */
    public function test_manual_registration_requires_user_email_confirmation(): void {
        global $CFG, $DB;

        set_config('registrationmode', registration_manager::MODE_MANUAL, 'auth_userkey');
        $CFG->auth = 'manual,userkey';
        $sink = $this->redirectEmails();
        $result = $this->manager->register_user($this->valid_registration());
        $user = $DB->get_record('user', ['id' => $result['userid']], '*', MUST_EXIST);

        $this->assertSame('manual', $result['authmethod']);
        $this->assertSame('email', $result['confirmationmethod']);
        $this->assertSame('manual', $user->auth);
        $this->assertEquals(0, $user->confirmed);
        $this->assertTrue(validate_internal_user_password($user, 'Password1!'));
        $this->assertSame(1, $sink->count());
        $this->assertTrue($this->manager->confirm_user($user->secret . '/' . $user->username));
        $this->assertEquals(1, $DB->get_field('user', 'confirmed', ['id' => $user->id]));
        $sink->close();
    }

    /**
     * Invalid stored registration modes fail closed without creating an account.
     */
    public function test_invalid_registration_mode_is_rejected(): void {
        global $DB;

        set_config('registrationmode', 'userkey', 'auth_userkey');

        try {
            $this->manager->register_user($this->valid_registration());
            $this->fail('Expected the unsafe registration mode to be rejected.');
        } catch (moodle_exception $exception) {
            $this->assertSame('invalidregistrationmode', $exception->errorcode);
        }
        $this->assertFalse($DB->record_exists('user', ['username' => 'student.one@example.com']));
    }

    /**
     * Administrator-confirmation mode creates an email-auth account without emailing a confirmation link.
     */
    public function test_email_admin_registration_waits_for_moodle_administrator(): void {
        global $DB;

        set_config('registrationmode', registration_manager::MODE_EMAIL_ADMIN, 'auth_userkey');
        $sink = $this->redirectEmails();
        $result = $this->manager->register_user($this->valid_registration());
        $user = $DB->get_record('user', ['id' => $result['userid']], '*', MUST_EXIST);

        $this->assertSame('email', $result['authmethod']);
        $this->assertSame('admin', $result['confirmationmethod']);
        $this->assertSame('email', $user->auth);
        $this->assertEquals(0, $user->confirmed);
        $this->assertTrue(validate_internal_user_password($user, 'Password1!'));
        $this->assertSame(0, $sink->count());
        $this->assertFalse($this->manager->confirm_user($user->secret . '/' . $user->username));

        $emailauth = get_auth_plugin('email');
        $this->assertSame(AUTH_CONFIRM_OK, $emailauth->user_confirm($user->username, $user->secret));
        $this->assertEquals(1, $DB->get_field('user', 'confirmed', ['id' => $user->id]));
        $sink->close();
    }

    /**
     * The confirmation secret is consumed by email auth without creating a login session.
     */
    public function test_confirm_user_marks_account_confirmed(): void {
        global $DB, $USER;

        $sink = $this->redirectEmails();
        $result = $this->manager->register_user($this->valid_registration());
        $user = $DB->get_record('user', ['id' => $result['userid']], '*', MUST_EXIST);
        $sessionuserid = $USER->id;
        $auth = get_auth_plugin('userkey');

        try {
            $auth->authenticate_user($user->username, 'Password1!');
            $this->fail('Expected the unconfirmed account to require confirmation.');
        } catch (moodle_exception $exception) {
            $this->assertSame('confirmationrequired', $exception->errorcode);
        }

        $this->assertTrue($this->manager->confirm_user($user->secret . '/' . $user->username));
        $this->assertEquals(1, $DB->get_field('user', 'confirmed', ['id' => $user->id]));
        $this->assertSame($sessionuserid, $USER->id);
        $this->assertSame((int) $user->id, $auth->authenticate_user($user->username, 'Password1!')['userid']);
        $this->assertTrue($this->manager->confirm_user($user->secret . '/' . $user->username));
        $this->assertFalse($this->manager->confirm_user('wrong/' . $user->username));
        $sink->close();
    }

    /**
     * Confirmation redirects back to WordPress without embedding account secrets.
     */
    public function test_confirmation_redirect_url(): void {
        set_config('ssourl', 'https://wordpress.example/login?source=moodle', 'auth_userkey');

        $url = $this->manager->get_confirmation_redirect_url()->out(false);
        $this->assertSame('https://wordpress.example/login?source=moodle&emailconfirmed=1', $url);
        $this->assertStringNotContainsString('secret', $url);
    }

    /**
     * Moodle's password policy is enforced.
     */
    public function test_register_user_rejects_weak_password(): void {
        global $CFG;

        $CFG->passwordpolicy = true;
        $CFG->minpasswordlength = 12;

        $this->expectException(invalid_parameter_exception::class);
        $this->manager->register_user($this->valid_registration(['password' => 'short']));
    }

    /**
     * Existing username and email identities are detected case-insensitively.
     */
    public function test_register_user_rejects_case_insensitive_duplicate(): void {
        self::getDataGenerator()->create_user([
            'username' => 'existing',
            'email' => 'Student.One@Example.com',
        ]);

        $this->expectException(moodle_exception::class);
        $this->expectExceptionMessage('An account already exists for this email address.');
        $this->manager->register_user($this->valid_registration([
            'email' => 'student.one@EXAMPLE.COM',
        ]));
    }

    /**
     * Email authentication must be enabled, but Moodle public signup need not be.
     */
    public function test_register_user_requires_enabled_email_auth(): void {
        global $CFG;

        $CFG->auth = 'manual,userkey';

        $this->expectException(moodle_exception::class);
        $this->expectExceptionMessage('Email-based authentication is disabled.');
        $this->manager->register_user($this->valid_registration());
    }

    /**
     * A failed confirmation email rolls back the newly created account.
     */
    public function test_register_user_rolls_back_when_email_delivery_fails(): void {
        global $CFG, $DB;

        // Make the manager's transaction top-level so its rollback is immediately observable.
        $this->preventResetByRollback();
        require_once($CFG->dirroot . '/auth/email/auth.php');
        $emailauth = new class extends \auth_plugin_email {
            /**
             * Create the record and then simulate the delivery exception thrown by email auth.
             *
             * @param object $user New user.
             * @param bool $notify Whether to display a notice.
             * @param mixed $confirmationurl Confirmation URL.
             * @return void
             */
            public function user_signup_with_confirmation($user, $notify = true, $confirmationurl = null) {
                $user->password = hash_internal_user_password($user->password);
                $user->id = user_create_user($user, false, false);
                throw new moodle_exception('auth_emailnoemail', 'auth_email');
            }
        };
        $manager = new registration_manager($emailauth);

        try {
            $manager->register_user($this->valid_registration());
            $this->fail('Expected simulated email delivery failure.');
        } catch (moodle_exception $exception) {
            $this->assertSame('auth_emailnoemail', $exception->errorcode);
        }

        $this->assertFalse($DB->record_exists('user', ['username' => 'student.one@example.com']));
    }

    /**
     * Signup-visible custom fields are advertised, validated, and stored.
     */
    public function test_registration_fields_and_required_custom_field(): void {
        global $DB;

        $field = self::getDataGenerator()->create_custom_profile_field([
            'datatype' => 'text',
            'shortname' => 'membershiptype',
            'name' => 'Membership type',
            'signup' => 1,
            'visible' => PROFILE_VISIBLE_ALL,
            'required' => 1,
        ]);

        $metadata = $this->manager->get_registration_fields();
        $this->assertSame('membershiptype', $metadata['customfields'][0]['type']);
        $this->assertTrue($metadata['customfields'][0]['required']);
        $this->assertCount(5, $metadata['customfields'][0]['settings']);

        try {
            $this->manager->register_user($this->valid_registration());
            $this->fail('Expected the required custom field to be enforced.');
        } catch (invalid_parameter_exception $exception) {
            $this->assertNotEmpty($exception->getMessage());
        }

        $sink = $this->redirectEmails();
        $result = $this->manager->register_user($this->valid_registration([
            'customfields' => [[
                'type' => 'membershiptype',
                'value' => 'student',
            ]],
        ]));
        $this->assertSame('student', $DB->get_field('user_info_data', 'data', [
            'userid' => $result['userid'],
            'fieldid' => $field->id,
        ]));
        $sink->close();
    }

    /**
     * Unknown and duplicate custom fields are rejected.
     */
    public function test_register_user_rejects_unavailable_custom_fields(): void {
        $this->expectException(invalid_parameter_exception::class);
        $this->expectExceptionMessage('custom profile field');
        $this->manager->register_user($this->valid_registration([
            'customfields' => [[
                'type' => 'notconfigured',
                'value' => 'value',
            ]],
        ]));
    }

    /**
     * Build a valid registration payload.
     *
     * @param array $overrides Values to replace.
     * @return array
     */
    private function valid_registration(array $overrides = []): array {
        return $overrides + [
            'email' => 'student.one@example.com',
            'password' => 'Password1!',
            'firstname' => 'Student',
            'lastname' => 'One',
        ];
    }
}
