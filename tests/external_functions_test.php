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
use auth_userkey\external\authenticate_user;
use auth_userkey\external\get_registration_fields;
use auth_userkey\external\register_user;
use auth_userkey\external\request_password_reset;
use core_external\external_api;
use PHPUnit\Framework\Attributes\CoversClass;
use required_capability_exception;

/**
 * Tests for registration and credential external functions.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(register_user::class)]
#[CoversClass(get_registration_fields::class)]
#[CoversClass(authenticate_user::class)]
#[CoversClass(request_password_reset::class)]
final class external_functions_test extends advanced_testcase {
    /**
     * Enable both Moodle-owned auth plugins while leaving public signup disabled.
     */
    protected function setUp(): void {
        global $CFG;

        parent::setUp();
        $this->resetAfterTest();
        $CFG->auth = 'manual,email,userkey';
        $CFG->registerauth = '';
        $CFG->passwordpolicy = false;
    }

    /**
     * The registration external functions validate and clean their return contracts.
     */
    public function test_registration_external_contract(): void {
        global $DB;

        $this->setAdminUser();
        $sink = $this->redirectEmails();
        $metadata = get_registration_fields::execute();
        $metadata = external_api::clean_returnvalue(get_registration_fields::execute_returns(), $metadata);
        $this->assertArrayHasKey('passwordpolicy', $metadata);
        $this->assertArrayHasKey('customfields', $metadata);

        $result = register_user::execute([
            'email' => 'External.User@Example.com',
            'password' => 'Password1!',
            'firstname' => 'External',
            'lastname' => 'User',
        ]);
        $result = external_api::clean_returnvalue(register_user::execute_returns(), $result);

        $this->assertSame('external.user@example.com', $result['username']);
        $this->assertTrue($result['confirmationrequired']);
        $this->assertSame('email', $result['authmethod']);
        $this->assertSame('email', $result['confirmationmethod']);
        $this->assertEquals(0, $DB->get_field('user', 'confirmed', ['id' => $result['userid']]));
        $sink->close();
    }

    /**
     * Credential validation returns only immutable identity.
     */
    public function test_authentication_external_contract(): void {
        $this->setAdminUser();
        $user = self::getDataGenerator()->create_user([
            'username' => 'externalcredential',
            'password' => 'Password1!',
            'auth' => 'manual',
        ]);

        $result = authenticate_user::execute('externalcredential', 'Password1!');
        $result = external_api::clean_returnvalue(authenticate_user::execute_returns(), $result);

        $this->assertSame((int) $user->id, $result['userid']);
        $this->assertSame('externalcredential', $result['username']);
        $this->assertCount(2, $result);
    }

    /**
     * Password-reset requests send Moodle's native email without revealing account existence.
     */
    public function test_password_reset_external_contract_is_generic(): void {
        global $DB;

        $this->setAdminUser();
        $user = self::getDataGenerator()->create_user([
            'username' => 'resetuser',
            'email' => 'reset.user@example.com',
            'password' => 'Password1!',
            'auth' => 'manual',
        ]);
        $sink = $this->redirectEmails();

        $existing = request_password_reset::execute('RESET.USER@EXAMPLE.COM');
        $existing = external_api::clean_returnvalue(request_password_reset::execute_returns(), $existing);
        $this->assertTrue($existing['accepted']);
        $this->assertCount(1, $sink->get_messages());
        $this->assertTrue($DB->record_exists('user_password_resets', ['userid' => $user->id]));

        $missing = request_password_reset::execute('missing.user@example.com');
        $missing = external_api::clean_returnvalue(request_password_reset::execute_returns(), $missing);
        $this->assertSame($existing, $missing);
        $this->assertCount(1, $sink->get_messages());
        $sink->close();
    }

    /**
     * Unconfirmed accounts receive Moodle's confirmation email without disclosing their state.
     */
    public function test_password_reset_does_not_disclose_ineligible_account_state(): void {
        global $DB;

        $this->setAdminUser();
        $user = self::getDataGenerator()->create_user([
            'username' => 'unconfirmedreset',
            'email' => 'unconfirmed.reset@example.com',
            'auth' => 'email',
        ]);
        $DB->set_field('user', 'confirmed', 0, ['id' => $user->id]);
        $sink = $this->redirectEmails();

        $ineligible = request_password_reset::execute($user->email);
        $missing = request_password_reset::execute('another.missing@example.com');

        $this->assertSame($missing, $ineligible);
        $this->assertCount(1, $sink->get_messages());
        $messages = $sink->get_messages();
        $message = reset($messages);
        $this->assertStringContainsString('/auth/userkey/confirm.php?data=', $message->body);
        $this->assertFalse($DB->record_exists('user_password_resets', ['userid' => $user->id]));
        $sink->close();
    }

    /**
     * Password-reset requests cannot bypass administrator confirmation.
     */
    public function test_password_reset_does_not_bypass_admin_confirmation(): void {
        $this->setAdminUser();
        set_config('registrationmode', registration_manager::MODE_EMAIL_ADMIN, 'auth_userkey');
        $sink = $this->redirectEmails();
        $manager = new registration_manager();
        $result = $manager->register_user([
            'email' => 'admin.confirm@example.com',
            'password' => 'Password1!',
            'firstname' => 'Admin',
            'lastname' => 'Confirm',
        ]);

        $response = request_password_reset::execute($result['username']);

        $this->assertTrue($response['accepted']);
        $this->assertCount(0, $sink->get_messages());
        $sink->close();
    }

    /**
     * Registration and authentication require their dedicated capabilities.
     */
    public function test_external_functions_require_dedicated_capabilities(): void {
        $this->setUser(self::getDataGenerator()->create_user());

        try {
            get_registration_fields::execute();
            $this->fail('Expected registration capability failure.');
        } catch (required_capability_exception $exception) {
            $this->assertNotEmpty($exception->getMessage());
        }

        try {
            request_password_reset::execute('someone@example.com');
            $this->fail('Expected password-reset capability failure.');
        } catch (required_capability_exception $exception) {
            $this->assertNotEmpty($exception->getMessage());
        }

        $this->expectException(required_capability_exception::class);
        authenticate_user::execute('someone', 'Password1!');
    }

    /**
     * Custom capabilities are not granted to any default role archetype.
     */
    public function test_capability_declaration_has_no_archetypes(): void {
        global $CFG;

        $capabilities = [];
        require($CFG->dirroot . '/auth/userkey/db/access.php');

        $this->assertSame([], $capabilities['auth/userkey:registeruser']['archetypes']);
        $this->assertSame([], $capabilities['auth/userkey:authenticate']['archetypes']);
        $this->assertSame([], $capabilities['auth/userkey:generatekey']['archetypes']);
        $this->assertSame([], $capabilities['auth/userkey:resetpassword']['archetypes']);
    }
}
