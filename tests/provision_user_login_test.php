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
use auth_userkey\external\provision_user_login;
use context_system;
use core_external\external_api;
use invalid_parameter_exception;
use PHPUnit\Framework\Attributes\CoversClass;
use required_capability_exception;

/**
 * Tests for the combined user provisioning and login external function.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(provision_user_login::class)]
final class provision_user_login_test extends advanced_testcase {
    /**
     * Enable the authentication plugin for each test.
     */
    protected function setUp(): void {
        global $CFG;

        parent::setUp();
        $this->resetAfterTest();
        $CFG->auth = 'userkey';
    }

    /**
     * Test that an authorised caller can create a user and receive their login URL.
     */
    public function test_provisions_user_and_returns_login_url(): void {
        global $CFG, $DB;

        $this->setAdminUser();
        set_config('createuser', true, 'auth_userkey');
        $field = self::getDataGenerator()->create_custom_profile_field([
            'datatype' => 'text',
            'shortname' => 'studenttype',
            'name' => 'Student type',
        ]);

        $result = provision_user_login::execute([
            'username' => 'provisioneduser',
            'email' => 'provisioned@example.com',
            'firstname' => 'Provisioned',
            'lastname' => 'User',
            'customfields' => [
                ['type' => 'studenttype', 'value' => 'remote'],
            ],
        ]);
        $result = external_api::clean_returnvalue(provision_user_login::execute_returns(), $result);

        $user = $DB->get_record('user', ['username' => 'provisioneduser'], '*', MUST_EXIST);
        $key = $DB->get_record('user_private_key', ['userid' => $user->id], '*', MUST_EXIST);
        $this->assertSame('userkey', $user->auth);
        $this->assertEquals(1, $user->confirmed);
        $this->assertSame($CFG->wwwroot . '/auth/userkey/login.php?key=' . $key->value, $result['loginurl']);
        $this->assertSame('remote', $DB->get_field('user_info_data', 'data', [
            'userid' => $user->id,
            'fieldid' => $field->id,
        ], MUST_EXIST));
    }

    /**
     * Test that the new capability is required in addition to key generation.
     */
    public function test_requires_create_user_capability(): void {
        global $DB;

        $serviceuser = self::getDataGenerator()->create_user();
        $roleid = create_role('User key login service', 'userkeyloginservice', '');
        $context = context_system::instance();
        assign_capability('auth/userkey:generatekey', CAP_ALLOW, $roleid, $context->id);
        role_assign($roleid, $serviceuser->id, $context->id);
        $this->setUser($serviceuser);
        set_config('createuser', true, 'auth_userkey');

        $this->expectException(required_capability_exception::class);

        provision_user_login::execute([
            'username' => 'notauthorised',
            'email' => 'notauthorised@example.com',
            'firstname' => 'Not',
            'lastname' => 'Authorised',
        ]);
    }

    /**
     * Test that the administrator setting remains an independent creation control.
     */
    public function test_rejects_creation_when_disabled(): void {
        $this->setAdminUser();
        set_config('createuser', false, 'auth_userkey');

        $this->expectException(invalid_parameter_exception::class);
        $this->expectExceptionMessage(get_string('usercreationdisabled', 'auth_userkey'));

        provision_user_login::execute([
            'username' => 'creationdisabled',
            'email' => 'creationdisabled@example.com',
            'firstname' => 'Creation',
            'lastname' => 'Disabled',
        ]);
    }

    /**
     * Test that provisioning cannot turn an existing identity into a login request.
     */
    public function test_rejects_existing_user(): void {
        $this->setAdminUser();
        set_config('createuser', true, 'auth_userkey');
        self::getDataGenerator()->create_user([
            'username' => 'existingprovisioned',
            'email' => 'existingprovisioned@example.com',
        ]);

        $this->expectException(invalid_parameter_exception::class);

        provision_user_login::execute([
            'username' => 'differentusername',
            'email' => 'existingprovisioned@example.com',
            'firstname' => 'Existing',
            'lastname' => 'User',
        ]);
    }
}
