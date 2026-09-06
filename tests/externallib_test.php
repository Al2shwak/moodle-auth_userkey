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
use auth_userkey\external\request_login_url;
use context_system;
use core_external\external_api;
use invalid_parameter_exception;
use moodle_exception;
use PHPUnit\Framework\Attributes\CoversClass;
use required_capability_exception;

/**
 * Tests for the login URL service contract.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(request_login_url::class)]
final class externallib_test extends advanced_testcase {
    /**
     * Enable the plugin and reset database state.
     */
    protected function setUp(): void {
        global $CFG;

        parent::setUp();
        $this->resetAfterTest();
        $CFG->auth = 'manual,email,userkey';
    }

    /**
     * The prebuilt service must contain the complete one-token integration contract.
     */
    public function test_service_declaration_is_complete(): void {
        global $CFG;

        $functions = [];
        $services = [];
        require($CFG->dirroot . '/auth/userkey/db/services.php');

        $service = $services['User key authentication web service'];
        $this->assertSame('auth_userkey', $service['shortname']);
        $this->assertSame(1, $service['restrictedusers']);
        $this->assertSame([
            'auth_userkey_get_registration_fields',
            'auth_userkey_register_user',
            'auth_userkey_authenticate_user',
            'auth_userkey_request_password_reset',
            'auth_userkey_request_login_url',
            'core_cohort_get_cohorts',
            'core_cohort_add_cohort_members',
            'core_cohort_delete_cohort_members',
            'core_webservice_get_site_info',
        ], $service['functions']);
    }

    /**
     * A fixed Moodle user ID produces a one-time URL.
     */
    public function test_request_login_url_uses_fixed_user_id(): void {
        global $CFG, $DB;

        $this->setAdminUser();
        $user = self::getDataGenerator()->create_user([
            'username' => 'unchanged',
            'email' => 'unchanged@example.com',
            'auth' => 'manual',
        ]);

        $result = request_login_url::execute(['id' => $user->id]);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);

        $key = $DB->get_record('user_private_key', ['userid' => $user->id], '*', MUST_EXIST);
        $this->assertSame($CFG->wwwroot . '/auth/userkey/login.php?key=' . $key->value, $result['loginurl']);
        $stored = $DB->get_record('user', ['id' => $user->id], '*', MUST_EXIST);
        $this->assertSame('unchanged', $stored->username);
        $this->assertSame('unchanged@example.com', $stored->email);
        $this->assertSame('manual', $stored->auth);
    }

    /**
     * Mutable identity fields are not part of the endpoint schema.
     */
    public function test_request_login_url_rejects_mutable_identity_fields(): void {
        $this->setAdminUser();
        $user = self::getDataGenerator()->create_user();

        $this->expectException(invalid_parameter_exception::class);
        request_login_url::execute([
            'id' => $user->id,
            'email' => 'attacker@example.com',
        ]);
    }

    /**
     * IP restriction makes the browser IP mandatory.
     */
    public function test_request_login_url_requires_valid_ip_when_enabled(): void {
        $this->setAdminUser();
        $user = self::getDataGenerator()->create_user();
        set_config('iprestriction', true, 'auth_userkey');

        $this->expectException(invalid_parameter_exception::class);
        request_login_url::execute(['id' => $user->id]);
    }

    /**
     * The external function enforces its dedicated capability.
     */
    public function test_request_login_url_requires_capability(): void {
        $caller = self::getDataGenerator()->create_user();
        $target = self::getDataGenerator()->create_user();
        $this->setUser($caller);

        $this->expectException(required_capability_exception::class);
        request_login_url::execute(['id' => $target->id]);
    }

    /**
     * The external function is available to an explicitly granted service role.
     */
    public function test_request_login_url_accepts_explicit_capability(): void {
        $caller = self::getDataGenerator()->create_user();
        $target = self::getDataGenerator()->create_user();
        $roleid = self::getDataGenerator()->create_role();
        assign_capability('auth/userkey:generatekey', CAP_ALLOW, $roleid, context_system::instance());
        role_assign($roleid, $caller->id, context_system::instance());
        accesslib_clear_all_caches_for_unit_testing();
        $this->setUser($caller);

        $result = request_login_url::execute(['id' => $target->id]);
        $this->assertArrayHasKey('loginurl', $result);
    }

    /**
     * Disabled plugins reject service requests.
     */
    public function test_disabled_plugin_is_rejected(): void {
        global $CFG;

        $CFG->auth = 'manual,email';
        $this->setAdminUser();

        $this->expectException(moodle_exception::class);
        $this->expectExceptionMessage('The userkey authentication plugin is disabled.');
        request_login_url::execute(['id' => 123]);
    }
}
