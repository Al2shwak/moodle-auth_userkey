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
use core_external\external_api;
use invalid_parameter_exception;
use moodle_exception;
use PHPUnit\Framework\Attributes\CoversClass;
use required_capability_exception;
use context_system;
/**
 * Tests for the request login URL external function.
 *
 * @covers \auth_userkey\external\request_login_url
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(request_login_url::class)]
final class externallib_test extends advanced_testcase {
    /**
     * User object.
     *
     * @var $user.
     */
    protected $user = [];

    /**
     * Test that the bundled restricted service has the shortname required by the token endpoint.
     */
    public function test_service_declaration_has_shortname(): void {
        global $CFG;

        $functions = [];
        $services = [];
        require($CFG->dirroot . '/auth/userkey/db/services.php');

        $service = $services['User key authentication web service'];
        $this->assertSame('auth_userkey', $service['shortname']);
        $this->assertSame(1, $service['restrictedusers']);
        $this->assertSame([
            'auth_userkey_request_login_url',
            'core_webservice_get_site_info',
        ], $service['functions']);
    }

    /**
     * Initial set up.
     */
    public function setUp(): void {
        parent::setUp();

        $this->resetAfterTest();

        $user = [];
        $user['username'] = 'username';
        $user['email'] = 'exists@test.com';
        $user['idnumber'] = 'idnumber';
        $this->user = self::getDataGenerator()->create_user($user);
    }

    /**
     * Test call with incorrect required parameter.
     */
    public function test_throwing_plugin_disabled_exception(): void {
        $this->setAdminUser();

        $params = [
            'bla' => 'exists@test.com',
        ];

        $this->expectException(moodle_exception::class);
        $this->expectExceptionMessage('The userkey authentication plugin is disabled.');

        // Simulate the web service server.
        $result = request_login_url::execute($params);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);
    }

    /**
     * Test successful web service calls.
     */
    public function test_successful_webservice_calls(): void {
        global $DB, $CFG;

        $CFG->auth = "userkey";
        $this->setAdminUser();

        // Email.
        $params = [
            'email' => 'exists@test.com',
        ];

        // Simulate the web service server.
        $result = request_login_url::execute($params);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);

        $actualkey = $DB->get_record('user_private_key', ['userid' => $this->user->id]);
        $expectedurl = $CFG->wwwroot . '/auth/userkey/login.php?key=' . $actualkey->value;

        $this->assertTrue(is_array($result));
        $this->assertTrue(key_exists('loginurl', $result));
        $this->assertEquals($expectedurl, $result['loginurl']);

        // Username.
        set_config('mappingfield', 'username', 'auth_userkey');
        $params = [
            'username' => 'username',
        ];

        // Simulate the web service server.
        $result = request_login_url::execute($params);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);

        $actualkey = $DB->get_record('user_private_key', ['userid' => $this->user->id]);
        $expectedurl = $CFG->wwwroot . '/auth/userkey/login.php?key=' . $actualkey->value;

        $this->assertTrue(is_array($result));
        $this->assertTrue(key_exists('loginurl', $result));
        $this->assertEquals($expectedurl, $result['loginurl']);

        // Idnumber.
        set_config('mappingfield', 'idnumber', 'auth_userkey');
        $params = [
            'idnumber' => 'idnumber',
        ];

        // Simulate the web service server.
        $result = request_login_url::execute($params);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);

        $actualkey = $DB->get_record('user_private_key', ['userid' => $this->user->id]);
        $expectedurl = $CFG->wwwroot . '/auth/userkey/login.php?key=' . $actualkey->value;

        $this->assertTrue(is_array($result));
        $this->assertTrue(key_exists('loginurl', $result));
        $this->assertEquals($expectedurl, $result['loginurl']);

        // Database Id.
        set_config('mappingfield', 'id', 'auth_userkey');
        $params = [
            'id' => $this->user->id,
        ];

        // Simulate the web service server.
        $result = request_login_url::execute($params);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);

        $actualkey = $DB->get_record('user_private_key', ['userid' => $this->user->id]);
        $expectedurl = $CFG->wwwroot . '/auth/userkey/login.php?key=' . $actualkey->value;

        $this->assertTrue(is_array($result));
        $this->assertTrue(key_exists('loginurl', $result));
        $this->assertEquals($expectedurl, $result['loginurl']);

        // IP restriction.
        set_config('iprestriction', true, 'auth_userkey');
        set_config('mappingfield', 'idnumber', 'auth_userkey');
        $params = [
            'idnumber' => 'idnumber',
            'ip' => '192.168.1.1',
        ];

        // Simulate the web service server.
        $result = request_login_url::execute($params);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);

        $actualkey = $DB->get_record('user_private_key', ['userid' => $this->user->id]);
        $expectedurl = $CFG->wwwroot . '/auth/userkey/login.php?key=' . $actualkey->value;

        $this->assertTrue(is_array($result));
        $this->assertTrue(key_exists('loginurl', $result));
        $this->assertEquals($expectedurl, $result['loginurl']);
    }

    /**
     * Test call with missing email required parameter.
     */
    public function test_exception_thrown_if_required_parameter_email_is_not_set(): void {
        global $CFG;

        $this->setAdminUser();
        $CFG->auth = "userkey";

        $params = [
            'bla' => 'exists@test.com',
        ];

        $this->expectException(invalid_parameter_exception::class);
        $this->expectExceptionMessage('Missing required key in single structure: email');

        request_login_url::execute($params);
    }

    /**
     * Test call with missing ip required parameter.
     */
    public function test_exception_thrown_if_required_parameter_op_is_not_set(): void {
        global $CFG;

        $this->setAdminUser();
        $CFG->auth = "userkey";

        set_config('iprestriction', true, 'auth_userkey');

        $params = [
            'email' => 'exists@test.com',
        ];

        $this->expectException(invalid_parameter_exception::class);
        $this->expectExceptionMessage('Missing required key in single structure: ip');

        request_login_url::execute($params);
    }

    /**
     * Test that IP restriction rejects a hostname instead of silently treating it as an IP address.
     */
    public function test_exception_thrown_if_ip_is_not_an_address(): void {
        global $CFG;

        $this->setAdminUser();
        $CFG->auth = 'userkey';
        set_config('iprestriction', true, 'auth_userkey');

        $this->expectException(invalid_parameter_exception::class);
        $this->expectExceptionMessage('Invalid parameter value detected (IP address is invalid.)');

        request_login_url::execute([
            'email' => 'exists@test.com',
            'ip' => 'example.com',
        ]);
    }

    /**
     * Test request for a user who is not exist.
     */
    public function test_request_not_existing_user(): void {
        global $CFG;

        $this->setAdminUser();
        $CFG->auth = "userkey";

        $params = [
            'email' => 'notexists@test.com',
        ];

        $this->expectException(invalid_parameter_exception::class);
        $this->expectExceptionMessage('Invalid parameter value detected (User is not exist)');

        // Simulate the web service server.
        $result = request_login_url::execute($params);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);
    }

    /**
     * Test that a login URL is not generated for a suspended user.
     */
    public function test_request_suspended_user(): void {
        global $CFG, $DB;

        $this->setAdminUser();
        $CFG->auth = 'userkey';
        $DB->set_field('user', 'suspended', 1, ['id' => $this->user->id]);

        $this->expectException(invalid_parameter_exception::class);
        $this->expectExceptionMessage('Invalid parameter value detected (User is suspended)');

        request_login_url::execute(['email' => 'exists@test.com']);
    }

    /**
     * Test that a login URL is not generated for an unconfirmed user.
     */
    public function test_request_unconfirmed_user(): void {
        global $CFG, $DB;

        $this->setAdminUser();
        $CFG->auth = 'userkey';
        $DB->set_field('user', 'confirmed', 0, ['id' => $this->user->id]);

        $this->expectException(invalid_parameter_exception::class);
        $this->expectExceptionMessage('Invalid parameter value detected (User is not active)');

        request_login_url::execute(['email' => 'exists@test.com']);
    }

    /**
     * Test that permission exception gets thrown if user doesn't have required permissions.
     */
    public function test_throwing_of_permission_exception(): void {
        global $CFG;

        $this->setUser($this->user);
        $CFG->auth = "userkey";

        $params = [
            'email' => 'notexists@test.com',
        ];

        $this->expectException(required_capability_exception::class);
        $this->expectExceptionMessage('Sorry, but you do not currently have permissions to do that (Generate login user key)');

        // Simulate the web service server.
        $result = request_login_url::execute($params);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);
    }

    /**
     * Test request gets executed correctly if use has required permissions.
     */
    public function test_request_gets_executed_if_user_has_permission(): void {
        global $CFG, $DB;

        $this->setUser($this->user);
        $CFG->auth = "userkey";

        $context = context_system::instance();
        $studentrole = $DB->get_record('role', ['shortname' => 'student'], '*', MUST_EXIST);
        assign_capability('auth/userkey:generatekey', CAP_ALLOW, $studentrole->id, $context->id);
        role_assign($studentrole->id, $this->user->id, $context->id);

        $params = [
            'email' => 'exists@test.com',
        ];

        // Simulate the web service server.
        $result = request_login_url::execute($params);
        $result = external_api::clean_returnvalue(request_login_url::execute_returns(), $result);

        $actualkey = $DB->get_record('user_private_key', ['userid' => $this->user->id]);
        $expectedurl = $CFG->wwwroot . '/auth/userkey/login.php?key=' . $actualkey->value;

        $this->assertTrue(is_array($result));
        $this->assertTrue(key_exists('loginurl', $result));
        $this->assertEquals($expectedurl, $result['loginurl']);
    }
}
