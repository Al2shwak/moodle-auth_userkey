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

namespace auth_userkey\privacy;

use auth_userkey\core_userkey_manager;
use core_privacy\local\request\approved_contextlist;
use core_privacy\local\request\approved_userlist;
use core_privacy\local\request\userlist;
use core_privacy\local\request\writer;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Tests for the auth_userkey privacy provider.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(provider::class)]
final class provider_test extends \core_privacy\tests\provider_testcase {
    /**
     * Reset Moodle state after each test.
     */
    protected function setUp(): void {
        parent::setUp();
        $this->resetAfterTest();
    }

    /**
     * Create a one-time login key for a user.
     *
     * @param int $userid User ID.
     */
    private function create_login_key(int $userid): void {
        create_user_key(core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT, $userid, $userid);
    }

    /**
     * Confirmation workflow state is included in Moodle privacy exports.
     */
    public function test_export_user_preferences(): void {
        $user = self::getDataGenerator()->create_user();
        set_user_preference('auth_userkey_confirmationmethod', 'admin', $user);

        provider::export_user_preferences($user->id);
        $preferences = writer::with_context(\context_system::instance())->get_user_preferences('auth_userkey');

        $this->assertSame('admin', $preferences->auth_userkey_confirmationmethod->value);
        $this->assertSame(
            get_string('privacy:metadata:preference:confirmationmethod', 'auth_userkey'),
            $preferences->auth_userkey_confirmationmethod->description
        );
    }

    /**
     * One-time keys add the user's context to privacy requests.
     */
    public function test_get_contexts_for_userid(): void {
        $user = self::getDataGenerator()->create_user();
        $this->create_login_key($user->id);

        $contextlist = provider::get_contexts_for_userid($user->id);

        $this->assertEquals([\context_user::instance($user->id)->id], $contextlist->get_contextids());
    }

    /**
     * One-time keys are included in Moodle privacy exports.
     */
    public function test_export_user_data(): void {
        $user = self::getDataGenerator()->create_user();
        $context = \context_user::instance($user->id);
        $this->create_login_key($user->id);

        $this->setUser($user);
        $this->export_context_data_for_user($user->id, $context, 'auth_userkey');
        $data = writer::with_context($context)->get_related_data([], 'userkeys');

        $this->assertCount(1, $data->keys);
        $this->assertSame(
            core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT,
            reset($data->keys)->script
        );
    }

    /**
     * Users with one-time keys are returned only in their user context.
     */
    public function test_get_users_in_context(): void {
        $user = self::getDataGenerator()->create_user();
        $this->create_login_key($user->id);

        $userlist = new userlist(\context_user::instance($user->id), 'auth_userkey');
        provider::get_users_in_context($userlist);
        $this->assertEquals([$user->id], $userlist->get_userids());

        $systemuserlist = new userlist(\context_system::instance(), 'auth_userkey');
        provider::get_users_in_context($systemuserlist);
        $this->assertCount(0, $systemuserlist);
    }

    /**
     * Context deletion removes the plugin's one-time keys.
     */
    public function test_delete_data_for_all_users_in_context(): void {
        global $DB;

        $user = self::getDataGenerator()->create_user();
        $this->create_login_key($user->id);

        provider::delete_data_for_all_users_in_context(\context_user::instance($user->id));

        $this->assertFalse($DB->record_exists('user_private_key', [
            'userid' => $user->id,
            'script' => core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT,
        ]));
    }

    /**
     * Approved context deletion removes keys only for that user.
     */
    public function test_delete_data_for_user(): void {
        global $DB;

        $user = self::getDataGenerator()->create_user();
        $otheruser = self::getDataGenerator()->create_user();
        $this->create_login_key($user->id);
        $this->create_login_key($otheruser->id);
        $contextlist = provider::get_contexts_for_userid($user->id);
        $approved = new approved_contextlist($user, 'auth_userkey', $contextlist->get_contextids());

        provider::delete_data_for_user($approved);

        $this->assertFalse($DB->record_exists('user_private_key', [
            'userid' => $user->id,
            'script' => core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT,
        ]));
        $this->assertTrue($DB->record_exists('user_private_key', [
            'userid' => $otheruser->id,
            'script' => core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT,
        ]));
    }

    /**
     * Approved user-list deletion removes only the listed user's keys.
     */
    public function test_delete_data_for_users(): void {
        global $DB;

        $user = self::getDataGenerator()->create_user();
        $otheruser = self::getDataGenerator()->create_user();
        $this->create_login_key($user->id);
        $this->create_login_key($otheruser->id);
        $context = \context_user::instance($user->id);
        $approved = new approved_userlist($context, 'auth_userkey', [$user->id]);

        provider::delete_data_for_users($approved);

        $this->assertFalse($DB->record_exists('user_private_key', [
            'userid' => $user->id,
            'script' => core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT,
        ]));
        $this->assertTrue($DB->record_exists('user_private_key', [
            'userid' => $otheruser->id,
            'script' => core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT,
        ]));
    }
}
