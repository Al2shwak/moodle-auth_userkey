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
 * Privacy provider.
 *
 * @package   auth_userkey
 * @author    Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @copyright 2020 Catalyst IT
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_userkey\privacy;

use auth_userkey\core_userkey_manager;
use core_privacy\local\request\approved_contextlist;
use core_privacy\local\request\approved_userlist;
use core_privacy\local\metadata\collection;
use core_privacy\local\metadata\provider as metadata_provider;
use core_privacy\local\request\contextlist;
use core_privacy\local\request\core_userlist_provider;
use core_privacy\local\request\plugin\provider as plugin_provider;
use core_privacy\local\request\userlist;
use core_privacy\local\request\user_preference_provider;
use core_privacy\local\request\writer;

/**
 * Privacy provider.
 *
 * @copyright  2020 Catalyst IT
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class provider implements core_userlist_provider, metadata_provider, plugin_provider, user_preference_provider {
    /**
     * Describe the confirmation workflow preference stored for pending users.
     *
     * @param collection $collection Privacy metadata collection.
     * @return collection
     */
    public static function get_metadata(collection $collection): collection {
        $collection->add_user_preference(
            'auth_userkey_confirmationmethod',
            'privacy:metadata:preference:confirmationmethod'
        );
        $collection->add_subsystem_link('core_userkey', [], 'privacy:metadata:core_userkey');
        return $collection;
    }

    /**
     * Get the user contexts containing one-time login keys.
     *
     * @param int $userid User ID.
     * @return contextlist
     */
    public static function get_contexts_for_userid(int $userid): contextlist {
        $sql = "SELECT ctx.id
                  FROM {user_private_key} k
                  JOIN {user} u ON k.userid = u.id
                  JOIN {context} ctx ON ctx.instanceid = u.id AND ctx.contextlevel = :contextlevel
                 WHERE k.userid = :userid AND k.script = :script";
        $params = [
            'userid' => $userid,
            'contextlevel' => CONTEXT_USER,
            'script' => core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT,
        ];

        $contextlist = new contextlist();
        $contextlist->add_from_sql($sql, $params);
        return $contextlist;
    }

    /**
     * Add users with one-time login keys in the supplied context.
     *
     * @param userlist $userlist User list to populate.
     */
    public static function get_users_in_context(userlist $userlist) {
        $context = $userlist->get_context();
        if (!$context instanceof \context_user) {
            return;
        }

        \core_userkey\privacy\provider::get_user_contexts_with_script(
            $userlist,
            $context,
            core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT
        );
    }

    /**
     * Export one-time login keys for the approved user context.
     *
     * @param approved_contextlist $contextlist Approved contexts.
     */
    public static function export_user_data(approved_contextlist $contextlist) {
        $contexts = $contextlist->get_contexts();
        if (count($contexts) === 0) {
            return;
        }

        $context = reset($contexts);
        if ($context->contextlevel !== CONTEXT_USER) {
            return;
        }

        \core_userkey\privacy\provider::export_userkeys(
            $context,
            [],
            core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT
        );
    }

    /**
     * Delete all one-time login keys in a user context.
     *
     * @param \context $context Context to delete from.
     */
    public static function delete_data_for_all_users_in_context(\context $context) {
        if ($context->contextlevel !== CONTEXT_USER) {
            return;
        }

        self::delete_userkeys($context->instanceid);
    }

    /**
     * Delete one-time login keys for users in an approved list.
     *
     * @param approved_userlist $userlist Approved users.
     */
    public static function delete_data_for_users(approved_userlist $userlist) {
        $context = $userlist->get_context();
        if ($context instanceof \context_user && in_array($context->instanceid, $userlist->get_userids())) {
            self::delete_userkeys($context->instanceid);
        }
    }

    /**
     * Delete one-time login keys for the approved user contexts.
     *
     * @param approved_contextlist $contextlist Approved contexts.
     */
    public static function delete_data_for_user(approved_contextlist $contextlist) {
        foreach ($contextlist->get_contexts() as $context) {
            if ($context->contextlevel === CONTEXT_USER && $context->instanceid == $contextlist->get_user()->id) {
                self::delete_userkeys($context->instanceid);
            }
        }
    }

    /**
     * Export the confirmation workflow preference for a user.
     *
     * @param int $userid User ID.
     */
    public static function export_user_preferences(int $userid) {
        $confirmationmethod = get_user_preferences('auth_userkey_confirmationmethod', null, $userid);
        if ($confirmationmethod !== null) {
            writer::export_user_preference(
                'auth_userkey',
                'auth_userkey_confirmationmethod',
                $confirmationmethod,
                get_string('privacy:metadata:preference:confirmationmethod', 'auth_userkey')
            );
        }
    }

    /**
     * Delete all one-time login keys owned by a user.
     *
     * @param int $userid User ID.
     */
    private static function delete_userkeys(int $userid): void {
        \core_userkey\privacy\provider::delete_userkeys(
            core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT,
            $userid
        );
    }
}
