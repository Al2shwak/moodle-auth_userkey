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
 * Upgrade script.
 *
 * @package    auth_userkey
 * @copyright  2018 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/**
 * Upgrade hook.
 *
 * @param string $oldversion Old version of the plugin.
 * @return bool
 */
function xmldb_auth_userkey_upgrade($oldversion) {
    if ($oldversion < 2026090402) {
        // Remove settings belonging to the retired create/update provisioning flow.
        unset_config('mappingfield', 'auth_userkey');
        unset_config('createuser', 'auth_userkey');
        unset_config('createusercohorts', 'auth_userkey');
        unset_config('updateuser', 'auth_userkey');
        foreach ((array) get_config('auth_userkey') as $name => $value) {
            if (str_starts_with($name, 'field_lock_')) {
                unset_config($name, 'auth_userkey');
            }
        }

        upgrade_plugin_savepoint(true, 2026090402, 'auth', 'userkey');
    }

    if ($oldversion < 2026090500) {
        if (get_config('auth_userkey', 'allowedauthmethods') === false) {
            set_config('allowedauthmethods', 'manual,email', 'auth_userkey');
        }

        upgrade_plugin_savepoint(true, 2026090500, 'auth', 'userkey');
    }

    if ($oldversion < 2026090600) {
        if (get_config('auth_userkey', 'registrationmode') === false) {
            set_config('registrationmode', 'email', 'auth_userkey');
        }

        upgrade_plugin_savepoint(true, 2026090600, 'auth', 'userkey');
    }

    return true;
}
