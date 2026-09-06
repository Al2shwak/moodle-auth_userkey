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
 * Strings for auth_userkey.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;
$string['accountalreadyexists'] = 'An account already exists for this email address.';
$string['allowedauthmethods'] = 'Allowed authentication methods for SSO';
$string['allowedauthmethods_desc'] = 'Accounts must use one of these enabled authentication methods to validate '
    . 'credentials or receive a one-time login URL. Only methods that implement Moodle password authentication are '
    . 'listed. Manual and email authentication are the recommended defaults. An empty selection denies all accounts.';
$string['allowedredirecthosts'] = 'Allowed redirect hosts';
$string['allowedredirecthosts_desc'] = 'External hosts that users may be redirected to after key-based authentication. '
    . 'Enter host names only, separated by semicolons, commas, or new lines. Leave empty to allow local Moodle URLs only.';
$string['auth_userkeydescription'] = 'Log in to Moodle using one time user key.';
$string['authmethodnotallowed'] = 'This account authentication method is not allowed for SSO.';
$string['confirmationemailfailed'] = 'Your email address must be confirmed, but Moodle could not send the confirmation email.';
$string['confirmationrequired'] = 'Your email address must be confirmed. Moodle has sent a new confirmation email.';
$string['differentuserloggedin'] = 'A different user is already logged in. Log out before using this login link.';
$string['emailauthdisabled'] = 'Email-based authentication is disabled.';
$string['incorrectkeylifetime'] = 'User key lifetime must be a number.';
$string['incorrectlogout'] = 'Incorrect logout request';
$string['incorrectredirecturl'] = 'You should provide valid URL';
$string['incorrectssourl'] = 'You should provide valid URL';
$string['invalidauthentication'] = 'Invalid login.';
$string['invalidcustomfield'] = 'A custom profile field is unknown, duplicated, or unavailable during signup.';
$string['invalidregistrationdata'] = 'The registration data is incomplete or invalid.';
$string['invalidregistrationmode'] = 'The configured registration authentication and confirmation mode is invalid.';
$string['iprestriction'] = 'IP restriction';
$string['iprestriction_desc'] = 'If enabled, a web call has to contain "ip" parameter when requesting login URL.
A user has to have provided IP to be able to use a key to login to LMS.';
$string['ipwhitelist'] = 'Whitelist IP ranges';
$string['ipwhitelist_desc'] = "Ignore IP restrictions if the IP address the token was issued for or the login attempt comes from falls within any of these ranges.
\nThis can happen when some users reach Moodle or the system issuing login tokens via a private network or DMZ.
\nIf the route to either the system issuing tokens or this Moodle is via a private address range then set this value to 10.0.0.0/8;172.16.0.0/12;192.168.0.0/16";
$string['keylifetime'] = 'User key lifetime';
$string['keylifetime_desc'] = 'Lifetime in seconds of each one-time user login key.';
$string['loginnotallowed'] = 'Login is not allowed for this account.';
$string['missingcustomfield'] = 'Required custom profile field "{$a}" is missing.';
$string['noip'] = 'Unable to fetch IP address of client.';
$string['passwordresetrequestaccepted'] = 'If an eligible account exists, Moodle will send password-reset instructions.';
$string['pluginisdisabled'] = 'The userkey authentication plugin is disabled.';
$string['pluginname'] = 'User key authentication';
$string['privacy:metadata:core_userkey'] = 'The one-time login keys created by the UserKey authentication plugin.';
$string['privacy:metadata:preference:confirmationmethod'] = 'Whether this pending account is confirmed by the user or a Moodle administrator.';
$string['redirecterrordetected'] = 'Unsupported redirect to {$a} detected, execution terminated.';
$string['redirecturl'] = 'Logout redirect URL';
$string['redirecturl_desc'] = 'Optionally you can redirect users to this URL after they logged out from LMS.';
$string['registrationauthdisabled'] = 'The selected registration authentication method "{$a}" is disabled.';
$string['registrationmode'] = 'Registration authentication and confirmation';
$string['registrationmode_desc'] = 'Controls the authentication method assigned to newly registered accounts and '
    . 'who confirms them. Existing accounts are not changed. Manual registrations still require email ownership '
    . 'confirmation before login.';
$string['registrationmode_email'] = 'Email-based — user confirms by email';
$string['registrationmode_emailadmin'] = 'Email-based — administrator confirms in Moodle';
$string['registrationmode_manual'] = 'Manual — user confirms by email';
$string['siteadminnotallowed'] = 'Login keys cannot be generated or used for site administrators.';
$string['ssourl'] = 'URL of SSO host';
$string['ssourl_desc'] = 'URL of the SSO host to redirect users to. If defined users will be redirected here on login instead of the Moodle Login page';
$string['userkey:authenticate'] = 'Validate Moodle user credentials';
$string['userkey:generatekey'] = 'Generate login user key';
$string['userkey:registeruser'] = 'Register unconfirmed Moodle users';
$string['userkey:resetpassword'] = 'Request Moodle password-reset emails';
