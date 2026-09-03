<a href="https://github.com/Al2shwak/moodle-auth_userkey/actions/workflows/ci.yml?query=branch%3AMOODLE_502_STABLE">
<img src="https://github.com/Al2shwak/moodle-auth_userkey/actions/workflows/ci.yml/badge.svg?branch=MOODLE_502_STABLE">
</a>

Log in to Moodle using one time user key.
=========================================

Auth plugin for organising simple one way SSO(single sign on) between moodle and your external web
application. The main idea is to make a web call to moodle and provide one of the possible matching
fields to find required user and generate one time login URL. A user can be redirected to this
URL to be log in to Moodle without typing username and password.

# Versions and branches

| Moodle Version   | Branch            |
|------------------|-------------------|
| Moodle 4.5 - 5.2 | MOODLE_502_STABLE |
| Moodle 3.3 - 4.1 | MOODLE_33PLUS     |

Using
-----
1. Install the plugin as usual.
2. Enable the userkey authentication plugin (Site administration -> Plugins -> Authentication and then enable User key).
3. Configure the plugin. Set the mapping field, user key lifetime, IP restriction, and redirect settings.
4. Enable the web services advanced feature (Site administration > General > Advanced features). See [Web services](https://docs.moodle.org/en/Web_services).
5. Enable one of the supported protocols (Site administration > Server > Web services > Manage protocols).
6. Create a token for a specific user and for the service 'User key authentication web service' (Site administration > Server > Web services > Manage tokens).
7. Make sure that the web service user has the `auth/userkey:generatekey` capability.
8. Authorise the web service user (Site administration > Server > Web services > External services > Authorised users).
9. Configure your external application to request a login URL.
10. Redirect the user to the returned URL.

The `auth/userkey:generatekey` capability permits impersonating any eligible Moodle user, including
privileged non-administrator accounts. Site administrators are excluded from key-based login and must use
another configured Moodle authentication method. Grant this capability only to a dedicated, tightly controlled
web-service account and protect its token as a privileged credential.

Configuration
-------------

**Mapping field**

Required data structure for web call is related to mapping field you configured.

For example XML-RPC (PHP structure) description for different mapping field settings:

***User name***

    [user] =>
        Array
            (
            [username] => string
            )

***Email Address***

    [user] =>
        Array
            (
            [email] => string
            )

***ID number***

    [user] =>
        Array
            (
            [idnumber] => string
            )

***Database Id***

    [user] =>
        Array
            (
            [id] => int
            )

***Web service will return following structure or standard Moodle webservice error message.***

    Array
        (
        [loginurl] => string
        )

Please navigate to API documentation to get full description for "auth_userkey_request_login_url" function.
e.g. http://yourmoodle.com/admin/webservice/documentation.php

You can amend login URL by "wantsurl" parameter to redirect user after they logged in to Moodle.

E.g. http://yourmoodle.com/auth/userkey/login.php?key=uniquekey&wantsurl=http://yourmoodle.com/course/view.php?id=3

The `wantsurl` parameter may point to a local Moodle URL. External HTTP(S) URLs are accepted only when their host is explicitly listed in the **Allowed redirect hosts** setting. Multiple hosts may be separated by semicolons, commas, or new lines. Enter host names without a protocol or path, for example `portal.example.com;app.example.org`.

An invalid or unapproved destination falls back to the Moodle site URL.

**Update existing users**

When enabled, profile fields supplied by the external service are applied to an existing user and that user's
authentication method is changed to **User key authentication**. This can be used as part of an intentional
account migration. Site administrators are excluded from this process and continue to use their existing Moodle
authentication method.

**Cohorts for newly created users**

When **Create user?** is enabled, the plugin can add each account it creates to one or more selected Moodle
cohorts. This applies only at account creation; requesting a key for an existing user or updating an existing
user does not change their cohort memberships. Deleted cohorts left in an older saved configuration are skipped.

Adding a user to a cohort can also enrol that user into courses configured with Moodle's cohort sync enrolment
method. Treat this setting as part of the access granted to accounts created through the SSO web service.


**User key life time**

This setting describes for how long a user key will be valid. If you try to use expired key then you will
get an error.

**IP restriction**

If this setting is set to yes, then your web application has to provie user's ip address to generate a user key. Then
the user should have provided ip when using this key. If ip address is different a user will get an error.

**Redirect after logout from Moodle**

You can set URL to redirect users after they logged out from Moodle. For example you can redirect them
to logout script of your web application to log users out from it as well. This setting is optional.

**URL of SSO host**

You can set URL to redirect users before they see Moodle login page. For example you can redirect them
to your web application to login page. You can use "enrolkey_skipsso" URL parameter to bypass this option.
E.g. http://yourmoodle.com/login/index.php?enrolkey_skipsso=1

**Logout URL**

To log out a userkey-authenticated session through the plugin endpoint, send the user to the logout script
with the required local `return` URL and the current Moodle `sesskey` CSRF token.

E.g. http://yourmoodle.com/auth/userkey/logout.php?return=/login/index.php&sesskey=users-session-key


Users will be logged out from Moodle and then redirected to the provided local Moodle URL. A logged-in
user is not logged out when the `sesskey` is missing or invalid.
In case when a user session is already expired, the user will be still redirected.


**Example client**

**Note:** the code below is not for production use. It's just a quick and dirty way to test the functionality.

The code below defines a function that can be used to obtain a login url.
You will need to add/remove parameters depending on whether you have update/create user enabled and which mapping field you are using.

The required library curl can be obtained from https://github.com/moodlehq/sample-ws-clients
```php
/**
 * @param   string $useremail Email address of user to create token for.
 * @param   string $firstname First name of user (used to update/create user).
 * @param   string $lastname Last name of user (used to update/create user).
 * @param   string $username Username of user (used to update/create user).
 * @param   string $ipaddress IP address of end user that login request will come from (probably $_SERVER['REMOTE_ADDR']).
 * @param int      $courseid Course id to send logged in users to, defaults to site home.
 * @param int      $modname Name of course module to send users to, defaults to none.
 * @param int      $activityid cmid to send logged in users to, defaults to site home.
 * @return bool|string
 */
function getloginurl($useremail, $firstname, $lastname, $username, $courseid = null, $modname = null, $activityid = null) {
    require_once('curl.php');

    $token        = 'YOUR_TOKEN';
    $domainname   = 'http://MOODLE_WWW_ROOT';
    $functionname = 'auth_userkey_request_login_url';

    $param = [
        'user' => [
            'firstname' => $firstname, // You will not need this parameter, if you are not creating/updating users
            'lastname'  => $lastname, // You will not need this parameter, if you are not creating/updating users
            'username'  => $username,
            'email'     => $useremail,
        ]
    ];

    $serverurl = $domainname . '/webservice/rest/server.php' . '?wstoken=' . $token . '&wsfunction=' . $functionname . '&moodlewsrestformat=json';
    $curl = new curl; // The required library curl can be obtained from https://github.com/moodlehq/sample-ws-clients

    try {
        $resp     = $curl->post($serverurl, $param);
        $resp     = json_decode($resp);
        if ($resp && !empty($resp->loginurl)) {
            $loginurl = $resp->loginurl;
        }
    } catch (Exception $ex) {
        return false;
    }

    if (!isset($loginurl)) {
        return false;
    }

    $path = '';
    if (isset($courseid)) {
        $path = '&wantsurl=' . urlencode("$domainname/course/view.php?id=$courseid");
    }
    if (isset($modname) && isset($activityid)) {
        $path = '&wantsurl=' . urlencode("$domainname/mod/$modname/view.php?id=$activityid");
    }

    return $loginurl . $path;
}

echo getloginurl('barrywhite@googlemail.com', 'barry', 'white', 'barrywhite', 2, 'certificate', 8);
```


# Crafted by Catalyst IT

This plugin was developed by Catalyst IT Australia:

https://www.catalyst-au.net/

![Catalyst IT](/pix/catalyst-logo.png?raw=true)

# Contributing and Support

Issues, and pull requests using github are welcome and encouraged!

https://github.com/catalyst/moodle-auth_userkey/issues

If you would like commercial support or would like to sponsor additional improvements
to this plugin please contact us:

https://www.catalyst-au.net/contact-us
