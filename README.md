# Moodle UserKey registration and SSO bridge

[![ci](https://github.com/Al2shwak/moodle-auth_userkey/actions/workflows/ci.yml/badge.svg?branch=MOODLE_502_STABLE)](https://github.com/Al2shwak/moodle-auth_userkey/actions/workflows/ci.yml)

This authentication plugin provides a restricted REST bridge for WordPress registration, Moodle credential
validation, and one-time browser SSO. Moodle remains the owner of user passwords and email confirmation.

Supported Moodle versions: **4.5 through 5.2**.

## Security model

- One restricted Moodle web-service account and one token may call the complete integration service.
- Registration creates an unconfirmed `auth=email` or `auth=manual` account according to the configured registration
  mode. The normalized lowercase email is both the username and email address.
- Moodle hashes the password. User-confirmed modes send Moodle's confirmation email; administrator-confirmed mode
  sends no confirmation link to the user. Passwords are never returned by the API.
- Confirmation does not log the browser into Moodle. It redirects the browser to the configured WordPress SSO URL.
- Credential validation uses Moodle's normal authentication and lockout handling, but creates no browser session.
  Both credential validation and login-link generation enforce the configured authentication-method allowlist.
- One-time login links are issued only by immutable Moodle user ID. The request cannot create or edit a user or
  change an authentication method.
- Guests, deleted, suspended, unconfirmed, `nologin`, and site-administrator accounts cannot receive UserKey links.
  A correct password for a user-confirmed pending account resends Moodle's confirmation email without creating a
  login session.
- WordPress must keep the Moodle token server-side and use HTTPS for every request.

Registration and payment are independent. WordPress may begin checkout immediately with the returned `userid`,
and may add an unconfirmed user to a paid cohort. WordPress must require both account confirmation and active payment
before requesting and sending the browser through a UserKey login URL.

## Installation

1. Build or download the release ZIP. Its top-level directory must be `userkey`.
2. In Moodle, install it through **Site administration > Plugins > Install plugins**, or extract it to
   `auth/userkey` and run the Moodle upgrade.
3. Under **Manage authentication**, enable the **User key authentication** and **Email-based self-registration**
   authentication methods (open their eye icons).
4. In that same page, keep the **Self registration** dropdown set to **Disable**. Enabling the email authentication
   method does not require making Moodle's public registration form available.
5. Configure Moodle outbound email and disable duplicate email addresses.
6. In the UserKey settings, choose **Registration authentication and confirmation**. The recommended default is
   **Email-based — user confirms by email**. Keep **Allowed authentication methods for SSO** set to `manual` and
   `email` unless a different password-capable Moodle method has been deliberately tested. Configure the key lifetime
   and the WordPress/Avada login page as **URL of SSO host**. Configure logout and redirect hosts if needed.
7. Enable REST under **Advanced features** and **Manage protocols**.

## Service account and token

The plugin installs the restricted service **User key authentication web service** with shortname
`auth_userkey`. Add one dedicated, non-administrator service user and create one token for that service.

Create a system role with no archetype and grant only:

- `auth/userkey:registeruser`
- `auth/userkey:authenticate`
- `auth/userkey:resetpassword`
- `auth/userkey:generatekey`
- `moodle/cohort:view`
- `moodle/cohort:assign`
- `moodle/user:viewdetails`
- `moodle/course:useremail`
- the REST protocol capability required by your Moodle configuration

Assign the role to the service user in the system context. The plugin capabilities intentionally have no default
role archetypes.

The service contains:

| Function | Purpose |
| --- | --- |
| `auth_userkey_get_registration_fields` | Password policy text and signup-enabled profile field metadata |
| `auth_userkey_register_user` | Create an unconfirmed account using the configured registration mode |
| `auth_userkey_authenticate_user` | Validate Moodle credentials and return immutable identity |
| `auth_userkey_request_password_reset` | Ask Moodle to send its native password-reset email |
| `auth_userkey_request_login_url` | Create a one-time browser SSO URL for a Moodle user ID |
| `core_user_get_users_by_field` | Retrieve a returning user's permitted Moodle profile fields by immutable ID |
| `core_cohort_get_cohorts` | List cohorts visible to the service account |
| `core_cohort_add_cohort_members` | Activate paid cohort access |
| `core_cohort_delete_cohort_members` | Revoke paid cohort access |
| `core_webservice_get_site_info` | Validate the token and integration |

## REST requests

POST requests use:

```text
https://moodle.example.com/webservice/rest/server.php
```

Include `wstoken=SERVER_SIDE_TOKEN`, `moodlewsrestformat=json`, and the relevant `wsfunction` in every request.
The examples below show form-encoded field names; JSON response bodies are shown beneath them.

### Retrieve a returning user's profile

Call this only with a Moodle user ID returned by successful authentication or held in a protected server-side
session. Never accept the ID from an unsigned browser request.

```text
wsfunction=core_user_get_users_by_field
field=id
values[0]=123
```

Moodle returns an array of matching profiles. WordPress must require exactly one result whose `id` equals the
requested ID. Profile fields are filtered by Moodle permissions, so it must also require `email`, `firstname`, and
`lastname` before continuing. The core response may include additional fields and does not include a `deleted`
field; do not treat the absence of `deleted` as an account-status assertion.

### Discover registration fields

```text
wsfunction=auth_userkey_get_registration_fields
```

```json
{
  "passwordpolicy": "Password policy description from Moodle",
  "customfields": [
    {
      "type": "membershiptype",
      "name": "Membership type",
      "datatype": "text",
      "required": true,
      "locked": false,
      "forceunique": false,
      "defaultvalue": "",
      "settings": [
        {"name": "param1", "value": "30"},
        {"name": "param2", "value": "2048"}
      ]
    }
  ]
}
```

WordPress should call this during configuration and render only fields returned by Moodle. Custom fields that are
not both visible and enabled for signup are rejected by registration.

### Register

```text
wsfunction=auth_userkey_register_user
user[email]=student@example.com
user[password]=the plaintext password over HTTPS
user[firstname]=Student
user[lastname]=Example
user[city]=Kuwait City
user[country]=KW
user[customfields][0][type]=membershiptype
user[customfields][0][value]=student
```

`city`, `country`, and `customfields` are optional unless Moodle profile-field configuration makes a custom field
required.

```json
{
  "userid": 123,
  "username": "student@example.com",
  "confirmationrequired": true,
  "authmethod": "email",
  "confirmationmethod": "email"
}
```

Store `userid` only in WordPress's server-side registration/payment context. Do not store or log the password.
The response identifies the actual Moodle authentication method and whether confirmation belongs to the user or an
administrator. In a user-confirmed mode, Moodle sends the confirmation message. Its link confirms the user and
returns the browser to the configured SSO URL with `emailconfirmed=1`; it does not log the user into Moodle.
The query parameter is only a user-interface notification. WordPress must never trust it as proof of confirmation;
it must validate the user's credentials successfully before requesting a one-time login URL.

Registration modes affect only accounts created after the setting is saved:

- **Email-based — user confirms by email:** creates `auth=email`, sends a confirmation link, and is the default.
- **Email-based — administrator confirms in Moodle:** creates `auth=email` without sending a confirmation link. An
  administrator confirms the pending account under **Site administration > Users > Accounts > Browse list of users**.
- **Manual — user confirms by email:** creates `auth=manual` and sends a confirmation link through this plugin.

All three modes create an initially unconfirmed account, so registration alone never permits authentication or SSO.
Administrator confirmation does not itself prove that the registrant controls the supplied email address. Use that
mode only when administrators have a separate identity-verification process before confirming accounts.

### Authenticate

```text
wsfunction=auth_userkey_authenticate_user
identifier=student@example.com
password=the plaintext password over HTTPS
```

The identifier may be the Moodle username or a unique email address. The account's authentication method must be
selected in the plugin allowlist. Every invalid password, unknown user, or ineligible account produces the same
`Invalid login.` error.

```json
{
  "userid": 123,
  "username": "student@example.com"
}
```

If the credentials are correct but the account is still awaiting user email confirmation, Moodle calls its standard
`send_confirmation_email()` function with this plugin's confirmation endpoint and returns an exception containing:

```json
{
  "errorcode": "confirmationrequired",
  "message": "Your email address must be confirmed. Moodle has sent a new confirmation email."
}
```

WordPress should redirect this outcome to its confirmation-instructions page. It must not create a session, request
a UserKey login URL, or continue payment/access routing. If Moodle could not accept the email for delivery, the error
code is `confirmationemailfailed`; WordPress should show a safe retry or support message. Administrator-confirmed
accounts never trigger email and retain the generic invalid-login response. Apply WordPress login rate limits to
prevent repeated valid-password submissions from sending excessive confirmation messages.

### Request a password reset

```text
wsfunction=auth_userkey_request_password_reset
email=student@example.com
```

Moodle sends its native password-reset email when an eligible account exists. WordPress must display the same
message for every request and must not infer account existence from timing or email delivery.

```json
{
  "accepted": true,
  "message": "If an eligible account exists, Moodle will send password-reset instructions."
}
```

The endpoint deliberately returns the same response for unknown, unconfirmed, suspended, unsupported, and
eligible accounts. Following Moodle's native behavior, an unconfirmed email-auth account receives another account
confirmation email instead of a password-reset token. Moodle's normal reset-token lifetime and repeat-request
limits still apply. If Moodle has an alternate forgotten-password URL configured, this endpoint does not bypass it
or send a Moodle reset email.

### Request one-time SSO URL

```text
wsfunction=auth_userkey_request_login_url
user[id]=123
```

If IP restriction is enabled, also send `user[ip]` with the browser's actual IP address.

```json
{
  "loginurl": "https://moodle.example.com/auth/userkey/login.php?key=..."
}
```

Send the browser to the URL immediately. It is a short-lived bearer credential and must never be logged, emailed,
cached, exposed to analytics, or fetched speculatively. It is invalidated after use.

### Cohort access

Retrieve the cohorts available to the service account:

```text
wsfunction=core_cohort_get_cohorts
```

Omit `cohortids` to return all cohorts the service account can view, or request specific cohorts with
`cohortids[0]=42`. Moodle returns each cohort's ID, name, ID number, description, visibility, and custom-field data.
WordPress should store and submit the immutable numeric `id` for membership changes; names and ID numbers can change.
The response can include hidden cohorts, so WordPress must expose only the cohorts intended for its own registration
or product configuration.

Grant access after successful payment:

```text
wsfunction=core_cohort_add_cohort_members
members[0][cohorttype][type]=id
members[0][cohorttype][value]=42
members[0][usertype][type]=id
members[0][usertype][value]=123
```

Revoke access after expiry, cancellation, or refund with:

```text
wsfunction=core_cohort_delete_cohort_members
members[0][cohortid]=42
members[0][userid]=123
```

Payment activation idempotency belongs in WordPress.

## Existing-user migration

This release does not modify existing Moodle accounts. Existing users of an allowed password-capable method can
validate their current Moodle credentials and then use ID-based SSO. The secure default allows `manual` and
confirmed `email` users. Existing `auth=userkey` accounts are deliberately not converted because they may not have
usable Moodle passwords.

Before a later migration, administrators should report and manually review those accounts:

```sql
SELECT id, username, email, confirmed, suspended
  FROM mdl_user
 WHERE auth = 'userkey' AND deleted = 0;
```

Do not change their `auth` field in bulk until a password-setup and ownership-verification flow is ready.

## Production operations

- Keep the Moodle REST token exclusively in server-side WordPress configuration. Never expose it in browser code,
  form markup, logs, support messages, or analytics.
- Use HTTPS for Moodle, WordPress, confirmation links, and every REST call. Keep the one-time key lifetime short.
- Use a dedicated non-administrator service account with only the capabilities listed above. Rotate its token after
  any suspected disclosure and update WordPress immediately.
- Configure and monitor Moodle outbound email. Test registration, confirmation, and password reset after mail or
  DNS changes.
- Apply WordPress-side rate limiting and bot protection to registration, authentication, and password-reset forms.
- Bookmark and test the local Moodle login bypass before enabling the SSO host URL:
  `https://moodle.example.com/login/index.php?enrolkey_skipsso=1`. This suppresses the SSO redirect for that browser
  session, allowing administrators to use Moodle credentials. It bypasses only the redirect, not authentication.
- Restrict access to the local-login bypass URL operationally if desired, but do not treat the parameter itself as
  an access control. Anyone who knows the URL can display the Moodle login form and must still provide valid Moodle
  credentials.
- Back up Moodle before plugin upgrades and verify the integration with `core_webservice_get_site_info` afterward.
- Periodically review pending unconfirmed accounts, the service user's role assignment, enabled authentication
  methods, and the plugin's SSO allowlist.

## Development and release

`build-release.command` creates a reproducible ZIP from the current committed revision under `dist/` and prints
its SHA-256 checksum. It refuses to package uncommitted tracked changes.

The plugin version upgrade removes obsolete `mappingfield`, `createuser`, `createusercohorts`, `updateuser`, and
legacy UserKey profile-lock settings. It does not change any user records.
