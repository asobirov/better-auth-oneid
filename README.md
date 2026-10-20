# better-auth-oneid

An unofficial, community-maintained Uzbekistan OneID provider helper for Better Auth.
Maintained by [asobirov](https://github.com/asobirov). MIT licensed.

**Status: pre-release.** Tested locally against Better Auth 1.7.12 using simulated
OneID responses. No live OneID sandbox or production verification has been performed.
This implements the legacy `Authorization.do` / `one_code` protocol; confirm its
parameters, endpoint, scope, response codes, and PKCE support with your OneID contact
before deployment. This package is not affiliated with OneID or Better Auth.

## Requirements

- Node.js 22 or newer; ESM.
- Better Auth `~1.7.12`. Earlier versions are not currently supported or tested.
- Your own OneID agreement, client ID, client secret, assigned information-system
  scope code, HTTPS endpoint, and registered callback URL.

## Install the experimental prerelease

```sh
npm install better-auth-oneid@next better-auth@~1.7.12
```

Prereleases use the `next` dist-tag and are not production verified. The stable
release remains gated on live OneID sandbox validation.

For local development, run `npm ci && npm pack` in this repository and install the
resulting `.tgz` into your application alongside the supported Better Auth version.

## Server configuration

```ts
import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { oneId } from "better-auth-oneid";

export const auth = betterAuth({
  // Your existing database, baseURL, secret, and social providers.
  account: {
    // Encrypt OAuth tokens stored by Better Auth.
    encryptOAuthTokens: true,
    accountLinking: {
      enabled: true,
      trustedProviders: ["oneid"],
      allowDifferentEmails: true,
      disableImplicitLinking: true,
    },
  },
  plugins: [
    genericOAuth({
      config: [
        oneId({
          clientId: process.env.ONEID_CLIENT_ID!,
          clientSecret: process.env.ONEID_CLIENT_SECRET!,
          scope: process.env.ONEID_SCOPE!,
          endpoint: process.env.ONEID_ENDPOINT!,
          redirectURI: "https://your-app.example/api/auth/callback/oneid",
        }),
      ],
    }),
  ],
});
```

Merge this configuration with your existing settings. Register the exact callback
URL with OneID; change the path if your Better Auth `basePath` differs. Keep all
credentials server-side. There is deliberately no default production or test host.
Use the exact endpoint the operator issues to you.

`scope` is a single assigned information-system code, **not** `openid profile`.
The server exchanges a code with `grant_type=one_authorization_code` and fetches
the profile with `grant_type=one_access_token_identify`. Both requests use POST.
The client ID and client secret are sent as query parameters by default to match
the legacy protocol. Set `parameterTransport: "body"` only if your deployment
accepts form-encoded POST parameters. Redact URL query strings from proxy/APM logs
when using query mode. Redirects are rejected to avoid forwarding credentials.

PKCE defaults to `false` for the legacy protocol. Confirm support with OneID;
set `pkce: true` if supported. Better Auth still generates and validates OAuth
state and binds the callback to the initiating browser. Requests time out after
10 seconds; configure `timeoutMs` to change this.

## Sign in or register

Use your regular Better Auth client; no additional client plugin is required.

```ts
await authClient.signIn.social({
  provider: "oneid",
  callbackURL: "/dashboard",
});
```

Use `disableSignUp: true` to allow only existing linked identities, or
`disableImplicitSignUp: true` to require Better Auth's explicit sign-up flow.

## Connect to an existing profile

Only offer this action to an authenticated user:

```ts
await authClient.linkSocial({
  provider: "oneid",
  callbackURL: "/settings/accounts",
});
```

The server configuration above is necessary for linking: OneID contact email is
not treated as verified. `trustedProviders` permits explicit OneID linking;
`allowDifferentEmails` allows the OneID placeholder to differ from the user's real
email. These are application-wide settings. `disableImplicitLinking` prevents
automatic email-based merging for **all** providers, so users must explicitly link
Google and other methods too. Do not mark the placeholder as verified to bypass
these settings. Linking cannot transfer an identity already owned by another user.

## Email and personal data

Accounts are identified by the stable OneID `user_id`, never by name, phone,
email, or PINFL. Better Auth requires an email for new social sign-ups, so this
helper assigns `sha256(user_id)@oneid.invalid`, with `emailVerified: false`.
It is a deterministic internal identifier, **not a deliverable address**; it is
not an anonymity guarantee. Do not send verification, reset, or notification mail
to it. Collect and verify a real contact email separately in your application.
If your app requires email verification before all sign-ins, design that onboarding
step explicitly; OneID cannot verify this placeholder email.

Only `id`, `name`, the placeholder `email`, and `emailVerified` are returned.
Passport, PINFL, address, phone, legal entities, and provider contact email are
not forwarded to Better Auth or persisted by this helper. The package does not
assign KYC status or claim that every OneID account has the same assurance level.
Any identity-verification records belong in the application under an explicit
consent, retention, and assurance policy.

Refresh tokens are intentionally not retained or supported. Authenticate through
OneID again if fresh provider data or another provider authorization is needed;
normal Better Auth sessions are managed independently.

## Development

```sh
npm ci
npm run typecheck
npm test
npm pack --dry-run
```

Tests exercise protocol parameters, profile minimization, errors, Better Auth
sign-up/sign-in, explicit linking, account ownership, invalid state, and callback
replay with synthetic responses. They do not demonstrate live OneID compatibility.
No React code is included; React Doctor is not applicable.

## References

- [OneID service and onboarding](https://uztech.egov.uz/ru/projects/oneid)
- [Better Auth Generic OAuth](https://better-auth.com/docs/plugins/generic-oauth)
- [Better Auth community provider helpers](https://better-auth.com/docs/authentication/other-social-providers)
- [Legacy protocol reference](https://github.com/begyy/id.egov.uz/blob/master/one_id/one_id.py)

The legacy reference is community code, not an operator-issued specification.
Live sandbox testing against the issued specification is a release prerequisite.

## Security reports

Report vulnerabilities privately through GitHub's security reporting feature;
do not include credentials, tokens, or personal data in public issues.
