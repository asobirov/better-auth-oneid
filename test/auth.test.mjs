import assert from 'node:assert/strict';
import { test } from 'node:test';
import { betterAuth } from 'better-auth';
import { genericOAuth } from 'better-auth/plugins/generic-oauth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { oneId } from '../dist/index.js';

const baseURL = 'https://app.example';
const options = {
  clientId: 'test-client', clientSecret: 'test-secret', scope: 'test_system',
  endpoint: 'https://oneid.example/Authorization.do',
  redirectURI: `${baseURL}/api/auth/callback/oneid`,
};
function fixture() {
  const db = { user: [], session: [], account: [], verification: [] };
  const requests = [];
  const auth = betterAuth({
    baseURL, secret: 'synthetic-secret-at-least-thirty-two-characters',
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    account: { accountLinking: { enabled: true, allowDifferentEmails: true, trustedProviders: ["oneid"], disableImplicitLinking: true } },
    plugins: [genericOAuth({ config: [oneId({ ...options, fetch: async (url) => {
      const params = new URL(url).searchParams;
      requests.push(params);
      return Response.json(params.get('grant_type') === 'one_authorization_code'
        ? { access_token: 'test-token' }
        : { user_id: 'test-user', full_name: 'Test User', email: 'untrusted@example.com' });
    }})] })],
    logger: { disabled: true },
  });
  return { auth, db, requests };
}
function cookies(response) {
  return response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
}
async function start(auth, path, data, cookie = '') {
  return auth.handler(new Request(`${baseURL}/api/auth/${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', origin: baseURL, cookie },
    body: JSON.stringify(data),
  }));
}
async function callback(auth, state, cookie) {
  return auth.handler(new Request(`${options.redirectURI}?code=synthetic-code&state=${encodeURIComponent(state)}`, {
    headers: { cookie },
  }));
}
async function authorize(auth, path = 'sign-in/social', cookie = '') {
  const response = await start(auth, path, { provider: 'oneid', callbackURL: `${baseURL}/done` }, cookie);
  assert.equal(response.status, 200, await response.clone().text());
  const url = new URL((await response.json()).url);
  assert.equal(url.searchParams.get('response_type'), 'one_code');
  assert.equal(url.searchParams.get('scope'), options.scope);
  assert.equal(url.searchParams.get('redirect_uri'), options.redirectURI);
  assert.ok(url.searchParams.get('state'));
  assert.ok(!url.searchParams.has('client_secret'));
  assert.ok(!url.searchParams.has('code_challenge'));
  return { state: url.searchParams.get('state'), cookie: [cookie, cookies(response)].filter(Boolean).join('; ') };
}

test('Better Auth signs up and signs in to the same OneID account', async () => {
  const { auth, db, requests } = fixture();
  for (let i = 0; i < 2; i++) {
    const flow = await authorize(auth);
    const response = await callback(auth, flow.state, flow.cookie);
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), `${baseURL}/done`);
    assert.match(cookies(response), /session_token=/);
  }
  assert.equal(db.user.length, 1);
  assert.equal(db.account.length, 1);
  assert.equal(db.account[0].providerId, 'oneid');
  assert.equal(db.account[0].accountId, 'test-user');
  assert.equal(db.user[0].emailVerified, false);
  assert.equal(requests.length, 4);
});

test('Better Auth links OneID to a signed-in user without creating a duplicate', async () => {
  const { auth, db } = fixture();
  const signup = await start(auth, 'sign-up/email', {
    email: 'existing@example.com', password: 'synthetic-password-123', name: 'Existing User',
  });
  assert.equal(signup.status, 200, await signup.clone().text());
  const originalId = db.user[0].id;
  const flow = await authorize(auth, 'link-social', cookies(signup));
  const response = await callback(auth, flow.state, flow.cookie);
  assert.equal(response.headers.get('location'), `${baseURL}/done`);
  assert.equal(db.user.length, 1);
  assert.equal(db.user[0].id, originalId);
  assert.equal(db.user[0].email, 'existing@example.com');
  assert.equal(db.account.find(account => account.providerId === 'oneid')?.userId, originalId);
  const login = await authorize(auth);
  const signedIn = await callback(auth, login.state, login.cookie);
  assert.equal(signedIn.headers.get('location'), `${baseURL}/done`);
  assert.equal(db.user.length, 1);
});

test('invalid state cannot exchange a token or create an account', async () => {
  const { auth, db, requests } = fixture();
  const flow = await authorize(auth);
  const response = await callback(auth, 'tampered-state', flow.cookie);
  assert.equal(response.status, 302);
  assert.notEqual(response.headers.get('location'), `${baseURL}/done`);
  assert.equal(requests.length, 0);
  assert.equal(db.account.length, 0);
});

test('callback replay cannot exchange a second token', async () => {
  const { auth, requests } = fixture();
  const flow = await authorize(auth);
  const first = await callback(auth, flow.state, flow.cookie);
  assert.equal(first.headers.get('location'), `${baseURL}/done`);
  const second = await callback(auth, flow.state, flow.cookie);
  assert.notEqual(second.headers.get('location'), `${baseURL}/done`);
  assert.equal(requests.length, 2);
});

test('OneID contact email never auto-links an existing account', async () => {
  const { auth, db } = fixture();
  await start(auth, 'sign-up/email', {
    email: 'untrusted@example.com', password: 'synthetic-password-123', name: 'Other User',
  });
  const originalId = db.user[0].id;
  const flow = await authorize(auth);
  const response = await callback(auth, flow.state, flow.cookie);
  assert.equal(response.headers.get('location'), `${baseURL}/done`);
  assert.equal(db.user.length, 2);
  assert.notEqual(db.account.find(account => account.providerId === 'oneid').userId, originalId);
});

test('a OneID identity already linked elsewhere cannot be transferred', async () => {
  const { auth, db } = fixture();
  const first = await authorize(auth);
  await callback(auth, first.state, first.cookie);
  const ownerId = db.account[0].userId;
  const signup = await start(auth, 'sign-up/email', {
    email: 'other@example.com', password: 'synthetic-password-123', name: 'Other User',
  });
  const link = await authorize(auth, 'link-social', cookies(signup));
  const response = await callback(auth, link.state, link.cookie);
  assert.notEqual(response.headers.get('location'), `${baseURL}/done`);
  assert.equal(db.account.find(account => account.providerId === 'oneid').userId, ownerId);
});
