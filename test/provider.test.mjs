import assert from 'node:assert/strict';
import { test } from 'node:test';
import { oneId, OneIdError } from '../dist/index.js';

export const settings = {
  clientId: 'synthetic-client', clientSecret: 'synthetic-secret', scope: 'test_system',
  endpoint: 'https://oneid.example/sso/oauth/Authorization.do',
  redirectURI: 'https://app.example/api/auth/callback/oneid',
};
const profile = { user_id: 'user-123', full_name: 'Test User', email: 'victim@example.com', pin: '12345678901234', pport_no: 'SECRET' };
const json = value => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });

test('legacy exchange uses OneID grants and keeps secrets out of authorization config', async () => {
  const calls = [];
  const provider = oneId({ ...settings, fetch: async (url, init) => {
    calls.push({ url: new URL(url), init });
    return json(calls.length === 1 ? { access_token: 'token', expires_in: 60 } : profile);
  }});
  assert.equal(provider.responseType, 'one_code');
  assert.equal(provider.pkce, false);
  assert.deepEqual(provider.scopes, ['test_system']);
  assert.ok(!provider.authorizationUrl.includes(settings.clientSecret));
  const tokens = await provider.getToken({ code: 'code &+', redirectURI: settings.redirectURI });
  assert.equal(tokens.accessToken, 'token');
  assert.ok(tokens.accessTokenExpiresAt > new Date());
  const user = await provider.getUserInfo(tokens);
  assert.equal(calls[0].url.searchParams.get('grant_type'), 'one_authorization_code');
  assert.equal(calls[0].url.searchParams.get('code'), 'code &+');
  assert.equal(calls[0].url.searchParams.get('client_secret'), settings.clientSecret);
  assert.equal(calls[1].url.searchParams.get('grant_type'), 'one_access_token_identify');
  for (const call of calls) {
    assert.equal(call.init.method, 'POST');
    assert.equal(call.init.redirect, 'error');
    assert.equal(call.init.cache, 'no-store');
    assert.ok(call.init.signal instanceof AbortSignal);
  }
  assert.equal(user.id, profile.user_id);
  assert.equal(user.name, profile.full_name);
  assert.match(user.email, /^[a-f0-9]{64}@oneid\.invalid$/);
  assert.equal(user.emailVerified, false);
  assert.ok(!JSON.stringify(user).includes(profile.pin));
  assert.ok(!JSON.stringify(user).includes(profile.pport_no));
  assert.ok(!JSON.stringify(user).includes(profile.email));
});

test('body transport sends credentials in form body and optionally passes PKCE', async () => {
  const provider = oneId({ ...settings, parameterTransport: 'body', pkce: true, fetch: async (url, init) => {
    assert.equal(new URL(url).search, '');
    assert.equal(init.body.get('client_secret'), settings.clientSecret);
    assert.equal(init.body.get('code_verifier'), 'verifier');
    return json({ access_token: 'token' });
  }});
  await provider.getToken({ code: 'code', redirectURI: settings.redirectURI, codeVerifier: 'verifier' });
});

test('rejects unsafe configuration', () => {
  for (const change of [
    { endpoint: 'http://oneid.example' }, { endpoint: 'https://user:secret@oneid.example' },
    { endpoint: 'https://oneid.example/?secret=x' }, { redirectURI: 'javascript:alert(1)' },
    { clientSecret: '' }, { scope: 'openid profile' }, { timeoutMs: 0 }, { parameterTransport: 'invalid' },
  ]) assert.throws(() => oneId({ ...settings, ...change }), OneIdError);
});

test('rejects callback mismatch and missing tokens without sending requests', async () => {
  const provider = oneId({ ...settings, fetch: async () => { assert.fail('must not fetch'); }});
  await assert.rejects(provider.getToken({ code: 'code', redirectURI: 'https://evil.example' }), OneIdError);
  await assert.rejects(provider.getToken({ code: '', redirectURI: settings.redirectURI }), OneIdError);
  await assert.rejects(provider.getUserInfo({}), OneIdError);
});

test('sanitizes upstream and network failures', async () => {
  for (const fetch of [
    async () => { throw new Error('synthetic-secret leaked'); },
    async () => new Response('synthetic-secret', { status: 500 }),
    async () => new Response('not-json synthetic-secret'),
    async () => json({ error: 'synthetic-secret' }),
    async () => json({ ret_cd: '500', access_token: 'token' }),
    async () => json([]), async () => json({}),
  ]) {
    const provider = oneId({ ...settings, fetch });
    await assert.rejects(provider.getToken({ code: 'code', redirectURI: settings.redirectURI }), error => {
      assert.ok(error instanceof OneIdError);
      assert.ok(!String(error).includes(settings.clientSecret));
      assert.equal(error.cause, undefined);
      return true;
    });
  }
});

test('requires stable user_id and never falls back to PINFL or email', async () => {
  for (const user_id of [undefined, '', 123]) {
    const provider = oneId({ ...settings, fetch: async () => json({ ...profile, user_id }) });
    await assert.rejects(provider.getUserInfo({ accessToken: 'token' }), OneIdError);
  }
});

test('identity remains stable when name or contact email changes', async () => {
  let current = profile;
  const provider = oneId({ ...settings, fetch: async () => json(current) });
  const first = await provider.getUserInfo({ accessToken: 'token' });
  current = { ...profile, full_name: 'Changed', email: 'different@example.com' };
  const second = await provider.getUserInfo({ accessToken: 'token' });
  assert.equal(first.id, second.id);
  assert.equal(first.email, second.email);
});
