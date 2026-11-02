import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs, { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { publishPair, readPair, withIssuanceLock } from '../scripts/github-app-auth-core.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const issuer = join(root, 'scripts', 'github-app-auth.mjs');
const wrapper = join(root, 'scripts', 'gh-app.mjs');
// Deliberately invalid credentials, used only by the local API fixture.
const TOKEN = 'invalid-fixture-installation-token-0123456789';
const NEXT_TOKEN = 'invalid-fixture-rotated-token-9876543210';
const permissions = { contents: 'write', issues: 'write', pull_requests: 'write', checks: 'read', statuses: 'read', metadata: 'read' };
const keys = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
const hash = value => createHash('sha256').update(value).digest('hex');

// A native Node executable plus command entry files is a portable fake gh:
// Windows needs neither a shell/.cmd launcher nor an executable-bit workaround.
// Only the external GitHub boundary is simulated; signing and file checks are real.
const fakeGh = String.raw`
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const args = [path.basename(process.argv[1]), ...process.argv.slice(2)];
const scenario = process.env.FIXTURE_SCENARIO || '';
const endpoint = args.find(a => a.startsWith('/'));
const token = process.env.GH_TOKEN || '';
const expected = scenario === 'rotate' ? 'invalid-fixture-rotated-token-9876543210' : 'invalid-fixture-installation-token-0123456789';
let jwtValid = false, claims;
if (token.split('.').length === 3) {
  const [header, payload, signature] = token.split('.');
  claims = JSON.parse(Buffer.from(payload, 'base64url'));
  jwtValid = JSON.parse(Buffer.from(header, 'base64url')).alg === 'RS256' &&
    crypto.verify('RSA-SHA256', Buffer.from(header + '.' + payload), fs.readFileSync(process.env.FIXTURE_PUBLIC_KEY), Buffer.from(signature, 'base64url'));
}
const input = args.includes('--input') ? fs.readFileSync(0, 'utf8') : '';
const config = process.env.GH_CONFIG_DIR;
const record = { args, endpoint, body: input ? JSON.parse(input) : null, jwtValid, claims,
  tokenValid: token === expected, argvContainsCredential: args.some(a => a.includes(token) && token),
  config, configEmpty: !!config && fs.readdirSync(config).length === 0,
  forbiddenEnv: ['GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN', 'GH_DEBUG'].filter(k => process.env[k]),
  host: process.env.GH_HOST, repository: process.env.GH_REPO };
fs.appendFileSync(process.env.FIXTURE_TRACE, JSON.stringify(record) + '\n');
const output = value => process.stdout.write(JSON.stringify(value));
if (scenario === 'downstream-fail' || scenario === 'http-fail') {
  process.stdout.write('unsafe stdout HTTP 502 locked ' + token);
  process.stderr.write(scenario === 'http-fail' ? process.env.FIXTURE_DIAGNOSTIC : 'unsafe stderr ' + token);
  process.stderr.write('\nsecret ' + token + ' ' + args.join(' ') + ' ' + process.env.FIXTURE_SECRET);
  process.exit(17);
}
if (args[0] !== 'api' || !endpoint) {
  process.stdout.write('normal output ' + token + ' again ' + token + '\n');
  process.stderr.write('diagnostic ' + token + '\n');
  process.exit(0);
}
if (scenario === 'invalid-json') { process.stdout.write('not-json ' + token); process.exit(0); }
const perms = { contents: 'write', issues: 'write', pull_requests: 'write', checks: 'read', statuses: 'read', metadata: 'read' };
if (endpoint === '/app') output({ id: scenario === 'wrong-app' ? 42 : 123, slug: 'sandbox-agent' });
else if (endpoint === '/app/installations/456') output({ id: 456,
  app_id: scenario === 'wrong-installation-app' ? 42 : 123,
  account: { login: scenario === 'wrong-owner' ? 'someone-else' : 'zx110511' },
  repository_selection: scenario === 'all-repositories' ? 'all' : 'selected',
  suspended_at: scenario === 'suspended' ? new Date().toISOString() : null });
else if (endpoint === '/app/installations/456/access_tokens') {
  if (scenario === 'extra-permission') perms.administration = 'write';
  if (scenario === 'elevated-permission') perms.checks = 'write';
  if (scenario === 'missing-permission') delete perms.metadata;
  const ttl = scenario === 'expired' ? -1000 : scenario === 'long-expiry' ? 7200000 : 3500000;
  output({ token: expected, permissions: perms, expires_at: new Date(Date.now() + ttl).toISOString() });
} else if (endpoint === '/installation/repositories') {
  const repositories = [{ id: 789, full_name: scenario === 'wrong-repository-name' ? 'zx110511/other' : 'zx110511/dazi-sandbox' }];
  if (scenario === 'wrong-repository-id') repositories[0].id = 42;
  const extra = [{ id: 999, full_name: 'zx110511/other' }];
  const count = scenario === 'multiple-repositories' ? 2 : 1;
  output([{ total_count: count, repositories }, ...(count === 2 ? [{ total_count: 2, repositories: extra }] : [])]);
} else if (endpoint === '/users/sandbox-agent[bot]') {
  if (scenario === 'replace-existing') fs.writeFileSync(path.join(process.env.DAZI_APP_DIR, 'superagent.token'), 'unrelated-replacement');
  output({ id: 321, login: 'sandbox-agent[bot]', type: scenario === 'not-bot' ? 'User' : 'Bot' });
} else { process.stderr.write('unexpected API'); process.exit(3); }
`;

function fixture(t, scenario = '') {
  const base = mkdtempSync(join(tmpdir(), 'dazi-app-test-'));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const output = join(base, 'credentials');
  mkdirSync(output);
  writeFileSync(join(base, 'fake-gh.cjs'), fakeGh);
  for (const cmd of ['api', 'pr', 'issue', 'auth']) writeFileSync(join(base, cmd), "require('./fake-gh.cjs');\n");
  const privateKey = join(base, 'host-key.pem');
  writeFileSync(privateKey, keys.privateKey, { mode: 0o600 });
  const publicKey = join(base, 'public-key.pem');
  writeFileSync(publicKey, keys.publicKey);
  const trace = join(base, 'trace.jsonl');
  const env = { ...process.env, DAZI_APP_DIR: output, DAZI_APP_GH: process.execPath,
    GH_TOKEN: 'invalid-parent-main-account', GITHUB_TOKEN: 'invalid-parent-github',
    GH_ENTERPRISE_TOKEN: 'invalid-parent-enterprise', GITHUB_ENTERPRISE_TOKEN: 'invalid-parent-enterprise-2',
    GH_CONFIG_DIR: join(base, 'main-account-config'), GH_DEBUG: 'api',
    FIXTURE_TRACE: trace, FIXTURE_PUBLIC_KEY: publicKey, FIXTURE_SCENARIO: scenario };
  const run = (script, args, input = '', overrides = {}) => spawnSync(process.execPath, [script, ...args], {
    cwd: base, env: { ...env, ...overrides }, input, encoding: 'utf8', timeout: 20000,
  });
  const issueArgs = ['--app-id', '123', '--installation-id', '456', '--repository', 'zx110511/dazi-sandbox',
    '--repository-id', '789', '--key-file', privateKey, '--output-dir', output];
  return { base, output, env, run, issueArgs, privateKey,
    issue: () => run(issuer, issueArgs),
    gh: (args, input, overrides) => run(wrapper, args, input, overrides),
    calls: () => existsSync(trace) ? readFileSync(trace, 'utf8').trim().split('\n').map(JSON.parse) : [],
    tokenFile: join(output, 'superagent.token'), identityFile: join(output, 'superagent.identity.json') };
}

function identity(token = TOKEN) {
  return { version: 1, app: { id: 123, slug: 'sandbox-agent' }, bot: { id: 321, login: 'sandbox-agent[bot]' },
    repository: { id: 789, full_name: 'zx110511/dazi-sandbox' }, permissions: { ...permissions },
    expires_at: new Date(Date.now() + 3500000).toISOString(), token_sha256: hash(token) };
}
function pair(f, info = identity(), token = TOKEN) {
  writeFileSync(f.tokenFile, token + '\n');
  writeFileSync(f.identityFile, JSON.stringify(info));
}
function rejected(result, prefix = 'gh-app:') {
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
  assert.ok(result.stderr.startsWith(prefix), 'must return a controlled, safe CLI diagnostic');
  for (const secret of [TOKEN, NEXT_TOKEN, 'invalid-parent-main-account']) assert.ok(!result.stderr.includes(secret));
}

function installAppScripts(f) {
  const installed = join(f.base, 'installed');
  mkdirSync(installed);
  // Model the flat scripts payload: ignored lib/ must not be required at runtime.
  for (const name of readdirSync(join(root, 'scripts')).filter(name => name.endsWith('.mjs'))) {
    writeFileSync(join(installed, name), readFileSync(join(root, 'scripts', name)), { mode: 0o644 });
  }
  // The container installer sets worker executability; never depend on Git mode
  // or add a native Windows worker launcher. Only touch the disposable install.
  if (process.platform !== 'win32') fs.chmodSync(join(installed, 'gh-app.mjs'), 0o755);
  return installed;
}

test('flat installed App modules issue and read identity without ignored lib files', t => {
  const f = fixture(t);
  const installed = installAppScripts(f);
  const issued = f.run(join(installed, 'github-app-auth.mjs'), f.issueArgs);
  assert.equal(issued.status, 0, issued.stderr);
  const result = f.run(join(installed, 'gh-app.mjs'), ['dazi-app', 'identity']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).repository.full_name, 'zx110511/dazi-sandbox');
  assert.ok(!result.stdout.includes(TOKEN));
});

test('POSIX installed worker executes through its shebang, not node script', { skip: process.platform === 'win32' }, t => {
  const f = fixture(t);
  const installed = installAppScripts(f);
  const issued = f.run(join(installed, 'github-app-auth.mjs'), f.issueArgs); // Host signer stays explicit node.
  assert.equal(issued.status, 0, issued.stderr);
  const executable = join(installed, 'gh-app.mjs');
  for (const args of [['dazi-app', 'identity'], ['pr', 'list']]) {
    const result = spawnSync(executable, args, { cwd: f.base, env: f.env, shell: false, encoding: 'utf8', timeout: 20000 });
    assert.equal(result.status, 0, result.error?.message || result.stderr);
    assert.ok(!result.stdout.includes(TOKEN) && !result.stderr.includes(TOKEN));
    if (args[0] === 'dazi-app') assert.equal(JSON.parse(result.stdout).bot.login, 'sandbox-agent[bot]');
    else assert.match(result.stdout, /normal output/);
  }
  assert.equal(fs.statSync(executable).mode & 0o777, 0o755);
});

// Removing signing, scoping, API verification, or publication should break this.
test('issuer signs a real RSA JWT and publishes only the verified single-repository pair', t => {
  const f = fixture(t);
  const result = f.issue();
  assert.equal(result.status, 0, result.stderr);
  assert.ok(!result.stdout.includes(TOKEN));
  const info = JSON.parse(readFileSync(f.identityFile, 'utf8'));
  assert.deepEqual({ ...info, expires_at: 'TIME' }, { ...identity(), expires_at: 'TIME' });
  assert.equal(readFileSync(f.tokenFile, 'utf8').trim(), TOKEN);
  assert.deepEqual(readdirSync(f.output).sort(), ['superagent.identity.json', 'superagent.token']);
  const calls = f.calls();
  assert.deepEqual(calls.map(c => c.endpoint), ['/app', '/app/installations/456', '/app/installations/456/access_tokens', '/installation/repositories', '/users/sandbox-agent[bot]']);
  for (const c of calls.slice(0, 3)) {
    assert.equal(c.jwtValid, true);
    assert.equal(String(c.claims.iss), '123');
    assert.ok(c.claims.iat <= Date.now() / 1000);
    assert.ok(c.claims.exp > Date.now() / 1000 && c.claims.exp - c.claims.iat <= 600);
  }
  assert.deepEqual(calls[2].body, { repository_ids: [789], permissions });
  assert.ok(calls[2].args.includes('POST') && calls[2].args.includes('--input'));
  assert.ok(calls[3].args.includes('--paginate') && calls[3].args.includes('--slurp'));
  for (const c of calls.slice(3)) assert.equal(c.tokenValid, true);
  for (const c of calls) {
    assert.equal(c.argvContainsCredential, false);
    assert.deepEqual(c.forbiddenEnv, []);
    assert.equal(c.configEmpty, true);
    assert.equal(c.host, 'github.com');
    assert.equal(existsSync(c.config), false, 'private gh config must be cleaned up');
  }
});

for (const scenario of ['wrong-app', 'wrong-installation-app', 'wrong-owner', 'all-repositories', 'suspended',
  'extra-permission', 'elevated-permission', 'missing-permission', 'expired', 'long-expiry',
  'multiple-repositories', 'wrong-repository-name', 'wrong-repository-id', 'not-bot', 'invalid-json', 'downstream-fail']) {
  test(`issuer fails closed without publishing for ${scenario}`, t => {
    const f = fixture(t, scenario);
    rejected(f.issue(), 'github-app-auth:');
    assert.deepEqual(readdirSync(f.output), []);
    if (['wrong-app', 'wrong-installation-app', 'wrong-owner', 'all-repositories', 'suspended'].includes(scenario)) {
      assert.ok(!f.calls().some(c => c.args.includes('POST')), 'must reject before minting');
    }
  });
}

test('issuer refuses arbitrary existing files before calling GitHub', t => {
  const f = fixture(t);
  writeFileSync(f.tokenFile, 'unrelated-file');
  rejected(f.issue(), 'github-app-auth:');
  assert.equal(readFileSync(f.tokenFile, 'utf8'), 'unrelated-file');
  assert.deepEqual(f.calls(), []);
});

test('issuer rotates an expired but well-formed bound credential pair', t => {
  const f = fixture(t, 'rotate');
  const old = identity();
  old.expires_at = new Date(Date.now() - 10000).toISOString();
  pair(f, old);
  const result = f.issue();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(f.tokenFile, 'utf8').trim(), NEXT_TOKEN);
  assert.equal(JSON.parse(readFileSync(f.identityFile, 'utf8')).token_sha256, hash(NEXT_TOKEN));
  assert.deepEqual(readdirSync(f.output).sort(), ['superagent.identity.json', 'superagent.token']);
});

test('failed rotation preserves both original files', t => {
  const f = fixture(t, 'extra-permission');
  pair(f);
  const before = readFileSync(f.identityFile, 'utf8');
  rejected(f.issue(), 'github-app-auth:');
  assert.equal(readFileSync(f.identityFile, 'utf8'), before);
  assert.equal(readFileSync(f.tokenFile, 'utf8').trim(), TOKEN);
});

function failSecondRename(t, beforeFailure = () => {}) {
  const rename = fs.renameSync;
  let count = 0;
  const mock = t.mock.method(fs, 'renameSync', (from, to) => {
    if (++count === 2) {
      beforeFailure(from, to);
      throw Object.assign(new Error('injected rename failure'), { code: 'EIO' });
    }
    return rename(from, to);
  });
  syncBuiltinESMExports();
  const restore = () => { mock.mock.restore(); syncBuiltinESMExports(); };
  t.after(restore);
  return restore;
}

for (const existing of [false, true]) {
  test(`publication second rename failure restores ${existing ? 'original bytes' : 'absence'} and permits reissuance`, t => {
    const f = fixture(t, 'rotate');
    if (existing) {
      // Preserve formatting and CRLF as bytes, not merely parsed equivalence.
      writeFileSync(f.tokenFile, TOKEN + '\r\n');
      writeFileSync(f.identityFile, JSON.stringify(identity(), null, 2) + '\r\n');
    }
    const before = existing ? [readFileSync(f.tokenFile), readFileSync(f.identityFile)] : null;
    const previous = readPair(f.output, { allowAbsent: true });
    let observedMixed = false;
    const restore = failSecondRename(t, () => {
      observedMixed = true;
      assert.throws(() => readPair(f.output), /hash do not match|both credential files/);
      rejected(f.gh(['pr', 'list']));
    });
    assert.throws(() => withIssuanceLock(f.output, dir => publishPair(dir, NEXT_TOKEN, identity(NEXT_TOKEN), previous)), /injected rename failure/);
    restore();
    assert.equal(observedMixed, true, 'must reach the real two-file publication window');
    if (existing) {
      assert.deepEqual(readFileSync(f.tokenFile), before[0]);
      assert.deepEqual(readFileSync(f.identityFile), before[1]);
      assert.equal(readPair(f.output).token, TOKEN);
    } else assert.deepEqual(readdirSync(f.output), []);
    assert.deepEqual(f.calls(), [], 'mixed generation must never invoke gh');
    const result = f.issue();
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readPair(f.output).token, NEXT_TOKEN);
    assert.deepEqual(readdirSync(f.output).sort(), ['superagent.identity.json', 'superagent.token']);
  });
}

for (const change of ['token-replaced', 'token-written', 'identity-replaced', 'new-generation', 'temporary-replaced']) {
  test(`publication rollback and cleanup preserve foreign ${change}`, t => {
    const f = fixture(t);
    pair(f);
    const previous = readPair(f.output);
    let foreign;
    const restore = failSecondRename(t, from => {
      foreign = change === 'temporary-replaced' ? from : change === 'identity-replaced' ? f.identityFile : f.tokenFile;
      if (change === 'new-generation') {
        pair(f, identity('invalid-concurrent-generation-0123456789'), 'invalid-concurrent-generation-0123456789');
      } else {
        if (change !== 'token-written') rmSync(foreign);
        writeFileSync(foreign, 'unrelated-foreign-bytes');
      }
    });
    assert.throws(() => withIssuanceLock(f.output, dir => publishPair(dir, NEXT_TOKEN, identity(NEXT_TOKEN), previous)));
    restore();
    if (change === 'new-generation') assert.equal(readPair(f.output).token, 'invalid-concurrent-generation-0123456789');
    else assert.equal(readFileSync(foreign, 'utf8'), 'unrelated-foreign-bytes');
    if (!['new-generation', 'temporary-replaced'].includes(change)) {
      assert.throws(() => readPair(f.output));
      rejected(f.issue(), 'github-app-auth:');
      assert.deepEqual(f.calls(), []);
    }
  });
}

test('publication lock cleanup preserves a replacement lock', t => {
  const f = fixture(t);
  const lock = join(f.output, '.superagent.auth.lock');
  withIssuanceLock(f.output, () => {
    rmSync(lock);
    writeFileSync(lock, 'foreign-lock');
  });
  assert.equal(readFileSync(lock, 'utf8'), 'foreign-lock');
});

test('publication rejects a changed staged identity instead of reporting a mixed pair as installed', t => {
  const f = fixture(t);
  pair(f);
  const previous = readPair(f.output);
  const rename = fs.renameSync;
  let foreign;
  const mock = t.mock.method(fs, 'renameSync', (from, to) => {
    const result = rename(from, to);
    if (to === f.tokenFile) {
      foreign = join(f.output, readdirSync(f.output).find(name => name.startsWith('.superagent.identity.json.') && name.endsWith('.tmp')));
      writeFileSync(foreign, 'foreign-staged-identity');
    }
    return result;
  });
  syncBuiltinESMExports();
  t.after(() => { mock.mock.restore(); syncBuiltinESMExports(); });
  assert.throws(() => withIssuanceLock(f.output, dir => publishPair(dir, NEXT_TOKEN, identity(NEXT_TOKEN), previous)));
  assert.equal(readFileSync(foreign, 'utf8'), 'foreign-staged-identity');
  assert.equal(readPair(f.output).token, TOKEN);
});

for (const mutation of ['app', 'repository', 'bot']) {
  test(`rotation rejects changed existing ${mutation} binding and preserves bytes`, t => {
    const f = fixture(t);
    const old = identity();
    old[mutation].id++;
    pair(f, old);
    const before = [readFileSync(f.tokenFile), readFileSync(f.identityFile)];
    rejected(f.issue(), 'github-app-auth:');
    assert.deepEqual(readFileSync(f.tokenFile), before[0]);
    assert.deepEqual(readFileSync(f.identityFile), before[1]);
    if (mutation !== 'bot') assert.deepEqual(f.calls(), []);
  });
}

test('malformed issuer options fail before reading keys or invoking gh', t => {
  const f = fixture(t);
  for (const args of [[], [...f.issueArgs, '--app-id', '123'], [...f.issueArgs, '--unknown', 'secret'],
    f.issueArgs.slice(0, -1), f.issueArgs.map(arg => arg === '123' ? '9007199254740992' : arg),
    f.issueArgs.map(arg => arg === '123' ? '-1' : arg)]) rejected(f.run(issuer, args), 'github-app-auth:');
  assert.deepEqual(f.calls(), []);
  assert.deepEqual(readdirSync(f.output), []);
});

test('issuer rejects missing key and non-RSA private keys without network calls', t => {
  const f = fixture(t);
  const badArgs = f.issueArgs.filter((_, i) => i !== 8 && i !== 9);
  rejected(f.run(issuer, badArgs), 'github-app-auth:');
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1', privateKeyEncoding: { format: 'pem', type: 'pkcs8' }, publicKeyEncoding: { format: 'pem', type: 'spki' } });
  writeFileSync(f.privateKey, ec.privateKey);
  rejected(f.issue(), 'github-app-auth:');
  assert.deepEqual(f.calls(), []);
});

test('custom identity is exact JSON, contains no token, and never fakes api user', t => {
  const f = fixture(t);
  const info = identity();
  pair(f, info);
  const result = f.gh(['dazi-app', 'identity']);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), info);
  assert.ok(!result.stdout.includes(TOKEN));
  assert.deepEqual(f.calls(), []);
});

for (const [name, mutate] of [
  ['expired', i => { i.expires_at = new Date(Date.now() - 1000).toISOString(); }],
  ['too-long-lived', i => { i.expires_at = new Date(Date.now() + 7200000).toISOString(); }],
  ['non-ISO-expiry', i => { i.expires_at = 'tomorrow'; }],
  ['hash-mismatch', i => { i.token_sha256 = '0'.repeat(64); }],
  ['extra-permission', i => { i.permissions.administration = 'write'; }],
  ['missing-permission', i => { delete i.permissions.metadata; }],
  ['elevated-permission', i => { i.permissions.statuses = 'write'; }],
  ['missing-field', i => { delete i.app; }],
  ['bad-id', i => { i.bot.id = '321'; }],
  ['bot-login-mismatch', i => { i.bot.login = 'someone[bot]'; }],
  ['unexpected-field', i => { i.token = TOKEN; }],
  ['bad-repository', i => { i.repository.full_name = 'owner/repo/extra'; }],
]) {
  test(`wrapper rejects ${name} before executing gh`, t => {
    const f = fixture(t);
    const info = identity();
    mutate(info);
    pair(f, info);
    rejected(f.gh(['pr', 'list']));
    assert.deepEqual(f.calls(), []);
  });
}

for (const missing of ['both', 'token', 'identity']) {
  test(`missing ${missing} cannot fall back to the parent main account`, t => {
    const f = fixture(t);
    if (missing === 'token') writeFileSync(f.identityFile, JSON.stringify(identity()));
    if (missing === 'identity') writeFileSync(f.tokenFile, TOKEN);
    rejected(f.gh(['pr', 'list']));
    assert.deepEqual(f.calls(), []);
  });
}

test('relative DAZI_APP_DIR and missing DAZI_APP_DIR are rejected', t => {
  const f = fixture(t);
  pair(f);
  for (const value of ['credentials', '']) rejected(f.gh(['pr', 'list'], '', { DAZI_APP_DIR: value }));
  assert.deepEqual(f.calls(), []);
});

test('non-regular credential files are rejected', t => {
  const f = fixture(t);
  mkdirSync(f.tokenFile);
  writeFileSync(f.identityFile, JSON.stringify(identity()));
  rejected(f.gh(['pr', 'list']));
  assert.deepEqual(f.calls(), []);
});

test('directory symlinks/junctions are rejected without following credentials', t => {
  const f = fixture(t);
  pair(f);
  const link = join(f.base, 'linked-credentials');
  symlinkSync(f.output, link, process.platform === 'win32' ? 'junction' : 'dir');
  rejected(f.gh(['pr', 'list'], '', { DAZI_APP_DIR: link }));
  assert.deepEqual(f.calls(), []);
});

test('credential file symlinks are rejected when the OS allows creating them', t => {
  const f = fixture(t);
  pair(f);
  const target = join(f.base, 'token-target');
  writeFileSync(target, TOKEN);
  rmSync(f.tokenFile);
  try { symlinkSync(target, f.tokenFile, 'file'); }
  catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES'].includes(error.code)) { t.skip('Windows file symlinks require host privileges; junction coverage still runs'); return; }
    throw error;
  }
  rejected(f.gh(['pr', 'list']));
  assert.deepEqual(f.calls(), []);
});

test('normal gh commands get isolated credentials and successful output is redacted', t => {
  const f = fixture(t);
  pair(f);
  const args = ['pr', 'list', '--repo', 'zx110511/dazi-sandbox', '--json', 'number'];
  const result = f.gh(args);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /normal output/);
  assert.ok(!result.stdout.includes(TOKEN) && !result.stderr.includes(TOKEN));
  const [call] = f.calls();
  assert.deepEqual(call.args, args);
  assert.equal(call.tokenValid, true);
  assert.deepEqual(call.forbiddenEnv, []);
  assert.equal(call.configEmpty, true);
  assert.equal(existsSync(call.config), false);
});

test('failed gh output is discarded, not relayed with partial redaction', t => {
  const f = fixture(t, 'downstream-fail');
  pair(f);
  const result = f.gh(['issue', 'list']);
  rejected(result);
  assert.ok(!result.stderr.includes('unsafe'));
});

for (const [diagnosis, status, locked = false] of [
  ['gh: Not Modified (HTTP 304)', 304],
  ['gh: Not Found (HTTP 404)', 404],
  ['gh: Gone (HTTP 410)', 410],
  ['gh: Forbidden (HTTP 403)', 403],
  ['gh: Issue is locked (HTTP 403)', 403, true],
  ['gh: Cannot comment on a locked issue (HTTP 403)', 403, true],
  ['gh: Issue is unlocked (HTTP 403)', 403],
  ['gh: Issue is not locked (HTTP 403)', 403],
  ['gh: Repository access blocked (HTTP 403)', 403],
  ['gh: Forbidden (HTTP 403) https://example.test/locked', 403],
  ['gh: Issue is locked (HTTP 404)', 404],
  ['gh: failure (HTTP 400)', 400],
  ['gh: failure (HTTP 599)', 599],
  ['gh: malformed HTTP 4030', null],
  ['gh: malformed HTTP 403x', null],
  ['gh: malformed HTTP 403.5', null],
  ['gh: invalid HTTP 200 HTTP 600 HTTP 399', null],
  ['gh: ambiguous HTTP 403 HTTP 404', null],
  ['gh: no HTTP diagnostic', null],
  ['open /tmp/HTTP 404 input.json: no such file or directory', null],
  ['gh: invalid argument\n--search HTTP 304', null],
  ['gh: open /tmp/HTTP 404 input.json: no such file or directory', null],
  ['gh: invalid argument --search HTTP 304', null],
  ['gh: Not Found (HTTP 404)\ngh: Forbidden (HTTP 403)', null],
  ['gh: HTTP 304', 304],
  ['gh: HTTP 304 (https://api.github.com/repos/owner/repo/issues)', 304],
  ['gh: Not Found (HTTP 404)\r\n', 404],
]) {
  test(`HTTP failure classification withholds all downstream secrets: ${diagnosis}`, t => {
    const f = fixture(t, 'http-fail');
    pair(f);
    const result = f.gh(['issue', 'list', '--search', 'argv-secret'], '', {
      FIXTURE_DIAGNOSTIC: `${diagnosis}\n${TOKEN}`, FIXTURE_SECRET: 'environment-secret',
    });
    rejected(result);
    // These are the downstream HTTP NNN and HTTP 403 + locked consumer contracts.
    assert.equal(result.stderr.match(/HTTP (\d{3})/)?.[1] ?? null, status === null ? null : String(status));
    assert.equal(result.stderr.includes('locked'), locked);
    assert.equal(result.stderr, status === null ? 'gh-app: gh command failed (exit 17); downstream output withheld.\n' :
      `gh-app: gh command failed: HTTP ${status}${locked ? ' locked' : ''}; downstream output withheld.\n`);
    for (const secret of ['argv-secret', 'environment-secret', 'unsafe', 'example.test']) assert.ok(!result.stderr.includes(secret));
  });
}

for (const args of [['auth', 'token'], ['auth', 'login'], ['auth', 'setup-git'], ['auth', 'status'],
  ['--repo', 'zx110511/dazi-sandbox', 'auth', 'token'], ['auth', 'git-credential', 'get', '--help'], ['alias', 'set', 'unsafe', '!env']]) {
  test(`wrapper rejects unsafe command ${args.join(' ')}`, t => {
    const f = fixture(t);
    pair(f);
    rejected(f.gh(args));
    assert.deepEqual(f.calls(), []);
  });
}

test('credential get emits a Git-compatible response only for the target GitHub host', t => {
  const f = fixture(t);
  pair(f);
  const result = f.gh(['auth', 'git-credential', 'get'], 'protocol=https\nhost=github.com\npath=zx110511/dazi-sandbox.git\n\n');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `username=x-access-token\npassword=${TOKEN}\n\n`);
  for (const input of ['protocol=https\nhost=evil.example\n\n', 'protocol=http\nhost=github.com\n\n', 'protocol=https\nhost=github.com\npath=other/repo.git\n\n']) {
    rejected(f.gh(['auth', 'git-credential', 'get'], input));
  }
});

for (const op of ['store', 'erase']) {
  test(`credential ${op} is a no-op and never persists credentials`, t => {
    const f = fixture(t);
    pair(f);
    const before = readdirSync(f.base).sort();
    const metadata = readFileSync(f.identityFile, 'utf8');
    const result = f.gh(['auth', 'git-credential', op], `protocol=https\nhost=github.com\npassword=${TOKEN}\n\n`);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
    assert.deepEqual(f.calls(), []);
    assert.deepEqual(readdirSync(f.base).sort(), before);
    assert.equal(readFileSync(f.identityFile, 'utf8'), metadata);
    assert.equal(readFileSync(f.tokenFile, 'utf8').trim(), TOKEN);
  });
}

test('wrapper pins implicit repository resolution instead of inheriting a main-account host', t => {
  const f = fixture(t);
  pair(f);
  const result = f.gh(['pr', 'list'], '', { GH_REPO: 'other.example/main/private', GH_HOST: 'other.example' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.calls()[0].repository, 'zx110511/dazi-sandbox');
  assert.equal(f.calls()[0].host, 'github.com');
});

for (const args of [
  ['api', 'https://other.example/user'], ['api', 'http://api.github.com/user'],
  ['api', '//other.example/user'], ['api', 'user', '--hostname', 'other.example'],
  ['pr', 'list', '--repo', 'other.example/main/private'],
  ['pr', 'list', '-Rother.example/main/private'],
  ['pr', 'list', '--repo=other.example/main/private'],
]) {
  test(`wrapper rejects alternate-host routing: ${args.join(' ')}`, t => {
    const f = fixture(t);
    pair(f);
    rejected(f.gh(args));
    assert.deepEqual(f.calls(), []);
  });
}

test('malformed wrapper selectors are rejected before invoking gh', t => {
  const f = fixture(t);
  pair(f);
  for (const args of [['pr', 'list', '--repo'], ['pr', 'list', '-R'], ['pr', 'list', '--repo='],
    ['pr', 'list', '--repo', '--json'], ['--repo'], ['api', 'user', '--hostname'],
    ['api', 'https://api.github.com:bad/user']]) rejected(f.gh(args));
  assert.deepEqual(f.calls(), []);
});

test('api user is really forwarded and is not substituted with App identity', t => {
  const f = fixture(t);
  pair(f);
  const result = f.gh(['api', 'user']);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(f.calls()[0].args, ['api', 'user']);
  assert.match(result.stdout, /normal output/);
  assert.ok(!result.stdout.includes(TOKEN));
});

test('missing gh executable cannot expose parent or installation credentials', t => {
  const f = fixture(t);
  pair(f);
  rejected(f.gh(['pr', 'list'], '', { DAZI_APP_GH: join(f.base, 'nonexistent-gh') }));
  assert.deepEqual(f.calls(), []);
});

test('issuer refuses a changed credential pair before publishing', t => {
  const f = fixture(t, 'replace-existing');
  pair(f);
  rejected(f.issue(), 'github-app-auth:');
  assert.equal(readFileSync(f.tokenFile, 'utf8'), 'unrelated-replacement');
  assert.equal(JSON.parse(readFileSync(f.identityFile, 'utf8')).token_sha256, hash(TOKEN));
  assert.deepEqual(readdirSync(f.output).sort(), ['superagent.identity.json', 'superagent.token']);
});

test('issuer cannot take over another issuer lock or a mismatched existing pair', t => {
  const f = fixture(t);
  const lock = join(f.output, '.superagent.auth.lock');
  writeFileSync(lock, 'another-issuer');
  rejected(f.issue(), 'github-app-auth:');
  assert.equal(readFileSync(lock, 'utf8'), 'another-issuer');
  rmSync(lock);
  pair(f, identity(NEXT_TOKEN));
  rejected(f.issue(), 'github-app-auth:');
  assert.deepEqual(f.calls(), []);
});
