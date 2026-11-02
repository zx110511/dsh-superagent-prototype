#!/usr/bin/env node
import { createPrivateKey, sign } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { PERMISSIONS, diagnostic, ghJson, publishPair, readPair, readRegular, requireThat, sha256,
  validateExpiry, validatePermissions, validateToken, validId, validRepository, validSlug, withIssuanceLock } from './github-app-auth-core.mjs';

function options(args) {
  const names = ['app-id', 'installation-id', 'repository', 'repository-id', 'key-file', 'output-dir'];
  const result = {};
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i].slice(2);
    requireThat(args[i].startsWith('--') && names.includes(name) && !Object.hasOwn(result, name) &&
      typeof args[i + 1] === 'string' && !args[i + 1].startsWith('--'), 'exactly six explicit issuance options are required.');
    result[name] = args[i + 1];
  }
  requireThat(names.every(name => Object.hasOwn(result, name)), 'app, installation, repository, repository ID, key file and output directory are required.');
  for (const name of ['app-id', 'installation-id', 'repository-id']) {
    requireThat(/^[1-9]\d*$/.test(result[name]) && validId(Number(result[name])), 'GitHub IDs must be positive safe integers.');
    result[name] = Number(result[name]);
  }
  requireThat(validRepository(result.repository), 'repository must be an explicit owner/name.');
  requireThat(isAbsolute(result['key-file']) && isAbsolute(result['output-dir']), 'key file and output directory must be absolute paths.');
  return result;
}

function issue(args) {
  const opts = options(args);
  const key = createPrivateKey(readRegular(opts['key-file'], 32768).text);
  requireThat(key.type === 'private' && key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails.modulusLength >= 2048,
    'an RSA private key of at least 2048 bits is required.');
  withIssuanceLock(opts['output-dir'], directory => {
    const previous = readPair(directory, { allowAbsent: true, allowExpired: true });
    if (previous) requireThat(previous.identity.app.id === opts['app-id'] &&
      previous.identity.repository.id === opts['repository-id'] && previous.identity.repository.full_name === opts.repository,
    'existing credential pair belongs to another app or repository.');
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ iat: now - 60, exp: now + 540, iss: opts['app-id'] })).toString('base64url');
    const unsigned = `${header}.${payload}`;
    const jwt = `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), key).toString('base64url')}`;
    const app = ghJson('GET', '/app', jwt);
    requireThat(app?.id === opts['app-id'] && validSlug(app.slug), 'GitHub App identity does not match the requested app.');
    const installation = ghJson('GET', `/app/installations/${opts['installation-id']}`, jwt);
    requireThat(installation?.id === opts['installation-id'] && installation.app_id === app.id &&
      installation.account?.login === opts.repository.split('/')[0] && installation.repository_selection === 'selected' &&
      installation.suspended_at === null, 'installation must be active, selected-repository, and owned by the requested account and app.');
    const credential = ghJson('POST', `/app/installations/${opts['installation-id']}/access_tokens`, jwt, {
      body: { repository_ids: [opts['repository-id']], permissions: PERMISSIONS },
    });
    validatePermissions(credential?.permissions);
    validateExpiry(credential?.expires_at);
    validateToken(credential?.token);
    const token = credential.token;
    const pages = ghJson('GET', '/installation/repositories', token, { paginate: true });
    requireThat(Array.isArray(pages) && pages.length > 0 && pages.every(page => page?.total_count === 1 && Array.isArray(page.repositories)),
      'installation token must expose exactly one repository across all pages.');
    const repositories = pages.flatMap(page => page.repositories);
    requireThat(repositories.length === 1 && repositories[0]?.id === opts['repository-id'] && repositories[0].full_name === opts.repository,
      'installation token repository set does not exactly match the requested repository.');
    const bot = ghJson('GET', `/users/${app.slug}[bot]`, token);
    requireThat(bot?.type === 'Bot' && validId(bot.id) && bot.login === `${app.slug}[bot]`, 'GitHub App bot identity is invalid.');
    if (previous) requireThat(previous.identity.app.slug === app.slug && previous.identity.bot.id === bot.id,
      'existing credential pair belongs to a different bot identity.');
    const identity = { version: 1, app: { id: app.id, slug: app.slug }, bot: { id: bot.id, login: bot.login },
      repository: { id: opts['repository-id'], full_name: opts.repository }, permissions: { ...PERMISSIONS },
      expires_at: credential.expires_at, token_sha256: sha256(token) };
    publishPair(directory, token, identity, previous);
    process.stdout.write('GitHub App credentials verified and installed.\n');
  });
}

try { issue(process.argv.slice(2)); }
catch (error) { process.stderr.write(diagnostic('github-app-auth', error)); process.exitCode = 1; }
