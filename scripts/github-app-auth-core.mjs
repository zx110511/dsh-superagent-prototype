import { constants, closeSync, fstatSync, fsyncSync, ftruncateSync, lstatSync, mkdtempSync, openSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';

export const PERMISSIONS = Object.freeze({ contents: 'write', issues: 'write', pull_requests: 'write', checks: 'read', statuses: 'read', metadata: 'read' });
const MAX_LIFETIME_MS = 3600000 + 60000; // One hour plus a fixed, non-configurable 60-second clock allowance.
const TOKEN_NAME = 'superagent.token';
const IDENTITY_NAME = 'superagent.identity.json';

// Only these deliberately credential-free messages may reach either CLI's stderr.
export class AuthError extends Error {}
export function requireThat(condition, message) {
  if (!condition) throw new AuthError(message);
}
export function diagnostic(prefix, error) {
  return `${prefix}: ${error instanceof AuthError ? error.message : 'operation failed; credential or filesystem validation did not complete.'}\n`;
}
export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}
function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
export function validId(value) {
  return Number.isSafeInteger(value) && value > 0;
}
export function validRepository(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value) &&
    !['.', '..'].includes(value.split('/')[1]);
}
export function validSlug(value) {
  return typeof value === 'string' && /^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$/.test(value);
}
export function validatePermissions(value) {
  requireThat(exactKeys(value, Object.keys(PERMISSIONS)) && Object.entries(PERMISSIONS).every(([k, v]) => value[k] === v),
    'permissions must exactly match the six required repository permissions.');
}
export function validateExpiry(value, allowExpired = false) {
  const time = typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ? Date.parse(value) : NaN;
  const now = Date.now();
  requireThat(Number.isFinite(time) && new Date(time).toISOString().replace('.000Z', 'Z') === value.replace('.000Z', 'Z') &&
    (allowExpired || time > now) && time <= now + MAX_LIFETIME_MS,
  'credential expiry is invalid, expired, or exceeds one hour plus clock allowance.');
}
export function validateToken(token) {
  requireThat(typeof token === 'string' && /^[A-Za-z0-9_-]{20,512}$/.test(token), 'credential token format is invalid.');
}
export function validateIdentity(info, token, { allowExpired = false } = {}) {
  requireThat(exactKeys(info, ['version', 'app', 'bot', 'repository', 'permissions', 'expires_at', 'token_sha256']) && info.version === 1,
    'credential identity schema is invalid.');
  requireThat(exactKeys(info.app, ['id', 'slug']) && validId(info.app.id) && validSlug(info.app.slug), 'app identity is invalid.');
  requireThat(exactKeys(info.bot, ['id', 'login']) && validId(info.bot.id) && info.bot.login === `${info.app.slug}[bot]`, 'bot identity is invalid.');
  requireThat(exactKeys(info.repository, ['id', 'full_name']) && validId(info.repository.id) && validRepository(info.repository.full_name), 'repository identity is invalid.');
  validatePermissions(info.permissions);
  validateExpiry(info.expires_at, allowExpired);
  validateToken(token);
  requireThat(typeof info.token_sha256 === 'string' && /^[a-f0-9]{64}$/.test(info.token_sha256) &&
    timingSafeEqual(Buffer.from(info.token_sha256, 'hex'), Buffer.from(sha256(token), 'hex')), 'credential token and identity hash do not match.');
  requireThat(!JSON.stringify(info).includes(token), 'credential identity contains secret material.');
  return info;
}

// Reject junctions as well as symlinks, including in ancestor directories.
// The host must own and protect the directory; this is not an ACL manager.
export function checkedDirectory(directory) {
  requireThat(typeof directory === 'string' && isAbsolute(directory), 'an absolute credential directory is required.');
  const result = resolve(directory);
  let current = result;
  while (true) {
    const stat = lstatSync(current);
    requireThat(stat.isDirectory() && !stat.isSymbolicLink(), 'credential directory must not contain symlinks or junctions.');
    if (current === parse(current).root) break;
    current = dirname(current);
  }
  return result;
}
function optionalStat(file) {
  try { return lstatSync(file); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}
export function readRegular(file, maxBytes = 16384) {
  const before = lstatSync(file);
  requireThat(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 && before.size <= maxBytes,
    'credential inputs must be bounded regular files, not links.');
  const fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const opened = fstatSync(fd);
    requireThat(opened.isFile() && sameFile(before, opened), 'credential file changed while opening.');
    const text = readFileSync(fd, 'utf8');
    requireThat(Buffer.byteLength(text) <= maxBytes && sameFile(opened, fstatSync(fd)) && sameFile(opened, lstatSync(file)),
      'credential file changed while reading.');
    return { text, stat: opened };
  } finally { closeSync(fd); }
}
export function readPair(directory, { allowAbsent = false, allowExpired = false } = {}) {
  const dir = checkedDirectory(directory);
  const tokenFile = join(dir, TOKEN_NAME);
  const identityFile = join(dir, IDENTITY_NAME);
  const tokenStat = optionalStat(tokenFile);
  const identityStat = optionalStat(identityFile);
  if (!tokenStat && !identityStat && allowAbsent) return null;
  requireThat(tokenStat && identityStat, 'both credential files are required; account fallback is disabled.');
  const rawToken = readRegular(tokenFile, 1024);
  const rawIdentity = readRegular(identityFile);
  // Accept one terminal newline, but never whitespace or a second credential.
  const token = rawToken.text.replace(/\r?\n$/, '');
  let identity;
  try { identity = JSON.parse(rawIdentity.text); }
  catch { throw new AuthError('credential identity is not valid JSON.'); }
  validateIdentity(identity, token, { allowExpired });
  requireThat(sameFile(rawToken.stat, lstatSync(tokenFile)) && sameFile(rawIdentity.stat, lstatSync(identityFile)),
    'credential pair changed while reading.');
  return { token, identity, rawToken, rawIdentity };
}

export function runGh(args, token, { input, inheritInput = false, repository } = {}) {
  const config = mkdtempSync(join(tmpdir(), 'dazi-app-gh-'));
  try {
    const env = { ...process.env };
    const removed = /^(?:GH_TOKEN|GITHUB_TOKEN|GH_ENTERPRISE_TOKEN|GITHUB_ENTERPRISE_TOKEN|GH_CONFIG_DIR|GH_HOST|GH_REPO|GH_DEBUG|GH_PAGER|PAGER|GH_BROWSER|BROWSER|GH_EDITOR|EDITOR|VISUAL)$/i;
    for (const name of Object.keys(env)) if (removed.test(name) || /^GIT_TRACE/i.test(name)) delete env[name];
    Object.assign(env, { GH_TOKEN: token, GH_CONFIG_DIR: config, GH_HOST: 'github.com', GH_PROMPT_DISABLED: '1',
      GH_PAGER: '', PAGER: '', GH_ACCESSIBLE_PROMPTER: '0' });
    if (repository) env.GH_REPO = repository;
    const executable = process.env.DAZI_APP_GH || 'gh';
    const result = spawnSync(executable, args, {
      env, shell: false, windowsHide: true, encoding: 'utf8',
      stdio: [inheritInput ? 'inherit' : 'pipe', 'pipe', 'pipe'], input,
      timeout: 120000, maxBuffer: 16 * 1024 * 1024,
    });
    if (result.error || result.signal || result.status !== 0) {
      // Only complete gh HTTP diagnostics count; filenames and echoed arguments may contain HTTP-like text.
      const stderr = typeof result.stderr === 'string' ? result.stderr : '';
      const diagnostics = stderr.split(/\r?\n/).flatMap(line => {
        const match = /^gh: (?:HTTP (304|[45]\d{2})(?: \(https:\/\/\S+\))?|.+ \(HTTP (304|[45]\d{2})\)(?: https:\/\/\S+)?)$/.exec(line);
        return match ? [{ line, code: match[1] ?? match[2] }] : [];
      });
      const codes = [...new Set(diagnostics.map(({ code }) => code))];
      if (!result.error && !result.signal && codes.length === 1) {
        const code = codes[0];
        // Recognize explicit gh lock diagnoses, not URLs, unlocked, blocked or
        // unrelated lines containing the word "locked".
        const locked = code === '403' && diagnostics.some(({ line }) =>
          /^gh: (?:(?:This )?(?:issue|pull request|conversation|repository) (?:is|was|has been) (?:currently )?locked|Cannot comment on (?:a |the |this )?locked (?:issue|pull request|conversation))\b[^\r\n]*\(HTTP 403\)/i.test(line));
        throw new AuthError(`gh command failed: HTTP ${code}${locked ? ' locked' : ''}; downstream output withheld.`);
      }
      throw new AuthError(Number.isInteger(result.status) ? `gh command failed (exit ${result.status}); downstream output withheld.` :
        'gh could not complete; downstream output withheld.');
    }
    return { stdout: result.stdout || '', stderr: result.stderr || '' };
  } finally { rmSync(config, { recursive: true, force: true }); }
}
export function ghJson(method, endpoint, token, { body, paginate = false } = {}) {
  const args = ['api', '--hostname', 'github.com', '--method', method, endpoint];
  if (body !== undefined) args.push('--input', '-');
  if (paginate) args.push('--paginate', '--slurp');
  const result = runGh(args, token, { input: body === undefined ? '' : JSON.stringify(body) });
  try { return JSON.parse(result.stdout); }
  catch { throw new AuthError('gh returned an invalid API response; downstream output withheld.'); }
}
export function redact(text, token) {
  const secrets = [token, Buffer.from(token).toString('base64'), Buffer.from(`x-access-token:${token}`).toString('base64')];
  for (const secret of secrets) text = text.split(secret).join('[REDACTED]');
  return text;
}

function assertUnchanged(directory, expected) {
  const actual = readPair(directory, { allowAbsent: true, allowExpired: true });
  requireThat((!actual && !expected) || (actual && expected &&
    actual.rawToken.text === expected.rawToken.text && actual.rawIdentity.text === expected.rawIdentity.text &&
    sameFile(actual.rawToken.stat, expected.rawToken.stat) && sameFile(actual.rawIdentity.stat, expected.rawIdentity.stat)),
  'existing credentials changed during issuance; refusing replacement.');
}
function ownsFile(file, stat) {
  const actual = optionalStat(file);
  return actual && actual.isFile() && !actual.isSymbolicLink() && actual.nlink === 1 && sameFile(actual, stat);
}
function matchesInput(file, expected) {
  try {
    if (!expected) return !optionalStat(file);
    const actual = readRegular(file);
    return actual.text === expected.text && sameFile(actual.stat, expected.stat);
  } catch { return false; }
}
export function withIssuanceLock(directory, action) {
  const dir = checkedDirectory(directory);
  const lock = join(dir, '.superagent.auth.lock');
  // Exclusive creation prevents cooperating issuers from interleaving. A stale
  // lock after a crash deliberately requires host intervention, never lock theft.
  const fd = openSync(lock, 'wx', 0o600);
  const stat = fstatSync(fd);
  try { return action(dir); }
  finally {
    try { if (ownsFile(lock, stat)) unlinkSync(lock); }
    finally { closeSync(fd); }
  }
}
export function publishPair(directory, token, identity, previous) {
  validateIdentity(identity, token);
  assertUnchanged(directory, previous);
  const temporary = [];
  const tokenFile = join(directory, TOKEN_NAME);
  const identityFile = join(directory, IDENTITY_NAME);
  let publishedToken;
  let complete = false;
  try {
    for (const [name, text] of [[TOKEN_NAME, `${token}\n`], [IDENTITY_NAME, `${JSON.stringify(identity)}\n`]]) {
      const file = join(directory, `.${name}.${randomUUID()}.tmp`);
      const fd = openSync(file, 'wx', 0o600);
      const entry = { file, fd, text, stat: fstatSync(fd) };
      temporary.push(entry);
      try { writeFileSync(fd, text, 'utf8'); fsyncSync(fd); }
      finally { entry.stat = fstatSync(fd); }
    }
    assertUnchanged(directory, previous);
    validateExpiry(identity.expires_at);
    // Keep previous bytes in memory and our new-token descriptor open until both
    // renames succeed. This is synchronous rollback, NOT a two-file transaction.
    // Readers reject mixed hashes or missing files throughout the publication.
    renameSync(temporary[0].file, tokenFile);
    publishedToken = { text: temporary[0].text, stat: fstatSync(temporary[0].fd) };
    requireThat(matchesInput(tokenFile, publishedToken) && matchesInput(identityFile, previous?.rawIdentity) &&
      matchesInput(temporary[1].file, temporary[1]),
      'credentials changed during publication; host intervention required.');
    renameSync(temporary[1].file, identityFile);
    complete = true;
  } catch (error) {
    if (publishedToken && !complete) {
      requireThat(matchesInput(tokenFile, publishedToken) && matchesInput(identityFile, previous?.rawIdentity),
        'credentials changed during publication; refusing rollback; host intervention required.');
      try {
        if (previous) {
          // Positional writes target only our still-open inode: a foreign path
          // replacement cannot be overwritten by a rollback rename. The trusted
          // directory and issuance lock remain required (not hostile-writer CAS).
          const bytes = Buffer.from(previous.rawToken.text, 'utf8');
          const fd = temporary[0].fd;
          let offset = 0;
          while (offset < bytes.length) {
            const written = writeSync(fd, bytes, offset, bytes.length - offset, offset);
            requireThat(written > 0, 'credential rollback write did not complete.');
            offset += written;
          }
          ftruncateSync(fd, bytes.length);
          fsyncSync(fd);
          const restored = readPair(directory, { allowExpired: true });
          requireThat(restored.rawToken.text === previous.rawToken.text && restored.rawIdentity.text === previous.rawIdentity.text,
            'credentials changed during rollback.');
        } else {
          if (ownsFile(tokenFile, publishedToken.stat)) unlinkSync(tokenFile);
          requireThat(readPair(directory, { allowAbsent: true }) === null, 'credentials changed during rollback.');
        }
      } catch { throw new AuthError('credential rollback did not complete; host intervention required.'); }
    }
    throw error;
  } finally {
    // No persistent recovery protocol: originals live only in memory. Following
    // a crash or rollback I/O failure, the host must stop issuers, inspect the
    // directory and install a verified complete pair before clearing a stale lock.
    // Never sweep by filename: even a matching temp name may now be foreign.
    let cleanupError;
    for (const entry of temporary) {
      try { if (ownsFile(entry.file, entry.stat)) unlinkSync(entry.file); }
      catch (error) { cleanupError ??= error; }
      finally { closeSync(entry.fd); }
    }
    if (cleanupError) throw cleanupError;
  }
}
