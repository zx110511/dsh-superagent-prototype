#!/usr/bin/env node
import { readSync } from 'node:fs';
import { diagnostic, readPair, redact, requireThat, runGh, validateExpiry, validRepository } from './github-app-auth-core.mjs';

function commandIndex(args) {
  let index = 0;
  while (index < args.length && args[index].startsWith('-')) {
    const arg = args[index++];
    if (arg === '--repo' || arg === '-R') {
      requireThat(index < args.length && !args[index].startsWith('-'), 'missing repository option.');
      index++;
    } else requireThat(/^--repo=.+/.test(arg) || /^-R.+/.test(arg) || ['--help', '-h', '--version'].includes(arg),
      'unsupported global option.');
  }
  return index;
}

function credentialInput() {
  const buffer = Buffer.alloc(65536);
  let used = 0;
  while (used < buffer.length) {
    const count = readSync(0, buffer, used, buffer.length - used, null);
    if (!count) break;
    used += count;
  }
  requireThat(used < buffer.length, 'credential request is too large.');
  const fields = Object.create(null);
  for (const line of buffer.subarray(0, used).toString('utf8').split(/\r?\n/)) {
    if (!line) break;
    const equals = line.indexOf('=');
    requireThat(equals > 0 && !Object.hasOwn(fields, line.slice(0, equals)), 'credential request is malformed.');
    fields[line.slice(0, equals)] = line.slice(equals + 1);
  }
  return fields;
}

function main(args) {
  // Validate for every invocation, including help and credential store/erase.
  // Never consult `gh auth status`, a keyring, or an inherited user token.
  const { token, identity } = readPair(process.env.DAZI_APP_DIR);
  const index = commandIndex(args);
  const command = args[index];
  if (command === 'dazi-app') {
    requireThat(index === 0 && args.length === 2 && args[1] === 'identity', 'only dazi-app identity is supported.');
    process.stdout.write(`${JSON.stringify(identity)}\n`);
    return;
  }
  if (command === 'auth') {
    requireThat(index === 0 && args.length === 3 && args[1] === 'git-credential' && ['get', 'store', 'erase'].includes(args[2]),
      'auth commands are disabled except git-credential get/store/erase.');
    // Git asks every helper to store/erase. Do not delegate these operations to
    // gh, which could change a host keyring or its configuration.
    if (args[2] !== 'get') return;
    const fields = credentialInput();
    requireThat(fields.protocol === 'https' && fields.host === 'github.com' &&
      (!fields.path || fields.path.replace(/\.git$/, '') === identity.repository.full_name),
    'credential request must target the authorized GitHub repository over HTTPS.');
    validateExpiry(identity.expires_at);
    process.stdout.write(`username=x-access-token\npassword=${token}\n\n`);
    return;
  }
  requireThat(!['alias', 'config', 'extension'].includes(command), 'global configuration and extension commands are disabled.');
  // Do not route this GitHub.com installation token to alternate API hosts.
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--hostname') requireThat(args[i + 1] === 'github.com', 'only the github.com API host is permitted.');
    if (arg.startsWith('--hostname=')) requireThat(arg === '--hostname=github.com', 'only the github.com API host is permitted.');
    if (arg === '--repo' || arg === '-R') requireThat(typeof args[i + 1] === 'string' && !args[i + 1].startsWith('-'),
      'missing repository option.');
    const repo = arg === '--repo' || arg === '-R' ? args[i + 1] :
      arg.startsWith('--repo=') ? arg.slice(7) : arg.startsWith('-R') ? arg.slice(2).replace(/^=/, '') : undefined;
    if (repo !== undefined) requireThat(validRepository(repo.replace(/^github\.com\//, '')), 'repository selectors must use github.com owner/name.');
    if (command === 'api') {
      requireThat(!arg.startsWith('//'), 'protocol-relative API endpoints are disabled.');
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(arg)) {
        const url = new URL(arg);
        requireThat(url.protocol === 'https:' && url.hostname === 'api.github.com' && !url.port && !url.username && !url.password,
          'absolute API endpoints must use https://api.github.com.');
      }
    }
  }
  const result = runGh(args, token, { inheritInput: true, repository: identity.repository.full_name });
  process.stdout.write(redact(result.stdout, token));
  process.stderr.write(redact(result.stderr, token));
}

try { main(process.argv.slice(2)); }
catch (error) { process.stderr.write(diagnostic('gh-app', error)); process.exitCode = 1; }
