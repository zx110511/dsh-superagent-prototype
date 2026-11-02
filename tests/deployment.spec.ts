import { execFile } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Config, executable, machineOf, resolveDeployment, resolveFeishuBot, type Machine, type Probe } from '../src/deployment.ts'
import { gitEnv } from './fixtures/git.ts'

const exec = promisify(execFile)
let dir: string
let path: string
const program = (file: string, body = ''): string => { writeFileSync(file, `#!/bin/sh\n${body}\n`); chmodSync(file, 0o755); return file }
/** Credential-free output of the App wrapper; only its bot identity is used for startup. */
const identity = (overrides: Record<string, unknown> = {}) => ({ version: 1, app: { id: 42, slug: 'agent-bot' },
  bot: { id: 7, login: 'agent-bot[bot]' }, repository: { id: 99, full_name: 'acme/widgets' },
  permissions: { contents: 'write', issues: 'write', pull_requests: 'write', checks: 'read', statuses: 'read', metadata: 'read' },
  expires_at: new Date(Date.now() + 3_600_000).toISOString(), token_sha256: 'a'.repeat(64), ...overrides })
const repositories = [{ total_count: 1, repositories: [{ id: 99, full_name: 'acme/widgets', private: true }] }]
/** A real subprocess fixture supporting only the App protocol and installation repository probe. */
const gh = (file: string): string => program(file, `case "$*" in\n  "dazi-app identity") echo '${JSON.stringify(identity())}' ;;\n  "api installation/repositories --paginate --slurp") echo '${JSON.stringify(repositories)}' ;;\n  *) exit 1 ;;\nesac`)
/** Fake lark-cli script body returning canned auth, strict-mode, and bot info responses. */
const lark = (status: object, mode = 'bot', bot: object = { bot: { open_id: 'ou_bot', app_name: 'Widgets Bot' }, code: 0 }): string =>
  `case "$*" in\n  "auth status") echo '${JSON.stringify(status)}' ;;\n  "config strict-mode") echo 'strict-mode: ${mode} (source: profile)' ;;\n  "api GET /open-apis/bot/v3/info --as bot --format ndjson") echo '${JSON.stringify(bot)}' ;;\nesac`
const minimal = (overrides: Record<string, unknown> = {}) => ({ stateDir: join(dir, 'state'), ...overrides })
const machine = (overrides: Partial<Machine> = {}): Machine => ({ ...machineOf(Config(minimal())), ...overrides })
/** Runs commands like worker shells do, but locally: the stand-ins first on PATH, then the system's git. */
const probe: Probe = async argv => (await exec(argv[0]!, argv.slice(1), { env: { PATH: path, HOME: dir } })).stdout
const setupError = (place: string, code: string, values: Record<string, unknown> = {}) => expect.objectContaining({ place, code, values: expect.objectContaining(values) })

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'deployment-'))
  mkdirSync(join(dir, 'bin')); mkdirSync(join(dir, 'state', 'worker-bin'), { recursive: true }); mkdirSync(join(dir, 'widgets', 'src'), { recursive: true })
  path = [join(dir, 'state-link', 'worker-bin'), `${join(dir, 'state', 'worker-bin')}/`, join(dir, 'bin'), '/usr/bin', '/bin'].join(':')
  gh(join(dir, 'bin', 'gh'))
  program(join(dir, 'bin', 'lark-cli'), lark({ appId: 'cli_bot', brand: 'lark', identities: { bot: { status: 'ready' } } }))
  // Stale worker shims with the same binary name must be skipped regardless of PATH normalization or symlinks.
  program(join(dir, 'state', 'worker-bin', 'gh'))
  symlinkSync(join(dir, 'state'), join(dir, 'state-link'))
  await exec('git', ['init', '-q', join(dir, 'widgets')], { env: gitEnv() })
  await exec('git', ['-C', join(dir, 'widgets'), 'remote', 'add', 'origin', 'git@github.com:acme/widgets.git'], { env: gitEnv() })
})
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

// Setup spawns CLI subprocesses that can take several seconds when tests run in parallel.
vi.setConfig({ testTimeout: 30_000 })

describe('configuration schema', () => {
  it('requires only the state directory and reads the editable fields through references', () => {
    expect(() => Config({})).toThrow('stateDir')
    const read = machineOf(Config({ stateDir: join(dir, 'state') }))
    // Limits are volatile references that the loader updates in place and callers read when used.
    expect({ ...read, promptMaxChars: read.promptMaxChars.get(), admissionContextMaxPages: read.admissionContextMaxPages.get(),
      admissionContextTimeoutMs: read.admissionContextTimeoutMs.get() })
      .toEqual({ stateDir: join(dir, 'state'), promptMaxChars: 100000, admissionContextMaxPages: 10, admissionContextTimeoutMs: 15000 })
    expect(() => Config(minimal({ stateDir: 'relative/dir' }))).toThrow()
    expect(() => Config(minimal({ stateDir: '~/dir' }))).toThrow()
  })
  it('names keys the configuration does not define, and where the values of older keys live now', () => {
    const raw = minimal({ repository: 'acme/widgets', repositoryPath: '/srv/widgets', blockedCommands: [], author: { name: 'Alice' }, extra: 1 })
    expect(() => machineOf(Config(raw))).toThrow('keys it does not use: repository (now on the GitHub Source), repositoryPath (now in the prepare command of the Execution settings), blockedCommands (now in the Execution settings), author (now prompt text), extra;')
  })
})

describe('setup', () => {
  it('reads the App bot identity and bound repository, skipping worker shims without an api user fallback', async () => {
    const calls: string[][] = []
    const deployment = await resolveDeployment(machine(), { repository: 'acme/widgets', cli: 'gh' }, async argv => {
      calls.push(argv); return probe(argv)
    }, path)
    expect(deployment.repository).toBe('acme/widgets')
    expect(deployment.github).toEqual({ cli: join(dir, 'bin', 'gh'), login: 'agent-bot[bot]', noreply: '7+agent-bot[bot]@users.noreply.github.com' })
    expect(deployment).not.toHaveProperty('feishu')
    expect(calls.map(argv => argv.slice(1))).toEqual([['dazi-app', 'identity'], ['api', 'installation/repositories', '--paginate', '--slurp']])
    // Renaming requires reissuing the binding and reconfiguring the Source, never silent canonical rebinding.
    await expect(resolveDeployment(machine(), { repository: 'acme/gadgets', cli: 'gh' }, probe, path))
      .rejects.toEqual(setupError('github', 'repositoryUnreported', { repository: 'acme/gadgets' }))
  })
  it.each([
    ['account-era output', () => ({ login: 'alice', id: 7 })],
    ['unknown root field', () => identity({ token: 'secret-marker' })],
    ['wrong version', () => identity({ version: 2 })],
    ['missing field', () => { const { token_sha256: _, ...rest } = identity(); return rest }],
    ['extra app field', () => identity({ app: { id: 42, slug: 'agent-bot', token: 'secret-marker' } })],
    ['extra bot field', () => identity({ bot: { id: 7, login: 'agent-bot[bot]', type: 'Bot' } })],
    ['extra repository field', () => identity({ repository: { id: 99, full_name: 'acme/widgets', private: true } })],
    ['unsafe app id', () => identity({ app: { id: Number.MAX_SAFE_INTEGER + 1, slug: 'agent-bot' } })],
    ['zero bot id', () => identity({ bot: { id: 0, login: 'agent-bot[bot]' } })],
    ['fractional repository id', () => identity({ repository: { id: 1.5, full_name: 'acme/widgets' } })],
    ['uppercase slug', () => identity({ app: { id: 42, slug: 'Agent-Bot' } })],
    ['invalid slug', () => identity({ app: { id: 42, slug: '-agent-' } })],
    ['mismatched bot', () => identity({ bot: { id: 7, login: 'other[bot]' } })],
    ['invalid repository', () => identity({ repository: { id: 99, full_name: 'acme/..' } })],
    ['extra permission', () => identity({ permissions: { ...identity().permissions, administration: 'read' } })],
    ['missing permission', () => identity({ permissions: { contents: 'write' } })],
    ['read-only contents', () => identity({ permissions: { ...identity().permissions, contents: 'read' } })],
    ['elevated checks', () => identity({ permissions: { ...identity().permissions, checks: 'write' } })],
    ['expired', () => identity({ expires_at: new Date(Date.now() - 1).toISOString() })],
    ['excessive lifetime', () => identity({ expires_at: new Date(Date.now() + 3_661_000).toISOString() })],
    ['non-ISO expiry', () => identity({ expires_at: 'tomorrow' })],
    ['normalized invalid date', () => identity({ expires_at: '2026-02-30T00:00:00Z' })],
    ['invalid hash', () => identity({ token_sha256: 'secret-marker' })],
  ])('rejects invalid App identity: %s', async (_label, value) => {
    const run: Probe = async () => JSON.stringify(value())
    await expect(resolveDeployment(machine(), { repository: 'acme/widgets', cli: 'gh' }, run, path))
      .rejects.toEqual(setupError('github', 'agentCliNoAccount'))
  })
  it.each([
    ['no pages', []], ['unwrapped page', repositories[0]],
    ['missing repositories', [{ total_count: 1 }]], ['empty repository list', [{ total_count: 1, repositories: [] }]],
    ['wrong count', [{ ...repositories[0], total_count: 2 }]],
    ['changed ID', [{ total_count: 1, repositories: [{ id: 100, full_name: 'acme/widgets' }] }]],
    ['renamed repository', [{ total_count: 1, repositories: [{ id: 99, full_name: 'acme/gadgets' }] }]],
    ['second repository', [{ total_count: 1, repositories: [...repositories[0]!.repositories, { id: 100, full_name: 'acme/other' }] }]],
    ['extra repository on later page', [...repositories, { total_count: 1, repositories: [{ id: 100, full_name: 'acme/other' }] }]],
    ['inconsistent later count', [...repositories, { total_count: 2, repositories: [] }]],
  ])('rejects installation access: %s', async (_label, pages) => {
    const run: Probe = async argv => JSON.stringify(argv[1] === 'dazi-app' ? identity() : pages)
    await expect(resolveDeployment(machine(), { repository: 'acme/widgets', cli: 'gh' }, run, path))
      .rejects.toEqual(setupError('github', 'repositoryUnreported', { repository: 'acme/widgets' }))
  })
  it('does not disclose raw identity or subprocess errors and never falls back to a personal account', async () => {
    for (const stage of ['dazi-app', 'api']) {
      const calls: string[][] = []
      const run: Probe = async argv => {
        calls.push(argv)
        if (argv[1] === stage) throw new Error('secret-marker')
        return JSON.stringify(identity())
      }
      const error = await resolveDeployment(machine(), { repository: 'acme/widgets', cli: 'gh' }, run, path).catch(error => error)
      expect(error).toEqual(setupError('github', stage === 'api' ? 'repositoryUnreadable' : 'agentCliSignedOut'))
      expect(JSON.stringify(error)).not.toContain('secret-marker')
      expect(String(error)).not.toContain('secret-marker')
      expect(calls.some(argv => argv.includes('user'))).toBe(false)
    }
    const legacy = program(join(dir, 'bin', 'gh-legacy'), `case "$*" in\n  "api user") echo '{"login":"alice","id":7}' ;;\n  *) exit 1 ;;\nesac`)
    await expect(resolveDeployment(machine(), { repository: 'acme/widgets', cli: legacy }, probe, path))
      .rejects.toEqual(setupError('github', 'agentCliSignedOut'))
  })
  it('names what setup needs and where it is set', async () => {
    const needs = (place: string, code: string, values: Record<string, unknown>, github: unknown) =>
      expect(resolveDeployment(machine(), github, probe, path)).rejects.toEqual(setupError(place, code, values))
    const repository = 'acme/widgets'
    await needs('github', 'repositoryUnset', {}, { cli: 'gh' })
    await needs('github', 'agentCliUnset', {}, { repository })
    await needs('github', 'agentCliMissing', { output: `${join(dir, 'missing')} is not an executable file` }, { repository, cli: join(dir, 'missing') })
    await needs('github', 'agentCliMissing', { output: 'bin/gh must be a command name or an absolute path' }, { repository, cli: 'bin/gh' })
    await needs('github', 'agentCliSignedOut', {}, { repository, cli: program(join(dir, 'bin', 'gh-broken'), 'exit 1') })
    // A valid App identity is not enough without the live installation repository probe.
    const unreadable = program(join(dir, 'bin', 'gh-outsider'),
      `case "$*" in\n  "dazi-app identity") echo '${JSON.stringify(identity())}' ;;\n  *) echo 'HTTP 404' >&2; exit 1 ;;\nesac`)
    await needs('github', 'repositoryUnreadable', { account: 'agent-bot[bot]', repository }, { repository, cli: unreadable })
    await needs('github', 'agentCliNoAccount', {}, { repository, cli: program(join(dir, 'bin', 'gh-anonymous'), `echo '{}'`) })
    expect(() => executable('nothing-here', join(dir, 'bin'))).toThrow('nothing-here is not an executable file on PATH')
  })
  it('reads the Feishu bot from a bot-only lark-cli, or finds none when the Feishu Source names no CLI', async () => {
    expect(await resolveFeishuBot(machine(), {}, probe, path)).toBeUndefined()
    expect(await resolveFeishuBot(machine(), { cli: 'lark-cli' }, probe, path)).toEqual({ cli: join(dir, 'bin', 'lark-cli'), appId: 'cli_bot', brand: 'lark', botId: 'ou_bot', name: 'Widgets Bot' })
    const refuses = async (code: string, values: Record<string, unknown> = {}) => expect(resolveFeishuBot(machine(), { cli: 'lark-cli' }, probe, path)).rejects.toEqual(setupError('feishu', code, values))
    program(join(dir, 'bin', 'lark-cli'), lark({ identities: { bot: { status: 'ready' } } }))
    await refuses('feishuNoApp')
    program(join(dir, 'bin', 'lark-cli'), lark({ appId: 'cli_bot', identities: { bot: { status: 'missing' } } }))
    await refuses('feishuBotNotReady', { app: 'cli_bot', status: 'missing' })
    program(join(dir, 'bin', 'lark-cli'), lark({ appId: 'cli_bot', identities: { bot: { status: 'ready' } } }, 'off'))
    await refuses('feishuUserIdentity', { mode: 'off' })
    program(join(dir, 'bin', 'lark-cli'), lark({ appId: 'cli_bot', identities: { bot: { status: 'ready' } } }, 'bot', { code: 0, data: {} }))
    await refuses('feishuNoBot')
    program(join(dir, 'bin', 'lark-cli'), 'echo "not configured" >&2; exit 1')
    await refuses('feishuCliFailed', { output: expect.stringContaining('not configured') })
  })
})
