/**
 * Durable settings for the dsh-no-auth plugin, editable from the DSH Settings
 * page.
 *
 * The bundle patch supplies defaults; this file stores the user's overrides
 * under `$DSH_HOME/dsh-no-auth/settings.json`. The Host settings endpoint
 * validates every change with the same IP/CIDR parser the runtime uses, applies
 * it to the live verification/gate, and rewrites this file atomically.
 *
 * Only the settings the page edits are persisted; everything else keeps coming
 * from the bundle patch.
 *
 * @module dsh-no-auth/settings-store
 */
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import { createClientMatcher, isLoopbackBind } from './access.js'
import { validateLanOptions } from './lan-proxy.js'

/** Environment variable naming the Harness home. */
const DSH_HOME_ENV = 'DSH_HOME'

/**
 * Resolve the Harness home with the same precedence the runtime uses:
 * `$DSH_HOME` when non-empty, otherwise `~/.dsh`.
 * @returns absolute Harness home path.
 */
export function dshHome() {
  const configured = process.env[DSH_HOME_ENV]
  if (typeof configured === 'string' && configured.trim() !== '') return configured.trim()
  return join(homedir(), '.dsh')
}

/**
 * Absolute path of this plugin's persisted settings file.
 * @returns the settings file path.
 */
export function settingsFilePath() {
  return join(dshHome(), 'dsh-no-auth', 'settings.json')
}

/**
 * Read persisted settings, ignoring absent or malformed files.
 * @returns the stored object, or null when there is nothing usable.
 */
export function loadSavedSettings() {
  try {
    const text = readFileSync(settingsFilePath(), 'utf8')
    const parsed = JSON.parse(text)
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null
  } catch {
    return null
  }
}

/**
 * Persist settings atomically (write a sibling temporary file, then rename).
 * @param settings - the object to store.
 */
export function storeSavedSettings(settings) {
  const file = settingsFilePath()
  mkdirSync(dirname(file), { recursive: true })
  const temporary = `${file}.tmp`
  writeFileSync(temporary, `${JSON.stringify(settings, null, 2)}\n`)
  renameSync(temporary, file)
}

/**
 * Validate and normalize a whitelist submitted by the settings page.
 * @param input - authored `allowedClients` value.
 * @returns `{ ok: true, value }` with trimmed entries, or `{ ok: false, error }`.
 */
export function normalizeAllowedClients(input) {
  if (!Array.isArray(input)) return { ok: false, error: 'allowedClients must be an array of IP or CIDR strings' }
  if (input.some((entry) => typeof entry !== 'string')) {
    return { ok: false, error: 'allowedClients entries must be strings' }
  }
  const value = input
    .flatMap((entry) => entry.split(/[\s,，;；]+/u))
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
  if (value.length > 0) {
    const matcher = createClientMatcher(value)
    if (matcher.error !== undefined) {
      return { ok: false, error: `invalid entry ${JSON.stringify(matcher.error.entry)}: ${matcher.error.reason}` }
    }
  }
  return { ok: true, value }
}

/**
 * Validate and normalize a `lanProxy` block submitted by the settings page.
 * @param input - authored `lanProxy` value.
 * @param current - the effective block, whose hidden fields are preserved.
 * @returns `{ ok: true, value }` or `{ ok: false, error }`.
 */
export function normalizeLanProxy(input, current) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'lanProxy must be an object' }
  }
  const enabled = typeof input.enabled === 'boolean' ? input.enabled : current.enabled
  const host = typeof input.host === 'string' ? input.host.trim() : current.host
  const port = input.port === undefined ? current.port : Number(input.port)
  const patchClientBundle =
    typeof input.patchClientBundle === 'boolean' ? input.patchClientBundle : current.patchClientBundle
  const candidate = { enabled, host, port, patchClientBundle }
  const error = validateLanOptions(candidate)
  if (error !== null) return { ok: false, error }
  return { ok: true, value: candidate }
}

/**
 * Apply persisted overrides on top of the bundle-patch options.
 * @param options - resolved options from `readOptions`.
 * @param saved - persisted settings from `loadSavedSettings`.
 * @returns merged options.
 */
export function mergeSavedOptions(options, saved) {
  const merged = { ...options }
  if (saved !== null && saved.allowedClients !== undefined) {
    const normalized = normalizeAllowedClients(saved.allowedClients)
    if (normalized.ok) merged.allowedClients = normalized.value
  }
  return merged
}

/**
 * Apply persisted overrides on top of the bundle-patch LAN config.
 * @param lan - resolved LAN options from `readLanOptions`.
 * @param saved - persisted settings from `loadSavedSettings`.
 * @returns merged LAN options.
 */
export function mergeSavedLan(lan, saved) {
  if (saved === null || saved.lanProxy === undefined) return lan
  const merged = normalizeLanProxy({ ...lan, ...saved.lanProxy }, lan)
  return merged.ok ? merged.value : lan
}

/**
 * Snapshot of the settings fields the page owns, for a GET response.
 * @param options - effective options.
 * @param lan - effective LAN options.
 * @returns plain JSON settings.
 */
export function settingsSnapshot(options, lan) {
  return {
    allowedClients: Array.isArray(options.allowedClients) ? options.allowedClients : [],
    lanProxy: {
      enabled: lan.enabled,
      host: lan.host,
      port: lan.port,
      patchClientBundle: lan.patchClientBundle,
    },
  }
}

/**
 * Whether a LAN listener restart is needed after a settings change.
 * @param previous - effective LAN options before the change.
 * @param next - effective LAN options after the change.
 * @returns true when bind address, port, or enabled state changed.
 */
export function lanNeedsRestart(previous, next) {
  return previous.enabled !== next.enabled || previous.host !== next.host || previous.port !== next.port
}

/**
 * Whether the dsh-listener visibility gate needs to be recomputed.
 * @param bindHost - the active dsh bind address.
 * @returns true for a non-loopback listener.
 */
export function bindNeedsClientGate(bindHost) {
  return typeof bindHost === 'string' && bindHost !== '' && !isLoopbackBind(bindHost)
}
