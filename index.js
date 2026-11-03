/**
 * dsh-no-auth — let the DSH Web GUI port grant access without the per-process
 * launch token, expose it to the LAN through a plugin-owned listener, and let
 * the whitelist / LAN listener be edited from the DSH Settings page.
 *
 * Capabilities:
 *
 * 1. Token bypass (wraps the live Connection service). Modes for the dsh
 *    listener configured through `dsh web --host <address>`:
 *    - `loopback` — shipped default; local access cannot be lost.
 *    - `open` — non-loopback listener with an empty `allowedClients`
 *      (`0.0.0.0/0` semantics).
 *    - `whitelist` — non-loopback listener with a non-empty valid list; the
 *      list is the only entry, clients outside get 403 even with a token.
 *
 * 2. LAN listener (`lanProxy`) — binds a LAN address/port and reverse-proxies
 *    HTTP and WebSocket traffic to the loopback dsh listener, applying the
 *    whitelist to the real client address. The listener injects the
 *    `crypto.randomUUID` polyfill for plain-HTTP LAN pages and rewrites the
 *    Connection client bundle so the LAN page keeps the loopback feature path.
 *
 * 3. Settings surface — `/api/dsh-no-auth/settings` (GET/POST) serves the
 *    Client settings section and applies changes live: whitelist updates take
 *    effect immediately, and a changed LAN host/port/enabled state restarts the
 *    listener. Changes persist under `$DSH_HOME/dsh-no-auth/settings.json`.
 *
 * Invalid whitelist entries fail closed: neither the bypass nor the LAN
 * listener is installed and the shipped token authentication stays enabled.
 *
 * A home-page boot marker (`__DSH_NO_AUTH__`) records the loaded build version,
 * active mode, and LAN listener.
 *
 * @module dsh-no-auth
 */
import { createRequire } from 'node:module'
import { createAccessPolicy, createClientGate, readOptions } from './lib/access.js'
import { applyNoAuth } from './lib/patch.js'
import {
  RANDOM_UUID_POLYFILL,
  readLanOptions,
  startLanProxy,
  validateLanOptions,
} from './lib/lan-proxy.js'
import {
  lanNeedsRestart,
  loadSavedSettings,
  mergeSavedLan,
  mergeSavedOptions,
  normalizeAllowedClients,
  normalizeLanProxy,
  settingsSnapshot,
  storeSavedSettings,
} from './lib/settings-store.js'

const require = createRequire(import.meta.url)
const VERSION = require('./package.json').version

/** Stable Cordis plugin name. */
export const name = 'dsh-no-auth'

/** Web GUI services whose live instance is wrapped. */
export const inject = ['connection', 'webServer']

/** Exact Fetch route the Client settings section reads and writes. */
const SETTINGS_PATH = '/api/dsh-no-auth/settings'

/**
 * Render any thrown value for a single-line diagnostic.
 * @param error - caught value.
 * @returns readable message text.
 */
function describeError(error) {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Render an `http://host:port` URL, bracketing IPv6 hosts.
 * @param host - bind address.
 * @param port - listening port.
 * @returns the URL text.
 */
function httpUrl(host, port) {
  const urlHost = host.includes(':') ? `[${host}]` : host
  return `http://${urlHost}:${String(port)}`
}

/**
 * Render the startup diagnostic for one active dsh-listener policy.
 * @param policy - resolved access policy.
 * @param host - configured bind address.
 * @returns the message logged after the patch is installed.
 */
function describePolicy(policy, host) {
  if (policy.mode === 'open') {
    return (
      `[dsh-no-auth] token authentication is disabled on ${host}: allowedClients is empty ` +
      '(treated as 0.0.0.0/0), so any client that can reach this address is admitted as the owner.'
    )
  }
  if (policy.mode === 'whitelist') {
    return (
      `[dsh-no-auth] token authentication is disabled on ${host} for ${String(policy.rangeCount)} ` +
      'client range(s); clients outside the list get 403 even with a valid token.'
    )
  }
  return (
    `[dsh-no-auth] token authentication is disabled on loopback ${host}: ` +
    'any local request that passes the Host/Origin fence is admitted as the owner.'
  )
}

/**
 * Log why the token bypass was not installed.
 * @param policy - inactive policy.
 * @param host - configured bind address, when known.
 */
function describeInactive(policy, host) {
  if (policy.mode !== 'off' || policy.reason === 'disabled') return
  if (policy.reason === 'invalid-entry' && policy.error !== undefined) {
    console.warn(
      `[dsh-no-auth] invalid allowedClients entry ${JSON.stringify(policy.error.entry)} ` +
        `(${policy.error.reason}); token authentication stays enabled.`,
    )
    return
  }
  if (policy.reason === 'invalid-whitelist' && policy.error !== undefined) {
    console.warn(
      `[dsh-no-auth] invalid allowedClients ${JSON.stringify(policy.error.entry)} ` +
        `(${policy.error.reason}); token authentication stays enabled.`,
    )
    return
  }
  if (policy.reason === 'unknown-bind') {
    console.warn('[dsh-no-auth] webServer.host is unavailable; token authentication stays enabled')
    return
  }
  console.warn(`[dsh-no-auth] not activating on ${String(host)} (${String(policy.reason)}); token authentication stays enabled`)
}

/**
 * Resolve the live dsh listener for the LAN proxy. Read per request so the
 * proxy can start before the Web carrier has bound its port.
 * @param ctx - Host plugin context.
 * @returns `{ host, port }`, or null when the listener is not ready or uses TLS.
 */
function resolveUpstream(ctx) {
  const port = ctx.webServer?.port
  const host = ctx.webServer?.host
  if (typeof port !== 'number' || port <= 0) return null
  if (typeof host !== 'string' || host === '') return null
  if (ctx.webServer.protocol !== 'http:') return null
  return { host, port }
}

/**
 * Facade whose mode/allows are read per request, so settings-page edits apply
 * to the already-installed Connection patch.
 * @param runtime - live plugin runtime.
 * @returns policy-shaped object.
 */
function policyFacade(runtime) {
  return {
    get mode() {
      return runtime.policyRef.current.mode
    },
    get rangeCount() {
      return runtime.policyRef.current.rangeCount
    },
    get whitelistIgnored() {
      return runtime.policyRef.current.whitelistIgnored
    },
    allows: (address) => runtime.policyRef.current.allows(address),
  }
}

/**
 * Facade for the LAN proxy gate, so whitelist edits need no listener restart.
 * @param runtime - live plugin runtime.
 * @returns gate-shaped object.
 */
function gateFacade(runtime) {
  return {
    get mode() {
      return runtime.gateRef.current.mode
    },
    get rangeCount() {
      return runtime.gateRef.current.rangeCount
    },
    allows: (address) => runtime.gateRef.current.allows(address),
  }
}

/**
 * Start the LAN listener for the runtime's current LAN config, closing any
 * previous one first.
 * @param ctx - Host plugin context.
 * @param runtime - live plugin runtime.
 */
function startLan(ctx, runtime) {
  stopLan(runtime)
  const lan = runtime.lan
  if (!lan.enabled) return
  runtime.lanError = null
  startLanProxy({
    host: lan.host,
    port: lan.port,
    gate: gateFacade(runtime),
    resolveUpstream: () => resolveUpstream(ctx),
    patchClientBundle: lan.patchClientBundle,
    onLog: (message) => console.warn(`[dsh-no-auth] ${message}`),
  })
    .then((handle) => {
      if (runtime.disposed) {
        void handle.close()
        return
      }
      runtime.lanHandle = handle
      runtime.lanListening = true
      runtime.lanPort = handle.address?.port ?? lan.port
      const gate = runtime.gateRef.current
      console.warn(
        `[dsh-no-auth] LAN listener is serving ${httpUrl(lan.host, runtime.lanPort)} for ` +
          (gate.mode === 'whitelist'
            ? `${String(gate.rangeCount)} client range(s) only`
            : 'every reachable client (allowedClients is empty)') +
          '. Configure it from Settings → dsh-no-auth.',
      )
    })
    .catch((error) => {
      if (runtime.disposed) return
      runtime.lanListening = false
      runtime.lanPort = undefined
      runtime.lanError = describeError(error)
      console.warn(
        `[dsh-no-auth] LAN listener could not start on ${lan.host}:${String(lan.port)}: ` +
          `${runtime.lanError}. Another process or reverse proxy may own that port; ` +
          'stop it or change the LAN port in Settings → dsh-no-auth.',
      )
    })
}

/**
 * Stop the LAN listener, if any.
 * @param runtime - live plugin runtime.
 */
function stopLan(runtime) {
  if (runtime.lanHandle !== null) {
    const handle = runtime.lanHandle
    runtime.lanHandle = null
    runtime.lanListening = false
    runtime.lanPort = undefined
    void handle.close()
  }
}

/**
 * Build the JSON answer for GET and successful POST calls.
 * @param ctx - Host plugin context.
 * @param runtime - live plugin runtime.
 * @returns JSON-serializable state.
 */
function snapshot(ctx, runtime) {
  return {
    ok: true,
    version: VERSION,
    settings: settingsSnapshot(runtime.options, runtime.lan),
    status: {
      mode: runtime.policyRef.current.mode,
      ranges: runtime.gateRef.current.rangeCount,
      dsh: {
        host: ctx.webServer?.host,
        port: ctx.webServer?.port,
      },
      lan: {
        enabled: runtime.lan.enabled,
        host: runtime.lan.host,
        port: runtime.lan.port,
        listening: runtime.lanListening,
        url: runtime.lanListening ? httpUrl(runtime.lan.host, runtime.lanPort ?? runtime.lan.port) : null,
        error: runtime.lanError,
      },
    },
  }
}

/**
 * Validate and apply one settings payload, persisting it when accepted.
 * @param ctx - Host plugin context.
 * @param runtime - live plugin runtime.
 * @param payload - parsed POST body.
 * @returns JSON-serializable answer (`ok:false` on validation failure).
 */
function applySettings(ctx, runtime, payload) {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, error: 'settings payload must be an object' }
  }
  const clients = normalizeAllowedClients(
    payload.allowedClients === undefined ? runtime.options.allowedClients : payload.allowedClients,
  )
  if (!clients.ok) return { ok: false, error: clients.error }

  const lan = normalizeLanProxy(payload.lanProxy === undefined ? runtime.lan : payload.lanProxy, runtime.lan)
  if (!lan.ok) return { ok: false, error: lan.error }

  const restart = lanNeedsRestart(runtime.lan, lan.value)
  runtime.options = { ...runtime.options, allowedClients: clients.value }
  runtime.lan = lan.value
  runtime.gateRef.current = createClientGate(runtime.options)
  runtime.policyRef.current = createAccessPolicy(runtime.options, ctx.webServer?.host)

  try {
    storeSavedSettings(settingsSnapshot(runtime.options, runtime.lan))
  } catch (error) {
    console.warn(`[dsh-no-auth] could not persist settings: ${describeError(error)}`)
    return { ok: false, error: `could not persist settings: ${describeError(error)}` }
  }

  if (restart) startLan(ctx, runtime)
  return snapshot(ctx, runtime)
}

/**
 * Handle one settings GET/POST request.
 * @param ctx - Host plugin context.
 * @param runtime - live plugin runtime.
 * @param request - Fetch request.
 * @returns Fetch response.
 */
async function handleSettings(ctx, runtime, request) {
  if (request.method === 'GET') return Response.json(snapshot(ctx, runtime))
  let payload
  try {
    payload = await request.json()
  } catch {
    return Response.json({ ok: false, error: 'body is not JSON' }, { status: 400 })
  }
  try {
    const result = applySettings(ctx, runtime, payload)
    return Response.json(result, { status: result.ok ? 200 : 400 })
  } catch (error) {
    return Response.json({ ok: false, error: describeError(error) }, { status: 500 })
  }
}

/**
 * Install the token bypass, the LAN listener, and the settings endpoint for
 * this Web profile.
 * @param ctx - Host plugin context carrying `connection` and `webServer`.
 * @param config - patch row config (see `readOptions` and `readLanOptions`).
 */
export function apply(ctx, config) {
  try {
    const saved = loadSavedSettings()
    const options = mergeSavedOptions(readOptions(config), saved)
    if (!options.enabled) return

    const host = ctx.webServer?.host
    const policy = createAccessPolicy(options, host)
    if (policy.mode === 'off') {
      describeInactive(policy, host)
      return
    }

    const lan = mergeSavedLan(readLanOptions(config?.lanProxy), saved)
    const lanError = validateLanOptions(lan)
    if (lanError !== null) console.warn(`[dsh-no-auth] LAN listener disabled: ${lanError}`)
    if (lanError !== null) lan.enabled = false
    const initialGate = lan.enabled ? createClientGate(options) : null
    if (initialGate !== null && initialGate.mode === 'off') {
      console.warn(
        `[dsh-no-auth] LAN listener disabled: allowedClients is invalid ` +
          `(${initialGate.error?.entry ?? ''}: ${initialGate.error?.reason ?? 'unknown'}).`,
      )
      lan.enabled = false
    }

    /** @type {{ options: any, lan: any, policyRef: { current: any }, gateRef: { current: any }, lanHandle: any, lanListening: boolean, lanPort: number | undefined, lanError: string | null, disposed: boolean }} */
    const runtime = {
      options,
      lan,
      policyRef: { current: policy },
      gateRef: { current: initialGate ?? createClientGate(options) },
      lanHandle: null,
      lanListening: false,
      lanPort: undefined,
      lanError: null,
      disposed: false,
    }

    /** Whether the bypass is currently installed (drives index injections). */
    let active = false
    ctx.on('webserver/index-inject', (table) => {
      if (!active) return
      table.push({
        kind: 'global',
        name: '__DSH_NO_AUTH__',
        value: {
          version: VERSION,
          mode: runtime.policyRef.current.mode,
          ranges: runtime.gateRef.current.rangeCount,
          lan: runtime.lan.enabled ? `${runtime.lan.host}:${String(runtime.lan.port)}` : null,
        },
      })
      if (runtime.lan.enabled) table.push({ kind: 'script', placement: 'head', text: RANDOM_UUID_POLYFILL })
    })

    if (policy.whitelistIgnored === true) {
      console.warn(
        '[dsh-no-auth] allowedClients is not applied to the loopback dsh listener itself; ' +
          'it gates the plugin LAN listener and any non-loopback dsh bind.',
      )
    }

    ctx.effect(() => {
      try {
        const restore = applyNoAuth(ctx.connection, options, policyFacade(runtime))
        if (restore === null) {
          console.warn(
            '[dsh-no-auth] unsupported Connection service shape for this DSH version; ' +
              'token authentication stays enabled. Check dsh-no-auth against the running dsh release.',
          )
          return
        }
        ctx.connection.fetch.register({
          path: SETTINGS_PATH,
          methods: ['GET', 'POST'],
          requestBody: 'buffered',
          fetch: (request) => handleSettings(ctx, runtime, request),
        })
        active = true
        console.warn(describePolicy(runtime.policyRef.current, host))
        console.warn(
          `[dsh-no-auth] settings are available in Settings → dsh-no-auth (GET/POST ${SETTINGS_PATH}).`,
        )
        startLan(ctx, runtime)

        return () => {
          runtime.disposed = true
          active = false
          stopLan(runtime)
          restore()
        }
      } catch (error) {
        console.warn(`[dsh-no-auth] could not install the bypass; token authentication stays enabled: ${describeError(error)}`)
      }
    }, 'dsh-no-auth: connection authentication bypass')
  } catch (error) {
    console.warn(`[dsh-no-auth] activation failed; token authentication stays enabled: ${describeError(error)}`)
  }
}
