/**
 * Client-address policy for the token bypass.
 *
 * This module owns the pure parts: reading the patch row's config, classifying
 * the listener, parsing IP / CIDR whitelist entries (IPv4 and IPv6), matching a
 * request's source address, and deciding which access mode is active.
 *
 * Semantics decided for this plugin:
 * - A loopback listener already only serves this machine; the whitelist is not
 *   applied there (it is reported as ignored) so local access cannot be lost.
 * - Any other listener with an empty `allowedClients` treats every reachable
 *   client as allowed (`0.0.0.0/0` semantics).
 * - A non-empty, fully valid whitelist is the *only* entry: clients outside it
 *   are refused even when they hold a valid launch token or cookie.
 * - An invalid whitelist fails closed: the bypass is not installed and the
 *   shipped token authentication stays in place.
 *
 * @module dsh-no-auth/access
 */

/** Defaults applied when the patch row omits a field. */
const DEFAULTS = Object.freeze({
  enabled: true,
  keepTokenInUrl: false,
})

/** Exactly four dotted decimal octets; range validation happens separately. */
const IPV4_PATTERN = /^\d{1,3}(?:\.\d{1,3}){3}$/

/** One hexadecimal IPv6 group. */
const IPV6_GROUP_PATTERN = /^[0-9a-f]{1,4}$/

/**
 * Read one boolean option, falling back when the authored value is not boolean.
 * @param value - raw authored value.
 * @param fallback - value used for a missing or non-boolean field.
 * @returns the validated boolean.
 */
function readBoolean(value, fallback) {
  return typeof value === 'boolean' ? value : fallback
}

/**
 * Resolve the patch row's config into validated options. `allowedClients` is
 * passed through untouched so `createAccessPolicy` can fail closed on a
 * non-array or invalid entry instead of silently treating it as empty.
 * @param config - raw loader config, possibly undefined.
 * @returns resolved patch options.
 */
export function readOptions(config) {
  const raw = config !== null && typeof config === 'object' ? config : {}
  return {
    enabled: readBoolean(raw.enabled, DEFAULTS.enabled),
    keepTokenInUrl: readBoolean(raw.keepTokenInUrl, DEFAULTS.keepTokenInUrl),
    allowedClients: raw.allowedClients === undefined ? [] : raw.allowedClients,
  }
}

/**
 * Parse dotted decimal IPv4 text into a 32-bit value.
 * @param text - candidate IPv4 text.
 * @returns the 32-bit value, or null when the text is not IPv4.
 */
function ipv4ToBigInt(text) {
  if (!IPV4_PATTERN.test(text)) return null
  let value = 0n
  for (const part of text.split('.')) {
    const octet = Number(part)
    if (octet > 255) return null
    value = (value << 8n) | BigInt(octet)
  }
  return value
}

/**
 * Parse IPv6 text into a 128-bit value, including `::` compression and an
 * embedded dotted-quad IPv4 tail.
 * @param text - candidate IPv6 text.
 * @returns the 128-bit value, or null when the text is not IPv6.
 */
function ipv6ToBigInt(text) {
  let source = text
  if (source.includes('.')) {
    const lastColon = source.lastIndexOf(':')
    if (lastColon < 0) return null
    const ipv4 = ipv4ToBigInt(source.slice(lastColon + 1))
    if (ipv4 === null) return null
    const high = ((ipv4 >> 16n) & 0xffffn).toString(16)
    const low = (ipv4 & 0xffffn).toString(16)
    source = `${source.slice(0, lastColon + 1)}${high}:${low}`
  }

  const compressed = source.split('::')
  if (compressed.length > 2) return null
  const head = compressed[0] === '' ? [] : compressed[0].split(':')
  const tail = compressed.length === 2 && compressed[1] !== '' ? compressed[1].split(':') : []
  const explicit = head.length + tail.length
  if (compressed.length === 1) {
    if (explicit !== 8) return null
  } else if (explicit > 7) {
    return null
  }

  const groups = [...head, ...Array(8 - explicit).fill('0'), ...tail]
  if (groups.length !== 8) return null
  let value = 0n
  for (const group of groups) {
    if (!IPV6_GROUP_PATTERN.test(group)) return null
    value = (value << 16n) | BigInt(parseInt(group, 16))
  }
  return value
}

/**
 * Normalize an address into a family, width, and integer value. IPv4-mapped
 * IPv6 forms (`::ffff:a.b.c.d` and their hexadecimal spellings) are reduced to
 * IPv4 so a whitelist entry of either spelling matches one client family.
 * @param raw - address text, possibly bracketed or carrying an interface zone.
 * @returns normalized address, or null when unparseable.
 */
function normalizeAddress(raw) {
  if (typeof raw !== 'string') return null
  let text = raw.trim().toLowerCase()
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1)
  const zone = text.indexOf('%')
  if (zone >= 0) text = text.slice(0, zone)
  if (text === '') return null

  const ipv4 = ipv4ToBigInt(text)
  if (ipv4 !== null) return { family: 4, bits: 32, value: ipv4 }

  const ipv6 = ipv6ToBigInt(text)
  if (ipv6 === null) return null
  if (ipv6 >> 32n === 0xffffn) {
    return { family: 4, bits: 32, value: ipv6 & 0xffffffffn }
  }
  return { family: 6, bits: 128, value: ipv6 }
}

/**
 * Parse one whitelist entry: a bare IPv4/IPv6 address or an `address/prefix`
 * CIDR form. An IPv4-mapped IPv6 spelling may carry its 96-bit offset prefix
 * (`::ffff:10.0.0.0/104`, equivalent to `10.0.0.0/8`).
 * @param entry - authored whitelist entry.
 * @returns parsed range, or `{ error }` describing why it is invalid.
 */
export function parseClientEntry(entry) {
  if (typeof entry !== 'string') return { error: 'entry must be a string' }
  const text = entry.trim()
  if (text === '') return { error: 'entry is empty' }

  const slash = text.indexOf('/')
  if (slash !== -1 && text.indexOf('/', slash + 1) !== -1) {
    return { error: 'entry has more than one "/"' }
  }
  const addressText = slash === -1 ? text : text.slice(0, slash)
  const prefixText = slash === -1 ? undefined : text.slice(slash + 1)
  const address = normalizeAddress(addressText)
  if (address === null) return { error: 'entry is not an IPv4 or IPv6 address' }

  let prefix = address.bits
  if (prefixText !== undefined) {
    if (!/^\d{1,3}$/.test(prefixText)) return { error: 'prefix is not a decimal number' }
    prefix = Number(prefixText)
    if (prefix > address.bits) {
      const mapped = addressText.includes(':') && address.family === 4
      if (!mapped || prefix < 96) {
        return { error: `prefix must be 0-${address.bits}` }
      }
      prefix -= 96
      if (prefix > address.bits) return { error: `prefix must be 0-${address.bits}` }
    }
  }

  return { family: address.family, bits: address.bits, prefix, value: address.value }
}

/**
 * Pre-compile whitelist entries into a matcher.
 * @param entries - authored `allowedClients` value (callers pass an array).
 * @returns a matcher, or `{ error: { entry, reason } }` for the first invalid entry.
 */
export function createClientMatcher(entries) {
  if (!Array.isArray(entries)) {
    return { error: { entry: String(entries), reason: 'allowedClients must be an array of IP or CIDR strings' } }
  }
  const ranges = []
  for (const entry of entries) {
    const parsed = parseClientEntry(entry)
    if (parsed.error !== undefined) {
      return { error: { entry: typeof entry === 'string' ? entry : String(entry), reason: parsed.error } }
    }
    ranges.push(parsed)
  }
  return {
    size: ranges.length,
    /**
     * Whether a client source address matches any configured range.
     * @param remoteAddress - `req.socket.remoteAddress` style text.
     * @returns true only for a parseable address inside one of the ranges.
     */
    allows(remoteAddress) {
      const remote = normalizeAddress(remoteAddress)
      if (remote === null) return false
      for (const range of ranges) {
        if (range.family !== remote.family) continue
        const shift = BigInt(range.bits - range.prefix)
        if (remote.value >> shift === range.value >> shift) return true
      }
      return false
    },
  }
}

/**
 * Normalize a bind address the way the Web carrier reads it before the
 * loopback decision: lower case, no trailing dot or interface zone, mapped
 * IPv4 forms reduced to their IPv4 text, and the dotted-quad IPv6 tail
 * (`::0.0.0.1`, the address's own low 32 bits) reduced to `::1`.
 * @param host - configured bind address.
 * @returns normalized address text.
 */
function normalizeBindHost(host) {
  let normalized = String(host).trim().toLowerCase()
  if (normalized.endsWith('.')) normalized = normalized.slice(0, -1)
  const zone = normalized.indexOf('%')
  if (zone >= 0) normalized = normalized.slice(0, zone)
  if (normalized === '::0.0.0.1') return '::1'
  if (normalized.startsWith('::ffff:')) normalized = normalized.slice('::ffff:'.length)
  return normalized
}

/**
 * Decide whether a configured bind address keeps the listener on this machine.
 * @param host - configured bind address from `webServer.host`.
 * @returns true for `::1`, mapped forms of it, and any address in `127.0.0.0/8`.
 */
export function isLoopbackBind(host) {
  const normalized = normalizeBindHost(host)
  if (normalized === '::1') return true
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized)
}

/**
 * Resolve the client gate for the plugin-owned LAN listener. Unlike the dsh
 * listener policy, this gate always applies the whitelist when one is
 * configured: the LAN listener sees real client addresses because it owns the
 * socket that the network dials.
 * @param options - resolved patch options from `readOptions`.
 * @returns `open` gate for an empty list, `whitelist` for validated ranges, or
 *   `off` (with `error`) so the caller can fail closed.
 */
export function createClientGate(options) {
  if (!Array.isArray(options.allowedClients)) {
    return {
      mode: 'off',
      reason: 'invalid-whitelist',
      error: {
        entry: String(options.allowedClients),
        reason: 'allowedClients must be an array of IP or CIDR strings',
      },
      rangeCount: 0,
      allows: () => false,
    }
  }
  if (options.allowedClients.length === 0) {
    return { mode: 'open', rangeCount: 0, allows: () => true }
  }
  const matcher = createClientMatcher(options.allowedClients)
  if (matcher.error !== undefined) {
    return { mode: 'off', reason: 'invalid-entry', error: matcher.error, rangeCount: 0, allows: () => false }
  }
  return {
    mode: 'whitelist',
    rangeCount: matcher.size,
    allows: (remoteAddress) => matcher.allows(remoteAddress),
  }
}

/**
 * Extract the TCP client address from an HTTP request or upgrade request.
 * @param request - node:http request carrying `socket` (or legacy `connection`).
 * @returns the source address text, or undefined when unavailable.
 */
export function clientAddressOf(request) {
  const socket = request?.socket ?? request?.connection
  const address = socket?.remoteAddress
  return typeof address === 'string' ? address : undefined
}

/** An inactive policy that refuses nothing and permits nothing. */
function offPolicy(reason, error) {
  return { mode: 'off', reason, error, rangeCount: 0, allows: () => false }
}

/**
 * Resolve the active access mode for this listener and config.
 * @param options - resolved patch options from `readOptions`.
 * @param bindHost - `webServer.host` of the active listener.
 * @returns policy with `mode`, `allows(remoteAddress)`, and diagnostics.
 */
export function createAccessPolicy(options, bindHost) {
  if (!options.enabled) return offPolicy('disabled')
  if (typeof bindHost !== 'string' || bindHost === '') return offPolicy('unknown-bind')

  let matcher = null
  if (!Array.isArray(options.allowedClients)) {
    return offPolicy('invalid-whitelist', {
      entry: String(options.allowedClients),
      reason: 'allowedClients must be an array of IP or CIDR strings',
    })
  }
  if (options.allowedClients.length > 0) {
    matcher = createClientMatcher(options.allowedClients)
    if (matcher.error !== undefined) return offPolicy('invalid-entry', matcher.error)
  }

  if (isLoopbackBind(bindHost)) {
    return {
      mode: 'loopback',
      rangeCount: 0,
      allows: () => true,
      whitelistIgnored: matcher !== null,
    }
  }
  if (matcher === null) {
    return { mode: 'open', rangeCount: 0, allows: () => true }
  }
  return {
    mode: 'whitelist',
    rangeCount: matcher.size,
    allows: (remoteAddress) => matcher.allows(remoteAddress),
  }
}
