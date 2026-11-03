/**
 * Plugin-owned LAN listener: an HTTP + WebSocket reverse proxy that exposes the
 * loopback DSH listener to the local network and applies the client IP/CIDR
 * whitelist itself.
 *
 * DSH binds one concrete address at startup, so a running instance cannot be
 * moved onto a LAN address. This listener solves that: it binds the configured
 * LAN interface/port, forwards to the dsh listener (usually 127.0.0.1), rewrites
 * `Host`/`Origin` to the upstream authority so the dsh Host/Origin fence passes,
 * and refuses clients outside `allowedClients` (the same list the token bypass
 * uses) before any bytes reach dsh.
 *
 * It also supplies the two browser fixes the LAN path needs, mirroring what a
 * typical DSH reverse-proxy deployment does by hand:
 * - an injected `crypto.randomUUID` polyfill for plain-HTTP LAN pages (non
 *   secure contexts do not expose `crypto.randomUUID`, which some client
 *   plugins call directly);
 * - an optional rewrite of the Connection client bundle so the LAN page reports
 *   `isLoopback: true`, keeping loopback-only settings actions available.
 *
 * @module dsh-no-auth/lan-proxy
 */
import http from 'node:http'
import net from 'node:net'

/** Anchor for the Connection client's `isLoopback` assignment (v0.2.1-rc.5). */
export const LOOPBACK_ASSIGNMENT_ANCHOR =
  'isLoopback: transport?.ownsHost === true || pageLocation === void 0 || isLoopbackHostname(pageLocation.hostname),'
/** Replacement keeping the LAN page on the loopback feature path. */
export const LOOPBACK_ASSIGNMENT_PATCH = 'isLoopback: true,'

/** Anchor for the shared loopback hostname classifier. */
export const LOOPBACK_HOSTNAME_ANCHOR =
  'if (hostname === "localhost" || hostname === "[::1]") return true;'
/** Replacement making the classifier accept every page hostname. */
export const LOOPBACK_HOSTNAME_PATCH = 'if (true) return true;'

/** Hop-by-hop headers that must not be forwarded between HTTP hops. */
const HOP_BY_HOP = [
  'connection',
  'keep-alive',
  'proxy-connection',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]

/** Inline polyfill for `crypto.randomUUID` on non-secure origins. */
export const RANDOM_UUID_POLYFILL = `if (window.crypto && !window.crypto.randomUUID) {
  window.crypto.randomUUID = function () {
    var c = new Uint8Array(16);
    crypto.getRandomValues(c);
    c[6] = (c[6] & 0x0f) | 0x40;
    c[8] = (c[8] & 0x3f) | 0x80;
    var h = "";
    for (var i = 0; i < c.length; i++) {
      if (i === 4 || i === 6 || i === 8 || i === 10) h += "-";
      h += c[i].toString(16).padStart(2, "0");
    }
    return h;
  };
}`

/**
 * Read the `lanProxy` config block.
 * @param raw - authored `config.lanProxy`, possibly undefined.
 * @returns complete LAN listener options.
 */
export function readLanOptions(raw) {
  const defaults = { enabled: false, host: '', port: 0, patchClientBundle: true }
  if (raw === undefined || raw === null) return defaults
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return { ...defaults, error: 'lanProxy must be an object' }
  }
  return {
    enabled: typeof raw.enabled === 'boolean' ? raw.enabled : true,
    host: typeof raw.host === 'string' ? raw.host.trim() : '',
    port: Number.isInteger(raw.port) ? raw.port : 0,
    patchClientBundle: typeof raw.patchClientBundle === 'boolean' ? raw.patchClientBundle : true,
  }
}

/**
 * Validate LAN listener options.
 * @param options - result of `readLanOptions`.
 * @returns an error message, or null when usable.
 */
export function validateLanOptions(options) {
  if (options.error !== undefined) return options.error
  if (!options.enabled) return null
  if (options.host === '') return 'lanProxy.host is required: one concrete local interface address'
  if (options.host === '0.0.0.0' || options.host === '::') {
    return 'lanProxy.host must be one concrete address, not a wildcard'
  }
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    return 'lanProxy.port must be an integer between 1 and 65535'
  }
  return null
}

/**
 * Format a host and port as an HTTP authority, bracketing IPv6 hosts.
 * @param host - upstream address text.
 * @param port - upstream port.
 * @returns the authority text.
 */
function formatAuthority(host, port) {
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`
}

/**
 * Extract the request pathname without trusting malformed request targets.
 * @param requestUrl - raw `req.url` value.
 * @returns the pathname, or `/` when unparseable.
 */
function pathnameOf(requestUrl) {
  try {
    return new URL(requestUrl ?? '/', 'http://lan.invalid').pathname
  } catch {
    return '/'
  }
}

/**
 * Build upstream request headers: drop hop-by-hop fields, point Host/Origin at
 * the dsh listener, and request identity encoding where the client bundle is
 * rewritten.
 * @param input - incoming request headers.
 * @param upstream - resolved upstream address.
 * @param pathname - request pathname.
 * @param patchClientBundle - whether `/plugins/` JavaScript is rewritten.
 * @returns headers for the upstream request.
 */
function rewriteHeaders(input, upstream, pathname, patchClientBundle) {
  const headers = { ...input }
  for (const name of HOP_BY_HOP) delete headers[name]
  const authority = formatAuthority(upstream.host, upstream.port)
  headers.host = authority
  if (headers.origin !== undefined) headers.origin = `http://${authority}`
  if (patchClientBundle && pathname.startsWith('/plugins/')) headers['accept-encoding'] = 'identity'
  return headers
}

/**
 * Apply the client-bundle loopback patch.
 * @param source - served JavaScript text.
 * @returns the patched text (unchanged when an anchor is absent).
 */
export function patchClientBundleJs(source) {
  let patched = source.replace(LOOPBACK_ASSIGNMENT_ANCHOR, LOOPBACK_ASSIGNMENT_PATCH)
  patched = patched.replace(LOOPBACK_HOSTNAME_ANCHOR, LOOPBACK_HOSTNAME_PATCH)
  return patched
}

/**
 * Write one complete plain-text response.
 * @param response - response not yet committed.
 * @param status - HTTP status code.
 * @param body - response body text.
 */
function writeText(response, status, body) {
  if (response.headersSent) {
    response.destroy()
    return
  }
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'text/plain; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
  })
  response.end(body)
}

/**
 * Start the LAN HTTP/WebSocket reverse proxy.
 * @param options - listener options.
 * @param options.host - LAN interface address to bind.
 * @param options.port - LAN port to bind.
 * @param options.gate - client-address gate from `createClientGate`.
 * @param options.resolveUpstream - returns `{ host, port }` of the dsh listener, or null.
 * @param options.patchClientBundle - whether to rewrite the Connection client bundle.
 * @param options.onLog - optional diagnostic sink.
 * @returns handle with `address` and an async `close`.
 */
export async function startLanProxy(options) {
  const { host, port, gate, resolveUpstream, patchClientBundle = true, onLog } = options
  const sockets = new Set()

  const server = http.createServer((request, response) => {
    if (gate.allows(request.socket.remoteAddress) !== true) {
      writeText(response, 403, 'dsh-no-auth: client address is not allowed\n')
      return
    }
    const upstream = resolveUpstream()
    if (upstream === null) {
      writeText(response, 503, 'dsh-no-auth: the dsh listener is not ready\n')
      return
    }
    forwardHttp(request, response, upstream, patchClientBundle)
  })

  server.on('upgrade', (request, socket, head) => {
    socket.on('error', () => {})
    if (gate.allows(request.socket.remoteAddress) !== true) {
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
      return
    }
    const upstream = resolveUpstream()
    if (upstream === null) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n')
      return
    }
    forwardUpgrade(request, socket, head, upstream, patchClientBundle)
  })

  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')
  })

  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening)
      reject(error)
    }
    const onListening = () => {
      server.off('error', onError)
      resolve()
    }
    server.once('error', onError)
    server.once('listening', onListening)
    server.listen(port, host)
  })
  server.on('error', (error) => onLog?.(`lan listener error: ${error.message}`))

  return {
    address: server.address(),
    async close() {
      await new Promise((resolve) => {
        server.close(() => resolve())
        for (const socket of sockets) socket.destroy()
      })
    },
  }
}

/**
 * Forward one HTTP request to the dsh listener, rewriting the page's client
 * bundle when requested.
 * @param request - incoming request.
 * @param response - incoming response.
 * @param upstream - resolved upstream address.
 * @param patchClientBundle - whether `/plugins/` JavaScript is rewritten.
 */
function forwardHttp(request, response, upstream, patchClientBundle) {
  const pathname = pathnameOf(request.url)
  const headers = rewriteHeaders(request.headers, upstream, pathname, patchClientBundle)
  const upstreamRequest = http.request({
    host: upstream.host,
    port: upstream.port,
    method: request.method,
    path: request.url,
    headers,
    setHost: false,
  })

  upstreamRequest.on('response', (upstreamResponse) => {
    const contentType = String(upstreamResponse.headers['content-type'] ?? '')
    const isClientBundle =
      patchClientBundle &&
      upstreamResponse.statusCode === 200 &&
      pathname.startsWith('/plugins/') &&
      /javascript/i.test(contentType)
    if (isClientBundle) {
      const chunks = []
      upstreamResponse.on('data', (chunk) => chunks.push(chunk))
      upstreamResponse.on('end', () => {
        const body = Buffer.from(patchClientBundleJs(Buffer.concat(chunks).toString('utf8')), 'utf8')
        const outHeaders = { ...upstreamResponse.headers }
        delete outHeaders['content-length']
        delete outHeaders['transfer-encoding']
        outHeaders['content-length'] = String(body.length)
        response.writeHead(upstreamResponse.statusCode ?? 200, outHeaders)
        response.end(body)
      })
      upstreamResponse.on('error', () => response.destroy())
      return
    }
    response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers)
    upstreamResponse.pipe(response)
    upstreamResponse.on('error', () => response.destroy())
  })

  upstreamRequest.on('error', (error) => {
    writeText(response, 502, `dsh-no-auth: upstream error: ${error.message}\n`)
  })
  request.on('error', () => upstreamRequest.destroy())
  request.pipe(upstreamRequest)
}

/**
 * Forward one WebSocket (or other protocol) upgrade to the dsh listener.
 * @param request - incoming upgrade request.
 * @param socket - client socket.
 * @param head - bytes already read from the client.
 * @param upstream - resolved upstream address.
 * @param patchClientBundle - whether `/plugins/` requests ask for identity encoding.
 */
function forwardUpgrade(request, socket, head, upstream, patchClientBundle) {
  const pathname = pathnameOf(request.url)
  const headers = rewriteHeaders(request.headers, upstream, pathname, patchClientBundle)
  headers.connection = 'Upgrade'
  headers.upgrade = String(request.headers.upgrade ?? 'websocket')

  let requestText = `${request.method ?? 'GET'} ${request.url ?? '/'} HTTP/1.1\r\n`
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue
    if (Array.isArray(value)) {
      for (const item of value) requestText += `${name}: ${item}\r\n`
    } else {
      requestText += `${name}: ${value}\r\n`
    }
  }
  requestText += '\r\n'

  const upstreamSocket = net.connect(upstream.port, upstream.host, () => {
    upstreamSocket.write(requestText)
    if (head !== undefined && head.length > 0) upstreamSocket.write(head)
    upstreamSocket.pipe(socket)
    socket.pipe(upstreamSocket)
  })
  upstreamSocket.on('error', () => socket.destroy())
  socket.on('error', () => upstreamSocket.destroy())
  socket.on('close', () => upstreamSocket.destroy())
  upstreamSocket.on('close', () => socket.destroy())
}
