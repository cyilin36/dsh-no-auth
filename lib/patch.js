/**
 * Relax the DSH Web GUI's launch-token authentication by wrapping the live
 * Connection service instance.
 *
 * The shipped Host Connection service funnels every browser-facing entry
 * point through four public methods:
 *
 * - `admit(request)` — Host/Origin fence, then browser cookie / API cookie
 *   check; returns `{ peer }` or `{ rejection: 401 | 403 }`. WebSocket upgrades
 *   reach it through `admitConnection()` and `requestRejection()`.
 * - `authorizeConnect(request, response)` — launch-token exchange on
 *   `/connect`; mints the signed API cookie.
 * - `authorizeIndex(request, response)` — launch-token exchange at `GET /`,
 *   signed cookie minting, and the 401 that stops `frontend-static` from
 *   serving index.html.
 * - `authenticatedUrl(baseUrl)` — the tokenized URL `dsh-web-app` prints and
 *   hands to the default browser.
 *
 * Replacing those methods on the instance covers the page, every `/api` RPC,
 * the `/api/remote.mux` WebSocket, and `/connect`. A `whitelist` policy is the
 * only entry: a client outside the list is refused with 403 on all four paths
 * even when it presents a valid token or cookie. `open` / `loopback` policies
 * admit every request as the shared owner Peer, as the first version did.
 *
 * @module dsh-no-auth/patch
 */
import { clientAddressOf } from './access.js'

export { createAccessPolicy, isLoopbackBind, readOptions } from './access.js'

/**
 * Whether a Connection admission value is a rejection envelope.
 * @param admission - value returned by `admit()`.
 * @returns true for `{ rejection }`.
 */
function isRejection(admission) {
  return admission !== null && typeof admission === 'object' && 'rejection' in admission
}

/**
 * Answer one request with the whitelist refusal, in the shipped 401 style.
 * @param request - node:http request (HEAD gets no body).
 * @param response - response not yet written by the caller.
 */
function writeForbidden(request, response) {
  if (response.writableEnded === true) return
  response.writeHead(403, {
    'cache-control': 'no-store',
    'content-type': 'text/plain; charset=utf-8',
  })
  response.end(request.method === 'HEAD' ? undefined : 'dsh web: client address is not allowed by the dsh-no-auth whitelist\n')
}

/**
 * Check that the live Connection service exposes the methods this patch knows
 * how to wrap. A future DSH release may rename them; a mismatch leaves the
 * shipped authentication in place instead of breaking the profile.
 * @param connection - live `ctx.connection` service instance.
 * @returns true when every wrapped method and the shared browser Peer exist.
 */
export function isPatchableConnection(connection) {
  return (
    connection !== null &&
    typeof connection === 'object' &&
    typeof connection.admit === 'function' &&
    typeof connection.authorizeConnect === 'function' &&
    typeof connection.authorizeIndex === 'function' &&
    typeof connection.authenticatedUrl === 'function' &&
    connection.browserPeer !== null &&
    connection.browserPeer !== undefined
  )
}

/**
 * Install the authentication bypass on the live Connection service.
 *
 * @param connection - live `ctx.connection` service instance.
 * @param options - resolved patch options (only `keepTokenInUrl` is consulted).
 * @param policy - resolved access policy; omitted means "open" (admit all).
 * @returns a restore function, or `null` when the service shape is unsupported.
 */
export function applyNoAuth(connection, options = {}, policy = null) {
  if (!isPatchableConnection(connection)) return null

  const access = policy ?? { mode: 'open', allows: () => true }
  /**
   * A request may bypass the token only when the policy admits its source.
   * The mode is read per request so a settings-page change can switch between
   * `open` and `whitelist` without reinstalling the patch.
   * @param request - HTTP or upgrade request.
   * @returns true when no whitelist gates it, or its client address matches.
   */
  const allowsRequest = (request) =>
    access.mode !== 'whitelist' || access.allows(clientAddressOf(request)) === true

  const original = {
    admit: connection.admit,
    authorizeConnect: connection.authorizeConnect,
    authorizeIndex: connection.authorizeIndex,
    authenticatedUrl: connection.authenticatedUrl,
  }

  connection.admit = function admitWithoutToken(request) {
    const admission = original.admit.call(connection, request)
    if (!allowsRequest(request)) {
      // A disposed service keeps its 401; an untrusted authority keeps its 403.
      // Everything else is an explicit whitelist refusal, including a request
      // that would otherwise have been admitted by its cookie or API Peer.
      if (connection.disposed === true) return admission
      if (isRejection(admission) && admission.rejection === 403) return admission
      return { rejection: 403 }
    }
    if (!isRejection(admission)) return admission
    if (admission.rejection !== 401 || connection.disposed === true) return admission
    return { peer: connection.browserPeer }
  }

  connection.authorizeConnect = function authorizeConnectFromAllowedClient(request, response) {
    if (!allowsRequest(request)) {
      writeForbidden(request, response)
      return
    }
    return original.authorizeConnect.call(connection, request, response)
  }

  connection.authorizeIndex = function authorizeIndexFromAllowedClient(request, response) {
    if (!allowsRequest(request)) {
      writeForbidden(request, response)
      return false
    }
    return true
  }

  connection.authenticatedUrl = options.keepTokenInUrl === true
    ? original.authenticatedUrl
    : function cleanApplicationUrl(baseUrl) {
        return String(baseUrl)
      }

  let restored = false
  return function restoreAuthentication() {
    if (restored) return
    restored = true
    connection.admit = original.admit
    connection.authorizeConnect = original.authorizeConnect
    connection.authorizeIndex = original.authorizeIndex
    connection.authenticatedUrl = original.authenticatedUrl
  }
}
