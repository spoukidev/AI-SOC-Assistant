// API client (Milestone 5.1): cookie sessions with CSRF protection.
// The session token lives in an HttpOnly cookie that page scripts cannot read. The only secret held
// in JavaScript is the CSRF token, kept in memory and sent as X-CSRF-Token on state-changing requests.
export const API: string = import.meta.env.VITE_API_URL || 'http://localhost:8000/api'
const LEGACY_TOKEN_KEY = 'soc-xai.access-token'
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export type CsrfStore = { get(): string | null; set(token: string): void; clear(): void }

export function createCsrfStore(): CsrfStore {
  let token: string | null = null
  return { get: () => token, set: (value) => { token = value }, clear: () => { token = null } }
}

export const csrfStore = createCsrfStore()

// Milestone 5.0 kept a bearer token in sessionStorage; remove any leftover copy.
if (typeof window !== 'undefined') { try { window.sessionStorage.removeItem(LEGACY_TOKEN_KEY) } catch { /* storage unavailable */ } }

export class UnauthorizedError extends Error {
  constructor() { super('Your session has expired. Sign in again.'); this.name = 'UnauthorizedError' }
}

const unauthorizedListeners = new Set<() => void>()
export function onUnauthorized(listener: () => void): () => void {
  unauthorizedListeners.add(listener)
  return () => { unauthorizedListeners.delete(listener) }
}

type FetchDeps = { fetchImpl?: typeof fetch; store?: CsrfStore; base?: string }

export async function apiFetch(path: string, init: RequestInit = {}, deps: FetchDeps = {}): Promise<Response> {
  const { fetchImpl = fetch, store = csrfStore, base = API } = deps
  const headers = new Headers(init.headers)
  const method = (init.method || 'GET').toUpperCase()
  const csrf = store.get()
  if (!SAFE_METHODS.has(method) && csrf) headers.set('X-CSRF-Token', csrf)
  const response = await fetchImpl(`${base}${path}`, { ...init, headers, credentials: 'include' })
  if (response.status === 401) {
    store.clear()
    unauthorizedListeners.forEach((listener) => listener())
    throw new UnauthorizedError()
  }
  return response
}

export async function errorMessage(response: Response, fallback: string): Promise<string> {
  const body = await response.json().catch(() => null)
  if (typeof body?.detail === 'string') return body.detail
  if (typeof body?.detail?.message === 'string') return body.detail.message
  if (Array.isArray(body?.detail) && typeof body.detail[0]?.msg === 'string') return body.detail[0].msg
  return fallback
}

export async function getJson<T>(path: string, fallback: string, deps?: FetchDeps): Promise<T> {
  const response = await apiFetch(path, {}, deps)
  if (!response.ok) throw new Error(await errorMessage(response, fallback))
  return response.json() as Promise<T>
}

export async function sendJson<T>(path: string, method: 'POST' | 'PATCH' | 'DELETE', body: unknown, fallback: string, deps?: FetchDeps): Promise<T> {
  const init: RequestInit = { method }
  if (body !== undefined) { init.headers = { 'Content-Type': 'application/json' }; init.body = JSON.stringify(body) }
  const response = await apiFetch(path, init, deps)
  if (!response.ok) throw new Error(await errorMessage(response, fallback))
  return response.json() as Promise<T>
}

export async function login(username: string, password: string, deps: FetchDeps = {}): Promise<string> {
  const { fetchImpl = fetch, store = csrfStore, base = API } = deps
  const response = await fetchImpl(`${base}/auth/login`, {
    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }),
  })
  if (!response.ok) throw new Error(await errorMessage(response, 'Sign-in failed'))
  const body = await response.json() as { csrf_token: string; username: string }
  store.set(body.csrf_token)
  return body.username
}

/** Restore an existing cookie session after a page load. Returns the username, or null when signed out. */
export async function restoreSession(deps: FetchDeps = {}): Promise<string | null> {
  const { fetchImpl = fetch, store = csrfStore, base = API } = deps
  const response = await fetchImpl(`${base}/auth/me`, { credentials: 'include' })
  if (!response.ok) { store.clear(); return null }
  const body = await response.json() as { username: string; csrf_token: string }
  store.set(body.csrf_token)
  return body.username
}

export async function logout(deps: FetchDeps = {}): Promise<void> {
  const { fetchImpl = fetch, store = csrfStore, base = API } = deps
  try { await fetchImpl(`${base}/auth/logout`, { method: 'POST', credentials: 'include' }) } finally {
    store.clear()
    unauthorizedListeners.forEach((listener) => listener())
  }
}
