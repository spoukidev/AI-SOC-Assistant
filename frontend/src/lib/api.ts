// API client with bearer-token auth (Milestone 5).
// The token lives in sessionStorage: it is cleared when the tab closes and expires server-side (default 60 min).
export const API: string = import.meta.env.VITE_API_URL || 'http://localhost:8000/api'
const TOKEN_KEY = 'soc-xai.access-token'

type KeyValueStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>
export type TokenStore = { get(): string | null; set(token: string): void; clear(): void }

export function createTokenStore(storage: KeyValueStorage | null): TokenStore {
  let memory: string | null = null
  return {
    get: () => (storage ? storage.getItem(TOKEN_KEY) : memory),
    set: (token) => { if (storage) storage.setItem(TOKEN_KEY, token); else memory = token },
    clear: () => { if (storage) storage.removeItem(TOKEN_KEY); else memory = null },
  }
}

export const tokenStore = createTokenStore(typeof window !== 'undefined' ? window.sessionStorage : null)

export class UnauthorizedError extends Error {
  constructor() { super('Your session has expired. Sign in again.'); this.name = 'UnauthorizedError' }
}

const unauthorizedListeners = new Set<() => void>()
export function onUnauthorized(listener: () => void): () => void {
  unauthorizedListeners.add(listener)
  return () => { unauthorizedListeners.delete(listener) }
}

type FetchDeps = { fetchImpl?: typeof fetch; store?: TokenStore; base?: string }

export async function apiFetch(path: string, init: RequestInit = {}, deps: FetchDeps = {}): Promise<Response> {
  const { fetchImpl = fetch, store = tokenStore, base = API } = deps
  const headers = new Headers(init.headers)
  const token = store.get()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetchImpl(`${base}${path}`, { ...init, headers })
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
  const { fetchImpl = fetch, store = tokenStore, base = API } = deps
  const response = await fetchImpl(`${base}/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }),
  })
  if (!response.ok) throw new Error(await errorMessage(response, 'Sign-in failed'))
  const body = await response.json() as { access_token: string; username: string }
  store.set(body.access_token)
  return body.username
}

export function logout(store: TokenStore = tokenStore): void {
  store.clear()
  unauthorizedListeners.forEach((listener) => listener())
}
