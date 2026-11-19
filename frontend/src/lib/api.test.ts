import { describe, expect, it, vi } from 'vitest'
import { UnauthorizedError, apiFetch, createCsrfStore, errorMessage, login, logout, onUnauthorized, restoreSession } from './api'

const ok = (body: unknown = {}) => vi.fn(async () => new Response(JSON.stringify(body), { status: 200 }))
const call = (mock: ReturnType<typeof vi.fn>, index = 0) => mock.mock.calls[index] as unknown as [string, RequestInit]

describe('api client cookie sessions', () => {
  it('always sends cookies and never an Authorization header', async () => {
    const fetchImpl = ok()
    await apiFetch('/alerts', {}, { fetchImpl, store: createCsrfStore(), base: 'http://api' })
    const [url, init] = call(fetchImpl)
    expect(url).toBe('http://api/alerts')
    expect(init.credentials).toBe('include')
    expect(new Headers(init.headers).has('Authorization')).toBe(false)
  })

  it('adds the CSRF token to state-changing requests only', async () => {
    const store = createCsrfStore()
    store.set('csrf-123')
    const fetchImpl = ok()
    await apiFetch('/alerts', {}, { fetchImpl, store, base: '' })
    await apiFetch('/incidents', { method: 'POST' }, { fetchImpl, store, base: '' })
    await apiFetch('/incidents/1/alerts/2', { method: 'delete' }, { fetchImpl, store, base: '' })
    expect(new Headers(call(fetchImpl, 0)[1].headers).has('X-CSRF-Token')).toBe(false)
    expect(new Headers(call(fetchImpl, 1)[1].headers).get('X-CSRF-Token')).toBe('csrf-123')
    expect(new Headers(call(fetchImpl, 2)[1].headers).get('X-CSRF-Token')).toBe('csrf-123')
  })

  it('clears the CSRF token and notifies listeners on 401', async () => {
    const store = createCsrfStore()
    store.set('stale')
    const listener = vi.fn()
    const unsubscribe = onUnauthorized(listener)
    const fetchImpl = vi.fn(async () => new Response('{"detail":"Not authenticated"}', { status: 401 }))
    await expect(apiFetch('/alerts', {}, { fetchImpl, store, base: '' })).rejects.toBeInstanceOf(UnauthorizedError)
    expect(store.get()).toBeNull()
    expect(listener).toHaveBeenCalledOnce()
    unsubscribe()
  })

  it('keeps only the CSRF token after login and surfaces API errors', async () => {
    const store = createCsrfStore()
    const fetchImpl = ok({ csrf_token: 'csrf-abc', username: 'admin' })
    await expect(login('admin', 'pw', { fetchImpl, store, base: '' })).resolves.toBe('admin')
    expect(store.get()).toBe('csrf-abc')
    expect(call(fetchImpl)[1].credentials).toBe('include')
    const bad = vi.fn(async () => new Response(JSON.stringify({ detail: 'Invalid username or password' }), { status: 401 }))
    await expect(login('admin', 'nope', { fetchImpl: bad, store: createCsrfStore(), base: '' })).rejects.toThrow('Invalid username or password')
  })

  it('restores a session from the cookie and signs out', async () => {
    const store = createCsrfStore()
    await expect(restoreSession({ fetchImpl: ok({ username: 'admin', csrf_token: 'c1' }), store, base: '' })).resolves.toBe('admin')
    expect(store.get()).toBe('c1')
    const signedOut = vi.fn(async () => new Response('{}', { status: 401 }))
    await expect(restoreSession({ fetchImpl: signedOut, store, base: '' })).resolves.toBeNull()
    store.set('c2')
    const logoutFetch = ok()
    await logout({ fetchImpl: logoutFetch, store, base: '' })
    expect(call(logoutFetch)[1].method).toBe('POST')
    expect(store.get()).toBeNull()
  })

  it('reads FastAPI error shapes', async () => {
    expect(await errorMessage(new Response(JSON.stringify({ detail: [{ msg: 'field required' }] })), 'x')).toBe('field required')
    expect(await errorMessage(new Response('not json'), 'fallback')).toBe('fallback')
  })
})
