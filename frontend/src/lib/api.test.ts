import { describe, expect, it, vi } from 'vitest'
import { UnauthorizedError, apiFetch, createTokenStore, errorMessage, login, onUnauthorized } from './api'

function memoryStorage() {
  const data = new Map<string, string>()
  return { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => { data.set(k, v) }, removeItem: (k: string) => { data.delete(k) } }
}

describe('api client auth', () => {
  it('sends the stored bearer token', async () => {
    const store = createTokenStore(memoryStorage())
    store.set('abc.def.ghi')
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }))
    await apiFetch('/alerts', {}, { fetchImpl, store, base: 'http://api' })
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('http://api/alerts')
    expect(new Headers(init.headers).get('Authorization')).toBe('Bearer abc.def.ghi')
  })

  it('omits the header when signed out', async () => {
    const store = createTokenStore(memoryStorage())
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }))
    await apiFetch('/alerts', {}, { fetchImpl, store, base: '' })
    const [, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(new Headers(init.headers).has('Authorization')).toBe(false)
  })

  it('clears the token and notifies listeners on 401', async () => {
    const store = createTokenStore(memoryStorage())
    store.set('expired')
    const listener = vi.fn()
    const unsubscribe = onUnauthorized(listener)
    const fetchImpl = vi.fn(async () => new Response('{"detail":"Not authenticated"}', { status: 401 }))
    await expect(apiFetch('/alerts', {}, { fetchImpl, store, base: '' })).rejects.toBeInstanceOf(UnauthorizedError)
    expect(store.get()).toBeNull()
    expect(listener).toHaveBeenCalledOnce()
    unsubscribe()
  })

  it('stores the token after a successful login and surfaces API errors', async () => {
    const store = createTokenStore(null)
    const ok = vi.fn(async () => new Response(JSON.stringify({ access_token: 'tok', username: 'admin' }), { status: 200 }))
    await expect(login('admin', 'pw', { fetchImpl: ok, store, base: '' })).resolves.toBe('admin')
    expect(store.get()).toBe('tok')
    const bad = vi.fn(async () => new Response(JSON.stringify({ detail: 'Invalid username or password' }), { status: 401 }))
    await expect(login('admin', 'nope', { fetchImpl: bad, store: createTokenStore(null), base: '' })).rejects.toThrow('Invalid username or password')
  })

  it('reads FastAPI error shapes', async () => {
    expect(await errorMessage(new Response(JSON.stringify({ detail: [{ msg: 'field required' }] })), 'x')).toBe('field required')
    expect(await errorMessage(new Response('not json'), 'fallback')).toBe('fallback')
  })
})
