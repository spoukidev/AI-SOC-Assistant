import { useState, type FormEvent } from 'react'
import { LockKeyhole, ShieldCheck } from 'lucide-react'
import { login } from '../lib/api'

export function LoginPage({ onLogin }: { onLogin: (username: string) => void }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setPending(true); setError(null)
    try { onLogin(await login(username, password)) } catch (err) { setError(err instanceof Error ? err.message : 'Sign-in failed') } finally { setPending(false); setPassword('') }
  }
  return <div className="login-screen"><form className="panel login-card" onSubmit={submit}>
    <div className="brand"><div className="brand-mark"><ShieldCheck size={22}/></div><div><strong>SENTINEL XAI</strong><span>SOC ASSISTANT</span></div></div>
    <h1>Analyst sign-in</h1>
    <p>All alert, incident and model data requires an authenticated session.</p>
    <label className="field-label">Username<input autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} required/></label>
    <label className="field-label">Password<input type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} required/></label>
    <button className="primary-action" type="submit" disabled={pending || !username || !password}><LockKeyhole size={15}/> {pending ? 'Signing in…' : 'Sign in'}</button>
    {error && <div className="import-message failed" role="alert"><span>{error}</span></div>}
    <small>The admin account is configured with ADMIN_PASSWORD_HASH on the backend. See the README.</small>
  </form></div>
}
