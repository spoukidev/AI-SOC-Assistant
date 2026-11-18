import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Boxes, ChevronRight, Link2, Plus, Unlink, XCircle } from 'lucide-react'
import { getJson, sendJson } from '../lib/api'
import type { Incident, IncidentDetail } from '../lib/types'

export const INCIDENT_STATUSES = ['Open', 'Investigating', 'Contained', 'Resolved', 'Closed']
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational']

/** Parse "12, 15 18" into unique positive integer IDs; returns null when any token is invalid. */
export function parseAlertIds(input: string): number[] | null {
  const tokens = input.split(/[\s,]+/).map(token => token.trim().replace(/^ALT-/i, '')).filter(Boolean)
  const ids = tokens.map(Number)
  if (ids.some(id => !Number.isInteger(id) || id <= 0)) return null
  return [...new Set(ids)]
}

const when = (value: string) => new Date(value).toLocaleString()

export function IncidentsPage({ onOpenAlert }: { onOpenAlert: (id: number) => void }) {
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<number | null>(null)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ title: '', severity: 'Medium', summary: '', alertIds: '' })
  const [linkInput, setLinkInput] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const list = useQuery<Incident[]>({ queryKey: ['incidents'], queryFn: () => getJson('/incidents', 'Could not load incidents') })
  const detail = useQuery<IncidentDetail>({ queryKey: ['incident', selected], enabled: selected !== null,
    queryFn: () => getJson(`/incidents/${selected}`, 'Could not load the incident') })
  const refresh = async () => Promise.all(['incidents', 'incident', 'alerts', 'alert', 'dashboard'].map(key => queryClient.invalidateQueries({ queryKey: [key] })))
  const create = useMutation({
    mutationFn: (body: object) => sendJson<IncidentDetail>('/incidents', 'POST', body, 'Could not create the incident'),
    onSuccess: async (data) => { setCreating(false); setForm({ title: '', severity: 'Medium', summary: '', alertIds: '' }); setSelected(data.id); await refresh() },
  })
  const update = useMutation({
    mutationFn: (body: object) => sendJson<IncidentDetail>(`/incidents/${selected}`, 'PATCH', body, 'Could not update the incident'), onSuccess: refresh,
  })
  const link = useMutation({
    mutationFn: (alertIds: number[]) => sendJson<IncidentDetail>(`/incidents/${selected}/alerts`, 'POST', { alert_ids: alertIds }, 'Could not link alerts'),
    onSuccess: async () => { setLinkInput(''); await refresh() },
  })
  const unlink = useMutation({
    mutationFn: (alertId: number) => sendJson<IncidentDetail>(`/incidents/${selected}/alerts/${alertId}`, 'DELETE', undefined, 'Could not unlink the alert'), onSuccess: refresh,
  })
  const submitCreate = (event: FormEvent) => {
    event.preventDefault()
    const alertIds = form.alertIds.trim() ? parseAlertIds(form.alertIds) : []
    if (alertIds === null) { setFormError('Alert IDs must be numbers, e.g. 3, 4, 5'); return }
    setFormError(null)
    create.mutate({ title: form.title, severity: form.severity, summary: form.summary, alert_ids: alertIds })
  }

  if (selected !== null) {
    const incident = detail.data
    return <div className="alert-investigation"><button className="back-action" onClick={() => setSelected(null)}><ArrowLeft size={15}/> Back to incidents</button>
      {detail.isLoading ? <div className="empty-state">Loading incident…</div> : detail.error || !incident ? <div className="error">Incident is unavailable.</div> : <>
        <section className="alert-hero"><div><span>INC-{String(incident.id).padStart(4, '0')}{incident.synthetic ? ' · SYNTHETIC DEMO' : ''}</span><h2>{incident.title}</h2><p>{when(incident.first_seen)} → {when(incident.last_seen)} · {incident.alert_count} linked alerts</p></div>
          <div className="alert-hero-actions"><select aria-label="Severity" value={incident.severity} onChange={e => update.mutate({ severity: e.target.value })}>{SEVERITIES.map(x => <option key={x}>{x}</option>)}</select>
            <select aria-label="Status" value={incident.status} onChange={e => update.mutate({ status: e.target.value })}>{INCIDENT_STATUSES.map(x => <option key={x}>{x}</option>)}</select></div></section>
        <section className="panel evidence-card"><div className="panel-head"><div><span>ANALYST SUMMARY</span><h2>Case notes</h2></div></div><div className="evidence-statement"><p>{incident.summary}</p></div></section>
        <section className="panel table-panel"><div className="panel-head"><div><span>CORRELATED EVIDENCE</span><h2>Linked alerts</h2></div>
          <form className="inline-form" onSubmit={e => { e.preventDefault(); const ids = parseAlertIds(linkInput); if (ids?.length) link.mutate(ids) }}>
            <input aria-label="Alert IDs to link" placeholder="Alert IDs, e.g. 3, 4" value={linkInput} onChange={e => setLinkInput(e.target.value)}/>
            <button type="submit" disabled={!parseAlertIds(linkInput)?.length || link.isPending}><Link2 size={13}/> Link</button></form></div>
          {(link.error || unlink.error || update.error) && <div className="import-message failed"><XCircle size={17}/><span>{((link.error || unlink.error || update.error) as Error).message}</span></div>}
          <div className="table-wrap"><table><thead><tr><th>ALERT</th><th>TIME</th><th>SEVERITY</th><th>NETWORK PATH</th><th>DETECTION</th><th>STATUS</th><th></th></tr></thead><tbody>
            {incident.alerts.map(a => <tr key={a.id}><td><button className="link-button" onClick={() => onOpenAlert(a.id)}>ALT-{String(a.id).padStart(5, '0')}</button></td><td>{when(a.timestamp)}</td><td><span className={`badge ${a.severity.toLowerCase()}`}><i/>{a.severity}</span></td><td><strong>{a.source}</strong><span className="arrow">→</span>{a.destination}:{a.destination_port}</td><td>{a.detection}</td><td><span className="status">{a.status}</span></td><td><button className="icon-button" aria-label={`Unlink alert ${a.id}`} onClick={() => unlink.mutate(a.id)}><Unlink size={14}/></button></td></tr>)}
            {!incident.alerts.length && <tr><td colSpan={7} className="empty">No alerts linked yet.</td></tr>}
          </tbody></table></div></section>
      </>}</div>
  }

  return <div className="research-workspace">
    {creating && <form className="panel incident-form" onSubmit={submitCreate}><div className="panel-head"><div><span>NEW CASE</span><h2>Create incident</h2></div><button type="button" onClick={() => setCreating(false)}>Cancel</button></div>
      <label className="field-label">Title<input value={form.title} maxLength={200} onChange={e => setForm({ ...form, title: e.target.value })} required/></label>
      <label className="field-label">Severity<select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}>{SEVERITIES.map(x => <option key={x}>{x}</option>)}</select></label>
      <label className="field-label">Summary<textarea value={form.summary} maxLength={5000} rows={3} onChange={e => setForm({ ...form, summary: e.target.value })} required/></label>
      <label className="field-label">Alert IDs (optional)<input value={form.alertIds} placeholder="3, 4, 5" onChange={e => setForm({ ...form, alertIds: e.target.value })}/></label>
      <button className="primary-action" type="submit" disabled={create.isPending}>{create.isPending ? 'Creating…' : 'Create incident'}</button>
      {(formError || create.error) && <div className="import-message failed"><XCircle size={17}/><span>{formError || (create.error as Error).message}</span></div>}
    </form>}
    <section className="panel table-panel"><div className="panel-head"><div><span>CASE MANAGEMENT</span><h2>Incidents</h2></div>{!creating && <button onClick={() => setCreating(true)}><Plus size={12}/> New incident</button>}</div>
      <div className="table-wrap"><table><thead><tr><th>INCIDENT</th><th>SEVERITY</th><th>STATUS</th><th>ALERTS</th><th>WINDOW</th><th>PROVENANCE</th><th></th></tr></thead><tbody>
        {list.data?.map(item => <tr key={item.id} className="clickable-row" onClick={() => setSelected(item.id)}><td><strong>{item.title}</strong><small>INC-{String(item.id).padStart(4, '0')}</small></td><td><span className={`badge ${item.severity.toLowerCase()}`}><i/>{item.severity}</span></td><td><span className="status">{item.status}</span></td><td>{item.alert_count}</td><td>{when(item.first_seen)} → {when(item.last_seen)}</td><td><span className={item.synthetic ? 'source synthetic' : 'source imported'}>{item.synthetic ? 'Synthetic demo' : 'Analyst'}</span></td><td className="row-arrow"><ChevronRight size={16}/></td></tr>)}
        {!list.data?.length && <tr><td colSpan={7} className="empty">{list.isLoading ? 'Loading incidents…' : 'No incidents yet.'}</td></tr>}
      </tbody></table></div></section>
    <div className="research-note"><Boxes size={18}/><span>Incidents group alerts an analyst decided belong together. Correlation is manual; automatic correlation is not implemented.</span></div>
  </div>
}
