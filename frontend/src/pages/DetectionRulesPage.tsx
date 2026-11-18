import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileSearch, ShieldCheck, XCircle } from 'lucide-react'
import { getJson, sendJson } from '../lib/api'
import type { DetectionRule, DetectionRuleDetail } from '../lib/types'

export function RuleCard({ rule, onToggle, onRiskPoints, onShowAlerts, busy }: {
  rule: DetectionRule; onToggle: (enabled: boolean) => void; onRiskPoints: (points: number) => void; onShowAlerts: () => void; busy?: boolean
}) {
  const [points, setPoints] = useState(String(rule.risk_points))
  const parsed = Number(points)
  const valid = Number.isInteger(parsed) && parsed >= 0 && parsed <= 25
  return <article className={`panel rule-card ${rule.enabled ? '' : 'disabled'}`}>
    <div className="panel-head"><div><span>{rule.key} · v{rule.version}{rule.built_in ? ' · BUILT-IN' : ''}</span><h2>{rule.name}</h2></div>
      <label className="toggle"><input type="checkbox" checked={rule.enabled} disabled={busy} onChange={e => onToggle(e.target.checked)}/>{rule.enabled ? 'Enabled' : 'Disabled'}</label></div>
    <p className="panel-copy">{rule.description}</p>
    <dl className="rule-facts"><div><dt>Logic</dt><dd>{rule.logic}</dd></div><div><dt>Scope</dt><dd>{rule.scope}</dd></div><div><dt>Limitations</dt><dd>{rule.limitations}</dd></div></dl>
    <div className="rule-actions">
      <label className="field-label inline">Risk points (0–25)<input type="number" min={0} max={25} value={points} onChange={e => setPoints(e.target.value)}/></label>
      <button disabled={busy || !valid || parsed === rule.risk_points} onClick={() => onRiskPoints(parsed)}>Save</button>
      <button className="link-button" onClick={onShowAlerts}>{rule.alert_count} matched alerts</button>
    </div>
  </article>
}

export function DetectionRulesPage({ onOpenAlert }: { onOpenAlert: (id: number) => void }) {
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<number | null>(null)
  const rules = useQuery<DetectionRule[]>({ queryKey: ['detection-rules'], queryFn: () => getJson('/detection-rules', 'Could not load detection rules') })
  const detail = useQuery<DetectionRuleDetail>({ queryKey: ['detection-rule', selected], enabled: selected !== null,
    queryFn: () => getJson(`/detection-rules/${selected}`, 'Could not load the rule') })
  const update = useMutation({
    mutationFn: ({ id, body }: { id: number; body: object }) => sendJson<DetectionRule>(`/detection-rules/${id}`, 'PATCH', body, 'Could not update the rule'),
    onSuccess: async () => Promise.all([queryClient.invalidateQueries({ queryKey: ['detection-rules'] }), queryClient.invalidateQueries({ queryKey: ['detection-rule'] })]),
  })
  return <div className="research-workspace">
    {update.error && <div className="import-message failed"><XCircle size={17}/><span>{(update.error as Error).message}</span></div>}
    <section className="rule-grid">{rules.data?.map(rule => <RuleCard key={`${rule.id}-${rule.version}`} rule={rule} busy={update.isPending}
      onToggle={enabled => update.mutate({ id: rule.id, body: { enabled } })}
      onRiskPoints={risk_points => update.mutate({ id: rule.id, body: { risk_points } })}
      onShowAlerts={() => setSelected(rule.id)}/>)}
      {!rules.data?.length && <div className="empty-state">{rules.isLoading ? 'Loading rules…' : 'No detection rules stored.'}</div>}</section>
    {selected !== null && <section className="panel table-panel"><div className="panel-head"><div><span>RULE EVIDENCE</span><h2>Alerts raised by {detail.data?.name || 'this rule'}</h2></div><FileSearch size={19}/></div>
      <div className="table-wrap"><table><thead><tr><th>ALERT</th><th>SEVERITY</th><th>NETWORK PATH</th><th>RISK</th><th>STATUS</th></tr></thead><tbody>
        {detail.data?.recent_alerts.map(a => <tr key={a.id} className="clickable-row" onClick={() => onOpenAlert(a.id)}><td><strong>ALT-{String(a.id).padStart(5, '0')}</strong></td><td><span className={`badge ${a.severity.toLowerCase()}`}><i/>{a.severity}</span></td><td><strong>{a.source}</strong><span className="arrow">→</span>{a.destination}:{a.destination_port}</td><td>{a.risk_score ?? '—'}</td><td><span className="status">{a.status}</span></td></tr>)}
        {!detail.data?.recent_alerts.length && <tr><td colSpan={5} className="empty">{detail.isLoading ? 'Loading…' : 'No alerts linked to this rule.'}</td></tr>}
      </tbody></table></div></section>}
    <div className="research-note"><ShieldCheck size={18}/><span>Rule edits are versioned and apply to future evaluations only; existing alerts keep the evidence and risk they were created with. There is no live rule engine for imported events yet.</span></div>
  </div>
}
