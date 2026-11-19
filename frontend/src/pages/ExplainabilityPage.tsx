import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, ChevronRight, Info } from 'lucide-react'
import { getJson } from '../lib/api'
import { barWidths, featureLabel, outputSpaceLabel } from '../lib/explain'
import type { AlertSummary, GlobalExplanation, ModelRef, StabilityReport } from '../lib/types'

const modelLabel = (name: string) => ({ logistic_regression: 'Logistic Regression', random_forest: 'Random Forest', xgboost: 'XGBoost' }[name] || name)

export function GlobalImportance({ explanation }: { explanation: GlobalExplanation }) {
  if (explanation.status !== 'available') return <div className="empty-state">{explanation.reason || 'Global explanation unavailable.'}</div>
  const widths = barWidths(explanation.importance.map(item => item.mean_abs_shap))
  return <div className="shap-bars global">{explanation.importance.map((item, index) => <div className="shap-row" key={item.feature}>
    <span className="shap-feature">{featureLabel(item.feature)}</span>
    <span className="shap-track"><i className="neutral" style={{ width: `${widths[index]}%` }}/></span>
    <b>{item.mean_abs_shap.toFixed(4)}</b>
  </div>)}</div>
}

export function StabilitySummary({ stability }: { stability?: StabilityReport }) {
  if (!stability) return null
  if (stability.status !== 'available') return <div className="stability-box unavailable"><strong>Stability not measured</strong><span>{stability.reason}</span></div>
  const pct = (value?: number) => (typeof value === 'number' ? `${Math.round(value * 100)}%` : '—')
  return <div className={`stability-box ${stability.verdict?.replace(' ', '-')}`}>
    <strong>Explanation stability: {stability.verdict}</strong>
    <span>Explainer rebuilt on {stability.resamples} random halves of the reference sample ({stability.reference_rows_per_resample} rows each).</span>
    <div className="stability-metrics">
      <span>Global top-{stability.top_k} overlap <b>{pct(stability.global_top_k_jaccard)}</b></span>
      <span>Per-alert top-3 overlap <b>{pct(stability.local_top3_jaccard)}</b></span>
      <span>Ranking correlation <b>{stability.global_rank_spearman?.toFixed(3)}</b></span>
    </div>
    <small>{stability.thresholds}. This measures sensitivity to the reference sample only, not to retraining or input changes.</small>
  </div>
}

export function ExplainabilityPage({ onOpenAlert }: { onOpenAlert: (id: number) => void }) {
  const models = useQuery<ModelRef[]>({ queryKey: ['models'], queryFn: () => getJson('/models', 'Could not load models') })
  const [modelId, setModelId] = useState<number | null>(null)
  useEffect(() => { if (modelId === null && models.data?.length) setModelId(models.data[0].id) }, [models.data, modelId])
  const global = useQuery<GlobalExplanation>({ queryKey: ['model-explanation', modelId], enabled: modelId !== null,
    queryFn: () => getJson(`/models/${modelId}/explanation`, 'Could not load the model explanation') })
  const alerts = useQuery<AlertSummary[]>({ queryKey: ['alerts'], queryFn: () => getJson('/alerts', 'Could not load alerts') })
  const mlAlerts = (alerts.data || []).filter(a => a.evidence_type === 'ML prediction')
  return <div className="research-workspace">
    <section className="experiment-layout">
      <article className="panel"><div className="panel-head"><div><span>GLOBAL EXPLAINABILITY</span><h2>Feature importance (mean |SHAP|)</h2></div><Activity size={20}/></div>
        {models.data?.length ? <>
          <label className="field-label">Model version<select value={modelId ?? ''} onChange={e => setModelId(Number(e.target.value))}>{models.data.map(m => <option key={m.id} value={m.id}>{modelLabel(m.model_name)} · {m.version}</option>)}</select></label>
          {global.isLoading ? <div className="empty-state">Computing SHAP values…</div> : global.error ? <div className="error">{(global.error as Error).message}</div> : global.data && <>
            <GlobalImportance explanation={global.data}/>
            {global.data.status === 'available' && <small className="shap-rest">{global.data.method} · {global.data.samples} background samples · units: {outputSpaceLabel(global.data.output_space)}</small>}
            {global.data.status === 'available' && <StabilitySummary stability={global.data.stability}/>}
          </>}
        </> : <div className="empty-state">No trained models yet. Run an experiment to get SHAP explanations.</div>}
      </article>
      <article className="panel research-guardrail"><div className="panel-head"><div><span>HOW TO READ THIS</span><h2>Explanation contract</h2></div></div>
        {['Computed from the trained model, never hard-coded', 'Reference: stored training background sample (no IPs)', 'Logistic regression: log-odds; tree models: probability', 'One-hot columns are summed back to their flow-v1 feature', 'Rule-only alerts are labeled "not applicable"'].map(item => <div className="guardrail-row" key={item}><Info size={15}/><span>{item}</span></div>)}
        {global.data && <p className="panel-copy">{global.data.note}</p>}
      </article>
    </section>
    <section className="panel table-panel"><div className="panel-head"><div><span>LOCAL EXPLANATIONS</span><h2>ML alerts with per-alert SHAP</h2></div><span className="record-count">{mlAlerts.length} alerts</span></div>
      <div className="table-wrap"><table><thead><tr><th>ALERT</th><th>SEVERITY</th><th>NETWORK PATH</th><th>DETECTION</th><th>CONFIDENCE</th><th></th></tr></thead><tbody>
        {mlAlerts.map(a => <tr key={a.id} className="clickable-row" onClick={() => onOpenAlert(a.id)}><td><strong>ALT-{String(a.id).padStart(5, '0')}</strong></td><td><span className={`badge ${a.severity.toLowerCase()}`}><i/>{a.severity}</span></td><td><strong>{a.source}</strong><span className="arrow">→</span>{a.destination}:{a.destination_port}</td><td>{a.detection}</td><td>{a.model_probability === null ? '—' : `${(a.model_probability * 100).toFixed(1)}%`}</td><td className="row-arrow"><ChevronRight size={16}/></td></tr>)}
        {!mlAlerts.length && <tr><td colSpan={6} className="empty">No ML alerts yet. Rule-only demo alerts have no model score to explain.</td></tr>}
      </tbody></table></div>
    </section>
  </div>
}
