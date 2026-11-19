import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { ExplanationPanel } from './ExplanationPanel'
import { GlobalImportance } from '../pages/ExplainabilityPage'
import { RuleCard } from '../pages/DetectionRulesPage'
import { parseAlertIds } from '../pages/IncidentsPage'

const note = 'SHAP values explain the model, not proof of malicious activity.'

describe('ExplanationPanel', () => {
  it('renders signed contributions for an ML alert', () => {
    const html = renderToStaticMarkup(<ExplanationPanel explanation={{
      status: 'available', method: 'SHAP TreeExplainer (interventional)', output_space: 'probability', base_value: 0.5, model_output: 0.93,
      contributions: [
        { feature: 'packets_per_second', value: 40, shap_value: 0.3, direction: 'increases_malicious_score' },
        { feature: 'duration', value: 2.5, shap_value: -0.05, direction: 'decreases_malicious_score' },
      ], other_features_total: 0.18, note,
    }}/>)
    expect(html).toContain('Packets per second')
    expect(html).toContain('+30.0 pts')
    expect(html).toContain('−5.0 pts')
    expect(html).toContain('Other features combined')
    expect(html).toContain(note)
  })

  it('labels rule-only alerts as not applicable instead of inventing values', () => {
    const html = renderToStaticMarkup(<ExplanationPanel explanation={{ status: 'not_applicable', reason: 'Rule-based alert: no ML model scored this event.', contributions: [], note }}/>)
    expect(html).toContain('Not applicable')
    expect(html).toContain('Rule-based alert')
    expect(html).not.toContain('shap-row')
  })
})

describe('Milestone 5 pages', () => {
  it('renders global importance or the unavailable reason', () => {
    const html = renderToStaticMarkup(<GlobalImportance explanation={{ status: 'available', note, importance: [{ feature: 'protocol', mean_abs_shap: 0.2, mean_shap: 0 }] }}/>)
    expect(html).toContain('Protocol')
    expect(renderToStaticMarkup(<GlobalImportance explanation={{ status: 'unavailable', reason: 'Retrain the model', importance: [], note }}/>)).toContain('Retrain the model')
  })

  it('renders a stored detection rule', () => {
    const html = renderToStaticMarkup(<RuleCard onToggle={() => {}} onRiskPoints={() => {}} onShowAlerts={() => {}} rule={{
      id: 1, key: 'demo-rule', name: 'Demo rule', description: 'd', logic: 'port in (22, 3389)', scope: 'demo', risk_points: 25,
      enabled: false, version: 3, limitations: 'not production', built_in: true, updated_at: '2026-01-01T00:00:00Z', alert_count: 4,
    }}/>)
    expect(html).toContain('demo-rule · v3 · BUILT-IN')
    expect(html).toContain('Disabled')
    expect(html).toContain('4 matched alerts')
  })

  it('parses alert ID lists for incident linking', () => {
    expect(parseAlertIds('3, 4 ALT-00005, 3')).toEqual([3, 4, 5])
    expect(parseAlertIds('3, x')).toBeNull()
    expect(parseAlertIds('0')).toBeNull()
  })
})

describe('Milestone 5.1 views', () => {
  it('reports measured SHAP stability honestly', async () => {
    const { StabilitySummary } = await import('../pages/ExplainabilityPage')
    const html = renderToStaticMarkup(<StabilitySummary stability={{ status: 'available', verdict: 'moderately stable', top_k: 5, resamples: 5,
      reference_rows_per_resample: 50, global_top_k_jaccard: 0.74, local_top3_jaccard: 0.66, global_rank_spearman: 0.91, thresholds: 'stable: both ≥ 0.8' }}/>)
    expect(html).toContain('moderately stable')
    expect(html).toContain('74%')
    expect(html).toContain('not to retraining')
    expect(renderToStaticMarkup(<StabilitySummary stability={{ status: 'unavailable', reason: 'Too few rows' }}/>)).toContain('Too few rows')
  })

  it('labels incident provenance and live rules', async () => {
    const { incidentProvenance } = await import('../pages/IncidentsPage')
    const base = { id: 1, title: 't', severity: 'High', status: 'Open', summary: 's', first_seen: '', last_seen: '', alert_count: 2 }
    expect(incidentProvenance({ ...base, synthetic: false, auto_correlated: true, correlation_key: 'src:203.0.113.5' })).toBe('Auto-correlated (source 203.0.113.5)')
    expect(incidentProvenance({ ...base, synthetic: false })).toBe('Analyst')
    expect(incidentProvenance({ ...base, synthetic: true })).toBe('Synthetic demo')
    const html = renderToStaticMarkup(<RuleCard onToggle={() => {}} onRiskPoints={() => {}} onShowAlerts={() => {}} rule={{
      id: 2, key: 'syn-probe', name: 'SYN probe', description: 'd', logic: 'packets ≤ 6', scope: 'live', risk_points: 20, enabled: true,
      version: 1, limitations: 'l', built_in: true, updated_at: '', alert_count: 0, evaluated_live: true }}/>)
    expect(html).toContain('LIVE')
  })
})
