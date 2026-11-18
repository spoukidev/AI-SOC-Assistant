import { Activity, Info } from 'lucide-react'
import { barWidths, explanationSummary, featureLabel, formatFeatureValue, formatShap, outputSpaceLabel } from '../lib/explain'
import type { LocalExplanation } from '../lib/types'

const statusLabel: Record<LocalExplanation['status'], string> = {
  available: 'SHAP explanation', not_applicable: 'Not applicable', unavailable: 'Unavailable', error: 'Explanation failed',
}

export function ExplanationPanel({ explanation }: { explanation: LocalExplanation | null | undefined }) {
  if (!explanation) return null
  const available = explanation.status === 'available'
  const widths = barWidths(explanation.contributions.map((item) => item.shap_value))
  return <section className="panel explanation-panel" aria-label="Model explanation">
    <div className="panel-head"><div><span>LOCAL EXPLAINABILITY</span><h2>Why the model scored this flow</h2></div><Activity size={19}/></div>
    <div className={`explanation-status ${explanation.status}`}><strong>{statusLabel[explanation.status]}</strong><span>{explanationSummary(explanation)}</span></div>
    {available && <>
      <div className="shap-meta">
        <span>Method <b>{explanation.method}</b></span>
        {explanation.model && <span>Model <b>{explanation.model.version}</b></span>}
        <span>Units <b>{outputSpaceLabel(explanation.output_space)}</b></span>
        <span>Baseline <b>{explanation.base_value?.toFixed(3)}</b> → output <b>{explanation.model_output?.toFixed(3)}</b></span>
      </div>
      <div className="shap-bars">{explanation.contributions.map((item, index) => <div className="shap-row" key={item.feature}>
        <span className="shap-feature">{featureLabel(item.feature)}<small>{formatFeatureValue(item.value)}</small></span>
        <span className="shap-track"><i className={item.shap_value >= 0 ? 'up' : 'down'} style={{ width: `${widths[index]}%` }}/></span>
        <b className={item.shap_value >= 0 ? 'up' : 'down'}>{formatShap(item.shap_value, explanation.output_space)}</b>
      </div>)}</div>
      {explanation.other_features_total !== undefined && explanation.other_features_total !== 0 && <small className="shap-rest">Other features combined: {formatShap(explanation.other_features_total, explanation.output_space)}</small>}
    </>}
    <p className="shap-note"><Info size={14}/><span>{explanation.note}</span></p>
  </section>
}
