export type Contribution = { feature: string; value: number | string | boolean | null; shap_value: number; direction: 'increases_malicious_score' | 'decreases_malicious_score' | 'neutral' }
export type ModelRef = { id: number; model_name: string; version: string; created_at: string; active: boolean }
export type LocalExplanation = {
  status: 'available' | 'not_applicable' | 'unavailable' | 'error'
  reason?: string; method?: string; output_space?: 'log_odds' | 'probability'
  base_value?: number; model_output?: number; predicted_probability?: number
  contributions: Contribution[]; other_features_total?: number; background_samples?: number
  note: string; model?: ModelRef
}
export type GlobalExplanation = {
  status: 'available' | 'unavailable' | 'error'; reason?: string; method?: string; output_space?: 'log_odds' | 'probability'
  base_value?: number; samples?: number; sample_description?: string
  importance: { feature: string; mean_abs_shap: number; mean_shap: number }[]; note: string; model?: ModelRef
}
export type AlertSummary = { id: number; timestamp: string; severity: string; source: string; destination: string; destination_port: number; protocol: string; detection: string; evidence_type: string; status: string; risk_score: number | null; model_probability: number | null; rule_id: number | null; incident_id: number | null }
export type DetectionRule = { id: number; key: string; name: string; description: string; logic: string; scope: string; risk_points: number; enabled: boolean; version: number; limitations: string; built_in: boolean; updated_at: string; alert_count: number }
export type DetectionRuleDetail = DetectionRule & { recent_alerts: AlertSummary[] }
export type Incident = { id: number; title: string; severity: string; status: string; summary: string; first_seen: string; last_seen: string; synthetic: boolean; alert_count: number }
export type IncidentDetail = Incident & { alerts: AlertSummary[] }
