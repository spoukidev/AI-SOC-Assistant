import type { Contribution, LocalExplanation } from './types'

const FEATURE_LABELS: Record<string, string> = {
  duration: 'Flow duration', total_packets: 'Total packets', total_bytes: 'Total bytes',
  bytes_per_packet: 'Bytes per packet', packets_per_second: 'Packets per second', bytes_per_second: 'Bytes per second',
  src_dst_byte_ratio: 'Source/destination byte ratio', src_dst_packet_ratio: 'Source/destination packet ratio',
  src_port_category: 'Source port category', dst_port_category: 'Destination port category',
  protocol: 'Protocol', has_tcp_flags: 'TCP flags present',
}

export const featureLabel = (feature: string) => FEATURE_LABELS[feature] || feature.replaceAll('_', ' ')

export const outputSpaceLabel = (space?: string) =>
  space === 'log_odds' ? 'log-odds of "malicious"' : space === 'probability' ? 'probability of "malicious"' : 'model output'

export function formatShap(value: number, space?: string): string {
  const sign = value > 0 ? '+' : value < 0 ? '−' : '±'
  const magnitude = Math.abs(value)
  return space === 'probability' ? `${sign}${(magnitude * 100).toFixed(1)} pts` : `${sign}${magnitude.toFixed(3)}`
}

export function formatFeatureValue(value: Contribution['value']): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (typeof value === 'number') return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(3)
  return value.replaceAll('_', ' ')
}

/** Bar widths (0–100%) relative to the largest absolute contribution shown. */
export function barWidths(values: number[]): number[] {
  const max = Math.max(0, ...values.map(Math.abs))
  return values.map((value) => (max === 0 ? 0 : Math.round((Math.abs(value) / max) * 100)))
}

export function explanationSummary(explanation: LocalExplanation): string {
  if (explanation.status !== 'available') return explanation.reason || 'No explanation is available.'
  const top = explanation.contributions.find((item) => item.shap_value !== 0)
  if (!top) return 'No single feature moved this model output away from its baseline.'
  const direction = top.shap_value > 0 ? 'pushed the score toward malicious' : 'pushed the score toward benign'
  return `${featureLabel(top.feature)} (${formatFeatureValue(top.value)}) ${direction} the most.`
}
