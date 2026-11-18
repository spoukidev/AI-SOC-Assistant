import { describe, expect, it } from 'vitest'
import { barWidths, explanationSummary, featureLabel, formatFeatureValue, formatShap } from './explain'

describe('explanation helpers', () => {
  it('labels flow-v1 features', () => {
    expect(featureLabel('bytes_per_packet')).toBe('Bytes per packet')
    expect(featureLabel('custom_feature')).toBe('custom feature')
  })
  it('formats SHAP values in their output units', () => {
    expect(formatShap(0.1234, 'probability')).toBe('+12.3 pts')
    expect(formatShap(-1.5, 'log_odds')).toBe('−1.500')
    expect(formatShap(0, 'log_odds')).toBe('±0.000')
  })
  it('scales bars to the largest absolute contribution', () => {
    expect(barWidths([0.5, -1, 0.25])).toEqual([50, 100, 25])
    expect(barWidths([0, 0])).toEqual([0, 0])
  })
  it('formats feature values', () => {
    expect(formatFeatureValue(true)).toBe('yes')
    expect(formatFeatureValue('well_known')).toBe('well known')
    expect(formatFeatureValue(0.12345)).toBe('0.123')
  })
  it('summarises the strongest contribution or the unavailable reason', () => {
    expect(explanationSummary({ status: 'available', note: '', contributions: [
      { feature: 'duration', value: 0.1, shap_value: 0.4, direction: 'increases_malicious_score' },
    ] })).toBe('Flow duration (0.100) pushed the score toward malicious the most.')
    expect(explanationSummary({ status: 'not_applicable', reason: 'Rule-based alert', note: '', contributions: [] })).toBe('Rule-based alert')
  })
})
