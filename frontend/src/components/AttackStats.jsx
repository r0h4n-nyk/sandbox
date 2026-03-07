import React, { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import { getAttackCounts } from '../utils/dataAggregator'

export default function AttackStats({ events }) {
  const attackCounts = useMemo(() => getAttackCounts(events, 24), [events])

  const sparkOption = useMemo(() => ({
    backgroundColor: 'transparent',
    grid: { left: 0, right: 0, top: 0, bottom: 0 },
    xAxis: { type: 'category', show: false, data: attackCounts.map(d => d.time) },
    yAxis: { type: 'value', show: false },
    series: [{
      type: 'line',
      data: attackCounts.map(d => d.count),
      smooth: true,
      symbol: 'none',
      lineStyle: { color: '#8b5cf6', width: 1.5 },
      areaStyle: {
        color: {
          type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
          colorStops: [
            { offset: 0, color: 'rgba(139,92,246,0.3)' },
            { offset: 1, color: 'rgba(139,92,246,0.02)' },
          ],
        },
      },
    }],
  }), [attackCounts])

  const stats = useMemo(() => {
    const now = Date.now()
    const last60 = events.filter(e => now - new Date(e.timestamp).getTime() < 60_000)
    const lastHour = events.filter(e => now - new Date(e.timestamp).getTime() < 3_600_000)
    const uniqueIPs = new Set(events.map(e => e.src_ip)).size
    const uniqueCountries = new Set(events.map(e => e.geolocation?.country).filter(Boolean)).size
    const highThreats = events.filter(e => e.threat_score >= 71).length
    const avgScore = events.length
      ? Math.round(events.reduce((s, e) => s + (e.threat_score || 0), 0) / events.length)
      : 0

    return { last60: last60.length, lastHour: lastHour.length, uniqueIPs, uniqueCountries, highThreats, avgScore }
  }, [events])

  return (
    <div className="panel p-3 col-span-12">
      <div className="grid grid-cols-7 gap-3 items-center">
        {[
          { label: 'EVENTS / MIN', value: stats.last60, color: '#00ff9c' },
          { label: 'EVENTS / HOUR', value: stats.lastHour, color: '#06b6d4' },
          { label: 'UNIQUE IPs', value: stats.uniqueIPs, color: '#f97316' },
          { label: 'COUNTRIES', value: stats.uniqueCountries, color: '#8b5cf6' },
          { label: 'HIGH THREAT', value: stats.highThreats, color: '#ff3b3b' },
          { label: 'AVG SCORE', value: stats.avgScore, color: '#eab308' },
          { label: 'TOTAL EVENTS', value: events.length.toLocaleString(), color: '#e5e7eb' },
        ].map(s => (
          <div key={s.label} className="text-center">
            <div className="section-label mb-0.5">{s.label}</div>
            <div
              className="font-mono text-lg font-bold"
              style={{ color: s.color, textShadow: `0 0 8px ${s.color}40` }}
            >
              {s.value}
            </div>
          </div>
        ))}
      </div>
      {attackCounts.length > 2 && (
        <div className="mt-2 h-8">
          <ReactECharts
            option={sparkOption}
            style={{ height: 32, width: '100%' }}
            opts={{ renderer: 'canvas' }}
          />
        </div>
      )}
    </div>
  )
}