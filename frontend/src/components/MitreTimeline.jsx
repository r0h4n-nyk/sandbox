import React, { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import { getMitreTactics } from '../utils/dataAggregator'

const TACTIC_COLORS = {
  'Initial Access':       '#8b5cf6',
  'Credential Access':    '#06b6d4',
  'Discovery':            '#eab308',
  'Execution':            '#f97316',
  'Privilege Escalation': '#ec4899',
  'Persistence':          '#ff3b3b',
  'Exfiltration':         '#dc2626',
  'Impact':               '#7f1d1d',
}

const DEFAULT_COLOR = '#6b7280'

function TacticCard({ tactic, idx, total }) {
  const color = TACTIC_COLORS[tactic.tactic] || DEFAULT_COLOR
  const barWidth = Math.min(100, (tactic.count / Math.max(1, total)) * 100)

  return (
    <div
      className="relative flex flex-col gap-1 p-2.5 rounded border transition-all"
      style={{
        borderColor: `${color}30`,
        background: `linear-gradient(135deg, ${color}08, transparent)`,
      }}
    >
      {/* Sequence number */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span
            className="inline-flex items-center justify-center w-5 h-5 rounded text-xs font-bold font-mono shrink-0"
            style={{ background: `${color}25`, color, border: `1px solid ${color}50` }}
          >
            {idx + 1}
          </span>
          <span
            className="font-mono text-xs font-bold"
            style={{ color }}
          >
            {tactic.tactic}
          </span>
        </div>
        <span className="font-mono text-xs" style={{ color: '#4b5563' }}>
          ×{tactic.count}
        </span>
      </div>

      {/* Techniques */}
      <div className="flex flex-wrap gap-1 mt-0.5">
        {tactic.techniques.slice(0, 3).map(t => (
          <span key={t} className="stix-tag" style={{ fontSize: 9, padding: '1px 5px' }}>
            {t.split(':')[0]}
          </span>
        ))}
        {tactic.techniques.length > 3 && (
          <span className="section-label" style={{ alignSelf: 'center' }}>
            +{tactic.techniques.length - 3} more
          </span>
        )}
      </div>

      {/* Bar */}
      <div className="h-0.5 bg-gray-800 rounded-full overflow-hidden mt-1">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${barWidth}%`, background: color, boxShadow: `0 0 4px ${color}` }}
        />
      </div>

      {/* Connector line (except last) */}
      {idx < total - 1 && (
        <div
          className="absolute left-1/2 -bottom-2.5 w-px h-2.5"
          style={{ background: `linear-gradient(${color}, ${TACTIC_COLORS[Object.keys(TACTIC_COLORS)[idx + 1]] || DEFAULT_COLOR})` }}
        />
      )}
    </div>
  )
}

export default function MitreTimeline({ events }) {
  const tactics = useMemo(() => getMitreTactics(events), [events])

  const totalEvents = useMemo(
    () => tactics.reduce((s, t) => s + t.count, 0),
    [tactics]
  )

  // ECharts donut for the overview
  const option = useMemo(() => {
    if (!tactics.length) return {}

    return {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        backgroundColor: '#111827',
        borderColor: '#1f2937',
        textStyle: { color: '#e5e7eb', fontFamily: 'JetBrains Mono', fontSize: 11 },
        formatter: params => {
          const t = tactics.find(t => t.tactic === params.name)
          if (!t) return params.name
          return [
            `<b style="color:${params.color}">${t.tactic}</b>`,
            `Events: <b>${t.count}</b> (${params.percent}%)`,
            t.techniques.slice(0, 2).map(te => `· ${te}`).join('<br/>'),
          ].join('<br/>')
        },
      },
      legend: {
        show: false,
      },
      series: [{
        type: 'pie',
        radius: ['42%', '72%'],
        center: ['50%', '52%'],
        avoidLabelOverlap: true,
        padAngle: 2,
        itemStyle: {
          borderRadius: 4,
          borderColor: '#111827',
          borderWidth: 2,
        },
        label: {
          show: true,
          position: 'outside',
          fontFamily: 'JetBrains Mono',
          fontSize: 9,
          fontWeight: 600,
          formatter: params => `${params.name}\n${params.percent}%`,
          color: '#9ca3af',
          lineHeight: 14,
        },
        labelLine: {
          length: 8,
          length2: 12,
          lineStyle: { width: 1, opacity: 0.6 },
        },
        emphasis: {
          scale: true,
          scaleSize: 6,
          itemStyle: {
            shadowBlur: 16,
            shadowOffsetX: 0,
            shadowColor: 'rgba(0,0,0,0.6)',
          },
          label: {
            fontWeight: 700,
            color: '#e5e7eb',
            fontSize: 10,
          },
        },
        data: tactics.map(t => ({
          value: t.count,
          name: t.tactic,
          itemStyle: {
            color: {
              type: 'radial', x: 0.5, y: 0.5, r: 0.8,
              colorStops: [
                { offset: 0, color: `${TACTIC_COLORS[t.tactic] || DEFAULT_COLOR}dd` },
                { offset: 1, color: `${TACTIC_COLORS[t.tactic] || DEFAULT_COLOR}66` },
              ],
            },
          },
        })),
      }],
    }
  }, [tactics])

  return (
    <div className="panel h-full flex flex-col" style={{ minHeight: 340 }}>
      <div className="corner-decoration corner-tl" />
      <div className="corner-decoration corner-tr" />

      <div className="flex items-center justify-between px-3 pt-3 pb-2 shrink-0">
        <span className="panel-title">MITRE ATT&CK TIMELINE</span>
        <span className="font-mono text-xs text-gray-500">{totalEvents} mapped events</span>
      </div>

      <div className="flex flex-1 min-h-0 gap-0">
        {/* Left: funnel chart */}
        <div className="flex-1 min-h-0" style={{ minWidth: 0 }}>
          {tactics.length > 0 ? (
            <ReactECharts
              option={option}
              style={{ width: '100%', height: '100%', minHeight: 220 }}
              opts={{ renderer: 'canvas' }}
            />
          ) : (
            <div className="flex items-center justify-center h-full text-gray-600 font-mono text-xs">
              Waiting for tactic data...
            </div>
          )}
        </div>

        {/* Right: tactic cards */}
        <div className="w-44 overflow-y-auto p-2 flex flex-col gap-2.5 border-l border-gray-800 shrink-0">
          {tactics.map((tactic, i) => (
            <TacticCard
              key={tactic.tactic}
              tactic={tactic}
              idx={i}
              total={tactics.length}
            />
          ))}
          {tactics.length === 0 && (
            <div className="text-gray-600 font-mono text-xs p-2">No tactics yet</div>
          )}
        </div>
      </div>
    </div>
  )
}