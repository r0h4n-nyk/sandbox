import React, { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import { getSessions, getThreatScoreAverage, threatSeverity, threatColor } from '../utils/dataAggregator'

export default function ThreatScoreGauge({ events, selectedSession }) {
  const sessions = useMemo(() => getSessions(events), [events])

  const score = useMemo(() => {
    if (selectedSession) {
      const sess = sessions.find(s => s.session_id === selectedSession)
      if (sess) return sess.maxThreatScore
    }
    return getThreatScoreAverage(events.slice(-100))
  }, [events, sessions, selectedSession])

  const severity = threatSeverity(score)
  const color = threatColor(score)

  const option = useMemo(() => ({
    backgroundColor: 'transparent',
    series: [
      {
        type: 'gauge',
        center: ['50%', '72%'],
        radius: '78%',
        startAngle: 210,
        endAngle: -30,
        min: 0,
        max: 100,
        splitNumber: 10,
        itemStyle: {
          color,
          shadowColor: color,
          shadowBlur: 12,
        },
        progress: {
          show: true,
          roundCap: true,
          width: 12,
          itemStyle: { color },
        },
        pointer: {
          icon: 'path://M2090.36389,615.30999 L2090.36389,615.30999 C2091.48372,615.30999 2092.40883,616.25846 2092.40883,617.4147 L2092.40883,646.4039 C2092.40883,647.56014 2091.48372,648.5086 2090.36389,648.5086 L2090.36389,648.5086 C2089.24406,648.5086 2088.31895,647.56014 2088.31895,646.4039 L2088.31895,617.4147 C2088.31895,616.25846 2089.24406,615.30999 2090.36389,615.30999 Z',
          length: '60%',
          width: 4,
          offsetCenter: [0, '-5%'],
          itemStyle: { color },
        },
        axisLine: {
          roundCap: true,
          lineStyle: {
            width: 12,
            color: [
              [0.3, '#1f2937'],
              [0.7, '#1f2937'],
              [1, '#1f2937'],
            ],
          },
        },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: {
          show: true,
          distance: -40,
          color: '#4b5563',
          fontSize: 9,
          fontFamily: 'JetBrains Mono',
          formatter: (v) => {
            if (v === 0) return '0'
            if (v === 30) return '30'
            if (v === 70) return '70'
            if (v === 100) return '100'
            return ''
          },
        },
        anchor: {
          show: true,
          showAbove: false,
          size: 16,
          icon: 'circle',
          offsetCenter: [0, '-3%'],
          keepAspect: false,
          itemStyle: {
            color: '#111827',
            borderColor: color,
            borderWidth: 2,
          },
        },
        title: { show: false },
        detail: {
          valueAnimation: true,
          fontSize: 28,
          fontWeight: 700,
          fontFamily: 'Orbitron',
          color,
          textShadowColor: color,
          textShadowBlur: 8,
          offsetCenter: [0, '30'],
          formatter: '{value}',
        },
        data: [{ value: score }],
      },

      // Background arc zones
      {
        type: 'gauge',
        center: ['50%', '72%'],
        radius: '78%',
        startAngle: 210,
        endAngle: -30,
        min: 0,
        max: 100,
        splitNumber: 3,
        pointer: { show: false },
        progress: { show: false },
        axisLine: {
          roundCap: true,
          lineStyle: {
            width: 12,
            color: [
              [0.3, 'rgba(0,255,156,0.1)'],
              [0.7, 'rgba(249,115,22,0.1)'],
              [1, 'rgba(255,59,59,0.1)'],
            ],
          },
        },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        detail: { show: false },
        data: [{ value: 0 }],
      },
    ],
  }), [score, color])

  return (
    <div className="panel h-full flex flex-col" style={{ minHeight: 260 }}>
      <div className="corner-decoration corner-tl" />
      <div className="corner-decoration corner-tr" />

      <div className="flex items-center justify-between px-3 pt-3 pb-1 shrink-0">
        <span className="panel-title">THREAT SCORE</span>
        <span className="section-label">{selectedSession ? 'SESSION' : 'AVG LAST 100'}</span>
      </div>

      <div className="flex-1 min-h-0">
        <ReactECharts
          option={option}
          style={{ width: '100%', height: '100%', minHeight: 180 }}
          opts={{ renderer: 'canvas' }}
        />
      </div>

      {/* Severity label */}
      <div className="flex items-center justify-center gap-3 pb-3 shrink-0">
        <span
          className="font-mono text-xs font-bold px-4 py-1 rounded"
          style={{
            color,
            border: `1px solid ${color}40`,
            background: `${color}15`,
            textShadow: `0 0 8px ${color}80`,
          }}
        >
          {severity}
        </span>
      </div>

      {/* Score bands */}
      <div className="flex justify-between px-4 pb-3 shrink-0">
        {[
          { label: 'LOW', range: '0-30', c: '#00ff9c' },
          { label: 'MED', range: '31-70', c: '#f97316' },
          { label: 'HIGH', range: '71-100', c: '#ff3b3b' },
        ].map(b => (
          <div key={b.label} className="text-center">
            <div className="section-label" style={{ color: b.c }}>{b.label}</div>
            <div className="font-mono text-xs" style={{ color: '#374151' }}>{b.range}</div>
          </div>
        ))}
      </div>
    </div>
  )
}