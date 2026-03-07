import React, { useMemo } from 'react'
import { getSessions } from '../utils/dataAggregator'

const PERSONA_ICONS = {
  'script kiddie':      { icon: '👾', color: '#00ff9c' },
  'nation state actor': { icon: '🏛', color: '#ff3b3b' },
  'cybercriminal':      { icon: '💀', color: '#f97316' },
  'hacktivist':         { icon: '✊', color: '#8b5cf6' },
  'insider threat':     { icon: '🕵', color: '#eab308' },
  'apt group':          { icon: '⚡', color: '#ff3b3b' },
  'unknown':            { icon: '❓', color: '#6b7280' },
}

function PersonaBadge({ persona }) {
  const key = (persona || '').toLowerCase()
  const { icon, color } = PERSONA_ICONS[key] || PERSONA_ICONS['unknown']

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded font-mono text-xs font-bold"
      style={{
        background: `${color}15`,
        border: `1px solid ${color}40`,
        color,
      }}
    >
      <span>{icon}</span>
      <span style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>{persona || 'UNKNOWN'}</span>
    </span>
  )
}

export default function AISummaryPanel({ events, selectedSession }) {
  const sessions = useMemo(() => getSessions(events), [events])

  const session = useMemo(() => {
    if (selectedSession) {
      return sessions.find(s => s.session_id === selectedSession) || sessions[0] || null
    }
    return sessions[0] || null
  }, [sessions, selectedSession])

  // Collect unique personas
  const allPersonas = useMemo(() => {
    const counts = {}
    for (const s of sessions) {
      const p = (s.persona || 'unknown').toLowerCase()
      counts[p] = (counts[p] || 0) + 1
    }
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
  }, [sessions])

  const recentSummaries = useMemo(() => {
    return sessions
      .filter(s => s.aiSummary)
      .slice(0, 3)
  }, [sessions])

  if (!session) {
    return (
      <div className="panel h-full flex items-center justify-center">
        <span className="font-mono text-xs text-gray-600">No session data</span>
      </div>
    )
  }

  return (
    <div className="panel h-full flex flex-col" style={{ minHeight: 260 }}>
      <div className="corner-decoration corner-tl" />
      <div className="corner-decoration corner-tr" />

      {/* Header */}
      <div className="flex items-center justify-between px-3 pt-3 pb-2 shrink-0">
        <span className="panel-title">AI ANALYSIS</span>
      </div>

      {/* Active session summary */}
      <div className="px-3 pb-3 shrink-0 border-b border-gray-800">
        <div className="flex items-center gap-2 mb-2">
          <PersonaBadge persona={session.persona} />
          <span className="font-mono text-xs text-gray-500">{session.session_id}</span>
        </div>

        {session.aiSummary ? (
          <div
            className="font-mono text-xs leading-relaxed p-2.5 rounded border"
            style={{
              color: '#d1d5db',
              background: 'rgba(139,92,246,0.05)',
              borderColor: 'rgba(139,92,246,0.2)',
              lineHeight: 1.7,
            }}
          >
            <span style={{ color: '#8b5cf6' }}>» </span>
            {session.aiSummary}
          </div>
        ) : (
          <div className="font-mono text-xs text-gray-600 italic">No AI summary available</div>
        )}

        {/* Tactics */}
        {session.tactics?.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {session.tactics.map(t => (
              <span key={t} className="stix-tag" style={{ fontSize: 9 }}>{t}</span>
            ))}
          </div>
        )}
      </div>

      {/* Persona distribution */}
      <div className="px-3 py-2 shrink-0 border-b border-gray-800">
        <div className="section-label mb-2">THREAT ACTOR BREAKDOWN</div>
        <div className="space-y-1.5">
          {allPersonas.map(([persona, count]) => {
            const key = persona.toLowerCase()
            const { color } = PERSONA_ICONS[key] || PERSONA_ICONS['unknown']
            const pct = Math.round((count / sessions.length) * 100)

            return (
              <div key={persona} className="flex items-center gap-2">
                <span className="font-mono text-xs w-28 truncate" style={{ color }}>{persona}</span>
                <div className="flex-1 h-1 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${pct}%`, background: color, boxShadow: `0 0 4px ${color}40` }}
                  />
                </div>
                <span className="font-mono text-xs text-gray-500 w-8 text-right">{pct}%</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Recent summaries */}
      <div className="flex-1 overflow-y-auto min-h-0 px-3 py-2">
        <div className="section-label mb-2">RECENT ACTIVITY</div>
        <div className="space-y-2">
          {recentSummaries.map(s => (
            <div
              key={s.session_id}
              className="flex gap-2 p-2 rounded border"
              style={{ borderColor: '#1f2937', background: 'rgba(0,0,0,0.2)' }}
            >
              <div className="flex flex-col gap-1 min-w-0">
                <div className="flex items-center gap-2">
                  <PersonaBadge persona={s.persona} />
                  <span className="font-mono text-xs text-gray-600">{s.src_ip}</span>
                </div>
                <p className="font-mono text-xs text-gray-400 leading-relaxed truncate">
                  {s.aiSummary}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}