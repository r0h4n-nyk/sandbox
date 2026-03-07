import React, { useEffect, useRef, useMemo, useCallback } from 'react'

const DANGER_CMDS = new Set(['wget', 'curl', 'chmod', 'bash', 'nc', 'python', 'python3', 'perl', 'ruby', 'dd', 'rm', 'mkfs'])
const SUSPICIOUS_CMDS = new Set(['cat', 'find', 'grep', 'iptables', 'sudo', 'su', 'crontab', 'history', 'netstat', 'ps'])

// Real event_id format is "event.cowrie.login", "event.cowrie.command", etc.
const isLoginEvent = id => (id || '').toLowerCase().includes('login')

function getEntryStyle(event) {
  if (!event) return { color: '#6b7280', label: '···', labelColor: '#374151' }
  const id = event.event_id || ''
  const input = (event.input || '').toLowerCase()
  const firstWord = input.trim().split(/\s+/)[0]

  if (isLoginEvent(id)) return { color: '#00ff9c', label: 'AUTH', labelColor: '#00ff9c' }
  if (DANGER_CMDS.has(firstWord)) return { color: '#ff3b3b', label: 'CRIT', labelColor: '#ff3b3b' }
  if (SUSPICIOUS_CMDS.has(firstWord)) return { color: '#f97316', label: 'SUSP', labelColor: '#f97316' }
  return { color: '#eab308', label: ' CMD', labelColor: '#eab308' }
}

function highlightCommand(input) {
  if (!input) return input
  const parts = input.trim().split(/\s+/)
  const first = parts[0]
  if (DANGER_CMDS.has(first)) {
    return (
      <>
        <span className="cmd-danger">{first}</span>
        {parts.length > 1 && ' ' + parts.slice(1).join(' ')}
      </>
    )
  }
  if (SUSPICIOUS_CMDS.has(first)) {
    return (
      <>
        <span className="cmd-suspicious">{first}</span>
        {parts.length > 1 && ' ' + parts.slice(1).join(' ')}
      </>
    )
  }
  return input
}

function formatTime(ts) {
  try {
    const d = new Date(ts)
    return d.toTimeString().slice(0, 8)
  } catch {
    return '??:??:??'
  }
}

const FeedEntry = React.memo(function FeedEntry({ event }) {
  const style = getEntryStyle(event)
  const isLogin = isLoginEvent(event.event_id)

  return (
    <div className="feed-entry flex items-start gap-1.5 py-0.5 px-1.5 hover:bg-white/3 rounded transition-colors group">
      {/* Timestamp */}
      <span className="font-mono text-xs shrink-0" style={{ color: '#374151' }}>
        [{formatTime(event.timestamp)}]
      </span>

      {/* Label badge */}
      <span
        className="font-mono text-xs font-bold shrink-0 w-8 text-center"
        style={{ color: style.labelColor }}
      >
        {style.label}
      </span>

      {/* IP */}
      <span className="font-mono text-xs shrink-0" style={{ color: '#6b7280' }}>
        {event.src_ip}
      </span>

      {/* Country flag / code */}
      <span className="font-mono text-xs shrink-0 text-gray-600">
        [{event.geolocation?.country || '??'}]
      </span>

      {/* Content */}
      <span className="font-mono text-xs flex-1 min-w-0 truncate" style={{ color: style.color }}>
        {isLogin
          ? <>login <span style={{ color: '#e5e7eb' }}>{event.username}</span>:<span style={{ color: '#6b7280' }}>{event.password}</span></>
          : highlightCommand(event.input)
        }
      </span>

      {/* Threat score */}
      {event.threat_score != null && (
        <span
          className="font-mono text-xs shrink-0 font-bold"
          style={{
            color: event.threat_score >= 71 ? '#ff3b3b' : event.threat_score >= 31 ? '#f97316' : '#00ff9c',
          }}
        >
          {event.threat_score}
        </span>
      )}
    </div>
  )
})

export default function LiveAttackFeed({ events }) {
  const containerRef = useRef(null)
  const isAtBottomRef = useRef(true)

  const recentEvents = useMemo(() => events.slice(-200), [events])

  const handleScroll = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    const threshold = 50
    isAtBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < threshold
  }, [])

  useEffect(() => {
    const el = containerRef.current
    if (!el || !isAtBottomRef.current) return
    el.scrollTop = el.scrollHeight
  }, [recentEvents])

  const counts = useMemo(() => {
    const last60 = events.filter(e => {
      const t = new Date(e.timestamp).getTime()
      return Date.now() - t < 60_000
    })
    const logins = last60.filter(e => isLoginEvent(e.event_id)).length
    const cmds = last60.filter(e => !isLoginEvent(e.event_id)).length
    const high = last60.filter(e => e.threat_score >= 71).length
    return { logins, cmds, high, total: last60.length }
  }, [events])

  return (
    <div className="panel h-full flex flex-col" style={{ minHeight: 340 }}>
      <div className="corner-decoration corner-tl" />
      <div className="corner-decoration corner-tr" />

      {/* Header */}
      <div className="flex items-center justify-between px-3 pt-3 pb-2 shrink-0">
        <span className="panel-title">LIVE FEED</span>
        <div className="flex gap-2 text-xs font-mono">
          <span className="text-green-400">{counts.logins} login</span>
          <span className="text-yellow-400">{counts.cmds} cmd</span>
          <span className="text-red-400">{counts.high} crit</span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 px-3 pb-2 shrink-0 border-b border-gray-800">
        {[
          { color: '#00ff9c', label: 'AUTH' },
          { color: '#eab308', label: 'CMD' },
          { color: '#f97316', label: 'SUSP' },
          { color: '#ff3b3b', label: 'CRIT' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1">
            <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ background: color }} />
            <span className="section-label">{label}</span>
          </div>
        ))}
        <span className="section-label ml-auto">{recentEvents.length} events</span>
      </div>

      {/* Feed */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto py-1 min-h-0"
      >
        {recentEvents.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-600 font-mono text-xs">
            Waiting for events...
          </div>
        ) : (
          recentEvents.map((event, i) => (
            <FeedEntry key={event._id || i} event={event} />
          ))
        )}
        {recentEvents.length > 0 && (
          <div className="px-2 py-1">
            <span className="font-mono text-xs text-gray-700 cursor">▮</span>
          </div>
        )}
      </div>
    </div>
  )
}