import React, { useState, useEffect, useMemo } from 'react'

const HONEYPOT_ADDR    = 'blr.honeypot:22'
const HONEYPOT_STARTED = Date.now()

export default function HoneypotHealth({ events, connectionStatus }) {
  const [cpu,    setCpu]    = useState(12)
  const [mem,    setMem]    = useState(34)
  const [uptime, setUptime] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      setCpu(prev  => Math.max(5,  Math.min(95, prev + (Math.random() - 0.4)  * 8)))
      setMem(prev  => Math.max(20, Math.min(85, prev + (Math.random() - 0.45) * 4)))
      setUptime(Math.floor((Date.now() - HONEYPOT_STARTED) / 1000))
    }, 2000)
    return () => clearInterval(interval)
  }, [])

  const stats = useMemo(() => {
    const now       = Date.now()
    const oneMinAgo = now - 60_000
    const sessionsPerMin = events.filter(e =>
      e.event_id?.toLowerCase().includes('login') &&
      new Date(e.timestamp).getTime() > oneMinAgo
    ).length
    const ingestionRate = events.filter(e =>
      new Date(e.timestamp).getTime() > oneMinAgo
    ).length
    const uniqueIPs = new Set(events.map(e => e.src_ip)).size
    return { sessionsPerMin, ingestionRate, uniqueIPs }
  }, [events])

  const statusLabel = {
    connected:    'ONLINE',
    connecting:   'CONNECTING',
    disconnected: 'RECONNECTING',
  }[connectionStatus] ?? 'OFFLINE'

  const statusColor = {
    connected:    '#00ff9c',
    connecting:   '#f97316',
    disconnected: '#eab308',
  }[connectionStatus] ?? '#ff3b3b'

  const uptimeStr = uptime < 60
    ? `${uptime}s`
    : uptime < 3600
    ? `${Math.floor(uptime / 60)}m ${uptime % 60}s`
    : `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`

  const metrics = [
    {
      label: 'HONEYPOT STATUS',
      value: statusLabel,
      sub:   HONEYPOT_ADDR,
      color: statusColor,
      dot:   true,
    },
    {
      label: 'UPTIME',
      value: uptimeStr,
      sub:   'since start',
      color: '#06b6d4',
    },
    {
      label: 'CPU USAGE',
      value: `${cpu.toFixed(1)}%`,
      sub:   'system load',
      color: cpu > 70 ? '#ff3b3b' : cpu > 40 ? '#f97316' : '#00ff9c',
      bar:   cpu,
    },
    {
      label: 'MEMORY',
      value: `${mem.toFixed(1)}%`,
      sub:   '2.4 GB used',
      color: mem > 75 ? '#ff3b3b' : mem > 50 ? '#f97316' : '#06b6d4',
      bar:   mem,
    },
    {
      label: 'SESSIONS / MIN',
      value: stats.sessionsPerMin,
      sub:   'auth attempts',
      color: '#8b5cf6',
    },
    {
      label: 'LOG INGESTION',
      value: `${stats.ingestionRate}/min`,
      sub:   'events/minute',
      color: '#eab308',
    },
    {
      label: 'UNIQUE IPs',
      value: stats.uniqueIPs.toLocaleString(),
      sub:   'total attackers',
      color: '#f97316',
    },
    {
      label: 'TOTAL EVENTS',
      value: events.length.toLocaleString(),
      sub:   'in session',
      color: '#00ff9c',
    },
  ]

  return (
    <div className="panel p-3">
      <div className="corner-decoration corner-tl" />
      <div className="corner-decoration corner-tr" />

      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className="panel-title">HoneyPes // Threat Intelligence SOC Platform</span>
          <span className="section-label">v2.4.1</span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className="status-dot"
            style={{
              background:   statusColor,
              boxShadow:    `0 0 6px ${statusColor}`,
              display:      'inline-block',
              width:        8,
              height:       8,
              borderRadius: '50%',
              animation:    connectionStatus === 'connected' ? 'pulse-dot 2s infinite' : 'none',
            }}
          />
          <span className="font-mono text-xs" style={{ color: statusColor }}>
            {statusLabel}
          </span>
        </div>
      </div>

      {/* Metrics row */}
      <div className="grid grid-cols-8 gap-2">
        {metrics.map((m) => (
          <div
            key={m.label}
            className="bg-black bg-opacity-30 rounded border border-gray-800 p-2 relative overflow-hidden"
          >
            <div className="section-label mb-1">{m.label}</div>
            <div className="flex items-center gap-1.5">
              {m.dot && (
                <span style={{
                  display:      'inline-block',
                  width:        6,
                  height:       6,
                  borderRadius: '50%',
                  background:   m.color,
                  boxShadow:    `0 0 4px ${m.color}`,
                  flexShrink:   0,
                }} />
              )}
              <span
                className="font-mono text-sm font-bold"
                style={{ color: m.color, textShadow: `0 0 6px ${m.color}40` }}
              >
                {m.value}
              </span>
            </div>
            <div className="section-label mt-0.5" style={{ color: '#374151' }}>{m.sub}</div>
            {m.bar !== undefined && (
              <div className="mt-1.5 h-0.5 bg-gray-800 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${m.bar}%`, background: m.color }}
                />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}