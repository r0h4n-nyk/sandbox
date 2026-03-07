import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import { getSessions } from '../utils/dataAggregator'

const DANGER = new Set(['wget', 'curl', 'chmod', 'bash', 'nc', 'python3', 'python', 'perl', 'dd', 'rm', 'mkfs', 'sh'])
const SUSPICIOUS = new Set(['cat', 'find', 'grep', 'iptables', 'sudo', 'su', 'crontab', 'history', 'netstat', 'ps', 'id', 'whoami'])

const isLoginEvent = id => (id || '').toLowerCase().includes('login')

function classify(event) {
  if (isLoginEvent(event.event_id)) return 'login'
  const first = (event.input || '').trim().split(/\s+/)[0].toLowerCase()
  if (DANGER.has(first)) return 'danger'
  if (SUSPICIOUS.has(first)) return 'suspicious'
  return 'normal'
}

function lineColor(cls) {
  return {
    login: '#00ff9c',
    danger: '#ff3b3b',
    suspicious: '#f97316',
    normal: '#e5e7eb',
  }[cls]
}

function formatTs(ts) {
  try { return new Date(ts).toTimeString().slice(0, 8) } catch { return '' }
}

const SPEEDS = [0.5, 1, 2, 5, 10]

export default function SessionReplay({ events, selectedSession, onSelectSession }) {
  const sessions = useMemo(() => getSessions(events), [events])

  const activeSession = useMemo(() => {
    if (!selectedSession) return sessions[0] || null
    return sessions.find(s => s.session_id === selectedSession) || sessions[0] || null
  }, [sessions, selectedSession])

  const sessionEvents = useMemo(() =>
    activeSession ? activeSession.events.sort((a, b) =>
      new Date(a.timestamp) - new Date(b.timestamp)
    ) : [],
    [activeSession]
  )

  const [playhead, setPlayhead] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speedIdx, setSpeedIdx] = useState(1)
  const timerRef = useRef(null)
  const termRef = useRef(null)

  // Reset when session changes
  useEffect(() => {
    setPlayhead(0)
    setPlaying(false)
  }, [activeSession?.session_id])

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [playhead])

  // Playback engine
  useEffect(() => {
    if (!playing) { clearInterval(timerRef.current); return }
    const speed = SPEEDS[speedIdx]
    const interval = Math.max(50, 600 / speed)
    timerRef.current = setInterval(() => {
      setPlayhead(prev => {
        if (prev >= sessionEvents.length) { setPlaying(false); return prev }
        return prev + 1
      })
    }, interval)
    return () => clearInterval(timerRef.current)
  }, [playing, speedIdx, sessionEvents.length])

  const visibleEvents = sessionEvents.slice(0, playhead)

  const togglePlay = useCallback(() => {
    if (playhead >= sessionEvents.length) setPlayhead(0)
    setPlaying(p => !p)
  }, [playhead, sessionEvents.length])

  const cycleSpeed = useCallback(() => {
    setSpeedIdx(i => (i + 1) % SPEEDS.length)
  }, [])

  if (!activeSession) {
    return (
      <div className="panel h-full flex items-center justify-center">
        <span className="font-mono text-xs text-gray-600">No sessions available</span>
      </div>
    )
  }

  return (
    <div className="panel h-full flex flex-col" style={{ minHeight: 340 }}>
      <div className="corner-decoration corner-tl" />
      <div className="corner-decoration corner-tr" />

      {/* Header */}
      <div className="flex items-center justify-between px-3 pt-3 pb-2 shrink-0">
        <span className="panel-title">SESSION REPLAY</span>
        <div className="flex items-center gap-2">
          <div className="relative">
            <select
              value={activeSession.session_id}
              onChange={e => onSelectSession(e.target.value)}
              className="appearance-none outline-none cursor-pointer font-mono text-xs pr-6 pl-2 py-1 rounded"
              style={{
                background: 'rgba(0,255,156,0.05)',
                border: '1px solid rgba(0,255,156,0.25)',
                color: '#00ff9c',
                maxWidth: 160,
                boxShadow: '0 0 8px rgba(0,255,156,0.08)',
              }}
            >
              {sessions.slice(0, 20).map(s => (
                <option
                  key={s.session_id}
                  value={s.session_id}
                  style={{ background: '#111827', color: '#e5e7eb' }}
                >
                  {s.session_id} ({s.events.length}ev)
                </option>
              ))}
            </select>
            {/* chevron */}
            <span
              className="pointer-events-none absolute right-1.5 top-1/2 -translate-y-1/2 text-xs leading-none"
              style={{ color: '#00ff9c' }}
            >
              ▾
            </span>
          </div>
        </div>
      </div>

      {/* Session meta */}
      <div className="flex items-center gap-3 px-3 pb-2 shrink-0 border-b border-gray-800">
        <span className="font-mono text-xs text-gray-400">{activeSession.src_ip}</span>
        <span className="section-label">{activeSession.country} / {activeSession.city}</span>
        <span
          className="threat-badge ml-auto"
          style={{
            background: activeSession.maxThreatScore >= 71
              ? 'rgba(255,59,59,0.15)'
              : activeSession.maxThreatScore >= 31
              ? 'rgba(249,115,22,0.15)'
              : 'rgba(0,255,156,0.1)',
            color: activeSession.maxThreatScore >= 71 ? '#ff3b3b' : activeSession.maxThreatScore >= 31 ? '#f97316' : '#00ff9c',
            border: `1px solid ${activeSession.maxThreatScore >= 71 ? 'rgba(255,59,59,0.3)' : activeSession.maxThreatScore >= 31 ? 'rgba(249,115,22,0.3)' : 'rgba(0,255,156,0.2)'}`,
          }}
        >
          SCORE: {activeSession.maxThreatScore}
        </span>
      </div>

      {/* Terminal */}
      <div
        ref={termRef}
        className="flex-1 overflow-y-auto min-h-0 p-3 font-mono text-xs"
        style={{ background: 'rgba(0,0,0,0.4)', lineHeight: 1.7 }}
      >
        {/* Session header */}
        <div style={{ color: '#374151' }}>
          {'─'.repeat(40)} SESSION START {'─'.repeat(10)}
        </div>
        <div style={{ color: '#374151' }}>
          Connected from: {activeSession.src_ip} [{activeSession.country}]
        </div>
        <div style={{ color: '#374151', marginBottom: 8 }}>
          {formatTs(activeSession.startTime)}
        </div>

        {visibleEvents.map((event, i) => {
          const cls = classify(event)
          const color = lineColor(cls)

          if (isLoginEvent(event.event_id)) {
            return (
              <div key={i} style={{ color }}>
                <span style={{ color: '#4b5563' }}>{formatTs(event.timestamp)} </span>
                <span>login </span>
                <span style={{ color: '#e5e7eb', fontWeight: 600 }}>{event.username}</span>
                <span style={{ color: '#4b5563' }}>:</span>
                <span style={{ color: '#6b7280' }}>{event.password}</span>
                <span style={{ color: '#00ff9c' }}> ✓ authenticated</span>
              </div>
            )
          }

          return (
            <div key={i}>
              <span style={{ color: '#4b5563' }}>{formatTs(event.timestamp)} </span>
              <span style={{ color: '#8b5cf6' }}>$ </span>
              <span
                style={{ color }}
                className={cls === 'danger' ? 'cmd-danger' : cls === 'suspicious' ? 'cmd-suspicious' : ''}
              >
                {event.input}
              </span>
            </div>
          )
        })}

        {/* Cursor */}
        {playing && (
          <span style={{ color: '#00ff9c' }} className="cursor" />
        )}
        {!playing && playhead > 0 && playhead >= sessionEvents.length && (
          <div style={{ color: '#374151', marginTop: 8 }}>
            {'─'.repeat(40)} SESSION END {'─'.repeat(12)}
          </div>
        )}
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3 px-3 py-2 shrink-0 border-t border-gray-800">
        {/* Play/Pause */}
        <button
          className="btn-primary px-3 py-1"
          onClick={togglePlay}
          style={{ fontSize: 11 }}
        >
          {playing ? '⏸ PAUSE' : playhead >= sessionEvents.length ? '↺ REPLAY' : '▶ PLAY'}
        </button>

        {/* Speed */}
        <button
          onClick={cycleSpeed}
          className="font-mono text-xs px-2 py-1 rounded border border-gray-700 text-gray-400 hover:text-gray-200 transition-colors"
          title="Cycle speed"
        >
          {SPEEDS[speedIdx]}×
        </button>

        {/* Timeline slider */}
        <input
          type="range"
          min={0}
          max={sessionEvents.length}
          value={playhead}
          onChange={e => { setPlayhead(Number(e.target.value)); setPlaying(false) }}
          className="flex-1"
          style={{ accentColor: '#8b5cf6' }}
        />

        {/* Progress */}
        <span className="font-mono text-xs text-gray-500 shrink-0">
          {playhead}/{sessionEvents.length}
        </span>
      </div>
    </div>
  )
}