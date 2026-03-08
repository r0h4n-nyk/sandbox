import { useState, useEffect, useRef, useCallback } from 'react'

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

const WS_URL            = `ws://${window.location.hostname}:${window.location.port}`;
const MAX_EVENTS        = 1000
const RECONNECT_BASE_MS = 1_000
const RECONNECT_MAX_MS  = 30_000

// ─────────────────────────────────────────────────────────────────────────────
// normalizeEvent
// ─────────────────────────────────────────────────────────────────────────────
// Backend broadcasts this flat shape (from schema.js normalizeEvent):
// {
//   timestamp, src_ip, event_id, session_id, input, username, password,
//   tactic,
//   mitigations: [{ id, name, description }] | null,
//   ai_summary:  string | null,
//   persona:     "Human" | "bot" | "cant decide" | null
// }
// ─────────────────────────────────────────────────────────────────────────────

export function normalizeEvent(raw, _id) {
  // ── Identity ─────────────────────────────────────────────────────────────
  const srcIp     = raw['src ip']     ?? raw.src_ip     ?? '0.0.0.0'
  const timestamp = raw['time stamp'] ?? raw.timestamp  ?? new Date().toISOString()
  const eventId   = raw['event id']   ?? raw.event_id   ?? 'unknown'
  const sessionId = raw['session id'] ?? raw.session_id ?? 'session_unknown'
  const username  = raw.user          ?? raw.username   ?? 'unknown'

  // ── Tactic ───────────────────────────────────────────────────────────────
  const tactic = raw.tactic ?? raw.response?.tactic ?? 'Unknown'

  // ── Techniques ───────────────────────────────────────────────────────────
  // Shape B (backend normalized): flat mitigations array at top level
  // Shape A (raw fallback):       nested inside response.techniques[].mitigations[]
  let techniques = []
  if (Array.isArray(raw.mitigations) && raw.mitigations.length) {
    techniques = raw.mitigations.map(m => ({ id: m.id ?? 'T???', name: m.name ?? 'Unknown' }))
  } else {
    techniques = (raw.response?.techniques ?? []).flatMap(t => {
      if (t.id && t.name) return [{ id: t.id, name: t.name }]
      if (t.mitigations?.length) return t.mitigations.map(m => ({ id: m.id ?? 'T???', name: m.name ?? 'Unknown' }))
      return []
    })
  }

  // ── AI summary ───────────────────────────────────────────────────────────
  // Shape B: raw.ai_summary is a plain string
  // Shape A: raw.ai_response can be string | { summary: string|object }
  let aiSummary = ''
  if (typeof raw.ai_summary === 'string') {
    aiSummary = raw.ai_summary
  } else {
    const aiRaw = raw.ai_response ?? ''
    aiSummary = typeof aiRaw === 'string'
      ? aiRaw
      : typeof aiRaw.summary === 'string'
      ? aiRaw.summary
      : typeof aiRaw.summary === 'object' && aiRaw.summary !== null
      ? (Object.keys(aiRaw.summary)[0] ?? '')   // key IS the summary text
      : ''
  }

  // ── Persona ───────────────────────────────────────────────────────────────
  // Comes from the Python engine via ai_response.persona.
  // Values: "Human" | "bot" | "cant decide" | null
  // Backend passes it through as raw.persona (top-level in normalized shape).
  // Raw fallback reads raw.ai_response.persona directly.
  const persona =
    raw.persona                  ??   // backend normalized (shape B)
    raw.ai_response?.persona     ??   // raw fallback (shape A)
    null

  // ── Geo + threat score ───────────────────────────────────────────────────
  const geo         = raw.geolocation  ?? getGeoOrFetch(srcIp)
  const threatScore = raw.threat_score ?? computeThreatScore(eventId, raw.input ?? null, techniques)

  return {
    _id:         _id ?? (Date.now() + Math.random()),
    timestamp,
    src_ip:      srcIp,
    session_id:  sessionId,
    event_id:    eventId,
    username,
    password:    raw.password ?? null,
    input:       raw.input ?? (eventId.includes('login') ? 'ssh login attempt' : null),
    response: {
      tactic,
      techniques,
    },
    ai_response: {
      persona,        // "Human" | "bot" | "cant decide" | null
      summary: aiSummary,
    },
    geolocation:  geo,
    threat_score: threatScore,
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Geo cache + ip-api.com lookup
// ─────────────────────────────────────────────────────────────────────────────

const geoCache     = new Map()
const geoPending   = new Set()
const geoListeners = new Set()

export function subscribeGeo(fn) {
  geoListeners.add(fn)
  return () => geoListeners.delete(fn)
}

async function fetchGeo(ip) {
  if (geoCache.has(ip) || geoPending.has(ip)) return
  geoPending.add(ip)
  try {
    const res  = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,lat,lon,as`)
    const data = await res.json()
    if (data.status === 'success') {
      const geo = {
        country: data.countryCode,
        city:    data.city,
        lat:     data.lat,
        lon:     data.lon,
        asn:     data.as?.split(' ')[0] ?? '',
      }
      geoCache.set(ip, geo)
      geoListeners.forEach(fn => fn(ip, geo))
    }
  } catch { /* silently ignore — map skips points with no geo */ }
  finally { geoPending.delete(ip) }
}

function getGeoOrFetch(ip) {
  if (geoCache.has(ip)) return geoCache.get(ip)
  fetchGeo(ip)
  return null
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat score helper
// ─────────────────────────────────────────────────────────────────────────────

const DANGER_WORDS     = ['wget','curl','chmod','bash','nc ','python','miner','payload','exploit','reverse','shell']
const SUSPICIOUS_WORDS = ['passwd','shadow','crontab','sudo','iptables','history','find /']

function computeThreatScore(eventId, input, techniques) {
  let score      = 30
  const haystack = ((eventId ?? '') + ' ' + (input ?? '')).toLowerCase()
  if (DANGER_WORDS.some(w     => haystack.includes(w))) score += 40
  if (SUSPICIOUS_WORDS.some(w => haystack.includes(w))) score += 20
  if (techniques.length > 1) score += 10
  return Math.min(score, 100)
}

// ─────────────────────────────────────────────────────────────────────────────
// useWebSocket hook
// ─────────────────────────────────────────────────────────────────────────────

let _idCounter = 0

/**
 * connectionStatus values:
 *   'connecting'   — initial connect or reconnect attempt in progress
 *   'connected'    — live WebSocket open, receiving real events
 *   'disconnected' — connection lost, reconnect timer running
 */
export function useWebSocket() {
  const [events, setEvents]           = useState([])
  const [connectionStatus, setStatus] = useState('connecting')

  const wsRef          = useRef(null)
  const reconnectTimer = useRef(null)
  const attemptRef     = useRef(0)

  const pushEvent = useCallback((normalized) => {
    setEvents(prev => {
      const next = [...prev, normalized]
      return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next
    })
  }, [])

  const connect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onopen    = null
      wsRef.current.onmessage = null
      wsRef.current.onerror   = null
      wsRef.current.onclose   = null
      wsRef.current.close()
    }

    setStatus('connecting')
    const ws      = new WebSocket(WS_URL)
    wsRef.current = ws

    ws.onopen = () => {
      attemptRef.current = 0
      setStatus('connected')
      console.log('[ws] Connected to backend')
    }

    ws.onmessage = (msg) => {
      let raw
      try { raw = JSON.parse(msg.data) }
      catch { console.warn('[ws] Non-JSON message:', msg.data); return }
      pushEvent(normalizeEvent(raw, ++_idCounter))
    }

    ws.onerror = (err) => {
      console.warn('[ws] WebSocket error:', err)
    }

    ws.onclose = () => {
      setStatus('disconnected')
      const delay = Math.min(RECONNECT_BASE_MS * 2 ** attemptRef.current, RECONNECT_MAX_MS)
      attemptRef.current++
      console.log(`[ws] Disconnected — reconnecting in ${delay / 1000}s (attempt ${attemptRef.current})`)
      reconnectTimer.current = setTimeout(connect, delay)
    }
  }, [pushEvent])

  // Re-enrich events whose geo arrived after initial render
  useEffect(() => {
    return subscribeGeo((ip, geo) => {
      setEvents(prev =>
        prev.map(e => e.src_ip === ip && !e.geolocation ? { ...e, geolocation: geo } : e)
      )
    })
  }, [])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return { events, connectionStatus }
}
