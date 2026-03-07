// ── getTopAttackers ────────────────────────────────────────────────────────
export function getTopAttackers(events, limit = 10) {
  const map = {}
  for (const e of events) {
    if (!e.src_ip) continue
    if (!map[e.src_ip]) {
      map[e.src_ip] = {
        ip: e.src_ip,
        count: 0,
        country: e.geolocation?.country || '??',
        city: e.geolocation?.city || 'Unknown',
        asn: e.geolocation?.asn || '',
        maxScore: 0,
        lat: e.geolocation?.lat,
        lon: e.geolocation?.lon,
      }
    }
    map[e.src_ip].count++
    map[e.src_ip].maxScore = Math.max(map[e.src_ip].maxScore, e.threat_score || 0)
  }
  return Object.values(map)
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
}

// ── getCommandFrequency ────────────────────────────────────────────────────
export function getCommandFrequency(events, limit = 15) {
  const map = {}
  const SKIP_EVENTS = new Set(['login', 'ssh login attempt'])

  for (const e of events) {
    const input = e.input
    if (!input) continue
    if (SKIP_EVENTS.has(input)) continue
    if (e.event_id?.toLowerCase().includes('login')) continue

    // Extract the base command (first word)
    const base = input.trim().split(/\s+/)[0]
    if (!base || base.length < 2) continue
    map[base] = (map[base] || 0) + 1
  }

  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([cmd, count]) => ({ cmd, count }))
}

// ── getMitreTactics ────────────────────────────────────────────────────────
export function getMitreTactics(events) {
  const TACTIC_ORDER = [
    'Initial Access',
    'Credential Access',
    'Discovery',
    'Execution',
    'Privilege Escalation',
    'Persistence',
    'Exfiltration',
    'Impact',
  ]

  const map = {}
  for (const e of events) {
    const tactic = e.response?.tactic
    if (!tactic) continue
    if (!map[tactic]) {
      map[tactic] = {
        tactic,
        count: 0,
        techniques: new Set(),
        timestamps: [],
        events: [],
      }
    }
    map[tactic].count++
    for (const t of e.response?.techniques || []) {
      map[tactic].techniques.add(`${t.id}: ${t.name}`)
    }
    map[tactic].timestamps.push(e.timestamp)
    if (map[tactic].events.length < 5) map[tactic].events.push(e)
  }

  return TACTIC_ORDER
    .filter(t => map[t])
    .map(t => ({
      ...map[t],
      techniques: Array.from(map[t].techniques),
    }))
}

// ── getAttackCounts ────────────────────────────────────────────────────────
export function getAttackCounts(events, buckets = 20) {
  if (!events.length) return []

  const times = events
    .map(e => new Date(e.timestamp).getTime())
    .filter(t => !isNaN(t))
    .sort((a, b) => a - b)

  if (!times.length) return []

  const min = times[0]
  const max = times[times.length - 1]
  const range = max - min || 1
  const bucketSize = range / buckets

  const counts = new Array(buckets).fill(0)
  for (const t of times) {
    const idx = Math.min(Math.floor((t - min) / bucketSize), buckets - 1)
    counts[idx]++
  }

  return counts.map((count, i) => ({
    time: new Date(min + i * bucketSize).toISOString(),
    count,
  }))
}

// ── getSessions ────────────────────────────────────────────────────────────
export function getSessions(events) {
  const map = {}
  for (const e of events) {
    const sid = e.session_id
    if (!sid) continue
    if (!map[sid]) {
      map[sid] = {
        session_id: sid,
        events: [],
        src_ip: e.src_ip,
        country: e.geolocation?.country || '??',
        city: e.geolocation?.city || 'Unknown',
        startTime: e.timestamp,
        endTime: e.timestamp,
        maxThreatScore: 0,
        tactics: new Set(),
        persona: e.ai_response?.persona_classification || 'unknown',
        aiSummary: e.ai_response?.summary || '',
      }
    }
    map[sid].events.push(e)
    map[sid].endTime = e.timestamp
    map[sid].maxThreatScore = Math.max(map[sid].maxThreatScore, e.threat_score || 0)
    if (e.response?.tactic) map[sid].tactics.add(e.response.tactic)
    if (e.ai_response?.summary) map[sid].aiSummary = e.ai_response.summary
    if (e.ai_response?.persona_classification) map[sid].persona = e.ai_response.persona_classification
  }

  return Object.values(map)
    .map(s => ({ ...s, tactics: Array.from(s.tactics) }))
    .sort((a, b) => new Date(b.startTime) - new Date(a.startTime))
}

// ── getThreatScoreAverage ──────────────────────────────────────────────────
export function getThreatScoreAverage(events) {
  if (!events.length) return 0
  const withScore = events.filter(e => e.threat_score != null)
  if (!withScore.length) return 0
  return Math.round(withScore.reduce((s, e) => s + e.threat_score, 0) / withScore.length)
}

// ── getGeoPoints ───────────────────────────────────────────────────────────
export function getGeoPoints(events) {
  const map = {}
  for (const e of events) {
    const geo = e.geolocation
    if (!geo?.lat || !geo?.lon) continue
    const key = `${e.src_ip}`
    if (!map[key]) {
      map[key] = {
        ip: e.src_ip,
        lat: geo.lat,
        lon: geo.lon,
        country: geo.country,
        city: geo.city,
        asn: geo.asn,
        count: 0,
        maxScore: 0,
      }
    }
    map[key].count++
    map[key].maxScore = Math.max(map[key].maxScore, e.threat_score || 0)
  }
  return Object.values(map)
}

// ── threatSeverity ─────────────────────────────────────────────────────────
export function threatSeverity(score) {
  if (score >= 71) return 'HIGH'
  if (score >= 31) return 'MEDIUM'
  return 'LOW'
}

export function threatColor(score) {
  if (score >= 71) return '#ff3b3b'
  if (score >= 31) return '#f97316'
  return '#00ff9c'
}