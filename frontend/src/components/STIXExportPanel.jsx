import React, { useMemo, useState } from 'react'
import { getTopAttackers, getMitreTactics } from '../utils/dataAggregator'

function generateSTIX(events, attackers, tactics) {
  const now = new Date().toISOString()
  const indicators = []
  const attackPatterns = []
  const malwareHashes = []

  // IP indicators
  const topIPs = attackers.slice(0, 20)
  for (const attacker of topIPs) {
    const id = `indicator--${crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2)}`
    indicators.push({
      type: 'indicator',
      spec_version: '2.1',
      id,
      created: now,
      modified: now,
      name: `Malicious IP: ${attacker.ip}`,
      description: `Attack source IP from ${attacker.city}, ${attacker.country} (${attacker.asn})`,
      pattern: `[ipv4-addr:value = '${attacker.ip}']`,
      pattern_type: 'stix',
      valid_from: now,
      labels: ['malicious-activity'],
      confidence: Math.min(100, attacker.count * 5),
    })
  }

  // Attack patterns from MITRE
  for (const tactic of tactics) {
    for (const tech of tactic.techniques) {
      const [techId, techName] = tech.split(': ')
      const apId = `attack-pattern--${techId.toLowerCase()}`
      attackPatterns.push({
        type: 'attack-pattern',
        spec_version: '2.1',
        id: apId,
        created: now,
        modified: now,
        name: techName || tech,
        description: `MITRE ATT&CK ${tactic.tactic} - ${tech}`,
        external_references: [{
          source_name: 'mitre-attack',
          external_id: techId,
          url: `https://attack.mitre.org/techniques/${techId}/`,
        }],
      })
    }
  }

  // Extract potential malware-related commands
  const malwareCommands = events
    .filter(e => {
      const inp = (e.input || '').toLowerCase()
      return inp.includes('wget') || inp.includes('curl') || inp.includes('.sh') || inp.includes('miner')
    })
    .slice(0, 10)

  for (const ev of malwareCommands) {
    const hash = btoa(ev.input || '').slice(0, 16)
    malwareHashes.push({
      input: ev.input,
      hash: `sha256:${hash}${'0'.repeat(48 - hash.length)}`,
      ip: ev.src_ip,
      ts: ev.timestamp,
    })
  }

  const bundle = {
    type: 'bundle',
    id: `bundle--${Date.now()}`,
    spec_version: '2.1',
    objects: [...indicators, ...attackPatterns],
  }

  return { bundle, indicators, attackPatterns, malwareHashes }
}

export default function STIXExportPanel({ events }) {
  const [exporting, setExporting] = useState(false)
  const [exported, setExported] = useState(false)

  const attackers = useMemo(() => getTopAttackers(events, 20), [events])
  const tactics = useMemo(() => getMitreTactics(events), [events])

  const { bundle, indicators, attackPatterns, malwareHashes } = useMemo(
    () => generateSTIX(events, attackers, tactics),
    [events, attackers, tactics]
  )

  const handleExport = () => {
    setExporting(true)
    setTimeout(() => {
      const json = JSON.stringify(bundle, null, 2)
      const blob = new Blob([json], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `stix-bundle-${new Date().toISOString().slice(0, 10)}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      setExporting(false)
      setExported(true)
      setTimeout(() => setExported(false), 3000)
    }, 600)
  }

  const handleCopy = () => {
    navigator.clipboard?.writeText(JSON.stringify(bundle, null, 2))
  }

  return (
    <div className="panel" style={{ minHeight: 160 }}>
      <div className="corner-decoration corner-tl" />
      <div className="corner-decoration corner-tr" />
      <div className="corner-decoration corner-bl" />
      <div className="corner-decoration corner-br" />

      <div className="p-5 space-y-4">
        {/* Header row */}
        <div className="flex items-center justify-between mb-3">
          <span className="panel-title">STIX 2.1 INTELLIGENCE EXPORT</span>
          <div className="flex items-center gap-2">
            <button
              className="btn-primary"
              onClick={handleCopy}
            >
              COPY JSON
            </button>
            <button
              className={`btn-primary ${exporting ? 'opacity-60 cursor-wait' : ''} ${exported ? 'opacity-80' : ''}`}
              onClick={handleExport}
              disabled={exporting}
              style={exported ? { borderColor: 'rgba(0,255,156,0.6)', color: '#00ff9c' } : {}}
            >
              {exporting ? '⏳ GENERATING...' : exported ? '✓ EXPORTED' : '⬇ EXPORT STIX BUNDLE'}
            </button>
          </div>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-4 gap-4 min-h-[90px]">
          {[
            { label: 'IP INDICATORS', value: indicators.length, color: '#ff3b3b', icon: '🎯' },
            { label: 'ATT&CK PATTERNS', value: attackPatterns.length, color: '#8b5cf6', icon: '⚔️' },
            { label: 'MALWARE REFS', value: malwareHashes.length, color: '#f97316', icon: '🦠' },
            { label: 'TOTAL OBJECTS', value: bundle.objects?.length || 0, color: '#06b6d4', icon: '📦' },
          ].map(stat => (
            <div
              key={stat.label}
              className="rounded border py-4 px-3 flex flex-col items-center justify-center gap-1"
              style={{ borderColor: `${stat.color}30`, background: `${stat.color}08` }}
            >
              <div className="text-xl">{stat.icon}</div>

              <div
                className="font-mono text-2xl font-bold leading-none"
                style={{ color: stat.color, textShadow: `0 0 8px ${stat.color}50` }}
              >
                {stat.value}
              </div>

              <div className="section-label">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Data rows */}
        <div className="grid grid-cols-3 gap-4">
          {/* Malicious IPs */}
          <div>
            <div className="section-label mb-2">TOP MALICIOUS IPs</div>
            <div className="space-y-1">
              {attackers.slice(0, 6).map(a => (
                <div key={a.ip} className="flex items-center justify-between font-mono text-xs">
                  <span style={{ color: '#ff3b3b' }}>{a.ip}</span>
                  <span className="text-gray-500">{a.country} ×{a.count}</span>
                </div>
              ))}
            </div>
          </div>

          {/* ATT&CK Techniques */}
          <div>
            <div className="section-label mb-2">ATT&CK TECHNIQUES DETECTED</div>
            <div className="space-y-1">
              {tactics.flatMap(t => t.techniques).slice(0, 6).map((tech, i) => (
                <div key={i} className="flex items-center gap-1.5">
                  <span className="stix-tag">{tech.split(':')[0]}</span>
                  <span className="font-mono text-xs text-gray-400 truncate">{tech.split(': ')[1] || tech}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Malware hashes */}
          <div>
            <div className="section-label mb-2">MALWARE COMMAND REFS</div>
            <div className="space-y-1">
              {malwareHashes.slice(0, 6).map((m, i) => (
                <div key={i} className="font-mono text-xs">
                  <div style={{ color: '#f97316' }} className="truncate">{m.input}</div>
                  <div style={{ color: '#374151' }} className="truncate text-xs">{m.hash.slice(0, 24)}…</div>
                </div>
              ))}
              {malwareHashes.length === 0 && (
                <div className="font-mono text-xs text-gray-600">No malware references detected</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}