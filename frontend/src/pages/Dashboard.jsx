import React, { useState } from 'react'
import { useWebSocket } from '../hooks/useWebSocket'
import HoneypotHealth from '../components/HoneypotHealth'
import AttackMap from '../components/AttackMap'
import LiveAttackFeed from '../components/LiveAttackFeed'
import SessionReplay from '../components/SessionReplay'
import MitreTimeline from '../components/MitreTimeline'
import CommandHeatmap from '../components/CommandHeatmap'
import ThreatScoreGauge from '../components/ThreatScoreGauge'
import AISummaryPanel from '../components/AISummaryPanel'
import STIXExportPanel from '../components/STIXExportPanel'
import AttackStats from '../components/AttackStats'

export default function Dashboard() {
  const { events, connectionStatus } = useWebSocket()
  const [selectedSession, setSelectedSession] = useState(null)

  return (
    <div
      className="min-h-screen flex flex-col"
      style={{ background: '#0b0f17', padding: '10px', gap: 10 }}
    >
      {/* ── HEADER: Honeypot Health ──────────────────────────────────────── */}
      <HoneypotHealth events={events} connectionStatus={connectionStatus} />

      {/* ── STATS BAR ────────────────────────────────────────────────────── */}
      <AttackStats events={events} />

      {/* ── ROW 1: Global Threat Overview ────────────────────────────────── */}
      <div
        className="grid gap-2.5"
        style={{
          display: 'grid',
          gridTemplateColumns: '3fr 1fr',
          height: 380,
          gap: 10,
        }}
      >
        {/* Attack Map — col-span-9 equivalent */}
        <div style={{ minHeight: 0 }}>
          <AttackMap events={events} />
        </div>

        {/* Live Feed — col-span-3 equivalent */}
        <div style={{ minHeight: 0 }}>
          <LiveAttackFeed events={events} />
        </div>
      </div>

      {/* ── ROW 2: Tactical Analysis ──────────────────────────────────────── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          height: 360,
          gap: 10,
        }}
      >
        {/* Session Replay — col-span-6 */}
        <SessionReplay
          events={events}
          selectedSession={selectedSession}
          onSelectSession={setSelectedSession}
        />

        {/* MITRE Timeline — col-span-6 */}
        <MitreTimeline events={events} />
      </div>

      {/* ── ROW 3: Threat Analytics ───────────────────────────────────────── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr 1fr',
          height: 320,
          gap: 10,
        }}
      >
        {/* Command Heatmap — col-span-4 */}
        <CommandHeatmap events={events} />

        {/* Threat Score Gauge — col-span-4 */}
        <ThreatScoreGauge events={events} selectedSession={selectedSession} />

        {/* AI Summary — col-span-4 */}
        <AISummaryPanel events={events} selectedSession={selectedSession} />
      </div>

      {/* ── ROW 4: Intelligence Export ────────────────────────────────────── */}
      <STIXExportPanel events={events} />

      {/* Footer */}
      <div className="flex items-center justify-between py-1 px-2">
        <span className="section-label">
          Honeypes THREAT INTELLIGENCE PLATFORM
        </span>
        <span className="font-mono text-xs text-gray-700">
          {new Date().toUTCString()}
        </span>
      </div>
    </div>
  )
}