import React, { useMemo, useState, useCallback, useEffect, useRef } from 'react'
import DeckGL from '@deck.gl/react'
import { Map } from 'react-map-gl/maplibre'
import { ScatterplotLayer, ArcLayer } from '@deck.gl/layers'
import { getGeoPoints } from '../utils/dataAggregator'

// Honeypot target location — Bangalore, India
const HONEYPOT = { lon: 77.5946, lat: 12.9716 }

const INITIAL_VIEW_STATE = {
  longitude: 60,
  latitude: 20,
  zoom: 1.4,
  pitch: 0,
  bearing: 0,
}

const MAP_STYLE = 'https://basemaps.cartocdn.com/gl/dark-matter-nolabels-gl-style/style.json'

function scoreToColor(score) {
  if (score >= 71) return [255, 59, 59]
  if (score >= 31) return [249, 115, 22]
  return [0, 255, 156]
}

export default function AttackMap({ events }) {
  const [tooltip, setTooltip] = useState(null)
  const [pulseRadius, setPulseRadius] = useState(0)
  const animRef = useRef(null)
  const prevCountRef = useRef(0)
  const [flashIp, setFlashIp] = useState(null)

  // Animate pulse radius
  useEffect(() => {
    let frame = 0
    const animate = () => {
      frame++
      setPulseRadius(Math.sin(frame * 0.05) * 0.3 + 0.7)
      animRef.current = requestAnimationFrame(animate)
    }
    animRef.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(animRef.current)
  }, [])

  // Flash newest IP
  useEffect(() => {
    if (events.length > prevCountRef.current && events.length > 0) {
      const newest = events[events.length - 1]
      if (newest?.src_ip) {
        setFlashIp(newest.src_ip)
        const t = setTimeout(() => setFlashIp(null), 1500)
        prevCountRef.current = events.length
        return () => clearTimeout(t)
      }
    }
    prevCountRef.current = events.length
  }, [events])

  const geoPoints = useMemo(() => getGeoPoints(events), [events])

  const scatterLayer = useMemo(() => new ScatterplotLayer({
    id: 'scatter-attacks',
    data: geoPoints,
    getPosition: d => [d.lon, d.lat],
    getRadius: d => {
      const base = 30000 + d.count * 8000
      if (d.ip === flashIp) return base * (1 + pulseRadius * 0.6)
      return base
    },
    getFillColor: d => {
      const [r, g, b] = scoreToColor(d.maxScore)
      const alpha = d.ip === flashIp ? 220 : 140
      return [r, g, b, alpha]
    },
    getLineColor: d => {
      const [r, g, b] = scoreToColor(d.maxScore)
      return [r, g, b, 255]
    },
    lineWidthMinPixels: 1,
    stroked: true,
    filled: true,
    pickable: true,
    updateTriggers: {
      getRadius: [flashIp, pulseRadius],
      getFillColor: [flashIp],
    },
    onHover: ({ object, x, y }) => {
      setTooltip(object ? { data: object, x, y } : null)
    },
  }), [geoPoints, flashIp, pulseRadius])

  const arcLayer = useMemo(() => new ArcLayer({
    id: 'arc-attacks',
    data: geoPoints.filter(p => p.count > 0),
    getSourcePosition: d => [d.lon, d.lat],
    getTargetPosition: () => [HONEYPOT.lon, HONEYPOT.lat],
    getSourceColor: d => {
      const [r, g, b] = scoreToColor(d.maxScore)
      return [r, g, b, 120]
    },
    getTargetColor: () => [6, 182, 212, 180],
    getWidth: d => Math.min(1 + d.count * 0.3, 4),
    greatCircle: true,
    pickable: false,
  }), [geoPoints])

  // Honeypot target dot
  const honeypotLayer = useMemo(() => new ScatterplotLayer({
    id: 'honeypot-target',
    data: [{ lon: HONEYPOT.lon, lat: HONEYPOT.lat }],
    getPosition: d => [d.lon, d.lat],
    getRadius: () => 40000 + pulseRadius * 25000,
    getFillColor: () => [6, 182, 212, 160],
    getLineColor: () => [6, 182, 212, 255],
    stroked: true,
    lineWidthMinPixels: 2,
    updateTriggers: { getRadius: [pulseRadius] },
  }), [pulseRadius])

  const layers = [arcLayer, scatterLayer, honeypotLayer]

  const onViewStateChange = useCallback(({ viewState }) => viewState, [])

  return (
    <div className="panel h-full" style={{ minHeight: 340 }}>
      <div className="corner-decoration corner-tl" />
      <div className="corner-decoration corner-tr" />
      <div className="corner-decoration corner-bl" />
      <div className="corner-decoration corner-br" />

      {/* Header */}
      <div className="absolute top-0 left-0 right-0 z-10 flex items-center justify-between px-3 py-2 bg-gradient-to-b from-black/70 to-transparent">
        <span className="panel-title">GLOBAL THREAT MAP</span>
        <div className="flex items-center gap-4">
          <span className="font-mono text-xs text-gray-400">
            {geoPoints.length} <span className="text-gray-600">origins</span>
          </span>
          <div className="flex items-center gap-1.5">
            <span className="inline-block w-2 h-2 rounded-full bg-red-500" style={{ boxShadow: '0 0 4px #ff3b3b' }} />
            <span className="section-label">HIGH</span>
            <span className="inline-block w-2 h-2 rounded-full ml-2" style={{ background: '#f97316', boxShadow: '0 0 4px #f97316' }} />
            <span className="section-label">MED</span>
            <span className="inline-block w-2 h-2 rounded-full ml-2" style={{ background: '#00ff9c', boxShadow: '0 0 4px #00ff9c' }} />
            <span className="section-label">LOW</span>
            <span className="inline-block w-2 h-2 rounded-full ml-2" style={{ background: '#06b6d4', boxShadow: '0 0 4px #06b6d4' }} />
            <span className="section-label">BANGALORE</span>
          </div>
        </div>
      </div>

      {/* Map */}
      <div style={{ position: 'relative', width: '100%', height: '100%', borderRadius: 8, overflow: 'hidden' }}>
        <DeckGL
          initialViewState={INITIAL_VIEW_STATE}
          controller={true}
          layers={layers}
          onViewStateChange={onViewStateChange}
          style={{ borderRadius: 8 }}
        >
          <Map
            mapStyle={MAP_STYLE}
            attributionControl={false}
            style={{ borderRadius: 8 }}
          />
        </DeckGL>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="map-tooltip"
          style={{
            position: 'absolute',
            left: tooltip.x + 12,
            top: tooltip.y - 10,
            zIndex: 100,
            pointerEvents: 'none',
          }}
        >
          <div className="flex items-center gap-2 mb-1">
            <span
              className="inline-block w-2 h-2 rounded-full"
              style={{
                background: `rgb(${scoreToColor(tooltip.data.maxScore).join(',')})`,
                boxShadow: `0 0 4px rgb(${scoreToColor(tooltip.data.maxScore).join(',')})`,
              }}
            />
            <span className="font-bold" style={{ color: '#e5e7eb' }}>{tooltip.data.ip}</span>
          </div>
          <div className="text-gray-400 text-xs space-y-0.5">
            <div>📍 {tooltip.data.city}, {tooltip.data.country}</div>
            <div>🌐 {tooltip.data.asn}</div>
            <div>⚡ {tooltip.data.count} attack{tooltip.data.count !== 1 ? 's' : ''}</div>
            <div>🎯 Threat Score: <span style={{ color: `rgb(${scoreToColor(tooltip.data.maxScore).join(',')})` }}>{tooltip.data.maxScore}</span></div>
          </div>
        </div>
      )}
    </div>
  )
}