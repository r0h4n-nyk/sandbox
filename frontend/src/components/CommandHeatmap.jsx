import React, { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import { getCommandFrequency } from '../utils/dataAggregator'

const DANGER = new Set(['wget', 'curl', 'chmod', 'bash', 'nc', 'python3', 'python', 'perl', 'dd', 'rm', 'mkfs', 'sh'])
const SUSPICIOUS = new Set(['cat', 'find', 'grep', 'iptables', 'sudo', 'su', 'crontab', 'history', 'netstat', 'ps'])

function cmdColor(cmd) {
  if (DANGER.has(cmd)) return '#ff3b3b'
  if (SUSPICIOUS.has(cmd)) return '#f97316'
  return '#8b5cf6'
}

export default function CommandHeatmap({ events }) {
  const commands = useMemo(() => getCommandFrequency(events, 12), [events])

  const maxCount = useMemo(() => Math.max(...commands.map(c => c.count), 1), [commands])

  const option = useMemo(() => ({
    backgroundColor: 'transparent',
    grid: {
      left: 60,
      right: 16,
      top: 8,
      bottom: 8,
      containLabel: false,
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'none' },
      backgroundColor: '#111827',
      borderColor: '#1f2937',
      textStyle: { color: '#e5e7eb', fontFamily: 'JetBrains Mono', fontSize: 11 },
      formatter: params => {
        const d = params[0]
        const cmd = d.name
        const tag = DANGER.has(cmd) ? ' ⚠ DANGER' : SUSPICIOUS.has(cmd) ? ' ⚑ SUSPICIOUS' : ''
        return `<b>${cmd}</b>${tag}<br/>Count: ${d.value}`
      },
    },
    xAxis: {
      type: 'value',
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: {
        color: '#4b5563',
        fontFamily: 'JetBrains Mono',
        fontSize: 9,
      },
      splitLine: {
        lineStyle: { color: '#1f2937', type: 'dashed' },
      },
    },
    yAxis: {
      type: 'category',
      data: commands.map(c => c.cmd).reverse(),
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: {
        color: '#9ca3af',
        fontFamily: 'JetBrains Mono',
        fontSize: 10,
        width: 52,
        overflow: 'truncate',
      },
    },
    series: [
      {
        type: 'bar',
        data: commands.map(c => ({
          value: c.count,
          itemStyle: {
            color: {
              type: 'linear', x: 0, y: 0, x2: 1, y2: 0,
              colorStops: [
                { offset: 0, color: `${cmdColor(c.cmd)}15` },
                { offset: 1, color: `${cmdColor(c.cmd)}90` },
              ],
            },
            borderRadius: [0, 3, 3, 0],
          },
          label: {
            show: true,
            position: 'right',
            color: cmdColor(c.cmd),
            fontFamily: 'JetBrains Mono',
            fontSize: 9,
            formatter: () => c.count,
          },
        })).reverse(),
        barMaxWidth: 16,
        barGap: '30%',
        emphasis: {
          itemStyle: {
            shadowColor: '#00ff9c40',
            shadowBlur: 6,
          },
        },
      },
    ],
  }), [commands])

  return (
    <div className="panel h-full flex flex-col" style={{ minHeight: 260 }}>
      <div className="corner-decoration corner-tl" />
      <div className="corner-decoration corner-tr" />

      <div className="flex items-center justify-between px-3 pt-3 pb-2 shrink-0">
        <span className="panel-title">COMMAND FREQUENCY</span>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="inline-block w-2 h-2 rounded-sm" style={{ background: '#ff3b3b' }} />
            <span className="section-label">MALWARE</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block w-2 h-2 rounded-sm" style={{ background: '#f97316' }} />
            <span className="section-label">RECON</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block w-2 h-2 rounded-sm" style={{ background: '#8b5cf6' }} />
            <span className="section-label">OTHER</span>
          </div>
        </div>
      </div>

      <div className="flex-1 min-h-0">
        {commands.length > 0 ? (
          <ReactECharts
            option={option}
            style={{ width: '100%', height: '100%', minHeight: 180 }}
            opts={{ renderer: 'canvas' }}
          />
        ) : (
          <div className="flex items-center justify-center h-full">
            <span className="font-mono text-xs text-gray-600">No command data yet</span>
          </div>
        )}
      </div>

      {/* Quick stat */}
      {commands.length > 0 && (
        <div className="px-3 pb-2 shrink-0 border-t border-gray-800 pt-2">
          <div className="flex items-center justify-between">
            <span className="section-label">MOST USED</span>
            <span className="font-mono text-xs" style={{ color: cmdColor(commands[0]?.cmd) }}>
              {commands[0]?.cmd} × {commands[0]?.count}
            </span>
          </div>
        </div>
      )}
    </div>
  )
}