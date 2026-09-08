import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { system, type HunterStatus } from '../../lib/api'
import { cn, timeAgo } from '../../lib/utils'
import { ws } from '../../lib/websocket'

export function HunterCard({ compact = false }: { compact?: boolean }) {
  const nav = useNavigate()
  const [h, setH] = useState<HunterStatus | null>(null)
  const load = () => system.hunter().then(setH).catch(() => {})
  useEffect(() => {
    load()
    const i = setInterval(load, 8000)
    return () => clearInterval(i)
  }, [])
  useEffect(() => ws.on('agent_event', (payload: unknown) => {
    const ev = payload as { kind?: string }
    if (ev.kind === 'hunter_cycle') load()
  }), [])
  if (!h) return null
  const live = h.alive && h.enabled
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">24/7 hunter</p>
          <p className="text-sm text-text-primary mt-0.5">
            {live ? 'Cycling every authorized target' : h.enabled ? 'Armed — waiting for a key / copilot enable' : 'Parked'}
          </p>
        </div>
        <span className={cn('text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border',
          live ? 'text-severity-low border-severity-low/40 bg-severity-low/10' : 'text-text-muted border-border')}>
          {live ? 'live' : 'off'}
        </span>
      </div>
      {h.current_domain && (
        <p className="text-xs text-accent mb-2 truncate">Now: {h.current_playbook} · {h.current_domain}</p>
      )}
      {!compact && (
        <dl className="grid grid-cols-3 gap-2 mb-3">
          <div><dt className="text-[10px] uppercase text-text-muted">Watching</dt><dd className="text-sm tabular-nums">{h.watching}</dd></div>
          <div><dt className="text-[10px] uppercase text-text-muted">Cycles</dt><dd className="text-sm tabular-nums">{h.cycles}</dd></div>
          <div><dt className="text-[10px] uppercase text-text-muted">Every</dt><dd className="text-sm tabular-nums">{h.interval_seconds}s</dd></div>
        </dl>
      )}
      {h.last_summary && (
        <p className="text-[11px] text-text-secondary leading-relaxed mb-2">
          Last {h.last_playbook && <span className="font-mono text-accent">{h.last_playbook}</span>}
          {h.last_domain && <> on {h.last_domain}</>}
          {h.last_at && <> · {timeAgo(h.last_at)}</>}
          <span className="block mt-1 text-text-muted">{h.last_summary}</span>
        </p>
      )}
      {!compact && (h.recent || []).slice(0, 5).map(row => (
        <button key={row.target_id} type="button" onClick={() => nav(`/targets/${row.target_id}`)}
          className="w-full text-left px-2 py-1.5 rounded-lg hover:bg-white/[.04] text-[11px] flex gap-2">
          <span className="font-mono text-accent shrink-0">{row.playbook}</span>
          <span className="truncate text-text-secondary flex-1">{row.domain}</span>
          <span className="text-text-muted shrink-0">{row.cycles}×</span>
        </button>
      ))}
    </div>
  )
}
