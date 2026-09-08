import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { findings as findingsApi, type AllFinding } from '../lib/api'
import { timeAgo, truncate, cn } from '../lib/utils'

const SEVS = ['critical', 'high', 'medium', 'low', 'info'] as const
type Sev = typeof SEVS[number]

const sevText: Record<string, string> = {
  critical: 'text-severity-critical', high: 'text-severity-high',
  medium: 'text-severity-medium', low: 'text-severity-low', info: 'text-text-muted',
}
const sevBadge: Record<string, string> = {
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/30',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/30',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/30',
  info: 'bg-white/5 text-text-muted border-border',
}

export default function Findings() {
  const nav = useNavigate()
  const [rows, setRows] = useState<AllFinding[]>([])
  const [loading, setLoading] = useState(true)
  const [status, setStatus] = useState<'finding' | 'candidate'>('finding')
  const [sevFilter, setSevFilter] = useState<Sev | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const [autoFlipped, setAutoFlipped] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true); setErr('')
    findingsApi.all({ status })
      .then(r => {
        if (cancelled) return
        const list = r || []
        if (status === 'finding' && list.length === 0 && !autoFlipped) {
          setAutoFlipped(true)
          setStatus('candidate')
          return
        }
        setRows(list)
      })
      .catch(e => { if (!cancelled) setErr(e?.message || 'Failed to load findings') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [status, autoFlipped])

  const triage = async (f: AllFinding, decision: 'confirmed' | 'false_positive') => {
    setBusy(f.id + decision)
    try {
      await findingsApi.setTriage(f.target_id, f.id, decision)
      setRows(prev => prev.filter(x => x.id !== f.id))
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Triage failed')
    } finally { setBusy('') }
  }

  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const f of rows) c[f.severity?.toLowerCase()] = (c[f.severity?.toLowerCase()] || 0) + 1
    return c
  }, [rows])

  const shown = useMemo(
    () => sevFilter ? rows.filter(f => f.severity?.toLowerCase() === sevFilter) : rows,
    [rows, sevFilter])

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3 flex-wrap">
        <h1 className="text-xl font-semibold">Findings</h1>
        <span className="text-xs text-text-muted">across all targets</span>
        <div className="ml-auto flex items-center gap-1 text-xs">
          <button onClick={() => { setStatus('finding'); setSevFilter(null) }}
            className={cn('px-3 py-1.5 rounded border', status === 'finding' ? 'border-accent text-accent' : 'border-border text-text-muted')}>
            Confirmed
          </button>
          <button onClick={() => { setStatus('candidate'); setSevFilter(null) }}
            className={cn('px-3 py-1.5 rounded border', status === 'candidate' ? 'border-accent text-accent' : 'border-border text-text-muted')}>
            Needs Review
          </button>
        </div>
      </div>

      {/* severity summary — click to filter */}
      <div className="flex gap-2 flex-wrap">
        <button onClick={() => setSevFilter(null)}
          className={cn('px-3 py-2 rounded-lg border text-xs font-medium', !sevFilter ? 'border-accent text-accent' : 'border-border text-text-muted')}>
          All <span className="tabular-nums">{rows.length}</span>
        </button>
        {SEVS.map(s => (
          <button key={s} onClick={() => setSevFilter(sevFilter === s ? null : s)}
            disabled={!counts[s]}
            className={cn('px-3 py-2 rounded-lg border text-xs font-medium capitalize disabled:opacity-40',
              sevFilter === s ? 'border-accent' : 'border-border', sevText[s])}>
            {s} <span className="tabular-nums">{counts[s] || 0}</span>
          </button>
        ))}
      </div>

      {err && <div className="card p-4 text-sm text-severity-high">{err}</div>}

      <div className="card overflow-hidden" style={{ padding: 0 }}>
        {loading ? (
          <p className="text-sm text-text-muted p-8 text-center">Loading findings…</p>
        ) : shown.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-text-secondary text-sm mb-1">
              {status === 'finding' ? 'No confirmed findings yet.' : 'Nothing awaiting review.'}
            </p>
            <p className="text-text-muted text-xs">
              {status === 'finding'
                ? 'Nuclei hits land in Needs Review until you Confirm or Decline them.'
                : 'Scan a target to populate this view. Confirm keeps a hit; Decline marks it a false positive.'}
            </p>
            {status === 'finding' && (
              <button onClick={() => setStatus('candidate')} className="mt-3 px-3 py-1.5 rounded border border-accent text-accent text-xs">
                Open Needs Review
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  {['Severity', 'Type', 'Target', 'URL', 'Parameter', 'Conf.', 'Found', 'Triage'].map(h => (
                    <th key={h} className="table-header text-left">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {shown.map(f => (
                  <tr key={f.id} onClick={() => nav(`/targets/${f.target_id}`)}
                    className="border-b border-border/50 last:border-0 hover:bg-surface-3/50 transition-colors cursor-pointer">
                    <td className="table-cell">
                      <span className={cn('px-2 py-0.5 rounded border text-[10px] font-semibold uppercase', sevBadge[f.severity?.toLowerCase()] || sevBadge.info)}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="table-cell font-mono text-xs">
                      {f.type}
                      {f.source === 'nuclei' && <span className="ml-1 text-[9px] uppercase tracking-wide text-accent">nuclei</span>}
                    </td>
                    <td className="table-cell text-xs text-text-secondary">{f.domain}</td>
                    <td className="table-cell font-mono text-xs text-text-muted" title={f.url}>{truncate(f.url, 60)}</td>
                    <td className="table-cell font-mono text-xs">{f.parameter || '—'}</td>
                    <td className="table-cell text-xs tabular-nums">{f.confidence || '—'}</td>
                    <td className="table-cell text-xs text-text-muted whitespace-nowrap">{timeAgo(f.created_at)}</td>
                    <td className="table-cell" onClick={e => e.stopPropagation()}>
                      <div className="flex flex-wrap gap-1">
                        <button disabled={!!busy} onClick={() => triage(f, 'confirmed')}
                          className="px-1.5 py-0.5 rounded border text-[10px] font-semibold border-severity-low/40 text-severity-low hover:bg-severity-low/10 disabled:opacity-50">
                          {busy === f.id + 'confirmed' ? '…' : 'Confirm'}
                        </button>
                        <button disabled={!!busy} onClick={() => triage(f, 'false_positive')}
                          className="px-1.5 py-0.5 rounded border text-[10px] font-semibold border-severity-critical/40 text-severity-critical hover:bg-severity-critical/10 disabled:opacity-50">
                          {busy === f.id + 'false_positive' ? '…' : 'Decline'}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
