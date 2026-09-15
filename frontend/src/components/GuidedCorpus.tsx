import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  captures,
  type CapturedRequest,
  type CapturePreflight,
  type CaptureTemplate,
  type GuidedCheck,
  type GuidedOpportunity,
  type GuidedReport,
  type GuidedRun,
} from '../lib/api'
import { Badge, Button, EmptyState, Modal } from './ui'
import { useUIStore } from '../store/ui'

type GuidedResult = NonNullable<GuidedReport['results']>[number]
type Candidate = { template: CaptureTemplate; suggestion: GuidedOpportunity }
type BusyAction = 'preflight' | 'queue' | 'edit' | 'save' | 'delete' | 'reveal' | null

const moduleOrder = ['idor', 'sqli', 'xss', 'nosqli', 'ssrf', 'open_redirect', 'lfi', 'ssti', 'cors', 'csrf', 'jwt', 'xxe', 'cmdi']
const moduleInfo: Record<string, { title: string; short: string; description: string }> = {
  idor: { title: 'IDOR / object access', short: 'IDOR', description: 'Object identifiers that need ownership and identity-aware comparison.' },
  sqli: { title: 'SQL injection', short: 'SQLi', description: 'Database-shaped inputs tested with paired boolean and error controls.' },
  xss: { title: 'Cross-site scripting', short: 'XSS', description: 'Text inputs checked for unsafe HTML and JavaScript contexts.' },
  nosqli: { title: 'NoSQL injection', short: 'NoSQLi', description: 'JSON and query fields that may accept document operators.' },
  ssrf: { title: 'Server-side request forgery', short: 'SSRF', description: 'URL-shaped values tested with bounded in-band differentials.' },
  open_redirect: { title: 'Open redirect', short: 'Redirect', description: 'Navigation parameters checked without following external redirects.' },
  lfi: { title: 'File / path traversal', short: 'LFI', description: 'File-shaped inputs tested with non-destructive controls.' },
  ssti: { title: 'Template injection', short: 'SSTI', description: 'Text fields that may be rendered by a server-side template engine.' },
  cors: { title: 'Cross-origin policy', short: 'CORS', description: 'Credentialed reads checked using two unrelated Origin controls.' },
  csrf: { title: 'Cross-site request forgery', short: 'CSRF', description: 'Cookie-authenticated state changes needing browser and side-effect review.' },
  jwt: { title: 'JWT / token', short: 'JWT', description: 'Token-shaped authorization headers needing an alternate test identity.' },
  xxe: { title: 'XML external entity', short: 'XXE', description: 'XML bodies requiring deliberate entity and callback setup.' },
  cmdi: { title: 'Command injection', short: 'CMDi', description: 'Command-shaped fields reserved for explicit active validation.' },
}

const decode = (value: string | null) => new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(value || ''), character => character.charCodeAt(0)))
const encode = (value: string) => { let raw = ''; for (const byte of new TextEncoder().encode(value)) raw += String.fromCharCode(byte); return btoa(raw) }
const isSafeTemplate = (template: CaptureTemplate) => ['GET', 'HEAD', 'OPTIONS'].includes(template.method.toUpperCase()) && ['read_only', 'query_like'].includes(template.kind)

function resultPresentation(result?: GuidedResult) {
  if (!result) return { label: 'NOT RUN', variant: 'neutral', detail: 'Waiting to run.' }
  if (result.findings.some(finding => finding.verdict !== 'INCONCLUSIVE')) return { label: 'HIT', variant: 'error', detail: result.reason || `${result.findings.length} signal(s) found.` }
  if (result.findings.length > 0 && result.findings.every(finding => finding.verdict === 'INCONCLUSIVE')) return { label: 'REVIEW', variant: 'warning', detail: result.reason || 'A differential signal needs manual proof.' }
  if (result.status === 'completed') return { label: 'NO HIT', variant: 'success', detail: result.reason || 'No signal found in this bounded check.' }
  if (result.status === 'partial') return { label: 'REVIEW', variant: 'warning', detail: result.reason || 'The check did not complete cleanly.' }
  if (result.status === 'blocked' || result.status === 'skipped') return { label: 'BLOCKED', variant: 'warning', detail: result.reason }
  if (result.status === 'failed') return { label: 'FAILED', variant: 'error', detail: result.reason }
  return { label: result.status.toUpperCase(), variant: 'neutral', detail: result.reason }
}

function replaceJSONPointer(raw: string, pointer: string, payload: string) {
  const root: unknown = JSON.parse(raw)
  const path = pointer.split('/').slice(1).map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'))
  if (!path.length) throw new Error('The suggested JSON parameter has no editable path')
  let value: unknown = payload
  try { value = JSON.parse(payload) } catch { /* keep a string payload */ }
  let node: unknown = root
  for (let index = 0; index < path.length - 1; index++) {
    if (typeof node !== 'object' || node === null) throw new Error('The suggested JSON path no longer exists')
    node = (node as Record<string, unknown>)[path[index]]
  }
  if (typeof node !== 'object' || node === null) throw new Error('The suggested JSON path no longer exists')
  ;(node as Record<string, unknown>)[path[path.length - 1]] = value
  return JSON.stringify(root, null, 2)
}

function uniqueChecks(checks: GuidedCheck[]) {
  const seen = new Set<string>()
  return checks.filter(check => {
    const key = `${check.template_id}\u0000${check.module}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function checksFor(candidates: Candidate[]) {
  return uniqueChecks(candidates.map(candidate => ({ template_id: candidate.template.id, module: candidate.suggestion.module })))
}

function uniqueTemplateIds(checks: GuidedCheck[]) {
  return [...new Set(checks.map(check => check.template_id))]
}

function batchChecks(checks: GuidedCheck[]) {
  const batches: GuidedCheck[][] = []
  let batch: GuidedCheck[] = []
  let templates = new Set<string>()
  for (const check of checks) {
    if (batch.length >= 200 || (!templates.has(check.template_id) && templates.size >= 50)) {
      batches.push(batch)
      batch = []
      templates = new Set<string>()
    }
    batch.push(check)
    templates.add(check.template_id)
  }
  if (batch.length) batches.push(batch)
  return batches
}

export default function GuidedCorpus({ targetId, importedId, onCaptureChange }: { targetId: string; importedId: string; onCaptureChange?: (id: string) => void }) {
  const [sessions, setSessions] = useState<Awaited<ReturnType<typeof captures.list>>>([])
  const [captureId, setCaptureId] = useState('')
  const [templates, setTemplates] = useState<CaptureTemplate[]>([])
  const [category, setCategory] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [unsafe, setUnsafe] = useState(false)
  const [advanced, setAdvanced] = useState(false)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState<BusyAction>(null)
  const [view, setView] = useState<'plan'|'results'>('plan')
  const [preflight, setPreflight] = useState<CapturePreflight | null>(null)
  const [runs, setRuns] = useState<GuidedRun[]>([])
  const [revealed, setRevealed] = useState<GuidedReport | null>(null)
  const [editor, setEditor] = useState<{ id: string; version: string; request: CapturedRequest } | null>(null)
  const [activeOpportunity, setActiveOpportunity] = useState<GuidedOpportunity | null>(null)
  const [body, setBody] = useState('')
  const [binary, setBinary] = useState(false)
  const [headers, setHeaders] = useState('')
  const { addToast } = useUIStore()
  const isBusy = busy !== null
  const error = (value: unknown) => addToast('error', value instanceof Error ? value.message : 'Capture operation failed')

  const candidates = useMemo<Candidate[]>(() => templates.flatMap(template => (template.suggestions || []).map(suggestion => ({ template, suggestion }))), [templates])
  const categories = useMemo(() => [...new Set(candidates.map(candidate => candidate.suggestion.module))].sort((left, right) => {
    const leftIndex = moduleOrder.indexOf(left); const rightIndex = moduleOrder.indexOf(right)
    return (leftIndex < 0 ? 999 : leftIndex) - (rightIndex < 0 ? 999 : rightIndex) || left.localeCompare(right)
  }), [candidates])
  const selectedCandidates = useMemo(() => candidates.filter(candidate => candidate.suggestion.module === category), [candidates, category])
  const categoryTemplates = useMemo(() => {
    const ids = new Set<string>()
    return selectedCandidates.filter(candidate => !ids.has(candidate.template.id) && !!ids.add(candidate.template.id)).map(candidate => candidate.template)
  }, [selectedCandidates])
  const automaticCandidates = useMemo(() => candidates.filter(candidate => candidate.suggestion.automated), [candidates])
  const plannedCandidates = useMemo(() => automaticCandidates.filter(candidate => unsafe || isSafeTemplate(candidate.template)), [automaticCandidates, unsafe])
  const plannedChecks = useMemo(() => checksFor(plannedCandidates), [plannedCandidates])
  const plannedTemplates = useMemo(() => new Set(plannedChecks.map(check => check.template_id)).size, [plannedChecks])
  const active = runs.some(run => ['pending', 'running', 'paused'].includes(run.status))
  const activeRun = runs.find(run => ['pending', 'running', 'paused'].includes(run.status))

  const latestResult = (templateId: string, module: string) => {
    for (const run of runs) {
      const result = run.report.results?.find(row => row.template_id === templateId && row.module === module)
      if (result) return result
    }
    return undefined
  }

  const resultChecks = checksFor(automaticCandidates)
  const resultStats = resultChecks.reduce((stats, check) => {
    const presentation = resultPresentation(latestResult(check.template_id, check.module))
    if (presentation.label === 'HIT') stats.hits++
    else if (presentation.label === 'NO HIT') stats.clean++
    else if (presentation.label !== 'NOT RUN') stats.review++
    return stats
  }, { hits: 0, clean: 0, review: 0 })
  const unresolvedChecks = resultChecks.filter(check => ['REVIEW', 'BLOCKED', 'FAILED'].includes(resultPresentation(latestResult(check.template_id, check.module)).label))

  useEffect(() => {
    let live = true
    captures.list(targetId).then(value => {
      if (live) { setSessions(value); setCaptureId(current => importedId || current || value[0]?.id || '') }
    }).catch(value => { if (live) error(value) })
    return () => { live = false }
  }, [targetId, importedId])

  useEffect(() => {
    let live = true
    setTemplates([]); setRuns([]); setEditor(null); setActiveOpportunity(null); setRevealed(null); setPreflight(null); setConfirmed(false); setUnsafe(false); setAdvanced(false); setView('plan')
    if (!captureId) return
    setLoading(true)
    captures.templates(targetId, captureId).then(value => { if (live) setTemplates(value) }).catch(value => { if (live) error(value) }).finally(() => { if (live) setLoading(false) })
    const poll = () => captures.runs(targetId, captureId).then(value => { if (live) setRuns(value) }).catch(() => undefined)
    void poll()
    const timer = setInterval(poll, 4000)
    return () => { live = false; clearInterval(timer) }
  }, [targetId, captureId])

  useEffect(() => {
    if (!categories.includes(category)) setCategory(categories[0] || '')
  }, [categories, category])

  useEffect(() => { onCaptureChange?.(captureId) }, [captureId, onCaptureChange])

  const enqueue = async (requested: GuidedCheck[]) => {
    const checks = uniqueChecks(requested)
    if (!checks.length) throw new Error('There are no automated checks in this selection')
    const batches = batchChecks(checks)
    let queued = 0
    try {
      for (const batch of batches) {
        await captures.analyzeChecks(targetId, captureId, batch, unsafe)
        queued++
      }
    } finally {
      if (queued > 0) {
        try { setRuns(await captures.runs(targetId, captureId)) } catch { /* polling will retry */ }
      }
    }
    return { checks: checks.length, batches: batches.length }
  }

  const validateTemplates = async (requestedIds: string[]) => {
    const ids = [...new Set(requestedIds.filter(Boolean))]
    if (!ids.length) throw new Error('There are no auto-safe request baselines to validate')
    const aggregate: CapturePreflight = {
      capture_id: captureId, ready: 0, blocked: 0, failed_or_stale: 0,
      requests_sent: 0, mutations_sent: 0, mode: ids.length > 100 ? 'batched_baseline_only' : 'baseline_only', results: [],
    }
    for (let index = 0; index < ids.length; index += 100) {
      const result = await captures.preflight(targetId, captureId, ids.slice(index, index + 100))
      aggregate.ready += result.ready
      aggregate.blocked += result.blocked
      aggregate.failed_or_stale += result.failed_or_stale
      aggregate.requests_sent += result.requests_sent
      aggregate.mutations_sent += result.mutations_sent
      aggregate.results.push(...result.results)
    }
    setPreflight(aggregate)
    return aggregate
  }

  const validatedChecks = async (requested: GuidedCheck[]) => {
    const checks = uniqueChecks(requested)
    const byId = new Map(templates.map(template => [template.id, template]))
    const safeIds = uniqueTemplateIds(checks.filter(check => {
      const template = byId.get(check.template_id)
      return !!template && isSafeTemplate(template)
    }))
    const baseline = safeIds.length ? await validateTemplates(safeIds) : null
    const ready = new Set(baseline?.results.filter(result => result.status === 'ready').map(result => result.template_id) || [])
    const executable = checks.filter(check => {
      const template = byId.get(check.template_id)
      return !!template && (isSafeTemplate(template) ? ready.has(template.id) : unsafe)
    })
    if (!executable.length) throw new Error('No selected checks have a fresh baseline. Review validation results or recapture the session.')
    return executable
  }

  const runChecks = async (requested: GuidedCheck[], label = 'Selected checks') => {
    if (!confirmed) { addToast('error', 'Confirm authorization before sending target requests.'); return }
    if (active) { addToast('error', 'Wait for the active guided run or control it from Scan activity.'); return }
    setBusy('preflight')
    try {
      const executable = await validatedChecks(requested)
      setBusy('queue')
      const queued = await enqueue(executable)
      setConfirmed(false); setView('results')
      addToast('success', `${label}: ${queued.checks} checks queued in ${queued.batches} bounded run${queued.batches === 1 ? '' : 's'}`)
    } catch (value) { error(value) } finally { setBusy(null) }
  }

  const runPreflightOnly = async () => {
    if (!confirmed) { addToast('error', 'Confirm authorization before validating live baselines.'); return }
    setBusy('preflight')
    try {
      const safeIds = templates.filter(isSafeTemplate).map(template => template.id)
      const value = await validateTemplates(safeIds)
      setTemplates(await captures.templates(targetId, captureId))
      const needsAttention = value.blocked + value.failed_or_stale
      addToast(needsAttention ? 'warning' : 'success', `${value.ready} baselines ready; ${needsAttention} need attention`)
    } catch (value) { error(value) } finally { setBusy(null) }
  }

  const runRecommended = async () => {
    if (!confirmed) { addToast('error', 'Confirm authorization before starting automation.'); return }
    if (active) { addToast('error', 'A guided run is already active.'); return }
    setBusy('preflight')
    try {
      const freshTemplates = await captures.templates(targetId, captureId)
      setTemplates(freshTemplates)
      const freshCandidates = freshTemplates.flatMap(template => (template.suggestions || []).map(suggestion => ({ template, suggestion })))
      const safeIds = [...new Set(freshCandidates.filter(candidate => candidate.suggestion.automated && isSafeTemplate(candidate.template)).map(candidate => candidate.template.id))]
      const baseline = safeIds.length ? await validateTemplates(safeIds) : null
      const ready = new Set(baseline?.results.filter(result => result.status === 'ready').map(result => result.template_id) || [])
      const executable = freshCandidates.filter(candidate => candidate.suggestion.automated && (isSafeTemplate(candidate.template) ? ready.has(candidate.template.id) : unsafe))
      const checks = checksFor(executable)
      if (!checks.length) throw new Error('No automated checks have a fresh baseline. Review the preflight results and recapture stale sessions.')
      setBusy('queue')
      const queued = await enqueue(checks)
      setConfirmed(false); setView('results')
      const skipped = safeIds.length - (baseline?.ready || 0)
      addToast(skipped ? 'warning' : 'success', `${baseline?.ready || 0} safe baselines validated; ${queued.checks} recommended checks queued${skipped ? `; ${skipped} stale or blocked` : ''}`)
    } catch (value) { error(value) } finally { setBusy(null) }
  }

  const edit = async (template: CaptureTemplate, opportunity?: GuidedOpportunity) => {
    setBusy('edit')
    try {
      const value = await captures.reveal(targetId, captureId, template.id)
      setHeaders(JSON.stringify(value.request.headers || [], null, 2))
      try { setBody(decode(value.request.body)); setBinary(false) } catch { setBody(value.request.body || ''); setBinary(true) }
      setEditor({ id: template.id, ...value }); setActiveOpportunity(opportunity || null); setRevealed(null)
    } catch (value) { error(value) } finally { setBusy(null) }
  }

  const applyPayload = (payload: string) => {
    if (!editor || !activeOpportunity) return
    try {
      const opportunity = activeOpportunity
      if (opportunity.location === 'query') {
        const url = new URL(editor.request.url)
        url.searchParams.set(opportunity.parameter, payload)
        setEditor({ ...editor, request: { ...editor.request, url: url.toString() } })
      } else if (opportunity.location === 'path') {
        const match = /^path\[(\d+)]$/.exec(opportunity.parameter)
        if (!match) throw new Error('The suggested path segment could not be identified')
        const url = new URL(editor.request.url)
        const parts = url.pathname.split('/')
        const indexes = parts.map((part, index) => part ? index : -1).filter(index => index >= 0)
        const target = indexes[Number(match[1])]
        if (target === undefined) throw new Error('The suggested path segment no longer exists')
        parts[target] = encodeURIComponent(payload)
        url.pathname = parts.join('/')
        setEditor({ ...editor, request: { ...editor.request, url: url.toString() } })
      } else if (opportunity.location === 'header') {
        const parsed = JSON.parse(headers) as { name: string; value: string }[]
        if (!Array.isArray(parsed)) throw new Error('Headers are not a JSON array')
        const found = parsed.find(header => header.name.toLowerCase() === opportunity.parameter.toLowerCase())
        if (found) found.value = payload
        else parsed.push({ name: opportunity.parameter, value: payload })
        setHeaders(JSON.stringify(parsed, null, 2))
      } else if (opportunity.location === 'body') {
        if (binary) throw new Error('Suggested payloads cannot be applied to a binary body')
        if ((editor.request.mime_type || '').toLowerCase().includes('json')) setBody(replaceJSONPointer(body, opportunity.parameter, payload))
        else { const values = new URLSearchParams(body); values.set(opportunity.parameter, payload); setBody(values.toString()) }
      } else throw new Error('This signal needs a manual workflow rather than a single-field edit')
      addToast('success', `Applied a suggested value to ${opportunity.parameter}. Review before saving.`)
    } catch (value) { error(value) }
  }

  const closeEditor = () => { setEditor(null); setActiveOpportunity(null); setBody(''); setHeaders('') }
  const save = async (runAfterSave = false) => {
    if (!editor) return
    const opportunity = activeOpportunity
    setBusy('save')
    try {
      const parsed: unknown = JSON.parse(headers)
      if (!Array.isArray(parsed) || parsed.some(header => typeof header?.name !== 'string' || typeof header?.value !== 'string')) throw new Error('Headers must be an array of {name, value} objects')
      if (binary) atob(body)
      await captures.edit(targetId, captureId, editor.id, { ...editor.request, headers: parsed, body: binary ? body : encode(body) }, editor.version)
      const templateId = editor.id
      closeEditor()
      setPreflight(null)
      const freshTemplates = await captures.templates(targetId, captureId)
      setTemplates(freshTemplates)
      if (runAfterSave && opportunity?.automated) {
        const template = freshTemplates.find(value => value.id === templateId)
        if (!template) throw new Error('Saved request is no longer available')
        if (isSafeTemplate(template)) {
          setBusy('preflight')
          const baseline = await validateTemplates([templateId])
          if (!baseline.results.some(result => result.template_id === templateId && result.status === 'ready')) throw new Error('Request saved, but its live baseline is stale or unavailable. Review validation before running it.')
        } else if (!unsafe) throw new Error('Request saved. Enable state-changing requests before running this guarded check.')
        setBusy('queue')
        const queued = await enqueue([{ template_id: templateId, module: opportunity.module }])
        setConfirmed(false); setView('results')
        addToast('success', `Request saved and ${queued.checks} check queued`)
      } else addToast('success', 'Encrypted request saved. Use Validate & run to rebuild its baseline.')
    } catch (value) { error(value) } finally { setBusy(null) }
  }

  const revealReport = async (id: string) => {
    setBusy('reveal')
    try { setRevealed(await captures.revealReport(targetId, captureId, id)); closeEditor() } catch (value) { error(value) } finally { setBusy(null) }
  }

  const removeCapture = async () => {
    if (!captureId || !window.confirm('Delete this saved capture and all encrypted guided evidence?')) return
    setBusy('delete')
    try {
      await captures.remove(targetId, captureId)
      const remaining = await captures.list(targetId)
      setSessions(remaining); setCaptureId(remaining[0]?.id || '')
      setTemplates([]); setRuns([]); closeEditor(); setRevealed(null)
      addToast('success', 'Saved capture and encrypted evidence deleted.')
    } catch (value) { error(value) } finally { setBusy(null) }
  }

  const download = () => {
    if (!revealed) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(revealed, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'reconner-guided-test-cases.json'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const categoryChecks = checksFor(selectedCandidates.filter(candidate => candidate.suggestion.automated && (unsafe || isSafeTemplate(candidate.template))))
  const editorTemplate = editor ? templates.find(template => template.id === editor.id) : undefined
  const editorNeedsUnsafe = editor ? !['GET', 'HEAD', 'OPTIONS'].includes(editor.request.method.toUpperCase()) || !!editorTemplate && !isSafeTemplate(editorTemplate) : false

  return <section className="card overflow-hidden">
    <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-3 border-b border-border px-4 py-3">
      <div><p className="text-sm font-semibold">3 · Automated test workspace</p><p className="text-[11px] text-text-muted mt-0.5">One focused plan: validate baselines, run relevant proof ladders, review only actionable output.</p></div>
      <div className="flex items-end gap-2">
        <label className="min-w-0 sm:min-w-80"><span className="label">Saved capture</span><select className="input" disabled={isBusy} value={captureId} onChange={event => setCaptureId(event.target.value)}><option value="">Select capture…</option>{sessions.map(session => <option key={session.id} value={session.id}>{session.label || session.source} · {session.imported} requests</option>)}</select></label>
        <Button size="sm" variant="danger" loading={busy === 'delete'} disabled={isBusy || active || !captureId} onClick={removeCapture}>Delete</Button>
      </div>
    </div>

    {!captureId ? <EmptyState title="Import or select a capture" description="The passive preview above does not save requests. Import it once, then automation appears here."/> : loading ? <EmptyState title="Building test plan…" description="Reconner is classifying request shapes and supported proof ladders."/> : !templates.length ? <EmptyState title="No saved requests" description="This capture contains no available in-scope request templates."/> : <>
      <div className="border-b border-border bg-[linear-gradient(120deg,rgba(34,211,238,.09),rgba(20,184,166,.025)_55%,transparent)] p-4 sm:p-5">
        <div className="grid xl:grid-cols-[minmax(0,1fr)_auto] gap-5 items-center">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2"><Badge variant="info">RECOMMENDED</Badge>{preflight ? <Badge variant={preflight.blocked + preflight.failed_or_stale ? 'warning' : 'success'}>{preflight.ready} baselines ready</Badge> : <Badge>baseline pending</Badge>}{active && <Badge variant="info">RUNNING</Badge>}</div>
            <div><h2 className="text-lg font-semibold">Validate once, then run {plannedChecks.length} relevant checks</h2><p className="text-xs text-text-secondary mt-1 max-w-3xl">Reconner preflights captured GET/HEAD/OPTIONS requests, skips stale sessions, and automatically queues only supported tests. No crawler, redirect following, browser, external tool, or OAST callback is started here.</p></div>
            <div className="flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-text-muted"><span><b className="text-text-primary">{plannedTemplates}</b> requests</span><span><b className="text-text-primary">{plannedChecks.length}</b> checks</span><span><b className="text-text-primary">{categories.length}</b> categories</span><span><b className="text-text-primary">{candidates.length - plannedCandidates.length}</b> manual/guarded signals</span></div>
          </div>
          <div className="xl:w-[360px] space-y-2">
            <label className="flex items-start gap-2 rounded-lg border border-border bg-surface-2/80 p-3 text-[11px]"><input className="mt-0.5" type="checkbox" disabled={isBusy || active} checked={confirmed} onChange={event => setConfirmed(event.target.checked)}/><span><b className="block text-text-primary">I am authorized to test this target</b><span className="text-text-muted">Use captured credentials and send bounded active probes.</span></span></label>
            <Button className="w-full justify-center" size="lg" variant="primary" loading={busy === 'preflight' || busy === 'queue'} disabled={isBusy || active || !confirmed || plannedChecks.length === 0} onClick={runRecommended}>{busy === 'preflight' ? 'Validating baselines…' : busy === 'queue' ? 'Queueing proof ladders…' : `Validate & run ${plannedChecks.length} checks →`}</Button>
            {activeRun && <p className="text-center text-[10px] text-accent">{activeRun.report.results?.length || 0} checks completed · <Link to={`/targets/${targetId}`}>open task controls</Link></p>}
          </div>
        </div>

        <div className="mt-3 border-t border-border/70 pt-3">
          <button type="button" className="text-[11px] text-text-muted hover:text-text-primary" onClick={() => setAdvanced(value => !value)}>{advanced ? '▾ Hide advanced controls' : '▸ Advanced controls'}</button>
          {advanced && <div className="mt-3 grid lg:grid-cols-[1fr_auto] gap-3 rounded-lg border border-border bg-surface-2/70 p-3">
            <label className="flex items-start gap-2 text-[11px]"><input className="mt-0.5" type="checkbox" disabled={isBusy || active} checked={unsafe} onChange={event => { setUnsafe(event.target.checked); setConfirmed(false) }}/><span><b className="block text-severity-medium">Include state-changing requests</b><span className="text-text-muted">May create, modify, delete, book, purchase, or invalidate sessions. Keep off unless the engagement explicitly permits it.</span></span></label>
            <div className="flex flex-wrap items-center gap-2"><Button size="sm" disabled={isBusy || active || !confirmed} loading={busy === 'preflight'} onClick={runPreflightOnly}>Validate only</Button><Button size="sm" disabled={isBusy || active || !confirmed || unresolvedChecks.length === 0} onClick={() => runChecks(unresolvedChecks, 'Unresolved checks')}>Retry {unresolvedChecks.length} unresolved</Button></div>
          </div>}
        </div>

        {preflight && <details className="mt-3 rounded-lg border border-border/70 bg-surface-2/60"><summary className="cursor-pointer px-3 py-2 text-[11px]"><span className="text-severity-low">{preflight.ready} ready</span> · <span className="text-severity-medium">{preflight.blocked} blocked · {preflight.failed_or_stale} stale/failed</span> · {preflight.requests_sent} baseline requests <span className="text-text-muted">— inspect validation</span></summary><div className="max-h-64 overflow-auto border-t border-border/70">{preflight.results.map(result => <div key={result.template_id} className="grid sm:grid-cols-[auto_minmax(0,1fr)_auto] gap-2 border-b border-border/50 px-3 py-2 text-[10px]"><Badge variant={result.status === 'ready' ? 'success' : 'warning'}>{result.status}</Badge><code className="break-all text-text-secondary">{result.method} {result.route}</code><span className="text-text-muted">{result.captured_status || '—'} → {result.http_status || '—'}</span>{result.reason && <p className="sm:col-start-2 text-text-muted">{result.reason}</p>}</div>)}</div></details>}
      </div>

      <div className="flex items-center gap-1 border-b border-border px-4 pt-2">
        <button className={`px-3 py-2 text-xs font-medium border-b-2 ${view === 'plan' ? 'border-accent text-text-primary' : 'border-transparent text-text-muted hover:text-text-primary'}`} onClick={() => setView('plan')}>Test plan <span className="ml-1 text-[10px]">{plannedChecks.length}</span></button>
        <button className={`px-3 py-2 text-xs font-medium border-b-2 ${view === 'results' ? 'border-accent text-text-primary' : 'border-transparent text-text-muted hover:text-text-primary'}`} onClick={() => setView('results')}>Results <span className="ml-1 text-[10px]">{runs.length}</span></button>
      </div>

      {view === 'plan' ? <div className="grid lg:grid-cols-[240px_minmax(0,1fr)] min-h-[520px]">
        <aside className="border-b lg:border-b-0 lg:border-r border-border bg-surface-3/20 p-3">
          <p className="px-2 pb-2 text-[10px] font-semibold uppercase tracking-wider text-text-muted">Discovered surfaces</p>
          <div className="flex lg:block gap-1 overflow-x-auto lg:overflow-visible pb-1 lg:pb-0">{categories.map(module => {
            const rows = candidates.filter(candidate => candidate.suggestion.module === module)
            const requestCount = new Set(rows.map(row => row.template.id)).size
            const hitCount = new Set(rows.filter(row => resultPresentation(latestResult(row.template.id, module)).label === 'HIT').map(row => row.template.id)).size
            const automated = rows.some(row => row.suggestion.automated)
            return <button type="button" key={module} onClick={() => setCategory(module)} className={`min-w-40 lg:min-w-0 lg:w-full text-left rounded-lg px-3 py-2.5 mb-1 transition-colors ${category === module ? 'bg-accent/10 text-text-primary ring-1 ring-accent/40' : 'text-text-secondary hover:bg-white/[.03]'}`}>
              <span className="flex items-center justify-between gap-2"><span className="text-xs font-semibold">{moduleInfo[module]?.short || module}</span>{hitCount ? <Badge variant="error">{hitCount} hit</Badge> : <span className="text-[10px] text-text-muted">{requestCount}</span>}</span>
              <span className="mt-1 block text-[9px] text-text-muted">{rows.length} signals · {automated ? 'automatic' : 'manual'}</span>
            </button>
          })}</div>
        </aside>

        <main className="min-w-0 p-3 sm:p-4">
          {!category ? <EmptyState title="No supported test surface" description="Inspect or recapture requests with parameters, object identifiers, JSON bodies, credentials, or navigation inputs."/> : <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 pb-1">
              <div><div className="flex flex-wrap items-center gap-2"><h3 className="text-base font-semibold">{moduleInfo[category]?.title || category}</h3><Badge>{categoryChecks.length ? `${categoryChecks.length} automatic` : 'manual workflow'}</Badge></div><p className="text-xs text-text-muted mt-1">{moduleInfo[category]?.description}</p></div>
              <Button size="sm" variant="primary" disabled={isBusy || active || !confirmed || categoryChecks.length === 0} onClick={() => runChecks(categoryChecks, moduleInfo[category]?.short || category)}>Run category</Button>
            </div>
            {categoryTemplates.map(template => {
              const suggestions = selectedCandidates.filter(candidate => candidate.template.id === template.id).map(candidate => candidate.suggestion)
              const result = latestResult(template.id, category)
              const presentation = resultPresentation(result)
              const safe = isSafeTemplate(template)
              return <details key={template.id} className="group rounded-xl border border-border bg-surface-3/15">
                <summary className="cursor-pointer list-none p-3 sm:p-4 flex items-center justify-between gap-3">
                  <span className="min-w-0"><span className="flex items-center gap-2"><Badge variant={safe ? 'success' : 'warning'}>{template.method}</Badge><code className="truncate text-xs text-text-secondary">{template.route}</code></span><span className="mt-1.5 block text-[10px] text-text-muted">{suggestions.length} parameter signal{suggestions.length === 1 ? '' : 's'} · {safe ? 'auto-safe' : 'guarded'} · baseline {template.preflight_status}</span></span>
                  <span className="flex shrink-0 items-center gap-2"><Badge variant={presentation.variant}>{presentation.label}</Badge><span className="text-text-muted transition-transform group-open:rotate-90">›</span></span>
                </summary>
                <div className="border-t border-border p-3 space-y-2">{suggestions.map((suggestion, index) => {
                  const canRun = suggestion.automated && (safe || unsafe)
                  return <div key={`${suggestion.parameter}-${index}`} className="grid xl:grid-cols-[minmax(0,1fr)_minmax(180px,.55fr)_auto] gap-3 rounded-lg border border-border/70 bg-surface-2 p-3">
                    <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><code className="text-xs font-semibold text-accent">{suggestion.parameter}</code><span className="text-[9px] uppercase tracking-wide text-text-muted">{suggestion.location}</span><span className="text-[9px] text-text-muted">{suggestion.confidence}% match</span></div><p className="mt-1 text-[11px] text-text-secondary">{suggestion.reason}</p></div>
                    <div className="min-w-0 self-center">{suggestion.payloads?.[0] ? <><p className="text-[9px] uppercase tracking-wide text-text-muted">Suggested edit</p><code className="mt-1 block truncate text-[10px] text-text-secondary" title={suggestion.payloads[0]}>{suggestion.payloads[0]}</code>{suggestion.payloads.length > 1 && <span className="text-[9px] text-text-muted">+{suggestion.payloads.length - 1} alternatives</span>}</> : <span className="text-[10px] text-text-muted">Manual context required</span>}</div>
                    <div className="flex items-center gap-2 xl:justify-end"><Button size="sm" disabled={isBusy} onClick={() => edit(template, suggestion)}>Inspect</Button>{canRun ? <Button size="sm" variant="primary" disabled={isBusy || active || !confirmed} onClick={() => runChecks([{ template_id: template.id, module: suggestion.module }], moduleInfo[suggestion.module]?.short || suggestion.module)}>Run</Button> : <Badge variant={suggestion.automated ? 'warning' : 'neutral'}>{suggestion.automated ? 'enable writes' : 'manual'}</Badge>}</div>
                  </div>
                })}{result && <div className="flex flex-col sm:flex-row sm:items-center gap-2 rounded-lg bg-surface-3/60 px-3 py-2 text-[11px]"><Badge variant={presentation.variant}>{presentation.label}</Badge><span className="text-text-secondary">{presentation.detail}</span><span className="sm:ml-auto shrink-0 text-text-muted">{result.requests} requests · {result.findings.length} signals</span></div>}</div>
              </details>
            })}
          </div>}
        </main>
      </div> : <div className="p-4 space-y-4">
        <div className="grid grid-cols-3 gap-2">{[[resultStats.hits, 'Hits', 'text-severity-critical'], [resultStats.clean, 'No hit', 'text-severity-low'], [resultStats.review, 'Needs review', 'text-severity-medium']].map(([value, label, color]) => <div key={String(label)} className="rounded-lg border border-border bg-surface-3/30 p-3"><p className={`text-xl font-bold ${color}`}>{value}</p><p className="text-[10px] uppercase tracking-wide text-text-muted">{label}</p></div>)}</div>
        {!runs.length ? <EmptyState title="No runs yet" description="Confirm authorization, then use Validate & run recommended checks."/> : runs.map(run => {
          const results = run.report.results || []
          const hits = results.filter(result => resultPresentation(result).label === 'HIT').length
          return <details key={run.id} className="rounded-xl border border-border"><summary className="cursor-pointer list-none p-3 flex flex-wrap items-center gap-3"><Badge variant={run.status === 'finished' ? 'success' : ['failed', 'cancelled'].includes(run.status) ? 'error' : 'info'}>{run.status}</Badge><span className="text-xs">{run.created_at}</span><span className="text-[10px] text-text-muted">{results.length} checks</span>{hits > 0 && <Badge variant="error">{hits} hit</Badge>}<span className="ml-auto flex items-center gap-2"><Link className="text-[10px] text-accent" to={`/targets/${targetId}`}>Task {run.task_id.slice(0, 8)}</Link><Button size="sm" disabled={isBusy || !results.length} loading={busy === 'reveal'} onClick={event => { event.preventDefault(); void revealReport(run.id) }}>Evidence</Button></span></summary><div className="border-t border-border p-2 space-y-1">{results.map((result, index) => { const presentation = resultPresentation(result); return <div key={index} className="grid sm:grid-cols-[auto_90px_90px_minmax(0,1fr)_auto] items-center gap-2 rounded-lg px-2 py-2 text-[10px] hover:bg-white/[.02]"><Badge variant={presentation.variant}>{presentation.label}</Badge><span>{moduleInfo[result.module]?.short || result.module}</span><code className="text-text-muted">{result.template_id.slice(0, 8)}</code><span className="text-text-secondary">{presentation.detail}</span><span className="text-text-muted">{result.requests} req</span></div>})}</div></details>
        })}
      </div>}
    </>}

    <Modal open={!!editor} onClose={() => { if (!isBusy) closeEditor() }} title={`Request editor${activeOpportunity ? ` · ${moduleInfo[activeOpportunity.module]?.short || activeOpportunity.module}` : ''}`} width="xl">
      {editor && <div className="space-y-4">
        <div className="rounded-lg border border-severity-medium/30 bg-severity-medium/5 p-3 text-[11px]"><b>Captured secrets are visible.</b> Editing and saving are local and encrypted. Target traffic is sent only when you explicitly run a check.</div>
        {activeOpportunity && <div className="rounded-xl border border-accent/35 bg-accent/5 p-3"><div className="flex flex-wrap items-center gap-2"><span className="text-[10px] uppercase tracking-wide text-text-muted">Payload assistant</span><code className="text-xs font-semibold text-accent">{activeOpportunity.parameter}</code><Badge>{activeOpportunity.location}</Badge></div><p className="mt-1 text-[11px] text-text-secondary">{activeOpportunity.reason}</p>{!!activeOpportunity.payloads?.length && <div className="mt-3 flex flex-wrap gap-2">{activeOpportunity.payloads.map(payload => <Button size="sm" key={payload} disabled={isBusy || binary && activeOpportunity.location === 'body'} onClick={() => applyPayload(payload)}>Apply <code className="ml-1 max-w-56 truncate">{payload}</code></Button>)}</div>}</div>}
        <div className="flex gap-2"><select className="input max-w-28" disabled={isBusy} value={editor.request.method} onChange={event => setEditor({ ...editor, request: { ...editor.request, method: event.target.value } })}>{['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].map(method => <option key={method}>{method}</option>)}</select><input aria-label="Request URL" className="input font-mono text-xs" dir="ltr" disabled={isBusy} value={editor.request.url} onChange={event => setEditor({ ...editor, request: { ...editor.request, url: event.target.value } })}/></div>
        <label><span className="label">Content-Type</span><input className="input font-mono text-xs" disabled={isBusy} value={editor.request.mime_type || ''} onChange={event => setEditor({ ...editor, request: { ...editor.request, mime_type: event.target.value } })}/></label>
        <div className="grid lg:grid-cols-2 gap-3"><label className="block"><span className="label">Headers · JSON name/value array</span><textarea className="input font-mono text-xs h-64" dir="ltr" spellCheck={false} disabled={isBusy} value={headers} onChange={event => setHeaders(event.target.value)}/></label><label className="block"><span className="label">Body {binary ? '· base64 binary' : '· UTF-8'}</span><textarea className="input font-mono text-xs h-64" dir="ltr" spellCheck={false} disabled={isBusy} value={body} onChange={event => setBody(event.target.value)}/></label></div>
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3"><Button variant="ghost" disabled={isBusy} onClick={closeEditor}>Cancel</Button><div className="flex gap-2"><Button loading={busy === 'save'} disabled={isBusy} onClick={() => save(false)}>Save encrypted</Button>{activeOpportunity?.automated && <Button variant="primary" loading={busy === 'save' || busy === 'preflight' || busy === 'queue'} disabled={isBusy || active || !confirmed || editorNeedsUnsafe && !unsafe} onClick={() => save(true)}>Save, validate & run</Button>}</div></div>
      </div>}
    </Modal>

    <Modal open={!!revealed} onClose={() => { if (!isBusy) setRevealed(null) }} title="Reproduction evidence" width="xl">
      {revealed && <div className="space-y-3"><div className="rounded-lg border border-severity-medium/30 bg-severity-medium/5 p-3 text-[11px]">This report can contain live credentials. DETECTED is a signal, not automatically a confirmed vulnerability.</div><div className="flex gap-2"><Button variant="primary" onClick={download}>Download JSON</Button><Button onClick={() => setRevealed(null)}>Close</Button></div><pre dir="ltr" className="max-h-[60vh] overflow-auto rounded-lg border border-border bg-surface-3 p-3 text-[10px] whitespace-pre-wrap break-all">{JSON.stringify(revealed, null, 2)}</pre></div>}
    </Modal>
  </section>
}
