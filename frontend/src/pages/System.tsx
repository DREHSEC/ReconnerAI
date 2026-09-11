import { useEffect, useRef, useState, type ReactNode } from 'react'
import { system, type AIStatus, type ApiKeyState, type ToolCatalogEntry } from '../lib/api'
import { HunterCard } from '../components/system/HunterCard'
import { Button, Spinner } from '../components/ui'
import { cn } from '../lib/utils'
import { ws } from '../lib/websocket'
import { useUIStore } from '../store/ui'
import { useAuthStore } from '../store/auth'
import { UsersAdmin } from '../components/system/UsersAdmin'
import { useUpdateCenter } from '../components/layout/UpdateCenter'

interface SystemLogLine { level: string; module: string; message: string; time: string }

export default function System() {
  const [activeTab, setActiveTab] = useState<'overview' | 'integrations' | 'toolchain' | 'team'>('overview')
  const [tools, setTools] = useState<Record<string,boolean>>({})
  const [catalog, setCatalog] = useState<ToolCatalogEntry[]>([])
  const [installing, setInstalling] = useState<Record<string, boolean>>({})
  const [stats, setStats] = useState<Record<string,number>>({})
  const [loading, setLoading] = useState(true)
  const [templateLog, setTemplateLog] = useState<SystemLogLine[]>([])
  const [updatingTemplates, setUpdatingTemplates] = useState(false)
  const [apiKeys, setApiKeys] = useState<ApiKeyState[]>([])
  const [ai, setAi] = useState<AIStatus | null>(null)
  const [drafts, setDrafts] = useState<Record<string,string>>({})
  const [savingKeys, setSavingKeys] = useState(false)
  const [agentDraft, setAgentDraft] = useState<Record<string, string>>({})
  const [savingAgent, setSavingAgent] = useState(false)
  const { addToast } = useUIStore()
  const isAdmin = useAuthStore(s => s.user?.role === 'admin')
  const { info: updateInfo, checking: checkingUpdate, refresh: refreshUpdate, showDetails: showUpdateDetails } = useUpdateCenter()
  const templateTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const load = async () => {
    try {
      const [t, cat, s, ks] = await Promise.all([
        system.tools(),
        system.toolCatalog().catch(() => [] as ToolCatalogEntry[]),
        system.stats(),
        system.getSettings().catch(() => ({ api_keys: [] as ApiKeyState[], ai: undefined })),
      ])
      setTools(t||{}); setCatalog(cat||[]); setStats(s||{}); setApiKeys(ks?.api_keys || []); setAi(ks?.ai || null)
      if (ks?.ai) setAgentDraft(agentDraftFrom(ks.ai))
    }
    catch { /**/ } finally { setLoading(false) }
  }

  const installTool = async (name: string) => {
    setInstalling(p => ({ ...p, [name]: true }))
    try {
      const r = await system.installTool(name)
      if (r.installed) {
        addToast('success', `${name} installed`)
        const cat = await system.toolCatalog().catch(() => catalog)
        setCatalog(cat)
        setTools(await system.tools().catch(() => tools))
      } else if (r.manual) {
        addToast('info', `${name}: run manually → ${r.command || r.doc || 'see docs'}`)
      } else {
        addToast('error', `${name}: ${r.message || 'install failed'}`)
      }
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : `Failed to install ${name}`)
    } finally {
      setInstalling(p => ({ ...p, [name]: false }))
    }
  }

  const saveAgent = async () => {
    const patch: Record<string, string> = { ...agentDraft }
    if (Object.keys(patch).length === 0) { addToast('info', 'No agent changes to save'); return }
    setSavingAgent(true)
    try {
      const res = await system.updateSettings(patch)
      setAi(res.ai || ai)
      if (res.ai) setAgentDraft(agentDraftFrom(res.ai))
      addToast('success', 'Agent settings saved')
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Failed to save agent settings')
    } finally { setSavingAgent(false) }
  }

  const saveKeys = async () => {
    const patch: Record<string,string> = {}
    for (const [k, v] of Object.entries(drafts)) if (v !== undefined) patch[k] = v
    if (Object.keys(patch).length === 0) { addToast('info', 'No key changes to save'); return }
    setSavingKeys(true)
    try {
      const res = await system.updateSettings(patch)
      setApiKeys(res.api_keys || []); setAi(res.ai || ai); setDrafts({})
      addToast('success', 'API keys saved')
    } catch {
      addToast('error', 'Failed to save API keys')
    } finally { setSavingKeys(false) }
  }
  useEffect(() => {
    load()
    const i = setInterval(() => system.stats().then(s => setStats(s || {})).catch(() => {}), 30000)
    return () => clearInterval(i)
  }, [])

  // nuclei -update-templates + the official/community repo sync (see
  // nuclei.go's syncExtraTemplates) runs in the background on the server;
  // progress streams here as "system_log" events. The backend emits an
  // explicit "Template sync complete." line when it's actually done — that's
  // the real signal the spinner clears on. The timeout below is ONLY a
  // safety net (server restarted mid-sync, missed websocket event, etc.), so
  // it's set comfortably past the backend's own 15-minute cap rather than a
  // guess shorter than the work could actually take.
  useEffect(() => ws.on('system_log', (payload: unknown) => {
    const line = payload as SystemLogLine
    if (line.module !== 'nuclei_templates') return
    setTemplateLog(p => [...p.slice(-49), line])
    if (line.message === 'Template sync complete.') {
      if (templateTimeoutRef.current) { clearTimeout(templateTimeoutRef.current); templateTimeoutRef.current = null }
      setUpdatingTemplates(false)
      addToast('success', 'Nuclei template sync complete')
    }
  }), [])

  const handleUpdateTemplates = async () => {
    setUpdatingTemplates(true)
    setTemplateLog([])
    try {
      const res = await system.updateTemplates()
      addToast('info', res.message)
    } catch (e: unknown) {
      addToast('error', e instanceof Error ? e.message : 'Failed to start template update')
      setUpdatingTemplates(false)
      return
    }
    // Safety-net only — the real "done" signal is the system_log completion
    // line above. 18 min > the backend's 15-min sync budget, so this should
    // essentially never fire under normal conditions.
    if (templateTimeoutRef.current) clearTimeout(templateTimeoutRef.current)
    templateTimeoutRef.current = setTimeout(() => setUpdatingTemplates(false), 18 * 60 * 1000)
  }

  if (loading) return <div className="flex items-center justify-center h-64"><Spinner className="w-10 h-10"/></div>

  const tabs: { id: 'overview' | 'integrations' | 'toolchain' | 'team'; label: string; hidden?: boolean }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'integrations', label: 'Integrations' },
    { id: 'toolchain', label: 'Toolchain' },
    { id: 'team', label: 'Team', hidden: !isAdmin },
  ]
  const formatDate = (value?: string) => value && value !== 'unknown'
    ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    : 'Unknown'

  return (
    <div className="space-y-5">
      <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[.18em] text-accent">Platform control</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">System &amp; updates</h1>
          <p className="mt-1 text-xs text-text-muted">Release health, integrations, scanner tools and team access.</p>
        </div>
        <div className="flex items-center gap-2">
          {activeTab === 'toolchain' && (
            <Button size="sm" variant="secondary" loading={updatingTemplates} onClick={handleUpdateTemplates}>↻ Update templates</Button>
          )}
          <Button size="sm" variant="ghost" onClick={load}>↻ Refresh</Button>
        </div>
      </header>

      <div className="flex gap-1 overflow-x-auto no-scrollbar border-b border-border" role="tablist">
        {tabs.filter(t => !t.hidden).map(t => (
          <button key={t.id} type="button" role="tab" aria-selected={activeTab === t.id}
            onClick={() => setActiveTab(t.id)}
            className={cn('relative shrink-0 px-4 py-2.5 text-xs font-medium transition-colors',
              activeTab === t.id ? 'text-text-primary' : 'text-text-muted hover:text-text-secondary')}>
            {t.label}
            {activeTab === t.id && <span className="absolute left-3 right-3 bottom-0 h-0.5 rounded-full bg-accent" />}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div className="space-y-6 animate-fade-in">
          <section className="card overflow-hidden">
            <div className="grid lg:grid-cols-[1.35fr_.65fr]">
              <div className="p-5 sm:p-6 bg-gradient-to-br from-accent/[.10] via-transparent to-transparent">
                <div className="flex items-center gap-2 text-xs">
                  <span className={cn('w-2.5 h-2.5 rounded-full', updateInfo?.update_available ? 'bg-accent animate-pulse' : updateInfo?.error ? 'bg-severity-medium' : 'bg-severity-low')} />
                  <span className="font-semibold text-text-primary">
                    {!updateInfo ? 'Loading release status…' : !updateInfo.enabled ? 'Automatic checks disabled' : updateInfo.update_available ? `Reconner v${updateInfo.latest} is ready` : 'Reconner is up to date'}
                  </span>
                </div>
                <h2 className="mt-4 text-3xl sm:text-4xl font-semibold tracking-tight">v{updateInfo?.current || '—'}</h2>
                <p className="mt-2 text-sm text-text-secondary max-w-xl">
                  Reconner checks the latest stable GitHub release every six hours using a cached conditional request. It never interrupts scans or updates itself automatically.
                </p>
                <div className="mt-5 flex flex-wrap gap-2">
                  {updateInfo?.update_available && <Button variant="primary" onClick={showUpdateDetails}>Review update</Button>}
                  <Button variant="secondary" loading={checkingUpdate} onClick={refreshUpdate}>Check now</Button>
                  {updateInfo?.url && <a href={updateInfo.url} target="_blank" rel="noreferrer" className="btn-ghost">GitHub release ↗</a>}
                </div>
              </div>
              <dl className="grid grid-cols-2 lg:grid-cols-1 border-t lg:border-t-0 lg:border-l border-border bg-black/[.10]">
                {[
                  ['Channel', updateInfo?.channel || 'stable'],
                  ['Commit', updateInfo?.current_commit && updateInfo.current_commit !== 'unknown' ? updateInfo.current_commit.slice(0, 12) : 'unknown'],
                  ['Built', formatDate(updateInfo?.build_date)],
                  ['Next check', formatDate(updateInfo?.next_check_at)],
                ].map(([label, value]) => (
                  <div key={label} className="p-4 border-b border-r lg:border-r-0 border-border last:border-b-0">
                    <dt className="text-[10px] uppercase tracking-wider text-text-muted">{label}</dt>
                    <dd className="mt-1 text-xs font-mono text-text-secondary break-all">{value}</dd>
                  </div>
                ))}
              </dl>
            </div>
            {updateInfo?.error && <div className="px-5 py-2.5 text-[11px] text-severity-medium border-t border-severity-medium/20 bg-severity-medium/[.05]">GitHub check: {updateInfo.error}{updateInfo.stale ? ' · showing the last successful result' : ''}</div>}
          </section>

          {Object.keys(stats).length > 0 && (
            <section>
              <p className="section-title">Runtime health</p>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                {Object.entries(stats).map(([k,v]) => (
                  <div key={k} className="card p-4">
                    <p className="text-[10px] uppercase tracking-wider text-text-muted">{k.replace(/_/g,' ')}</p>
                    <p className="mt-2 text-xl font-semibold tabular-nums">{typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(1)) : v}</p>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {activeTab === 'integrations' && (
        <section className="animate-fade-in">
          <div className="card p-4 mb-4 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
              <div className="min-w-0">
                <h2 className="text-sm font-semibold">Agent</h2>
                <p className="text-xs text-text-muted mt-1">
                  Copilot and 24/7 hunter. Saved to <span className="font-mono">config.json</span> and applied immediately.
                  {ai?.key_from_env ? ' Inference key is pinned by AI_API_KEY in the environment.' : ' Set the LiteLLM key below if it is not in the environment.'}
                </p>
              </div>
              <Button size="sm" variant="primary" loading={savingAgent} onClick={saveAgent}>Save agent settings</Button>
            </div>
            <div className="flex flex-wrap gap-6">
              <label className="flex items-center gap-3 text-sm">
                <button type="button" onClick={() => setAgentDraft(d => ({ ...d, ai_enabled: d.ai_enabled === 'true' ? 'false' : 'true' }))}
                  className={cn('relative w-11 h-6 rounded-full shrink-0 transition-colors', agentDraft.ai_enabled === 'true' ? 'bg-accent' : 'bg-surface-3 border border-border')}>
                  <span className={cn('absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform', agentDraft.ai_enabled === 'true' ? 'translate-x-5' : 'translate-x-0.5')} />
                </button>
                Copilot
              </label>
              <label className="flex items-center gap-3 text-sm">
                <button type="button" onClick={() => setAgentDraft(d => ({ ...d, ai_hunter_enabled: d.ai_hunter_enabled === 'true' ? 'false' : 'true' }))}
                  className={cn('relative w-11 h-6 rounded-full shrink-0 transition-colors', agentDraft.ai_hunter_enabled === 'true' ? 'bg-accent' : 'bg-surface-3 border border-border')}>
                  <span className={cn('absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform', agentDraft.ai_hunter_enabled === 'true' ? 'translate-x-5' : 'translate-x-0.5')} />
                </button>
                24/7 hunter
              </label>
              <label className="flex items-center gap-3 text-sm">
                <button type="button" onClick={() => setAgentDraft(d => ({ ...d, ai_hunter_skip_running: d.ai_hunter_skip_running === 'true' ? 'false' : 'true' }))}
                  className={cn('relative w-11 h-6 rounded-full shrink-0 transition-colors', agentDraft.ai_hunter_skip_running === 'true' ? 'bg-accent' : 'bg-surface-3 border border-border')}>
                  <span className={cn('absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform', agentDraft.ai_hunter_skip_running === 'true' ? 'translate-x-5' : 'translate-x-0.5')} />
                </button>
                Skip targets mid-scan
              </label>
              <label className="flex items-center gap-3 text-sm">
                <button type="button" onClick={() => setAgentDraft(d => ({ ...d, ai_exec_enabled: d.ai_exec_enabled === 'true' ? 'false' : 'true' }))}
                  className={cn('relative w-11 h-6 rounded-full shrink-0 transition-colors', agentDraft.ai_exec_enabled === 'true' ? 'bg-accent' : 'bg-surface-3 border border-border')}>
                  <span className={cn('absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform', agentDraft.ai_exec_enabled === 'true' ? 'translate-x-5' : 'translate-x-0.5')} />
                </button>
                Container shell
              </label>
              <label className="flex items-center gap-3 text-sm">
                <button type="button" onClick={() => setAgentDraft(d => ({ ...d, ai_browser_enabled: d.ai_browser_enabled === 'true' ? 'false' : 'true' }))}
                  className={cn('relative w-11 h-6 rounded-full shrink-0 transition-colors', agentDraft.ai_browser_enabled === 'true' ? 'bg-accent' : 'bg-surface-3 border border-border')}>
                  <span className={cn('absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform', agentDraft.ai_browser_enabled === 'true' ? 'translate-x-5' : 'translate-x-0.5')} />
                </button>
                Obscura browser
              </label>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              <AgentField label="Model" hint="LiteLLM / OpenAI model id">
                <input className="input font-mono text-xs" value={agentDraft.ai_model ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_model: e.target.value }))} />
              </AgentField>
              <AgentField label="Base URL" hint="OpenAI-compatible …/v1">
                <input className="input font-mono text-xs" value={agentDraft.ai_base_url ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_base_url: e.target.value }))} />
              </AgentField>
              <AgentField label="Copilot iterations" hint="Tool-use turns per chat/hunt">
                <input type="number" min={1} max={200} className="input font-mono text-xs" value={agentDraft.ai_max_iterations ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_max_iterations: e.target.value }))} />
              </AgentField>
              <AgentField label="Max tokens" hint="Completion cap per model call">
                <input type="number" min={256} className="input font-mono text-xs" value={agentDraft.ai_max_tokens ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_max_tokens: e.target.value }))} />
              </AgentField>
              <AgentField label="LLM timeout (s)" hint="HTTP timeout to LiteLLM">
                <input type="number" min={15} max={600} className="input font-mono text-xs" value={agentDraft.ai_timeout_seconds ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_timeout_seconds: e.target.value }))} />
              </AgentField>
              <AgentField label="Hunter interval (s)" hint="Pause between targets (min 15)">
                <input type="number" min={15} className="input font-mono text-xs" value={agentDraft.ai_hunter_interval_seconds ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_hunter_interval_seconds: e.target.value }))} />
              </AgentField>
              <AgentField label="Hunter iterations" hint="Steps in one always-on cycle">
                <input type="number" min={1} max={200} className="input font-mono text-xs" value={agentDraft.ai_hunter_iterations ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_hunter_iterations: e.target.value }))} />
              </AgentField>
              <AgentField label="Cycle cap (min)" hint="Wall clock per hunter cycle">
                <input type="number" min={1} max={120} className="input font-mono text-xs" value={agentDraft.ai_hunter_cycle_minutes ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_hunter_cycle_minutes: e.target.value }))} />
              </AgentField>
              <AgentField label="Hunter HTTP / min / host" hint="Always-on budget for http_request, browser_open, exec-with-hosts">
                <input type="number" min={1} max={600} className="input font-mono text-xs" value={agentDraft.ai_hunter_http_per_min ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_hunter_http_per_min: e.target.value }))} />
              </AgentField>
              <AgentField label="Hunter scan modules" hint="Max start_scan modules per cycle">
                <input type="number" min={1} max={10} className="input font-mono text-xs" value={agentDraft.ai_hunter_scan_cap ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_hunter_scan_cap: e.target.value }))} />
              </AgentField>
              <AgentField label="Probe timeout (s)" hint="In-scope http_request timeout">
                <input type="number" min={5} max={120} className="input font-mono text-xs" value={agentDraft.ai_http_timeout_seconds ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_http_timeout_seconds: e.target.value }))} />
              </AgentField>
              <AgentField label="Probe body cap (bytes)" hint="Truncated HTTP body to the model">
                <input type="number" min={1024} className="input font-mono text-xs" value={agentDraft.ai_http_body_cap ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_http_body_cap: e.target.value }))} />
              </AgentField>
              <AgentField label="Dead-end suppress (h)" hint="remember(dead_end) lifetime">
                <input type="number" min={1} className="input font-mono text-xs" value={agentDraft.ai_hunter_dead_end_hours ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_hunter_dead_end_hours: e.target.value }))} />
              </AgentField>
              <AgentField label="WAF backoff (min)" hint="429/503 host cooldown">
                <input type="number" min={1} className="input font-mono text-xs" value={agentDraft.ai_hunter_waf_minutes ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_hunter_waf_minutes: e.target.value }))} />
              </AgentField>
              <AgentField label="Shell timeout (s)" hint="exec tool wall clock (5–180)">
                <input type="number" min={5} max={180} className="input font-mono text-xs" value={agentDraft.ai_exec_timeout_seconds ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_exec_timeout_seconds: e.target.value }))} />
              </AgentField>
              <AgentField label="Browser timeout (s)" hint="Obscura navigate/click wall clock (5–180)">
                <input type="number" min={5} max={180} className="input font-mono text-xs" value={agentDraft.ai_browser_timeout_seconds ?? ''} onChange={e => setAgentDraft(d => ({ ...d, ai_browser_timeout_seconds: e.target.value }))} />
              </AgentField>
            </div>
          </div>
          <div className="mb-4"><HunterCard /></div>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
            <div>
              <h2 className="text-sm font-semibold">Passive intelligence providers</h2>
              <p className="text-xs text-text-muted mt-1">Optional credentials are persisted server-side and are never returned in full.</p>
            </div>
            <Button size="sm" variant="primary" loading={savingKeys} onClick={saveKeys}>Save changes</Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {apiKeys.map(k => (
              <div key={k.name} className="card p-4">
                <div className="flex items-center justify-between gap-3 mb-2">
                  <span className="text-sm font-medium">{k.label}</span>
                  <span className={cn('text-[10px]', k.set ? 'text-severity-low' : 'text-text-muted')}>{k.set ? `● connected ${k.masked ? `(${k.masked})` : ''}` : '○ not configured'}</span>
                </div>
                <input type="password" autoComplete="off" placeholder={k.set ? 'Enter a new value to replace' : k.hint}
                  value={drafts[k.name] ?? ''} onChange={e => setDrafts(d => ({ ...d, [k.name]: e.target.value }))}
                  className="input font-mono" />
                <p className="text-[10px] text-text-muted mt-2">Expected format: <span className="font-mono">{k.hint}</span></p>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeTab === 'toolchain' && (
        <section className="space-y-5 animate-fade-in">
          {templateLog.length > 0 && (
            <div className="card p-4">
              <p className="section-title">Template sync</p>
              <div className="space-y-1 max-h-44 overflow-y-auto font-mono text-xs">
                {templateLog.map((l, i) => <p key={i} className={l.level === 'error' ? 'text-severity-critical' : l.level === 'warn' ? 'text-severity-medium' : 'text-text-secondary'}>{l.message}</p>)}
              </div>
            </div>
          )}
          <div>
            <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-2 mb-4">
              <div>
                <h2 className="text-sm font-semibold">Scanner toolchain</h2>
                <p className="text-xs text-text-muted mt-1">{(catalog.length ? catalog.filter(t => t.installed).length : Object.values(tools).filter(Boolean).length)}/{catalog.length || Object.keys(tools).length} tools available</p>
              </div>
              <p className="text-[11px] text-text-muted">The official Docker image bundles and verifies the complete toolchain.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
              {(catalog.length ? catalog : Object.entries(tools).map(([name, installed]) => ({ name, installed, method: '', command: '', doc: '', notes: '', one_click: false }))).map(t => (
                <div key={t.name} className="card p-3 flex items-center gap-3">
                  <span className={cn('w-2 h-2 rounded-full shrink-0', t.installed ? 'bg-severity-low' : 'bg-severity-critical')} />
                  <div className="flex-1 min-w-0">
                    <span className="text-sm font-mono">{t.name}</span>
                    {!t.installed && <span className="block text-[10px] text-text-muted truncate" title={t.command || t.doc}>{t.notes || t.command || 'Unavailable'}</span>}
                  </div>
                  {t.installed ? <span className="text-xs text-severity-low">✓</span> : t.one_click ? (
                    <Button size="sm" variant="secondary" disabled={!!installing[t.name]} onClick={() => installTool(t.name)}>{installing[t.name] ? <Spinner /> : 'Install'}</Button>
                  ) : (
                    <div className="flex gap-1">
                      {t.command && <button onClick={() => { navigator.clipboard?.writeText(t.command); addToast('success', 'Command copied') }} className="btn-ghost !px-2 !py-1 text-xs">Copy</button>}
                      {t.doc && <a href={t.doc} target="_blank" rel="noreferrer" className="btn-ghost !px-2 !py-1 text-xs">Docs</a>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {activeTab === 'team' && isAdmin && <div className="animate-fade-in"><UsersAdmin /></div>}
    </div>
  )
}

function agentDraftFrom(ai: AIStatus): Record<string, string> {
  return {
    ai_enabled: ai.enabled ? 'true' : 'false',
    ai_hunter_enabled: ai.hunter?.enabled ? 'true' : 'false',
    ai_hunter_skip_running: (ai.hunter_skip_running ?? true) ? 'true' : 'false',
    ai_model: ai.model || 'GLM-5.3-Flash',
    ai_base_url: ai.base_url || '',
    ai_max_iterations: String(ai.max_iterations ?? 40),
    ai_max_tokens: String(ai.max_tokens ?? 8192),
    ai_timeout_seconds: String(ai.timeout_seconds ?? 180),
    ai_http_timeout_seconds: String(ai.http_timeout_seconds ?? 20),
    ai_http_body_cap: String(ai.http_body_cap ?? 16384),
    ai_hunter_interval_seconds: String(ai.hunter?.interval_seconds ?? 90),
    ai_hunter_iterations: String(ai.hunter?.iterations ?? 28),
    ai_hunter_http_per_min: String(ai.hunter_http_per_min ?? 20),
    ai_hunter_scan_cap: String(ai.hunter_scan_cap ?? 2),
    ai_hunter_cycle_minutes: String(ai.hunter_cycle_minutes ?? 12),
    ai_hunter_dead_end_hours: String(ai.hunter_dead_end_hours ?? 168),
    ai_hunter_waf_minutes: String(ai.hunter_waf_minutes ?? 30),
    ai_exec_enabled: (ai.exec_enabled ?? true) ? 'true' : 'false',
    ai_exec_timeout_seconds: String(ai.exec_timeout_seconds ?? 45),
    ai_browser_enabled: (ai.browser_enabled ?? true) ? 'true' : 'false',
    ai_browser_timeout_seconds: String(ai.browser_timeout_seconds ?? 45),
  }
}

function AgentField({ label, hint, children }: { label: string; hint: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="text-[11px] font-medium text-text-secondary">{label}</span>
      <div className="mt-1">{children}</div>
      <span className="block text-[10px] text-text-muted mt-1">{hint}</span>
    </label>
  )
}
