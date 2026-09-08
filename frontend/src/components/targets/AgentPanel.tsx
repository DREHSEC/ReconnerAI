import { useEffect, useMemo, useRef, useState } from 'react'
import { agent as agentApi, system, targets as targetsApi, type AgentLead, type AgentMessage, type AgentThread, type AIStatus, type HunterStatus } from '../../lib/api'
import { Button } from '../ui'
import { Markdown } from '../ui/Markdown'
import { ws } from '../../lib/websocket'
import { cn, timeAgo } from '../../lib/utils'
import { useUIStore } from '../../store/ui'

const SUGGESTIONS = [
  'What is the most interesting attack surface?',
  'Why are these XSS rows still candidates?',
  'Hunt from the latest monitor changes.',
]

type EventPayload = {
  target_id: string
  thread_id: string
  run_id: string
  kind: 'tool_call' | 'tool_result' | 'message' | 'done' | 'error' | 'usage' | 'compact' | string
  payload: Record<string, string | number>
}

function newLocal(role: string, content: string, tool = ''): AgentMessage {
  return {
    id: 'local-' + Math.random().toString(36).slice(2),
    thread_id: '',
    role,
    content,
    tool_name: tool,
    created_at: new Date().toISOString(),
  }
}

function chatKey(targetId: string) {
  return `reconner.copilot.thread.${targetId}`
}

function fmtTok(n: number) {
  const v = Math.max(0, Math.round(n || 0))
  if (v < 1000) return String(v)
  if (v < 10_000) {
    const t = (v / 1000).toFixed(1)
    return t.endsWith('.0') ? `${t.slice(0, -2)}k` : `${t}k`
  }
  return `${Math.round(v / 1000)}k`
}

export function AgentPanel({ targetId }: { targetId: string }) {
  const { addToast } = useUIStore()
  const [status, setStatus] = useState<AIStatus | null>(null)
  const [hunter, setHunter] = useState<HunterStatus | null>(null)
  const [chats, setChats] = useState<AgentThread[]>([])
  const [messages, setMessages] = useState<AgentMessage[]>([])
  const [thread, setThread] = useState<AgentThread | null>(null)
  const [threadStatus, setThreadStatus] = useState('idle')
  const [draft, setDraft] = useState('')
  const [huntOpen, setHuntOpen] = useState(false)
  const [hypothesis, setHypothesis] = useState('')
  const [sending, setSending] = useState(false)
  const [running, setRunning] = useState(false)
  const [compacting, setCompacting] = useState(false)
  const [leads, setLeads] = useState<AgentLead[]>([])
  const [identityCount, setIdentityCount] = useState(0)
  const [scopeText, setScopeText] = useState('')
  const [scopeOpen, setScopeOpen] = useState(false)
  const [leadsOpen, setLeadsOpen] = useState(false)
  const [leadFocus, setLeadFocus] = useState<string | null>(null)
  const [hunterActive, setHunterActive] = useState(false)
  const [query, setQuery] = useState('')
  const [renaming, setRenaming] = useState(false)
  const [renameDraft, setRenameDraft] = useState('')
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const [tokenPrompt, setTokenPrompt] = useState(0)
  const [tokenCompletion, setTokenCompletion] = useState(0)
  const [tokenContext, setTokenContext] = useState(0)
  const [tokenBudget, setTokenBudget] = useState(20000)
  const bottomRef = useRef<HTMLDivElement>(null)
  const threadIdRef = useRef('')
  const composerRef = useRef<HTMLTextAreaElement>(null)

  const ready = !!status?.enabled && !!status?.key_set
  const selectedId = thread?.id || threadIdRef.current

  const applyThread = (th: AgentThread | null) => {
    setThread(th)
    setMessages(th?.messages || [])
    setThreadStatus(th?.status || 'idle')
    setRunning(th?.status === 'running' || !!th?.live)
    setHunterActive(!!th?.hunter_active)
    setTokenPrompt(th?.token_prompt || 0)
    setTokenCompletion(th?.token_completion || 0)
    setTokenContext(th?.token_context || 0)
    setTokenBudget(th?.token_budget || 20000)
    if (th?.id) {
      threadIdRef.current = th.id
      try { sessionStorage.setItem(chatKey(targetId), th.id) } catch { /* ignore */ }
    }
  }

  const loadChats = async () => {
    const list = await agentApi.threads(targetId).catch(() => [] as AgentThread[])
    setChats(list || [])
    return list || []
  }

  const loadThread = async (id: string) => {
    const th = await agentApi.thread(targetId, id).catch(() => null)
    if (th?.id) applyThread(th)
    return th
  }

  const load = async (preferId = '') => {
    try {
      const stored = preferId || (() => { try { return sessionStorage.getItem(chatKey(targetId)) || '' } catch { return '' } })()
      const [ai, hun, ld, ids, list] = await Promise.all([
        system.ai(),
        system.hunter().catch(() => null),
        agentApi.leads(targetId, 'pending').catch(() => [] as AgentLead[]),
        targetsApi.identities(targetId).catch(() => []),
        loadChats(),
      ])
      setStatus(ai)
      setHunter(hun)
      setLeads(ld || [])
      setLeadsOpen((ld || []).length > 0 && (ld || []).length <= 4)
      setIdentityCount((ids || []).length)
      const pick = (stored && list.some(c => c.id === stored) ? stored : list[0]?.id) || ''
      if (pick) {
        const th = await agentApi.thread(targetId, pick).catch(() => null)
        if (th?.id) applyThread(th)
        else applyThread(null)
      } else {
        applyThread(null)
        threadIdRef.current = ''
      }
      setHunterActive(!!hun?.current_target && hun.current_target === targetId)
    } catch {
      setStatus({ enabled: false, key_set: false, key_from_env: false, model: 'GLM-5.3-Flash', max_iterations: 40 })
    }
  }

  useEffect(() => { threadIdRef.current = ''; setHunterActive(false); load() }, [targetId])
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, running])

  useEffect(() => ws.on('agent_event', (payload: unknown) => {
    const ev = payload as EventPayload
    if (ev.target_id !== targetId) return
    if (ev.kind === 'hunter_cycle') {
      system.hunter().then(h => {
        setHunter(h)
        setHunterActive(h?.current_target === targetId)
      }).catch(() => {})
      return
    }
    if (ev.kind === 'compact') {
      const after = Number(ev.payload?.after_tokens || 0)
      if (after) setTokenContext(after)
      loadChats()
      return
    }
    if (ev.kind === 'usage') {
      if (ev.thread_id && threadIdRef.current && ev.thread_id !== threadIdRef.current) return
      setTokenPrompt(Number(ev.payload?.prompt || 0))
      setTokenCompletion(Number(ev.payload?.completion || 0))
      if (ev.payload?.context) setTokenContext(Number(ev.payload.context))
      if (ev.payload?.token_budget) setTokenBudget(Number(ev.payload.token_budget))
      return
    }
    const mine = threadIdRef.current
    if (ev.thread_id && mine && ev.thread_id !== mine) return
    if (ev.thread_id && !mine) return
    if (ev.kind === 'tool_call') {
      setMessages(m => [...m, newLocal('call', String(ev.payload?.arguments || ''), String(ev.payload?.name || ''))])
    } else if (ev.kind === 'tool_result') {
      setMessages(m => [...m, newLocal('tool', String(ev.payload?.result || ''), String(ev.payload?.name || ''))])
    } else if (ev.kind === 'message' && ev.payload?.content) {
      setMessages(m => [...m, newLocal('assistant', String(ev.payload.content))])
    } else if (ev.kind === 'error') {
      addToast('error', String(ev.payload?.error || 'Agent error'))
      setRunning(false)
      setSending(false)
    } else if (ev.kind === 'done') {
      setRunning(false)
      setSending(false)
      setThreadStatus(String(ev.payload?.status || 'idle'))
      loadThread(threadIdRef.current).then(() => loadChats()).catch(() => {})
    }
  }), [targetId, addToast])

  const send = async (text: string) => {
    const content = text.trim()
    if (!content || !ready || running) return
    setDraft('')
    setSending(true)
    setRunning(true)
    setThreadStatus('running')
    setMessages(m => [...m, newLocal('user', content)])
    try {
      const res = await agentApi.send(targetId, content, threadIdRef.current)
      if (res?.thread_id) {
        threadIdRef.current = res.thread_id
        try { sessionStorage.setItem(chatKey(targetId), res.thread_id) } catch { /* ignore */ }
      }
      setHunterActive(false)
      loadChats()
    } catch (e) {
      setRunning(false)
      setSending(false)
      setThreadStatus('idle')
      addToast('error', e instanceof Error ? e.message : 'Failed to send')
    }
  }

  const startHunt = async () => {
    if (!ready || running) return
    setSending(true)
    setRunning(true)
    setHuntOpen(false)
    setThreadStatus('running')
    const label = hypothesis.trim() ? `Hunt: ${hypothesis.trim()}` : 'Hunt this target toward a confirmed finding.'
    setMessages(m => [...m, newLocal('user', label)])
    try {
      const res = await agentApi.hunt(targetId, hypothesis.trim(), threadIdRef.current)
      if (res?.thread_id) threadIdRef.current = res.thread_id
      setHypothesis('')
      setHunterActive(false)
      loadChats()
    } catch (e) {
      setRunning(false)
      setSending(false)
      setThreadStatus('idle')
      addToast('error', e instanceof Error ? e.message : 'Failed to start hunt')
    }
  }

  const cancel = async () => {
    try {
      await agentApi.cancel(targetId)
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Cancel failed')
    } finally {
      setRunning(false)
      setSending(false)
      setThreadStatus('idle')
      loadThread(threadIdRef.current)
    }
  }

  const spawnChat = async () => {
    try {
      const th = await agentApi.createThread(targetId)
      applyThread({ ...th, messages: th.messages || [] })
      setChats(c => [th, ...c.filter(x => x.id !== th.id)])
      setDraft('')
      composerRef.current?.focus()
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Could not open a new chat')
    }
  }

  const switchChat = async (id: string) => {
    if (id === threadIdRef.current) return
    await loadThread(id)
  }

  const compactNow = async () => {
    if (!selectedId || running || compacting) return
    setCompacting(true)
    try {
      const r = await agentApi.compact(targetId, selectedId)
      await loadThread(selectedId)
      loadChats()
      if (r.compacted) addToast('success', `Compacted — saved ${fmtTok(r.saved_tokens)} tokens`)
      else addToast('success', 'Already within the context budget')
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Compact failed')
    } finally {
      setCompacting(false)
    }
  }

  const saveTitle = async () => {
    if (!selectedId) return
    const title = renameDraft.trim()
    setRenaming(false)
    if (!title) return
    try {
      const th = await agentApi.renameThread(targetId, selectedId, title)
      applyThread(th)
      loadChats()
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Rename failed')
    }
  }

  const removeChat = async (id: string) => {
    try {
      await agentApi.deleteThread(targetId, id)
      const next = chats.filter(c => c.id !== id)
      setChats(next)
      setConfirmDelete(null)
      if (id === threadIdRef.current) {
        if (next[0]) await loadThread(next[0].id)
        else {
          applyThread(null)
          threadIdRef.current = ''
        }
      }
    } catch (e) {
      addToast('error', e instanceof Error ? e.message : 'Delete failed')
    }
  }

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return chats
    return chats.filter(c => (c.title || 'New chat').toLowerCase().includes(q) || (c.preview || '').toLowerCase().includes(q))
  }, [chats, query])

  const compactAfter = thread?.compact_after ? new Date(thread.compact_after).getTime() : 0
  const older = compactAfter ? messages.filter(m => new Date(m.created_at).getTime() < compactAfter) : []
  const liveMsgs = compactAfter ? messages.filter(m => new Date(m.created_at).getTime() >= compactAfter) : messages
  const used = tokenPrompt || tokenContext
  const pct = Math.min(100, Math.round((used / Math.max(tokenBudget, 1)) * 100))

  return (
    <div className="card overflow-hidden flex flex-col h-[min(78vh,48rem)] min-h-[30rem]">
      <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[.18em] text-accent">Copilot workspace</p>
          <p className="text-xs text-text-muted mt-0.5 truncate">
            {status?.model || 'GLM-5.3-Flash'} · {running || threadStatus === 'running' ? 'running' : 'idle'}
            {hunterActive && !running ? ' · 24/7 hunter on this target' : ''}
            {chats.length ? ` · ${chats.length} chat${chats.length === 1 ? '' : 's'}` : ''}
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <TokenMeter used={used} budget={tokenBudget} prompt={tokenPrompt} completion={tokenCompletion} pct={pct} />
          {running && <Button size="sm" variant="ghost" onClick={cancel}>Cancel</Button>}
          <a href={`/api/targets/${targetId}/report.html`} target="_blank" rel="noreferrer" className="btn-ghost text-xs">Report</a>
        </div>
      </div>

      {identityCount < 2 && (
        <div className="px-4 py-2 text-[11px] text-severity-medium border-b border-border bg-severity-medium/[.06]">
          Authz hunt is idle — add a victim and an attacker session in Identities (Cookie or Bearer). IDOR/diff_identities will not run with {identityCount} session{identityCount === 1 ? '' : 's'}.
        </div>
      )}
      {leads.length > 0 && (
        <div className="border-b border-border bg-severity-medium/[.06] shrink-0">
          <button type="button" onClick={() => setLeadsOpen(o => !o)}
            className="w-full px-4 py-2 flex items-center justify-between gap-2 text-left">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-severity-medium">
              {leads.length} hunter lead{leads.length === 1 ? '' : 's'} — not verified findings
            </p>
            <span className="text-[10px] text-text-muted">{leadsOpen ? 'hide' : 'show'}</span>
          </button>
          {leadsOpen && (
            <div className="px-4 pb-2 max-h-40 overflow-y-auto space-y-1.5">
              <p className="text-[10px] text-text-muted">Hunter leads are not findings. Confirm &amp; verify enqueues a URL-scoped verify (and a matching detector). Reconner’s verifier still has to promote a finding.</p>
              {leads.map(l => {
                const open = leadFocus === l.id
                return (
                  <div key={l.id} className="text-[11px] border border-border rounded-lg p-2 bg-black/20">
                    <button type="button" onClick={() => setLeadFocus(open ? null : l.id)} className="w-full text-left">
                      <p className="font-semibold text-text-primary truncate">{l.severity ? `${l.severity} · ` : ''}{l.title}</p>
                      {l.url && <p className="font-mono text-accent truncate mt-0.5">{l.method || 'GET'} {l.url}</p>}
                      {open && l.body && <p className="text-text-secondary mt-1 whitespace-pre-wrap break-words">{l.body}</p>}
                    </button>
                    <div className="flex gap-1 flex-wrap justify-end mt-1.5">
                      {l.url && (
                        <Button size="sm" variant="secondary" onClick={async () => {
                          try {
                            await targetsApi.replay(targetId, { method: l.method || 'GET', url: l.url })
                            addToast('success', 'Replayed in-scope')
                          } catch (e) { addToast('error', e instanceof Error ? e.message : 'Replay failed') }
                        }}>Replay</Button>
                      )}
                      <Button size="sm" variant="secondary" disabled={!ready || running} onClick={() => {
                        const lines = [
                          'Investigate this hunter lead in-scope and gather evidence. Do not claim a verified finding.',
                          `Title: ${l.title}`,
                          l.body,
                          l.url ? `${l.method || 'GET'} ${l.url}` : '',
                          l.evidence ? `Evidence: ${l.evidence}` : '',
                        ].filter(Boolean).join('\n')
                        send(lines)
                      }}>Ask copilot</Button>
                      <Button size="sm" variant="primary" onClick={async () => {
                        try {
                          const r = await agentApi.triageLead(targetId, l.id, 'confirmed')
                          setLeads(x => x.filter(i => i.id !== l.id))
                          if (r.report) {
                            try { await navigator.clipboard.writeText(r.report) } catch { /* ignore */ }
                          }
                          if (r.verify_error) {
                            addToast('error', `Lead confirmed, verify did not queue: ${r.verify_error}`)
                          } else if (r.task_id) {
                            addToast('success', `Queued ${ (r.modules || ['verify']).join(', ') } on this URL`)
                          } else {
                            addToast('success', 'Lead confirmed — disclosure draft copied (no URL to verify)')
                          }
                        } catch (e) { addToast('error', e instanceof Error ? e.message : 'Failed') }
                      }}>{l.url ? 'Confirm & verify' : 'Confirm'}</Button>
                      <Button size="sm" variant="ghost" onClick={async () => {
                        try { await agentApi.triageLead(targetId, l.id, 'dismissed'); setLeads(x => x.filter(i => i.id !== l.id)) }
                        catch (e) { addToast('error', e instanceof Error ? e.message : 'Failed') }
                      }}>Dismiss</Button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {hunterActive && !running && (
        <div className="px-4 py-2 text-[11px] text-accent border-b border-border bg-accent/[.06]">
          24/7 hunter is working this target — sending a message pauses it for copilot.
        </div>
      )}
      {hunter?.enabled && hunter.last_target === targetId && hunter.last_summary && (
        <div className="px-4 py-2 text-[11px] text-text-secondary border-b border-border bg-accent/[.04]">
          24/7 hunter last cycle · <span className="font-mono text-accent">{hunter.last_playbook}</span>
          {hunter.last_at ? ` · ${hunter.last_at}` : ''}
          <span className="block text-text-muted mt-0.5">{hunter.last_summary}</span>
        </div>
      )}

      {!ready && (
        <div className="px-4 py-3 text-xs text-text-secondary border-b border-border bg-white/[.02]">
          Copilot is off. Enable it in <span className="text-accent">System → Integrations</span>
          {status && !status.key_set ? ' and set AI_API_KEY (or paste the LiteLLM key).' : '.'}
        </div>
      )}

      <div className="flex-1 min-h-0 flex">
        <aside className="hidden md:flex w-56 shrink-0 flex-col border-r border-border bg-black/20">
          <div className="p-2 border-b border-border space-y-2">
            <Button size="sm" variant="primary" className="w-full" disabled={!ready} onClick={spawnChat}>New chat</Button>
            {chats.length > 4 && (
              <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search chats"
                className="input text-[11px] h-8" />
            )}
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto p-1.5 space-y-0.5">
            {filtered.length === 0 && (
              <p className="px-2 py-6 text-[11px] text-text-muted text-center">No chats yet. Spawn one and start hunting this target.</p>
            )}
            {filtered.map(c => {
              const active = c.id === selectedId
              return (
                <div key={c.id} className={cn(
                  'group rounded-lg px-2 py-1.5 cursor-pointer border',
                  active ? 'border-accent/40 bg-accent/10' : 'border-transparent hover:bg-white/[.04]',
                )}>
                  <button type="button" onClick={() => switchChat(c.id)} className="w-full text-left">
                    <p className={cn('text-[12px] truncate', active ? 'text-text-primary font-medium' : 'text-text-secondary')}>
                      {c.live ? <span className="inline-block w-1.5 h-1.5 rounded-full bg-accent mr-1.5 animate-pulse" /> : null}
                      {c.title || 'New chat'}
                    </p>
                    <p className="text-[10px] text-text-muted truncate mt-0.5">
                      {timeAgo(c.updated_at)} · {c.message_count || 0} msgs
                      {c.token_prompt || c.token_context ? ` · ${fmtTok(c.token_prompt || c.token_context || 0)}` : ''}
                    </p>
                  </button>
                  <div className="flex justify-end opacity-0 group-hover:opacity-100 transition-opacity">
                    {confirmDelete === c.id ? (
                      <button type="button" className="text-[10px] text-severity-critical" onClick={() => removeChat(c.id)}>Delete?</button>
                    ) : (
                      <button type="button" className="text-[10px] text-text-muted hover:text-severity-critical"
                        onClick={() => setConfirmDelete(c.id)}>Delete</button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </aside>

        <div className="flex-1 min-w-0 flex flex-col">
          <div className="flex items-center gap-2 px-3 py-2 border-b border-border shrink-0">
            <div className="md:hidden flex-1 min-w-0">
              <select className="input text-xs h-8 w-full" value={selectedId} onChange={e => switchChat(e.target.value)}>
                {chats.length === 0 && <option value="">New workspace</option>}
                {chats.map(c => <option key={c.id} value={c.id}>{c.title || 'New chat'}</option>)}
              </select>
            </div>
            <div className="hidden md:flex flex-1 min-w-0 items-center gap-2">
              {renaming ? (
                <input autoFocus value={renameDraft} onChange={e => setRenameDraft(e.target.value)}
                  onBlur={saveTitle} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); saveTitle() } }}
                  className="input text-sm h-8 max-w-sm" />
              ) : (
                <button type="button" className="text-sm text-text-primary truncate text-left" title="Rename"
                  onClick={() => { setRenameDraft(thread?.title || ''); setRenaming(true) }}>
                  {thread?.title || 'New chat'}
                </button>
              )}
              {thread?.mode === 'hunt' && <span className="text-[10px] uppercase tracking-wider text-accent">hunt</span>}
            </div>
            <Button size="sm" variant="ghost" className="md:hidden" disabled={!ready} onClick={spawnChat}>New</Button>
            <Button size="sm" variant="ghost" disabled={!ready || running || compacting || messages.length < 4} loading={compacting} onClick={compactNow}>
              Compact
            </Button>
            <Button size="sm" variant="ghost" onClick={async () => {
              const next = !scopeOpen
              setScopeOpen(next)
              if (next && !scopeText) {
                try {
                  const s = await targetsApi.scope(targetId)
                  const lines = (s.include || []).filter(Boolean)
                  if (lines.length) setScopeText(lines.join('\n'))
                } catch { /* ignore */ }
              }
            }}>Scope</Button>
            <Button size="sm" variant="secondary" disabled={!ready || running} onClick={() => setHuntOpen(o => !o)}>Hunt</Button>
          </div>

          {scopeOpen && (
            <div className="px-4 py-3 border-b border-border space-y-2">
              <p className="text-[11px] text-text-secondary">Paste HackerOne structured-scope JSON, Bugcrowd targets JSON, or a host list. Hunter HTTP will not leave this include list.</p>
              <textarea value={scopeText} onChange={e => setScopeText(e.target.value)} rows={4}
                placeholder='{"data":[{"attributes":{"asset_identifier":"*.example.com","eligible_for_submission":true}}]}'
                className="input font-mono text-xs min-h-[5rem]" />
              <div className="flex justify-end gap-2">
                <Button size="sm" variant="primary" onClick={async () => {
                  try {
                    const p = await targetsApi.importScope(targetId, scopeText)
                    addToast('success', `Imported ${p.format}: ${p.include?.length || 0} in, ${p.exclude?.length || 0} out`)
                    setScopeOpen(false)
                    setScopeText('')
                  } catch (e) { addToast('error', e instanceof Error ? e.message : 'Import failed') }
                }}>Import</Button>
              </div>
            </div>
          )}
          {huntOpen && (
            <div className="px-4 py-3 border-b border-border space-y-2 bg-accent/[.04]">
              <p className="text-[11px] text-text-secondary">Optional hypothesis — the hunt loop will use tools and enqueue the smallest module set that tests it.</p>
              <textarea value={hypothesis} onChange={e => setHypothesis(e.target.value)} rows={2}
                placeholder="e.g. reflected XSS on search, or BOLA on /api/orders/{id}"
                className="input font-mono text-xs min-h-[3.5rem]" />
              <div className="flex justify-end gap-2">
                <Button size="sm" variant="ghost" onClick={() => setHuntOpen(false)}>Close</Button>
                <Button size="sm" variant="primary" disabled={!ready || running} loading={sending && running} onClick={startHunt}>Start hunt</Button>
              </div>
            </div>
          )}

          <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-3">
            {messages.length === 0 && (
              <div className="py-8 text-center space-y-3">
                <p className="text-sm text-text-primary">New chat on this target</p>
                <p className="text-xs text-text-muted max-w-md mx-auto">Each chat is its own workspace. Compact old turns when the meter climbs — the model keeps a memory, you keep the full transcript.</p>
                <div className="flex flex-col sm:flex-row flex-wrap gap-2 justify-center">
                  {SUGGESTIONS.map(s => (
                    <button key={s} type="button" disabled={!ready || running} onClick={() => send(s)}
                      className="px-3 py-1.5 rounded-lg border border-border text-[11px] text-text-secondary hover:text-text-primary hover:border-accent/40 disabled:opacity-40">
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {older.length > 0 && (
              <details className="rounded-lg border border-border bg-white/[.03] px-3 py-2">
                <summary className="cursor-pointer text-[11px] text-text-muted select-none">
                  {older.length} earlier turn{older.length === 1 ? '' : 's'} compacted for the model
                  {thread?.compact_summary ? ' · memory kept' : ''}
                </summary>
                {thread?.compact_summary && (
                  <p className="mt-2 text-[11px] text-text-secondary whitespace-pre-wrap">{thread.compact_summary}</p>
                )}
                <div className="mt-2 space-y-2 max-h-48 overflow-y-auto">
                  {older.filter(m => m.role === 'user' || m.role === 'assistant').map((m, i) => (
                    <Bubble key={m.id || i} msg={m} />
                  ))}
                </div>
              </details>
            )}
            {liveMsgs.filter(m => m.role === 'user' || m.role === 'assistant' || m.role === 'call' || m.role === 'tool').map((m, i) => (
              <Bubble key={m.id || i} msg={m} />
            ))}
            {running && <p className="text-[11px] text-accent animate-pulse">Working…</p>}
            <div ref={bottomRef} />
          </div>

          <form className="border-t border-border p-3 flex gap-2 items-end shrink-0" onSubmit={e => { e.preventDefault(); send(draft) }}>
            <div className="flex-1 min-w-0">
              <textarea ref={composerRef} value={draft} onChange={e => setDraft(e.target.value)} rows={2} disabled={!ready || running}
                placeholder={ready ? 'Ask about findings, params, or what to scan next…' : 'Copilot disabled'}
                onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(draft) } }}
                className="input w-full font-sans text-sm min-h-[2.75rem] resize-none" />
              <p className="mt-1 text-[10px] text-text-muted font-mono">
                {fmtTok(used)} / {fmtTok(tokenBudget)} tok
                {tokenPrompt ? ` · last turn ${fmtTok(tokenPrompt)} → ${fmtTok(tokenCompletion)}` : ''}
                {pct >= 72 ? ' · compact recommended' : ''}
              </p>
            </div>
            <Button type="submit" variant="primary" size="sm" disabled={!ready || running || !draft.trim()} loading={sending && !huntOpen}>Send</Button>
          </form>
        </div>
      </div>
    </div>
  )
}

function TokenMeter({ used, budget, prompt, completion, pct }: { used: number; budget: number; prompt: number; completion: number; pct: number }) {
  const bar = pct >= 90 ? 'bg-severity-critical' : pct >= 72 ? 'bg-severity-medium' : 'bg-accent'
  return (
    <div className="hidden sm:flex flex-col items-end min-w-[7.5rem]" title={prompt ? `Last turn ${fmtTok(prompt)} in → ${fmtTok(completion)} out` : 'Estimated context tokens for the next turn'}>
      <p className="text-[10px] font-mono text-text-muted leading-none mb-1">
        <span className="text-text-secondary">{fmtTok(used)}</span>
        <span className="text-text-muted"> / {fmtTok(budget)} tok</span>
      </p>
      <div className="w-full h-1 rounded-full bg-white/10 overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', bar)} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function Bubble({ msg }: { msg: AgentMessage }) {
  if (msg.role === 'call') {
    return (
      <div className="flex items-center gap-2 text-[11px] font-mono text-text-muted">
        <span className="px-1.5 py-0.5 rounded border border-accent/30 bg-accent/10 text-accent">{msg.tool_name || 'tool'}</span>
        <span className="truncate">{clipArgs(msg.content)}</span>
      </div>
    )
  }
  if (msg.role === 'tool') {
    return (
      <details className="text-[11px] text-text-muted">
        <summary className="cursor-pointer select-none">
          <span className="font-mono text-text-secondary">{msg.tool_name}</span> result
        </summary>
        <pre className="mt-1 font-mono text-[10px] whitespace-pre-wrap break-all bg-black/30 rounded p-2 max-h-40 overflow-auto">{clipArgs(msg.content, 1200)}</pre>
      </details>
    )
  }
  const mine = msg.role === 'user'
  return (
    <div className={cn('max-w-[90%] rounded-lg px-3 py-2',
      mine ? 'ml-auto bg-accent/15 text-text-primary' : 'bg-white/[.04] border border-white/[.06] text-text-secondary')}>
      <Markdown>{msg.content}</Markdown>
    </div>
  )
}

function clipArgs(s: string, n = 160) {
  const t = (s || '').replace(/\s+/g, ' ').trim()
  return t.length > n ? t.slice(0, n) + '…' : t
}
