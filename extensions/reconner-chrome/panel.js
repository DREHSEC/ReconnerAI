const MAX_ENTRIES = 5000
const MAX_BODY_BYTES = 2 * 1024 * 1024
const entries = []
const fingerprints = new Set()
let capturing = false
let seen = 0
let duplicates = 0
let bodyBytes = 0

const $ = id => document.getElementById(id)
const utf8Base64 = value => {
  const bytes = new TextEncoder().encode(value || '')
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(binary)
}
const headerList = headers => (headers || []).map(h => ({ name: h.name, value: h.value || '' }))
const sensitiveName = name => /^(cookie|set-cookie|authorization|proxy-authorization)$/i.test(name) || /(csrf|xsrf|token|api-key|secret)/i.test(name)
const volatileName = name => /(^|[-_])(csrf|xsrf|token|nonce|timestamp|ts|session|sessionid|access[-_]?token|refresh[-_]?token|authenticity[-_]?token)($|[-_])/i.test(name)
const fingerprintURL = raw => {
  const u = new URL(raw)
  for (const name of u.searchParams.keys()) if (volatileName(name)) u.searchParams.set(name, '{volatile}')
  u.hash = ''
  return u.toString()
}
const fingerprintOf = async req => {
  const stableHeaders = headerList(req.headers).map(h => [h.name.toLowerCase(), sensitiveName(h.name) ? '{secret}' : h.value]).sort()
  const value = JSON.stringify([req.method, fingerprintURL(req.url), stableHeaders, normalizedBody(req)])
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return [...new Uint8Array(digest)].map(v => v.toString(16).padStart(2, '0')).join('')
}
const normalizedBody = req => {
  const raw = req.postData?.text || ''
  const mime = (req.postData?.mimeType || '').toLowerCase()
  if (mime.includes('json')) {
    try {
      const walk = value => {
        if (Array.isArray(value)) return value.map(walk)
        if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, volatileName(k) ? '{volatile}' : walk(v)]))
        return value
      }
      return JSON.stringify(walk(JSON.parse(raw)))
    } catch { return raw }
  }
  if (mime.includes('application/x-www-form-urlencoded')) {
    const form = new URLSearchParams(raw)
    for (const name of form.keys()) if (volatileName(name)) form.set(name, '{volatile}')
    form.sort(); return form.toString()
  }
  return raw
}
const scopes = () => $('scope').value.split(/\r?\n/).map(v => v.trim()).filter(Boolean)
const inScope = raw => scopes().some(rule => {
  try {
    const candidate = new URL(raw)
    if (!rule.includes('://')) return candidate.hostname === rule || candidate.hostname.endsWith('.' + rule)
    const wanted = new URL(rule)
    return candidate.origin === wanted.origin && (wanted.pathname === '/' || candidate.pathname.startsWith(wanted.pathname))
  } catch { return false }
})
const humanBytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KB` : `${(n/1048576).toFixed(1)} MB`
const render = () => {
  $('unique').textContent = entries.length
  $('seen').textContent = seen
  $('duplicates').textContent = duplicates
  $('bytes').textContent = humanBytes(bodyBytes)
  $('export').disabled = entries.length === 0
  $('rows').innerHTML = entries.slice(-250).reverse().map(e => `<tr><td>${e.sequence}</td><td>${e.request.method}</td><td class="url" title="${escapeHTML(e.request.url)}">${escapeHTML(e.request.url)}</td><td>${e.response.status || '-'}</td><td>${humanBytes((e.request.body?.length || 0) + (e.response.body?.length || 0))}</td></tr>`).join('')
}
const escapeHTML = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))
const getResponseContent = request => new Promise(resolve => request.getContent((content, encoding) => resolve({ content: content || '', encoding: encoding || '' })))

chrome.devtools.network.onRequestFinished.addListener(async item => {
  if (!capturing || !inScope(item.request.url) || entries.length >= MAX_ENTRIES) return
  seen++
  const fp = await fingerprintOf(item.request)
  if (fingerprints.has(fp)) { duplicates++; render(); return }
  fingerprints.add(fp)
  const content = await getResponseContent(item)
  const requestText = item.request.postData?.text || ''
  let responseBody = content.encoding === 'base64' ? content.content : utf8Base64(content.content)
  let requestBody = utf8Base64(requestText)
  if (atob(requestBody).length > MAX_BODY_BYTES) requestBody = ''
  if (responseBody && atob(responseBody).length > MAX_BODY_BYTES) responseBody = ''
  bodyBytes += Math.floor(requestBody.length * .75) + Math.floor(responseBody.length * .75)
  const mime = (item.response.content && item.response.content.mimeType) || ''
  entries.push({
    source: 'chrome-devtools', source_id: fp, sequence: entries.length + 1,
    started_at: item.startedDateTime || new Date().toISOString(), identity_label: $('identity').value.trim(),
    request: { method: item.request.method, url: item.request.url, http_version: item.request.httpVersion || '', headers: headerList(item.request.headers), body: requestBody, mime_type: item.request.postData?.mimeType || '' },
    response: { status: item.response.status || 0, http_version: item.response.httpVersion || '', headers: headerList(item.response.headers), body: responseBody, mime_type: mime, time_ms: Math.round(item.time || 0) }
  })
  render()
})

$('toggle').addEventListener('click', () => {
  if (!capturing && scopes().length === 0) { $('notice').textContent = 'Add at least one target hostname or URL prefix.'; return }
  capturing = !capturing
  $('toggle').textContent = capturing ? 'Stop capture' : 'Start capture'
  $('state').textContent = capturing ? 'Capturing' : 'Stopped'
  $('state').className = capturing ? 'on' : 'off'
  $('scope').disabled = capturing
  $('identity').disabled = capturing
  $('notice').textContent = capturing ? 'Capturing matching traffic. Requests are observed, never modified.' : 'Capture stopped. Export the unique request/response corpus when ready.'
})
$('clear').addEventListener('click', () => { entries.length = 0; fingerprints.clear(); seen = duplicates = bodyBytes = 0; render() })
$('export').addEventListener('click', () => {
  const envelope = { schema: 'reconner-capture/v1', source: 'chrome-devtools', label: $('label').value.trim(), exported_at: new Date().toISOString(), entries }
  const blob = new Blob([JSON.stringify(envelope)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a'); a.href = url; a.download = `reconner-capture-${Date.now()}.json`; a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
})

chrome.storage.local.get(['scope','identity'], saved => { if (saved.scope) $('scope').value = saved.scope; if (saved.identity) $('identity').value = saved.identity })
$('scope').addEventListener('change', () => chrome.storage.local.set({ scope: $('scope').value }))
$('identity').addEventListener('change', () => chrome.storage.local.set({ identity: $('identity').value }))
render()
