// in dev vite proxies /api, in prod set VITE_API_URL to the deployed backend
const BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '')

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`${BASE}/api${path}`, options)
  } catch {
    throw new Error('Could not reach the API. Is the server running?')
  }
  if (res.status === 204) return null
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`)
  return body
}

export const api = {
  listUploads: () => request('/uploads'),
  getUpload: (id) => request(`/uploads/${id}`),
  getIncident: (id, ref) => request(`/uploads/${id}/incidents/${ref}`),
  deleteUpload: (id) => request(`/uploads/${id}`, { method: 'DELETE' }),
  runSample: (name) => request(`/uploads/sample${name ? `?name=${encodeURIComponent(name)}` : ''}`, { method: 'POST' }),
  sampleUrl: (name) => `${BASE}/api/samples/${encodeURIComponent(name)}`,
  annotated: (id) => request(`/uploads/${id}/annotated`),
  lines: (id, file, from, to) => request(`/uploads/${id}/lines?${new URLSearchParams({ file, from, to })}`),
  events: (id, params) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== '' && v != null))
    return request(`/uploads/${id}/events?${qs}`)
  },
  upload: (files, formats) => {
    const fd = new FormData()
    files.forEach((f) => fd.append('files', f))
    fd.append('formats', formats.join(','))
    return request('/uploads', { method: 'POST', body: fd })
  },
}
