let currentJob = {switches: [], job_id: 'none'};
let statusTimer = null;
let lastStatusLine = '';

const form = document.getElementById('scanForm');
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  document.getElementById('summary').textContent = 'Scanning...';
  setStatus({state:'running', current_command:'Starting', last_result:'Scan request submitted.'});
  startStatusPolling();
  const fd = new FormData(form);
  for (const box of ['subnet_only','include_macs']) {
    if (!fd.has(box)) fd.set(box, 'false'); else fd.set(box, 'true');
  }
  try {
    const res = await fetch('/apps/port-map/scan', {method: 'POST', body: fd});
    currentJob = await res.json();
    render();
    await pollStatusOnce();
  } finally {
    stopStatusPollingSoon();
  }
});

for (const id of ['showAps','showEdges','showEmpty']) document.getElementById(id).addEventListener('change', render);

document.getElementById('jsonImport').addEventListener('change', async (e) => {
  const file = e.target.files[0]; if (!file) return;
  try {
    currentJob = JSON.parse(await file.text());
  } catch (err) {
    alert('That file is not valid JSON.');
    return;
  }
  await fetch('/apps/port-map/load-json', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(currentJob)});
  await pollStatusOnce();
  render();
});

document.getElementById('previewRename').addEventListener('click', async () => {
  const selected = [];
  for (const sw of currentJob.switches || []) for (const p of sw.ports || []) {
    if (p.rename_suggestion) selected.push({switch_ip: sw.ip, vendor: sw.vendor, port: p.port, name: p.rename_suggestion});
  }
  const res = await fetch('/apps/port-map/rename-preview', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({selected})});
  const data = await res.json();
  document.getElementById('renameOutput').textContent = data.plan.map(x => `${x.switch_ip} ${x.port} -> ${x.name}\n${x.commands.map(c=>'  '+c).join('\n')}`).join('\n\n') || 'No confident LLDP rename suggestions.';
});

function render(){
  const showAps = document.getElementById('showAps').checked;
  const showEdges = document.getElementById('showEdges').checked;
  const showEmpty = document.getElementById('showEmpty').checked;
  const tree = document.getElementById('tree'); tree.innerHTML = '';
  let total = 0, infra = 0, hidden = 0;
  for (const sw of currentJob.switches || []) {
    const details = document.createElement('details'); details.className = 'switch'; details.open = true;
    const summary = document.createElement('summary');
    summary.textContent = `${sw.hostname || sw.ip} (${sw.vendor || 'unknown'})`;
    details.appendChild(summary);
    const rows = document.createElement('div'); rows.className = 'portRows';
    const ports = [...(sw.ports || [])].sort((a,b)=>rank(a)-rank(b)||natural(a.port,b.port));
    for (const p of ports) {
      total++;
      if (p.category === 'infrastructure') infra++;
      if ((p.category === 'ap' && !showAps) || (['edge','endpoint'].includes(p.category) && !showEdges) || (p.category === 'empty' && !showEmpty)) { hidden++; continue; }
      const row = document.createElement('div'); row.className = `port ${p.category}`;
      row.innerHTML = `<div class="badge">${escapeHtml(p.port)}</div><div>${healthBadge(p)}</div><div class="badge">${escapeHtml(p.category)}</div><div><div class="device">${escapeHtml(deviceName(p))}</div><div class="muted">${escapeHtml(p.description || '')}</div></div><div><div>${escapeHtml(p.speed || '')} ${escapeHtml(p.duplex || '')}</div><div class="muted">MACs: ${p.mac_count || 0}</div></div>`;
      rows.appendChild(row);
    }
    details.appendChild(rows); tree.appendChild(details);
  }
  document.getElementById('summary').textContent = `${currentJob.switches?.length || 0} switches, ${total} actual ports, ${infra} infrastructure links. ${hidden} hidden by current filters.`;
}
function rank(p){return p.category==='infrastructure'?0:p.category==='ap'?1:['edge','endpoint'].includes(p.category)?2:3}
function natural(a,b){return String(a).localeCompare(String(b), undefined, {numeric:true, sensitivity:'base'})}
function deviceName(p){return p.confident_device || (p.lldp && (p.lldp.display_name || p.lldp.management_ip)) || ''}
function healthBadge(p){
  const bad = String(p.duplex||'').toLowerCase()==='half' || /10|100/.test(String(p.speed||''));
  const up = /up|connected/i.test(p.status||'');
  const cls = bad ? 'red' : up ? 'green' : 'yellow';
  const text = bad ? 'Mismatch/Slow' : up ? 'Up' : (p.status || 'Unknown');
  return `<span class="badge ${cls}">${escapeHtml(text)}</span>`;
}
function escapeHtml(s){return String(s ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
render();


async function pollStatusOnce(){
  try {
    const res = await fetch('/apps/port-map/status', {cache:'no-store'});
    if (!res.ok) return;
    const data = await res.json();
    setStatus(data);
  } catch (_err) {}
}
function startStatusPolling(){
  if (statusTimer) clearInterval(statusTimer);
  pollStatusOnce();
  statusTimer = setInterval(pollStatusOnce, 1000);
}
function stopStatusPollingSoon(){
  setTimeout(() => {
    pollStatusOnce();
    if (statusTimer) clearInterval(statusTimer);
    statusTimer = null;
  }, 1500);
}
function setStatus(data){
  const state = data.state || 'idle';
  const pulse = document.getElementById('statusPulse');
  if (pulse) pulse.className = 'pulse ' + (state === 'running' ? 'running' : state === 'complete' ? 'complete' : 'idle');
  setText('statusDevice', data.current_device || '—');
  setText('statusCommand', data.current_command || 'Idle');
  setText('statusScanned', data.devices_scanned ?? 0);
  setText('statusNeighbors', data.neighbors_found ?? 0);
  setText('statusQueue', data.queue_remaining ?? 0);
  setText('statusElapsed', `${data.elapsed_seconds ?? 0}s`);
  const line = data.last_result || 'No scan running.';
  const miniLog = document.getElementById('statusLog');
  if (miniLog && line !== lastStatusLine) {
    const stamp = new Date().toLocaleTimeString();
    miniLog.textContent = `[${stamp}] ${line}\n` + miniLog.textContent;
    lastStatusLine = line;
  }
}
function setText(id, value){
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}
pollStatusOnce();
