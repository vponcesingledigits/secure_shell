const form = document.getElementById('traceForm');
const statusBox = document.getElementById('status');
const resultBox = document.getElementById('result');

form.addEventListener('submit', async ev => {
  ev.preventDefault();
  statusBox.classList.remove('hidden');
  statusBox.textContent = 'Starting trace...';
  resultBox.innerHTML = '<section class="panel command-panel"><h2>Command / Progress Output</h2><pre id="liveLog" class="command-log">Starting trace...\n</pre></section>';
  const fd = new FormData(form);
  if (!fd.has('debug')) fd.append('debug', 'false');
  try {
    const start = await fetch('/apps/mac-trace/trace/start', {method:'POST', body:fd});
    if (!start.ok) throw new Error(await start.text());
    const job = await start.json();
    await pollJob(job.job_id);
  } catch (err) {
    statusBox.textContent = 'Trace failed: ' + err.message;
  }
});

async function pollJob(jobId){
  let done = false;
  while(!done){
    const res = await fetch('/apps/mac-trace/trace/status/' + encodeURIComponent(jobId));
    if(!res.ok) throw new Error(await res.text());
    const data = await res.json();
    statusBox.textContent = data.status === 'running' ? 'Trace running...' : 'Trace ' + data.status;
    updateLiveLog(data.events || []);
    if(data.status === 'complete'){
      done = true;
      statusBox.textContent = 'Trace complete.';
      render(data.result || {});
    } else if(data.status === 'failed'){
      done = true;
      statusBox.textContent = 'Trace failed: ' + (data.error || 'unknown error');
    } else {
      await new Promise(r => setTimeout(r, 900));
    }
  }
}

function updateLiveLog(events){
  const live = document.getElementById('liveLog');
  if(!live) return;
  if(!events.length){ live.textContent = 'Waiting for first command...\n'; return; }
  live.textContent = events.map(e => {
    const prefix = [e.time, e.host, e.level].filter(Boolean).join(' | ');
    const cmd = e.command ? '\n$ ' + e.command : '';
    return prefix + ' - ' + (e.message || '') + cmd;
  }).join('\n');
  live.scrollTop = live.scrollHeight;
}

function render(d){
  const f = d.final || {};
  resultBox.innerHTML = `
    <section class="panel callout">
      <h2>${esc(d.summary)}</h2>
      <div class="badges"><span class="badge ${esc(d.status)}">Status: ${esc(d.status)}</span><span class="badge ${esc(d.confidence)}">Confidence: ${esc(d.confidence)}</span><span class="badge ${esc(d.origin)}">Origin: ${esc(d.origin)}</span></div>
      <div class="cards">
        <div class="card"><span>MAC</span><strong>${esc(d.input?.mac)}</strong></div>
        <div class="card"><span>AP / Device</span><strong>${esc(f.device || 'Unknown')}</strong></div>
        <div class="card"><span>Switch / Port</span><strong>${esc((f.switch || '') + (f.port ? ' ' + f.port : ''))}</strong></div>
        <div class="card"><span>VLAN</span><strong>${esc(f.vlan || 'unknown')}</strong></div>
        <div class="card"><span>AP IP</span><strong>${esc(f.ap_ip || 'unknown')}</strong></div>
        <div class="card"><span>AP MAC</span><strong>${esc(f.ap_mac || 'unknown')}</strong></div>
      </div>
    </section>
    <section class="panel"><h2>Recursive Path</h2><div class="path">${renderPath(d.path || [])}</div></section>
    <section class="panel"><h2>Port Health Along Path</h2>${renderHealth(d.port_health || [])}</section>
    <section class="panel"><h2>Recommended Next Action</h2>${nextAction(d)}</section>
    <section class="panel command-panel"><h2>Command / Progress Output</h2>${renderEvents(d.events || [])}</section>
    <section class="panel"><details><summary>Details / AI Handoff JSON</summary><pre>${esc(JSON.stringify(d, null, 2))}</pre></details></section>`;
}

function renderEvents(events){
  if(!events.length) return '<p>No command events captured.</p>';
  return `<pre class="command-log">${events.map(e => {
    const prefix = [e.time, e.host, e.level].filter(Boolean).join(' | ');
    const cmd = e.command ? '\n$ ' + e.command : '';
    return esc(prefix + ' - ' + (e.message || '') + cmd);
  }).join('\n')}</pre>`;
}

function renderPath(path){
  if(!path.length) return '<p>No path data.</p>';
  return path.map((h,i)=>`<div class="hop"><strong>${esc(h.hostname || h.switch)}</strong><span>${esc(h.switch || '')}</span><br><span>${esc(h.port || '')}${h.vlan ? ' · VLAN '+esc(h.vlan):''}</span><br><span class="badge ${esc(h.neighbor_type || h.result || 'ok')}">${esc(h.neighbor_type || h.result)}</span>${h.neighbor?`<p>${esc(h.neighbor.neighbor_name || '')}${h.neighbor_ip?' · '+esc(h.neighbor_ip):''}${h.neighbor.neighbor_mac?' · MAC '+esc(h.neighbor.neighbor_mac):''}</p>`:''}</div>${i<path.length-1?'<div class="arrow">→</div>':''}`).join('');
}
function renderHealth(rows){
  if(!rows.length) return '<p>No port health rows.</p>';
  return `<table><thead><tr><th>Switch</th><th>Port</th><th>Role</th><th>Status</th><th>Speed/Duplex</th><th>PoE</th><th>Notes</th><th>Counters</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.switch)}<br><small>${esc(r.ip||'')}</small></td><td>${esc(r.port)}</td><td>${esc(r.role)}</td><td><span class="badge ${esc(r.severity)}">${esc(r.status)}</span></td><td>${esc(r.speed_duplex)}</td><td>${esc(r.poe)}</td><td><ul class="notes">${(r.notes||[]).map(n=>`<li>${esc(n)}</li>`).join('') || '<li>No immediate indicators</li>'}</ul></td><td>${renderCounters(r.counters || {})}</td></tr>`).join('')}</tbody></table>`;
}
function renderCounters(counters){
  const entries = Object.entries(counters || {}).filter(([k,v]) => Number(v) > 0);
  if(!entries.length) return '<small>none detected</small>';
  return '<ul class="notes">' + entries.map(([k,v]) => `<li>${esc(k)}: ${esc(v)}</li>`).join('') + '</ul>';
}
function nextAction(d){
  const s = d.status;
  if(s === 'found' && d.origin === 'ap') return '<ul><li>Use the AP name/IP to continue wireless-side client troubleshooting.</li><li>Review port-health notes for drops, CRC/FCS errors, PoE faults, and recent link events before escalating wireless-side.</li></ul>';
  if(s === 'likely_unmanaged_switch') return '<ul><li>Dispatch or investigate the downlink port for an unmanaged switch/non-LLDP bridge.</li><li>Check cabling and edge device count on the learned port.</li></ul>';
  if(s === 'needs_manual_next_hop') return '<ul><li>LLDP found a next switch but no management IP. Use the neighbor name/port to continue manually or add DNS/LLDP management address visibility.</li></ul>';
  if(s === 'connect_failed') return '<ul><li>Verify switch-to-switch SSH reachability and credentials for the next hop.</li></ul>';
  return '<ul><li>Review the recursive path and port health table before escalating.</li></ul>';
}
function esc(s){return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
