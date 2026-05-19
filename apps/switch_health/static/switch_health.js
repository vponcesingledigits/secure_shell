const form = document.getElementById('scanForm');
const statusBox = document.getElementById('status');
const summaryBox = document.getElementById('summary');
const resultsBox = document.getElementById('results');

form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  statusBox.classList.remove('hidden');
  statusBox.textContent = 'Scanning switches. Show tech and cable diagnostics can take longer on large targets.';
  summaryBox.classList.add('hidden');
  resultsBox.innerHTML = '';
  const fd = new FormData(form);
  for (const name of ['show_tech','cable_diagnostics','debug']) {
    if (!fd.has(name)) fd.append(name, 'false');
    else fd.set(name, 'true');
  }
  try {
    const res = await fetch('/apps/switch-health/scan', { method: 'POST', body: fd });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    renderSummary(data.summary);
    renderResults(data.results || []);
    statusBox.textContent = 'Scan complete.';
  } catch (err) {
    statusBox.textContent = 'Scan failed: ' + err.message;
  }
});

function renderSummary(s) {
  summaryBox.classList.remove('hidden');
  summaryBox.innerHTML = metric('Switches', s.switches) + metric('Connected', s.connected) + metric('Critical', s.critical) + metric('Warnings', s.warning) + metric('Info', s.info);
}
function metric(label, value) { return `<div class="metric"><span>${esc(label)}</span><b>${value}</b></div>`; }
function renderResults(results) {
  resultsBox.innerHTML = results.map(sw => {
    const findings = (sw.findings || []).sort((a,b) => sevRank(a.severity)-sevRank(b.severity)).map(renderFinding).join('');
    return `<article class="switch-card">
      <div class="switch-head">
        <div><h2>${esc(sw.hostname || sw.target)}</h2><div class="small">Target: ${esc(sw.target)} · Vendor: ${esc(sw.vendor)} · Connected: ${sw.connected ? 'yes' : 'no'}</div>${sw.error ? `<p class="critical pill">${esc(sw.error)}</p>` : ''}</div>
        <div class="actions"><span class="pill critical">Critical ${sw.critical_count}</span><span class="pill warning">Warning ${sw.warning_count}</span><span class="pill info">Info ${sw.info_count}</span></div>
      </div>
      ${findings}
      <details><summary>Raw command outputs</summary>${renderOutputs(sw.command_outputs || {})}</details>
    </article>`;
  }).join('');
}
function renderFinding(f) {
  return `<div class="finding ${esc(f.severity)}"><h3>${esc(f.title)} <span class="pill ${esc(f.severity)}">${esc(f.severity)}</span></h3><p>${esc(f.category)}${f.port ? ' · Port ' + esc(f.port) : ''}${f.count > 1 ? ' · Count ' + f.count : ''}</p><p>${esc(f.detail)}</p>${f.evidence ? `<pre class="evidence">${esc(f.evidence)}</pre>` : ''}</div>`;
}
function renderOutputs(outputs) {
  return Object.entries(outputs).map(([cmd,out]) => `<details><summary>${esc(cmd)}</summary><pre class="evidence">${esc(out)}</pre></details>`).join('');
}
function sevRank(s){ return s === 'critical' ? 0 : s === 'warning' ? 1 : 2; }
function esc(s){ return String(s ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
