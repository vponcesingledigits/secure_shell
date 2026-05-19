let project = window.INITIAL_PROJECT || {};
let manual = loadManual();

const schemas = {
  isp: {key:'isp_circuits', title:'ISP Circuit', prefix:'isp', fields:[
    ['label','Label / Circuit Role'],['mrc_number','MRC Number'],['circuit_id','Circuit ID'],['lec_circuit_id','LEC Circuit ID'],['bandwidth_up','Bandwidth Up'],['bandwidth_down','Bandwidth Down'],['circuit_provider','Circuit Provider'],['last_mile','Last Mile'],['support_contact_number','Support Contact Number'],['support_contact_email','Support Contact Email'],['support_contact_website','Support Contact Website'],['connected_device','Connected Device'],['connected_interface','Connected Interface'],['notes','Notes','textarea']
  ]},
  firewall: {key:'manual_firewalls', title:'Firewall', prefix:'fw', fields:[
    ['firewall_type','Firewall Type','select',['WatchGuard','Fortinet','pfSense','Juniper','Custom']],['custom_type','Custom Type'],['model','Model'],['hostname','Hostname'],['wan1_ip','WAN1 IP'],['wan1_interface','WAN1 Firewall Interface','text','eth0'],['vlan_interface','VLAN / LAN Firewall Interface','text','eth1'],['notes','Notes','textarea']
  ]},
  gateway: {key:'manual_gateways', title:'Gateway', prefix:'gw', fields:[
    ['gateway_type','Gateway Type','select',['Nomadix','MikroTik','Meraki','Custom']],['custom_type','Custom Type'],['model','Model'],['hostname','Hostname'],['wan1_ip','WAN1 IP'],['wan1_interface','WAN1 Interface'],['lan1_interface','LAN1 Interface'],['notes','Notes','textarea']
  ]},
  esxi: {key:'manual_esxi_hosts', title:'ESXi Host', prefix:'esxi', fields:[
    ['hardware_platform','Hardware Platform'],['hostname','Hostname'],['management_ip','Management IP'],['vmnic0','VMNIC0'],['vmnic0_switch','VMNIC0 Connected Switch'],['vmnic0_port','VMNIC0 Connected Port'],['vmnic1','VMNIC1'],['vmnic1_switch','VMNIC1 Connected Switch'],['vmnic1_port','VMNIC1 Connected Port'],['idrac_ip','iDRAC / iLO / OOB IP'],['idrac_switch','OOB Connected Switch'],['idrac_port','OOB Connected Port'],['notes','Notes','textarea']
  ]},
  pga: {key:'manual_pga_interfaces', title:'PGA VM', prefix:'pga', fields:[
    ['pga_version','PGA Version','select',['CLP','BAP']],['esxi_host','ESXi Host'],['pga_vm_name','PGA VM Name'],['pga_ip','PGA IP'],['pga_mask','PGA Mask'],['pga_gateway','PGA Gateway'],['connection_type','Connection Type','select',['Serial','IP']],['pms_type','PMS Type','select',['Marriott FSPMS','Marriott Fossee','Galaxy','Opera','Custom']],['custom_pms_type','Custom PMS Type'],['serial_port','Serial Port'],['baud_rate','Baud Rate','text','9800'],['data_bits','Data Bits','text','7'],['parity','Parity','select',['Odd','None','Even']],['stop_bits','Stop Bits','text','2'],['pms_ip','PMS IP'],['pms_port','PMS Port'],['router_address','Router Address'],['local_address','Local Address'],['local_subnet_mask','Local Subnet Mask'],['vlan_id','VLAN ID'],['vlan_name','VLAN Name'],['network_subnet','Network / Subnet'],['port_group','Port Group'],['vswitch','vSwitch'],['notes','Notes','textarea']
  ]},
  rpm: {key:'manual_rpm_vms', title:'RPM VM', prefix:'rpm', fields:[
    ['rpm_variant','RPM Variant','select',['CLP','BAP','PAN']],['esxi_host','ESXi Host'],['rpm_vm_name','RPM VM Name'],['rpm_ip','RPM IP','text','192.168.223.251'],['rpm_mask','RPM Subnet Mask','text','255.255.255.128'],['rpm_cidr','RPM CIDR','text','25'],['rpm_gateway','RPM Gateway','text','192.168.223.129'],['interface','Interface','text','single interface'],['vlan_id','VLAN ID'],['vlan_name','VLAN Name'],['network_subnet','Network / Subnet','text','192.168.223.128/25'],['port_group','Port Group'],['vswitch','vSwitch'],['notes','Notes','textarea']
  ]},
  vlan: {key:'vlans', title:'VLAN', prefix:'vlan', fields:[
    ['vlan_id','VLAN ID'],['vlan_name','VLAN Name'],['purpose','Purpose / Zone'],['subnet','Subnet'],['gateway_ip','Gateway IP'],['dhcp_source','DHCP Source'],['dns','DNS'],['brand_required','Brand Required'],['notes','Notes','textarea']
  ]},
  link: {key:'manual_links', title:'Manual Link', prefix:'link', fields:[
    ['from_device','From Device'],['from_interface','From Interface'],['to_device','To Device'],['to_interface','To Interface'],['link_type','Link Type','select',['WAN','LAN','Trunk','Access','HA','Management','Serial','Other']],['vlan_network','VLAN / Network'],['notes','Notes','textarea']
  ]}
};

const checklistItems = [
  'site_information_completed','isp_circuits_documented','firewall_documented','gateway_documented','esxi_documented','pga_documented_if_applicable','rpm_documented_if_applicable','vlan_summary_completed','mdf_core_switch_identified','idf_switches_identified','switch_uplinks_documented','unknown_lldp_devices_reviewed','port_sheet_exported','asbuilt_pdf_generated','salesforce_preview_generated','zabbix_preview_generated'
];

function esc(v){return String(v ?? '').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
function titleize(s){return String(s||'').replace(/_/g,' ').replace(/\b\w/g,m=>m.toUpperCase());}
function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.style.display='block';setTimeout(()=>t.style.display='none',2600);}
function loadManual(){try{return JSON.parse(localStorage.getItem('sdTopologyManual')||'{}')}catch(e){return {}}}
function saveManualLocal(){manual = collectManual(); localStorage.setItem('sdTopologyManual', JSON.stringify(manual));}

function renderProject(){
  const sum = project.summary || {};
  ['Devices','Switches','Links','Ports','Raw'].forEach(k=>{const el=document.getElementById('sum'+k); if(el) el.textContent = sum[k.toLowerCase()==='raw'?'raw_neighbors':k.toLowerCase()] || 0;});
  renderDevices(); renderTree(); renderPorts();
}
function renderDevices(){
  const wrap=document.getElementById('deviceList');
  const devices=project.devices||[];
  if(!devices.length){wrap.innerHTML='<div class="empty">No devices discovered yet.</div>';return;}
  wrap.innerHTML=devices.map(d=>`<div class="switch-pill"><strong>${esc(d.name||d.management_ip)}</strong><span>${esc(d.role||'unknown')} · ${esc(d.management_ip||'IP unknown')}</span>${d.mstp_priority?`<br><span>MSTP ${esc(d.mstp_priority)}</span>`:''}</div>`).join('');
}
function renderTree(){
  const wrap=document.getElementById('treeWrap');
  const tree=project.topology_tree||[];
  if(!tree.length){wrap.innerHTML='<div class="empty">Run a topology scan to build the hierarchy.</div>';return;}
  wrap.innerHTML=`<ul class="topology-tree">${tree.map(nodeHtml).join('')}</ul>`;
}
function nodeHtml(n){
  const ports=(n.local_port||n.remote_port)?`<em class="port-line">${esc(n.local_port||'—')} ⇄ ${esc(n.remote_port||'—')}</em>`:'';
  const kids=(n.children||[]).map(nodeHtml).join('');
  return `<li><div class="node-card">${ports}<strong>${esc(n.name)}</strong><span>${esc(n.ip||'IP unknown')}</span></div>${kids?`<ul>${kids}</ul>`:''}</li>`;
}
function renderPorts(){
  const wrap=document.getElementById('portsWrap');
  const rows=project.ports||[];
  if(!rows.length){wrap.innerHTML='<div class="empty">No port inventory yet.</div>';return;}
  const by={}; rows.forEach(r=>{const sw=r.switch_name||'Unknown Switch'; (by[sw]=by[sw]||[]).push(r);});
  wrap.innerHTML=Object.entries(by).sort().map(([sw,ports])=>`<details><summary>${esc(sw)} <span class="muted small">${ports.length} ports</span></summary><div class="details-body"><table><thead><tr><th>Switch Name</th><th>Local Port ID</th><th>Local Port Name</th><th>Patch Panel Port</th><th>Remote Hostname</th><th>Remote IP</th><th>Suggested Port Name</th></tr></thead><tbody>${ports.slice(0,80).map(p=>`<tr><td>${esc(sw)}</td><td>${esc(p.local_port_id)}</td><td>${esc(p.local_port_name)}</td><td></td><td>${esc(p.remote_hostname)}</td><td>${esc(p.remote_ip)}</td><td>${esc(p.suggested_port_name)}</td></tr>`).join('')}${ports.length>80?`<tr><td colspan="7" class="muted">${ports.length-80} more rows in export...</td></tr>`:''}</tbody></table></div></details>`).join('');
}

function renderManual(){
  renderSite();
  Object.keys(schemas).forEach(type=>renderCards(type));
  renderChecklist();
}
function renderSite(){
  document.querySelectorAll('[data-site]').forEach(el=>{el.value=(manual.site||{})[el.dataset.site]||'';});
}
function renderCards(type){
  const schema=schemas[type]; const wrap=document.getElementById('cards-'+type); if(!wrap)return;
  const arr=manual[schema.key]||[];
  if(!arr.length){wrap.innerHTML='<div class="empty">No '+esc(schema.title)+' cards yet.</div>';return;}
  wrap.innerHTML=arr.map((card,i)=>cardHtml(type,card,i)).join('');
  wrap.querySelectorAll('input,select,textarea').forEach(el=>el.addEventListener('input',()=>{updateCardFromDom(type, el.closest('.manual-card'));}));
  wrap.querySelectorAll('[data-remove]').forEach(btn=>btn.addEventListener('click',()=>{removeCard(type, Number(btn.dataset.remove));}));
  wrap.querySelectorAll('[data-dup]').forEach(btn=>btn.addEventListener('click',()=>{duplicateCard(type, Number(btn.dataset.dup));}));
  if(type==='pga') wrap.querySelectorAll('[data-field="pms_type"]').forEach(el=>el.addEventListener('change',()=>applyPmsDefaults(el.closest('.manual-card'))));
}
function cardHtml(type,card,i){
  const schema=schemas[type]; const title=card.label||card.hostname||card.pga_vm_name||card.rpm_vm_name||card.local_id||`${schema.title} ${i+1}`;
  return `<div class="manual-card" data-type="${type}" data-index="${i}"><div class="manual-card-head"><strong>${esc(title)}</strong><div><button class="btn ghost small" type="button" data-dup="${i}">Duplicate</button> <button class="btn danger small" type="button" data-remove="${i}">Remove</button></div></div><div class="manual-card-body"><div class="grid three-col">${schema.fields.map(f=>fieldHtml(f,card)).join('')}</div></div></div>`;
}
function fieldHtml(f,card){
  const [key,label,kind,extra]=f; const val=card[key] ?? (kind==='text' && extra ? extra : '');
  if(kind==='textarea') return `<div style="grid-column:1/-1"><label>${esc(label)}</label><textarea data-field="${esc(key)}">${esc(val)}</textarea></div>`;
  if(kind==='select') return `<div><label>${esc(label)}</label><select data-field="${esc(key)}"><option></option>${(extra||[]).map(o=>`<option ${String(val)===o?'selected':''}>${esc(o)}</option>`).join('')}</select></div>`;
  return `<div><label>${esc(label)}</label><input data-field="${esc(key)}" value="${esc(val)}"></div>`;
}
function addCard(type){
  const s=schemas[type]; manual[s.key]=manual[s.key]||[];
  const idx=manual[s.key].length+1; const card={local_id:`${s.prefix}-${String(idx).padStart(3,'0')}`};
  s.fields.forEach(f=>{if(f[2]==='text'&&f[3]) card[f[0]]=f[3];});
  if(type==='pga'){card.connection_type='Serial';card.pms_type='Marriott FSPMS';card.baud_rate='9800';card.data_bits='7';card.parity='Odd';card.stop_bits='2';}
  if(type==='rpm'){card.rpm_variant='CLP';}
  manual[s.key].push(card); saveManualLocal(); renderCards(type);
}
function updateCardFromDom(type, cardEl){
  if(!cardEl)return; const schema=schemas[type]; const idx=Number(cardEl.dataset.index); const card=manual[schema.key][idx];
  cardEl.querySelectorAll('[data-field]').forEach(el=>card[el.dataset.field]=el.value);
  saveManualLocal();
}
function removeCard(type,i){const s=schemas[type]; manual[s.key].splice(i,1); saveManualLocal(); renderCards(type);}
function duplicateCard(type,i){const s=schemas[type]; const copy=JSON.parse(JSON.stringify(manual[s.key][i]||{})); copy.local_id=`${s.prefix}-${String((manual[s.key]||[]).length+1).padStart(3,'0')}`; manual[s.key].push(copy); saveManualLocal(); renderCards(type);}
function applyPmsDefaults(cardEl){
  const typeSel=cardEl.querySelector('[data-field="pms_type"]'); const type=typeSel.value;
  const defaults={"Marriott FSPMS":['9800','7','Odd','2'],"Marriott Fossee":['9800','8','None','1'],"Galaxy":['9800','8','None','1'],"Opera":['9800','8','None','1']};
  const d=defaults[type]; if(!d)return;
  [['baud_rate',d[0]],['data_bits',d[1]],['parity',d[2]],['stop_bits',d[3]]].forEach(([k,v])=>{const el=cardEl.querySelector(`[data-field="${k}"]`); if(el) el.value=v;});
  updateCardFromDom('pga',cardEl);
}
function renderChecklist(){
  const wrap=document.getElementById('checklistWrap'); const data=manual.documentation_checklist||{};
  wrap.innerHTML=checklistItems.map(k=>`<label class="check"><input type="checkbox" data-check="${k}" ${data[k]?'checked':''}> ${titleize(k)}</label>`).join('');
  wrap.querySelectorAll('[data-check]').forEach(el=>el.addEventListener('change',()=>{manual.documentation_checklist=manual.documentation_checklist||{}; manual.documentation_checklist[el.dataset.check]=el.checked; saveManualLocal();}));
}
function collectManual(){
  const out={...manual, site:{}};
  document.querySelectorAll('[data-site]').forEach(el=>{out.site[el.dataset.site]=el.value;});
  Object.keys(schemas).forEach(type=>{
    const s=schemas[type]; const cards=[];
    document.querySelectorAll(`.manual-card[data-type="${type}"]`).forEach(cardEl=>{
      const idx=Number(cardEl.dataset.index); const existing=(manual[s.key]||[])[idx]||{}; const card={...existing};
      cardEl.querySelectorAll('[data-field]').forEach(el=>card[el.dataset.field]=el.value);
      cards.push(card);
    });
    out[s.key]=cards;
  });
  out.documentation_checklist={};
  document.querySelectorAll('[data-check]').forEach(el=>out.documentation_checklist[el.dataset.check]=el.checked);
  return out;
}
async function saveManualServer(){
  saveManualLocal();
  const res=await fetch('/apps/topology/project/manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(manual)});
  const data=await res.json(); if(data.ok){project=data.project; renderProject(); toast('Manual cards saved.');}
}
async function exportPost(url, filename){
  saveManualLocal();
  const res=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(manual)});
  if(!res.ok){toast('Export failed.');return;}
  const blob=await res.blob();
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=filename; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(a.href),1500);
}

// Events
renderProject(); renderManual();
document.getElementById('tabs').addEventListener('click',e=>{const b=e.target.closest('button[data-tab]'); if(!b)return; document.querySelectorAll('#tabs button').forEach(x=>x.classList.remove('active')); b.classList.add('active'); document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active')); document.getElementById('tab-'+b.dataset.tab).classList.add('active');});
document.querySelectorAll('[data-add]').forEach(btn=>btn.addEventListener('click',()=>addCard(btn.dataset.add)));
document.querySelectorAll('[data-site]').forEach(el=>el.addEventListener('input',saveManualLocal));
document.getElementById('saveManualBtn').addEventListener('click',saveManualServer);
document.querySelectorAll('[data-export]').forEach(btn=>btn.addEventListener('click',()=>exportPost(btn.dataset.export, btn.dataset.filename)));
document.getElementById('clearLog').addEventListener('click',()=>document.getElementById('debugLog').textContent='Waiting for scan activity...');

document.getElementById('scanForm').addEventListener('submit',async ev=>{
  ev.preventDefault(); saveManualLocal();
  const btn=document.getElementById('scanBtn'); const log=document.getElementById('debugLog'); const status=document.getElementById('scanStatus');
  btn.disabled=true; btn.textContent='Scanning...'; status.textContent='Starting...'; log.textContent='Submitting topology scan...';
  try{
    const fd=new FormData(ev.target);
    if(!fd.has('include_aps')) fd.append('include_aps','false');
    if(!fd.has('include_all_devices')) fd.append('include_all_devices','false');
    const res=await fetch('/apps/topology/scan/start',{method:'POST',body:fd}); const data=await res.json();
    if(!data.ok) throw new Error(data.error||'Unable to start scan');
    poll(data.job_id);
  }catch(err){status.textContent=err.message; log.textContent='ERROR | '+err.message; btn.disabled=false; btn.textContent='Build Topology';}
});
async function poll(jobId){
  const btn=document.getElementById('scanBtn'); const log=document.getElementById('debugLog'); const status=document.getElementById('scanStatus');
  try{
    const res=await fetch('/apps/topology/scan/status/'+jobId,{cache:'no-store'}); const data=await res.json();
    if(!data.ok) throw new Error(data.error||'Status failed');
    status.textContent=data.state; log.textContent=(data.logs||[]).join('\n')||'Waiting for scan activity...'; log.scrollTop=log.scrollHeight;
    if(data.data){project=data.data; renderProject();}
    if(data.state==='complete'||data.state==='error'){
      btn.disabled=false; btn.textContent='Build Topology'; if(data.state==='complete') saveManualServer(); if(data.state==='error') status.textContent='Error: '+(data.error||'scan failed'); return;
    }
    setTimeout(()=>poll(jobId),1200);
  }catch(err){status.textContent=err.message; btn.disabled=false; btn.textContent='Build Topology';}
}
