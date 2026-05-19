function showTab(name){
  document.querySelectorAll('.tab-panel').forEach(el=>el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el=>el.classList.remove('active'));
  document.getElementById('tab-'+name)?.classList.add('active');
  document.querySelector(`[data-tab="${name}"]`)?.classList.add('active');
}
function copyPreview(){
  const text=document.getElementById('preview-text')?.innerText || '';
  navigator.clipboard.writeText(text);
}
function setBrandModels(map){
  window.__deploymentModels = map;
}
function syncDeploymentModels(){
  const brand=document.getElementById('brand_profile')?.value;
  const dep=document.getElementById('deployment_model');
  if(!brand||!dep||!window.__deploymentModels) return;
  const current=dep.value;
  dep.innerHTML='';
  (window.__deploymentModels[brand]||['Standard']).forEach(v=>{
    const o=document.createElement('option');
    o.value=v;o.textContent=v;
    if(v===current) o.selected=true;
    dep.appendChild(o);
  });
}
