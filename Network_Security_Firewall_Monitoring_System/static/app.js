const form=document.getElementById("trafficForm");
form.addEventListener("submit",async e=>{
  e.preventDefault();
  const result=document.getElementById("result");
  result.classList.remove("hidden");
  result.textContent="Analyzing traffic...";
  try{
    const response=await fetch("/traffic",{method:"POST",body:new FormData(form)});
    const data=await response.json();
    if(!response.ok){result.textContent=data.error||"Invalid request";return;}
    result.innerHTML=`<strong style="color:${data.action==="ALLOW"?"#34d399":"#fb7185"}">${data.action==="ALLOW"?"✓ TRAFFIC ALLOWED":"⊘ TRAFFIC BLOCKED"}</strong><br><small>${data.source} → ${data.destination} : ${data.port}/${data.protocol}</small><br><small>${data.reason}</small>`;
    refresh();
  }catch(err){result.textContent="Could not contact the local firewall application."}
});
async function refresh(){
 try{
  const r=await fetch("/api/state"),d=await r.json();
  for(const k of ["total","allowed","blocked","suspicious"])document.getElementById(k).textContent=d.stats[k];
  document.getElementById("logsBody").innerHTML=d.logs.length?d.logs.map(l=>`<tr><td>${l.time}</td><td class="mono">${l.source}</td><td class="mono">${l.destination}</td><td>${l.port}</td><td>${l.protocol}</td><td><span class="badge ${l.action.toLowerCase()}">${l.action}</span></td><td>${l.reason}</td></tr>`).join(""):`<tr><td colspan="7" class="empty">No traffic recorded.</td></tr>`;
  document.getElementById("alertList").innerHTML=d.alerts.length?d.alerts.map(a=>`<div class="alert"><span class="warning">⚠</span><div><strong>${a.source} → port ${a.port}</strong><small>${a.time} · ${a.protocol} · ${a.action}</small><p>${a.reason}</p></div></div>`).join(""):`<div class="empty">No suspicious activity detected.</div>`;
 }catch(e){}
}
setInterval(refresh,4000);
