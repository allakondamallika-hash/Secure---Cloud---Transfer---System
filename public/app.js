let token = localStorage.getItem("secure_token");
let currentUser = null;

const $ = id => document.getElementById(id);
function api(path, options={}) {
  options.headers = options.headers || {};
  if (token) options.headers.Authorization = `Bearer ${token}`;
  return fetch(path, options).then(async r => {
    const data = await r.json().catch(()=>({}));
    if (!r.ok) throw Object.assign(new Error(data.message || "Request failed"), {data, status:r.status});
    return data;
  });
}

function showAuth(mode) {
  document.querySelectorAll(".tabs button").forEach((b,i)=>b.classList.toggle("active",(mode==="login"&&i===0)||(mode==="register"&&i===1)));
  $("loginForm").classList.toggle("hidden", mode!=="login");
  $("registerForm").classList.toggle("hidden", mode!=="register");
}

async function login(e) {
  e.preventDefault();
  $("loginMsg").textContent = "Authenticating…";
  $("loginMsg").className = "message";
  try {
    const data = await api("/api/auth/login", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({
      email:$("loginEmail").value,password:$("loginPassword").value
    })});
    token = data.token; localStorage.setItem("secure_token",token); boot();
  } catch(err) { $("loginMsg").textContent = err.message; $("loginMsg").className="message error"; }
}

async function register(e) {
  e.preventDefault();
  $("regMsg").textContent = "Creating anonymous identity…";
  try {
    const data = await api("/api/auth/register", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({
      name:$("regName").value,email:$("regEmail").value,password:$("regPassword").value
    })});
    token=data.token; localStorage.setItem("secure_token",token); boot();
  } catch(err) { $("regMsg").textContent=err.message; $("regMsg").className="message error"; }
}

function logout() { localStorage.removeItem("secure_token"); token=null; location.reload(); }

async function boot() {
  if (!token) return;
  try {
    const data = await api("/api/auth/me"); currentUser=data.user;
    $("authView").classList.add("hidden"); $("appView").classList.remove("hidden");
    $("name").textContent=currentUser.name; $("anonId").textContent=currentUser.anonymous_id;
    $("userArea").innerHTML=`<div class="top-user"><small>${currentUser.email}</small><button class="logout" onclick="logout()">Logout</button></div>`;
    loadDashboard();
  } catch { logout(); }
}

async function loadDashboard() {
  const data=await api("/api/dashboard");
  $("total").textContent=data.stats.total||0;
  $("successful").textContent=data.stats.successful||0;
  $("blocked").textContent=data.stats.blocked||0;
  $("bytes").textContent=formatBytes(data.stats.bytes||0);
  renderHistory(data.recent||[]);
}

function formatBytes(n) {
  if(!n)return "0 B"; const u=["B","KB","MB","GB"]; let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++} return n.toFixed(i?1:0)+" "+u[i];
}

async function checkNode() {
  const url=$("nodeUrl").value.trim(); if(!url)return;
  $("nodeStatus").textContent="AI analyzing…";
  try {
    const r=await api("/api/security/check-node",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({nodeUrl:url})});
    lastNode=r; renderStatus();
  } catch(e){$("nodeStatus").textContent=e.message}
}

function fileSelected() {
  const f=$("file").files[0]; $("fileLabel").textContent=f?`${f.name} • ${formatBytes(f.size)}`:"Choose a file";
  hideFileAlert();
  if (f) preCheckFile(f);
}

/* ---------- AI file risk signal ---------- */
let lastFile=null, lastNode=null;

/* One "AI SECURITY STATUS" that combines the file verdict and the destination-node verdict. */
function renderStatus() {
  const el=$("nodeStatus");
  if (lastFile && lastFile.blocked) {
    el.textContent=`UNTRUSTED • score ${lastFile.score}/100 • HIGH risk • file`;
    el.style.color="#c63d51";
  } else if (lastNode) {
    const bad=lastNode.status!=="TRUSTED";
    el.textContent=`${bad?"UNTRUSTED":"TRUSTED"} • score ${lastNode.score}/100 • ${lastNode.riskLevel} risk`;
    el.style.color=bad?"#c63d51":"#138a67";
  } else if (lastFile) {
    el.textContent=`FILE VERIFIED • score ${lastFile.score}/100 • ${lastFile.riskLevel} risk`;
    el.style.color=lastFile.riskLevel==="MEDIUM"?"#a26b00":"#138a67";
  } else {
    el.textContent="Not checked"; el.style.color="";
  }
}

function hideFileAlert() { $("fileAlert").classList.add("hidden"); lastFile=null; renderStatus(); }

function showFileAlert(a) {
  const box=$("fileAlert");
  box.className="file-alert";
  lastFile=a.signal==="CHECKING"?null:a; renderStatus();
  if (a.signal==="CHECKING") {
    box.classList.add("checking");
    $("faTitle").textContent="AI is checking this file…"; $("faScore").textContent=""; $("faReasons").innerHTML="";
    return;
  }
  const high=a.signal==="RED", medium=a.signal==="YELLOW";
  box.classList.add(high?"high":medium?"medium":"ok");
  $("faTitle").textContent=high?"HIGH RISK — transfer stopped":medium?"MEDIUM RISK — review before sending":"LOW RISK — file is secure";
  $("faScore").textContent=`${a.score}/100`;
  $("faReasons").innerHTML=(a.reasons||[]).map(r=>`<li>${escapeHtml(r)}</li>`).join("");
}

function readSlice(blob) {
  return blob.arrayBuffer().then(buf=>{
    const bytes=new Uint8Array(buf); let bin="";
    for(let i=0;i<bytes.length;i+=8192) bin+=String.fromCharCode.apply(null,bytes.subarray(i,i+8192));
    return btoa(bin);
  });
}

async function preCheckFile(f) {
  showFileAlert({signal:"CHECKING"});
  try {
    const head=await readSlice(f.slice(0,4096));
    const tail=await readSlice(f.slice(Math.max(0,f.size-8192)));
    const r=await api("/api/security/check-file",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({name:f.name,size:f.size,head,tail})});
    if ($("file").files[0]===f) showFileAlert(r);
  } catch { hideFileAlert(); }
}

async function transfer(e) {
  e.preventDefault();
  const f=$("file").files[0]; if(!f)return;
  const btn=$("transferBtn"); btn.disabled=true; btn.textContent="🔄 Securing transfer…";
  $("transferMsg").textContent="Running authentication → AI check → encryption → storage…";
  $("transferMsg").className="message";
  animatePipeline();
  const form=new FormData(); form.append("file",f); form.append("nodeUrl",$("nodeUrl").value);
  try {
    const r=await api("/api/transfer",{method:"POST",body:form});
    $("transferMsg").textContent=`✓ ${r.message}`;
    $("transferMsg").className="message success";
    finishPipeline(true);
    loadDashboard();
    $("transferForm").reset(); fileSelected();
    lastNode=null; renderStatus();
  } catch(err) {
    $("transferMsg").textContent=`✕ ${err.message}`;
    $("transferMsg").className="message error";
    if (err.data && err.data.fileAnalysis) { showFileAlert(err.data.fileAnalysis); failPipelineAtScan(); }
    else finishPipeline(false);
    loadDashboard();
  } finally {btn.disabled=false;btn.textContent="🔐 Encrypt & Transfer";}
}

let pipelineTimer=null;
function animatePipeline() {
  clearInterval(pipelineTimer);
  document.querySelectorAll(".step").forEach((s,i)=>{s.classList.remove("done","active","failed","stopped");if(i===0)s.classList.add("active")});
  let i=0; const timer=pipelineTimer=setInterval(()=>{
    const steps=document.querySelectorAll(".step");
    if(i<steps.length){steps[i].classList.remove("active");steps[i].classList.add("done");if(i+1<steps.length)steps[i+1].classList.add("active");i++}
    else clearInterval(timer);
  },260);
}
/* File failed the AI check: steps 1-4 done, step 5 red, encryption/transfer/storage stopped. */
function failPipelineAtScan() {
  clearInterval(pipelineTimer);
  document.querySelectorAll(".step").forEach((s,i)=>{
    s.classList.remove("done","active","failed","stopped");
    if(i<4)s.classList.add("done"); else if(i===4)s.classList.add("failed"); else s.classList.add("stopped");
  });
}
function finishPipeline(success) {
  clearInterval(pipelineTimer);
  document.querySelectorAll(".step").forEach(s=>s.classList.remove("active"));
  document.querySelectorAll(".step").forEach(s=>s.classList.add(success?"done":"active"));
}

function renderHistory(rows) {
  $("history").innerHTML=rows.length?rows.map(r=>`
    <tr>
      <td><b>${escapeHtml(r.original_name)}</b></td>
      <td>${escapeHtml(r.node_url)}</td>
      <td><b>${r.node_score}</b>/100</td>
      <td><span class="risk-${r.risk_level.toLowerCase()}">${r.risk_level}</span></td>
      <td><span class="badge ${r.status==='SUCCESS'?'success':'blocked'}">${r.status}</span></td>
      <td>${new Date(r.created_at+"Z").toLocaleString()}</td>
      <td>${r.status==='SUCCESS'?`<button class="download" onclick="downloadFile(${r.id})">Download</button>`:"—"}</td>
    </tr>`).join(""):`<tr><td colspan="7" style="text-align:center;color:#9aa2b5;padding:30px">No transfers yet. Upload your first secure file.</td></tr>`;
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
async function downloadFile(id) {
  const r=await fetch(`/api/files/${id}/download`,{headers:{Authorization:`Bearer ${token}`}});
  if(!r.ok){alert("Download failed.");return}
  const blob=await r.blob(); const url=URL.createObjectURL(blob); const a=document.createElement("a");
  a.href=url;a.download="secure-file";a.click();URL.revokeObjectURL(url);
}

boot();
