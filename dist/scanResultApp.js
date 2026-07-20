// Self-contained MCP App (UI resource) for the Surface scan verdict.
//
// This is a single, dependency-free HTML document served as a `ui://` resource
// (see registerResource in index.ts). An MCP-Apps-capable host renders it in a
// sandboxed iframe; the host pushes the scan tool's result to it via the
// `ui/notifications/tool-result` postMessage notification, and the card renders
// the verdict plus a proceed/block gate. Hosts WITHOUT app support ignore the
// `_meta.ui` link and simply show the tool's normal text result — so wiring this
// up is purely additive and never changes existing behavior.
//
// The client script implements the minimal MCP Apps postMessage handshake by
// hand (no bundler / no @modelcontextprotocol/ext-apps dependency) so the whole
// app ships as one string. It is intentionally defensive about the scan-result
// shape because the tools return pretty-printed JSON whose exact field names
// vary (score / threatLevel / engines / iocs, snake_case or camelCase).
export const SCAN_RESULT_APP_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Surface Scan Result</title>
<style>
  :root {
    --bg:#ffffff; --fg:#1a1a1a; --muted:#6b7280; --card:#f7f7f8; --border:#e5e7eb;
    --safe:#16a34a; --warn:#d97706; --danger:#dc2626;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0f1115; --fg:#e6e6e6; --muted:#9aa0a6; --card:#181b20; --border:#2a2e35; }
  }
  * { box-sizing:border-box; }
  html,body { margin:0; }
  body { font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; color:var(--fg); background:var(--bg); }
  .wrap { padding:16px; }
  .head { display:flex; align-items:center; gap:12px; }
  .verdict { font-size:18px; font-weight:650; }
  .score-badge { margin-left:auto; font-weight:700; padding:6px 12px; border-radius:999px; color:#fff; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-top:14px; }
  .tile { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:10px 12px; }
  .tile .k { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.04em; }
  .tile .v { font-weight:600; margin-top:3px; word-break:break-all; }
  .section { margin-top:16px; }
  .section h3 { font-size:12px; text-transform:uppercase; color:var(--muted); margin:0 0 8px; letter-spacing:.04em; }
  ul.list { margin:0; padding-left:18px; }
  ul.list li { margin:2px 0; word-break:break-word; }
  .gate { display:flex; gap:10px; margin-top:18px; flex-wrap:wrap; }
  button { font:inherit; font-weight:600; padding:10px 16px; border-radius:9px; border:1px solid var(--border); cursor:pointer; background:var(--card); color:var(--fg); }
  button.proceed { background:var(--safe); border-color:transparent; color:#fff; }
  button.block { background:var(--danger); border-color:transparent; color:#fff; }
  .empty { color:var(--muted); padding:24px 0; text-align:center; }
  pre { white-space:pre-wrap; word-break:break-word; background:var(--card); border:1px solid var(--border); border-radius:8px; padding:10px; margin:0; }
  code { background:var(--card); padding:1px 5px; border-radius:5px; }
</style>
</head>
<body>
<div class="wrap" id="root"><div class="empty">Waiting for scan result…</div></div>
<script>
(function(){
  var parentWin = window.parent;
  var reqId = 1;
  function send(m){ try { parentWin.postMessage(m, "*"); } catch(e){} }
  function rpc(method, params){ var id = reqId++; send({ jsonrpc:"2.0", id: id, method: method, params: params||{} }); return id; }
  function notify(method, params){ send({ jsonrpc:"2.0", method: method, params: params||{} }); }
  function ask(text){ send({ jsonrpc:"2.0", method:"ui/message", params:{ role:"user", content:{ type:"text", text:text } } }); }

  // MCP Apps handshake.
  var initId = rpc("ui/initialize", { capabilities:{}, clientInfo:{ name:"surface-scan", version:"1.0.0" }, protocolVersion:"2026-01-26" });

  function num(v){ return typeof v==="number" ? v : (v==null?null:(isNaN(Number(v))?null:Number(v))); }
  function pick(o){ for(var i=1;i<arguments.length;i++){ var k=arguments[i]; if(o && o[k]!=null) return o[k]; } return undefined; }
  function esc(s){ return String(s).replace(/[&<>]/g, function(c){ return {"&":"&amp;","<":"&lt;",">":"&gt;"}[c]; }); }

  // The scan tools return pretty-printed JSON inside a text content block. The
  // host forwards the tool result; dig the JSON out of whatever shape arrives.
  function extractResult(data){
    var p = (data && data.params) ? data.params : data;
    var cands = [ p && p.result, p && p.toolResult, p && p.structuredContent, p && p.content, data && data.result, data && data.content ];
    for (var i=0;i<cands.length;i++){
      var c = cands[i];
      if (c == null) continue;
      if (Array.isArray(c)) {
        var txt = c.map(function(b){ return (b && b.text) ? b.text : ""; }).join("\\n").trim();
        if (txt) { try { return JSON.parse(txt); } catch(e){ return { _raw: txt }; } }
      } else if (c.content && Array.isArray(c.content)) {
        var t2 = c.content.map(function(b){ return (b && b.text) ? b.text : ""; }).join("\\n").trim();
        if (t2) { try { return JSON.parse(t2); } catch(e){ return { _raw: t2 }; } }
      } else if (typeof c === "object") { return c;
      } else if (typeof c === "string") { try { return JSON.parse(c); } catch(e){ return { _raw: c }; } }
    }
    return null;
  }

  // Surface nests the verdict under safetyScore; fall back to top-level for
  // other shapes. Fields seen in production: safetyScore.{score, threatLevel,
  // confidence, confidenceReason, primaryThreat, enginesUsed, recommendedAction}.
  function verdictInfo(r){
    var sc = (r.safetyScore && typeof r.safetyScore==="object") ? r.safetyScore : r;
    var score = num(pick(sc,"score","safety_score","safetyScore"));
    var level = (pick(sc,"threatLevel","threat_level","verdict","level")||"").toString();
    var action = (pick(sc,"recommendedAction","recommended_action")||"").toString();
    var lower = level.toLowerCase();
    var danger = pick(sc,"malicious")===true || action.toLowerCase()==="block" || lower.indexOf("malicious")>=0 || lower.indexOf("high")>=0 || lower.indexOf("critical")>=0 || (score!=null && score<40);
    var warn = !danger && (lower.indexOf("suspicious")>=0 || lower.indexOf("medium")>=0 || lower.indexOf("low")>=0 || (score!=null && score<70));

    // Non-malware findings must still affect the headline. A prompt-injection
    // detection must never render as a green "Allow" — this content is about to
    // be handed to an agent, where injection IS the threat. Factor it in
    // regardless of the (malware-oriented) safety score.
    var pi = r.promptInjection || (sc && sc.promptInjection);
    var inj = !!(pi && (pi.detected===true || (pi.findings && pi.findings.length)));
    var injHigh = inj && (String((pi&&pi.risk)||"").toLowerCase()==="high" || ((pi&&pi.findings)||[]).some(function(f){ return String((f&&f.severity)||"").toLowerCase()==="high"; }));
    if (inj) { danger = danger || injHigh; warn = warn || !injHigh; }

    var label;
    if (inj && danger) label = "Prompt injection";
    else if (inj) label = "Prompt injection risk";
    else label = level || (danger?"Malicious":(warn?"Suspicious":"Clean"));

    return { sc:sc, score:score, level:level, action:action, inj:inj, injHigh:injHigh, pi:pi,
      label: label,
      color: danger?"var(--danger)":(warn?"var(--warn)":"var(--safe)"),
      pass: !danger && !inj };
  }

  function tile(k,v){ return '<div class="tile"><div class="k">'+k+'</div><div class="v">'+v+'</div></div>'; }
  function listSection(title, arr){
    if(!arr) return "";
    var items = Array.isArray(arr) ? arr : (typeof arr==="object" ? Object.keys(arr) : [arr]);
    if(!items.length) return "";
    return '<div class="section"><h3>'+esc(title)+'</h3><ul class="list">'+
      items.slice(0,20).map(function(x){ return '<li>'+esc(typeof x==="object"?JSON.stringify(x):x)+'</li>'; }).join("")+'</ul></div>';
  }
  // Handles enginesUsed (array of names), array of {name,result}, or an object map.
  function engineSection(engines){
    if(!engines) return "";
    var items = [];
    if(Array.isArray(engines)){
      engines.forEach(function(e){
        if(e==null) return;
        if(typeof e==="string"){ items.push(esc(e)); }
        else { var n=pick(e,"name","engine")||"engine"; var v=pick(e,"result","verdict","detected"); items.push(esc(n)+(v!=null?(": "+esc(typeof v==="object"?JSON.stringify(v):v)):"")); }
      });
    } else if(typeof engines==="object"){
      Object.keys(engines).forEach(function(k){ var v=engines[k]; items.push(esc(k)+": "+esc(typeof v==="object"?JSON.stringify(v):v)); });
    }
    if(!items.length) return "";
    return '<div class="section"><h3>Engines ('+items.length+')</h3><ul class="list">'+
      items.slice(0,25).map(function(x){ return '<li>'+x+'</li>'; }).join("")+'</ul></div>';
  }

  function render(r){
    var root = document.getElementById("root");
    if(!r){ root.innerHTML = '<div class="empty">No scan data.</div>'; return; }
    if(r._raw){ root.innerHTML = '<div class="section"><h3>Scan output</h3><pre>'+esc(r._raw)+'</pre></div>'; return; }
    // Unwrap the remote MCP endpoint's {status, body} proxy envelope (the local
    // server returns the scan result directly; the hosted one wraps it).
    if (r.status!==undefined && r.body!==undefined && typeof r.body==="object") r = r.body;
    var vi = verdictInfo(r); var sc = vi.sc;
    var name = pick(r,"name","filename","file_name");
    var hash = String(pick(r,"hash","sha256","sha_256")||"").replace(/^sha256:/i,"");
    var size = pick(r,"size");
    var ctype = pick(r,"contentType","content_type");
    var stype = pick(r,"scanType","scan_type");
    var confidence = pick(sc,"confidence");
    var confReason = pick(sc,"confidenceReason","confidence_reason");
    var primary = pick(sc,"primaryThreat","threatSummary","primary_threat");
    var injDetail = "";
    if (vi.inj && vi.pi && vi.pi.findings && vi.pi.findings.length){
      injDetail = vi.pi.findings.slice(0,6).map(function(f){
        return esc(pick(f,"category","type")||"finding") + (f&&f.pattern?(' — "'+esc(f.pattern)+'"'):"") + (f&&f.severity?(" (severity: "+esc(f.severity)+")"):"");
      }).join("<br>");
    }
    var hasThreat = vi.inj || (primary && String(primary).toLowerCase().indexOf("no threat")<0);

    var tiles = "";
    if(vi.score!=null) tiles += tile(vi.inj?"Malware score":"Safety score", vi.score+" / 100");
    if(vi.level) tiles += tile(vi.inj?"Malware threat":"Threat level", esc(vi.level));
    if(confidence) tiles += tile("Confidence", esc(confidence)+(confReason?(' <span style="color:var(--muted);font-weight:400">— '+esc(confReason)+'</span>'):''));
    if(vi.action) tiles += tile("Recommended", esc(vi.action)+((vi.inj && vi.action.toLowerCase()==="allow")?(' <span style="color:'+vi.color+';font-weight:400">— overridden, injection detected</span>'):''));
    if(name) tiles += tile("File", esc(name));
    if(size!=null) tiles += tile("Size", esc(size)+" B");
    if(ctype) tiles += tile("Type", esc(ctype));
    if(stype) tiles += tile("Scan type", esc(stype));
    if(hash) tiles += tile("SHA-256", '<code>'+esc(hash.slice(0,24))+'…</code>');

    var bannerBody = "";
    if (primary && String(primary).toLowerCase().indexOf("no threat")<0) bannerBody += esc(primary);
    if (injDetail) bannerBody += (bannerBody?"<br>":"") + injDetail;
    var banner = (hasThreat && bannerBody)
      ? '<div class="section"><div class="tile" style="border-color:'+vi.color+'"><div class="k" style="color:'+vi.color+'">'+(vi.inj?"Prompt injection":"Primary threat")+'</div><div class="v">'+bannerBody+'</div></div></div>'
      : "";

    root.innerHTML =
      '<div class="head"><span class="verdict">'+esc(vi.label)+'</span>'+
        (vi.score!=null ? '<span class="score-badge" style="background:'+vi.color+'">'+vi.score+'</span>' : '')+'</div>'+
      banner+
      '<div class="grid">'+tiles+'</div>'+
      engineSection(pick(sc,"enginesUsed","engines")||pick(r,"engines"))+
      listSection("Indicators of compromise", pick(r,"iocs","IOCs","indicators")||pick(sc,"iocs"))+
      listSection("YARA matches", pick(r,"yara","yara_matches","yaraMatches")||pick(sc,"yaraMatches"))+
      '<div class="gate">'+
        '<button class="'+(vi.pass?"proceed":"")+'" id="proceed">Proceed with deploy</button>'+
        '<button class="'+(vi.pass?"":"block")+'" id="block">Block deploy</button>'+
      '</div>';

    var summary = (name?(" of "+name):"")+" — "+vi.label+(vi.score!=null?(" ("+vi.score+"/100)"):"")+(hasThreat?(", "+primary):"");
    document.getElementById("proceed").onclick = function(){
      ask("Surface scan gate: PROCEED — user approved deployment after reviewing scan"+summary+".");
    };
    document.getElementById("block").onclick = function(){
      ask("Surface scan gate: BLOCK — user blocked deployment based on scan"+summary+". Do not flash or upload.");
    };
  }

  window.addEventListener("message", function(ev){
    var data = ev.data;
    if(!data || typeof data!=="object") return;
    if (data.id===initId && data.result){ send({ jsonrpc:"2.0", method:"ui/notifications/initialized", params:{} }); return; }
    var method = (data.method || "").toString();
    if (method.indexOf("tool-result")>=0) {
      var r = extractResult(data);
      if(r) render(r);
    }
  });
})();
</script>
</body>
</html>`;
