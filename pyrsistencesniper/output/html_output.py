# ruff: noqa: E501
from __future__ import annotations

import json
from typing import IO, Any

from jinja2 import Environment
from markupsafe import Markup

from pyrsistencesniper.models.finding import AnnotatedResult
from pyrsistencesniper.output.base import OutputBase

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PyrsistenceSniper Report</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
::selection { background: hsla(340,75%,55%,0.4); color: #f5f7fa; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background-color: #0a0e1a; color: #f5f7fa; line-height: 1.5; padding: 1.5rem;
  background-image:
    radial-gradient(1200px 600px at 20% -10%, hsla(340,85%,58%,0.18), transparent 60%),
    radial-gradient(900px 600px at 85% 0%, hsla(200,90%,60%,0.12), transparent 55%),
    radial-gradient(1000px 700px at 60% 110%, hsla(330,80%,50%,0.10), transparent 60%);
  background-attachment: fixed;
}
a { color: #d6336c; text-decoration: none; }
a:hover { text-decoration: underline; }
.report-header {
  margin-bottom: 1.5rem;
  display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem;
}
.brand { display: flex; flex-direction: column; }
.brand-name { font-size: 1.6rem; font-weight: 600; color: #f5f7fa; letter-spacing: -0.02em; }
.brand-tag { font-size: 0.85rem; color: #99a3b3; }
.report-header .timestamp { color: #99a3b3; font-size: 0.85rem; }
.stats-bar { display: flex; align-items: baseline; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 0.25rem 0; }
.stat-card {
  display: flex; align-items: baseline; gap: 0.35rem;
  padding: 0.3rem 1.1rem; border-left: 1px solid #252a36;
}
.stat-card:first-child { border-left: none; padding-left: 0; }
.stat-card .stat-label { font-size: 0.8rem; color: #99a3b3; order: -1; }
.stat-card .stat-value { font-size: 0.95rem; font-weight: 600; }
.stat-total .stat-value { color: #f5f7fa; }
.stat-high .stat-value { color: #e8366f; }
.stat-medium .stat-value { color: #f0983e; }
.stat-low .stat-value { color: #34d399; }
.stat-info .stat-value { color: #38bdf8; }
.controls { display: flex; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center; }
.controls input[type="text"] {
  background: #0a0e1a; border: 1px solid #252a36; border-radius: 0.6rem;
  color: #f5f7fa; padding: 0.4rem 0.75rem; font-size: 0.85rem; min-width: 220px;
}
.controls input[type="text"]:focus, .controls select:focus { outline: none; box-shadow: 0 0 0 2px hsla(340,75%,55%,0.3); }
.controls input[type="text"]::placeholder { color: #99a3b3; }
.controls select {
  background: #101626; border: 1px solid #252a36; border-radius: 0.6rem;
  color: #f5f7fa; padding: 0.4rem 0.5rem; font-size: 0.85rem;
}
.btn-reset, .btn-columns {
  background: transparent; border: 1px solid #252a36; border-radius: 0.6rem;
  color: #99a3b3; padding: 0.4rem 0.75rem; font-size: 0.85rem; cursor: pointer;
}
.btn-reset:hover, .btn-columns:hover { color: #f5f7fa; border-color: #99a3b3; }
.col-picker-wrap { position: relative; }
.col-picker {
  display: none; position: absolute; top: 100%; left: 0; margin-top: 0.35rem; z-index: 900;
  background: rgba(16,22,38,0.95); backdrop-filter: blur(8px); border: 1px solid #252a36;
  border-radius: 0.6rem; box-shadow: 0 8px 24px rgba(0,0,0,0.5); padding: 0.35rem 0;
  min-width: 180px; max-height: 320px; overflow-y: auto;
}
.col-picker.open { display: block; }
.col-picker label {
  display: flex; align-items: center; gap: 0.4rem; padding: 0.3rem 0.75rem;
  font-size: 0.8rem; color: #f5f7fa; cursor: pointer; white-space: nowrap;
}
.col-picker label:hover { background: #252a36; }
.col-picker input[type="checkbox"] { accent-color: #d6336c; }
.row-count { color: #99a3b3; font-size: 0.85rem; margin-left: auto; }
.table-wrapper { overflow-x: auto; border: 1px solid #252a36; border-radius: 0.6rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.8rem; }
th {
  background: #101626; color: #f5f7fa; border-bottom: 2px solid #252a36;
  padding: 0.6rem 0.75rem; text-align: left; position: sticky; top: 0; z-index: 1;
  cursor: pointer; user-select: none; white-space: nowrap;
}
th:hover { background: #202538; }
th .sort-indicator { margin-left: 0.3rem; display: inline-flex; vertical-align: middle; opacity: 0.4; }
th .sort-indicator.active { opacity: 1; }
th .col-resize {
  position: absolute; right: 0; top: 0; bottom: 0; width: 5px;
  cursor: col-resize; user-select: none;
}
th .col-resize:hover { background: hsla(340,75%,55%,0.4); }
td {
  padding: 0.5rem 0.75rem; border-bottom: 1px solid #252a36;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
tr:nth-child(odd) td { background: #0a0e1a; }
tr:nth-child(even) td { background: #101626; }
tr:hover td { background: #202538; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.75rem; font-weight: 600; }
.badge-high { background: rgba(232,54,111,0.14); color: #e8366f; }
.badge-medium { background: rgba(240,152,62,0.14); color: #f0983e; }
.badge-low { background: rgba(52,211,153,0.14); color: #34d399; }
.badge-info { background: rgba(56,189,248,0.14); color: #38bdf8; }
#context-menu {
  display: none; position: fixed; z-index: 1000;
  background: rgba(16,22,38,0.8); backdrop-filter: blur(8px); border: 1px solid #252a36;
  border-radius: 0.6rem; box-shadow: 0 8px 24px rgba(0,0,0,0.5); min-width: 200px; padding: 0.25rem 0;
}
#context-menu .ctx-item {
  display: block; width: 100%; border: none; background: none; color: #f5f7fa;
  padding: 0.5rem 0.75rem; text-align: left; font-size: 0.85rem; cursor: pointer;
}
#context-menu .ctx-item:hover { background: #252a36; }
#context-menu .ctx-sep { border-top: 1px solid #252a36; margin: 0.25rem 0; }
.report-footer {
  text-align: center; color: #99a3b3; font-size: 0.8rem;
  padding: 1.5rem 0 0.5rem; border-top: 1px solid #252a36; margin-top: 1.5rem;
}
</style>
</head>
<body>
<div class="report-header">
  <div class="brand">
    <span class="brand-name">PyrsistenceSniper</span>
    <span class="brand-tag">Offline Windows Persistence Detection</span>
  </div>
  <div class="timestamp" id="gen-time"></div>
</div>
<div class="stats-bar">
  <div class="stat-card stat-total"><div class="stat-value">{{ total }}</div><div class="stat-label">Total</div></div>
  <div class="stat-card stat-high"><div class="stat-value">{{ severity_counts.HIGH }}</div><div class="stat-label">High</div></div>
  <div class="stat-card stat-medium"><div class="stat-value">{{ severity_counts.MEDIUM }}</div><div class="stat-label">Medium</div></div>
  <div class="stat-card stat-low"><div class="stat-value">{{ severity_counts.LOW }}</div><div class="stat-label">Low</div></div>
  <div class="stat-card stat-info"><div class="stat-value">{{ severity_counts.INFO }}</div><div class="stat-label">Info</div></div>
</div>
<div class="controls">
  <input type="text" id="search" placeholder="Search all fields...">
  <select id="filter-severity"><option value="">All Severities</option></select>
  <select id="filter-technique"><option value="">All Techniques</option></select>
  <select id="filter-mitre"><option value="">All MITRE IDs</option></select>
  <select id="filter-access"><option value="">All Access Levels</option></select>
  <button type="button" id="reset-filters" class="btn-reset">Reset</button>
  <div class="col-picker-wrap">
    <button type="button" id="col-toggle" class="btn-columns">Columns</button>
    <div class="col-picker" id="col-picker"></div>
  </div>
  <span class="row-count" id="row-count"></span>
</div>
<div class="table-wrapper">
  <table>
    <thead><tr id="thead-row"></tr></thead>
    <tbody id="tbody"></tbody>
  </table>
</div>
<div id="context-menu">
  <button class="ctx-item" data-action="vt-search">Search on VirusTotal</button>
  <button class="ctx-item" data-action="vt-sha256" id="ctx-vt-sha256">Search SHA256 on VirusTotal</button>
  <button class="ctx-item" data-action="google">Search on Google</button>
  <div class="ctx-sep"></div>
  <button class="ctx-item" data-action="copy-value">Copy Value</button>
  <button class="ctx-item" data-action="copy-sha256" id="ctx-copy-sha256">Copy SHA256</button>
  <button class="ctx-item" data-action="copy-path">Copy Path</button>
  <button class="ctx-item" data-action="copy-json">Copy Row as JSON</button>
</div>
<div class="report-footer">
  Powered by <strong>PyrsistenceSniper</strong> &middot; Hexastrike Cybersecurity
</div>
<script>
(function(){
"use strict";
var DATA={{ results_json }};
var FIELDS={{ fieldnames_json }};
var sortField=null,sortAsc=true,ctxRow=null;
var visibleFields=new Set(FIELDS);
var searchEl=document.getElementById("search");
var theadRow=document.getElementById("thead-row");
var tbody=document.getElementById("tbody");
var rowCountEl=document.getElementById("row-count");
var ctxMenu=document.getElementById("context-menu");
var filterSev=document.getElementById("filter-severity");
var filterTech=document.getElementById("filter-technique");
var filterMitre=document.getElementById("filter-mitre");
var filterAccess=document.getElementById("filter-access");
var colPicker=document.getElementById("col-picker");
var SVG_UP='<svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 6.5L5 4L7.5 6.5"/></svg>';
var SVG_DN='<svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 3.5L5 6L7.5 3.5"/></svg>';
var SVG_BOTH='<svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 6.5L5 8L7.5 6.5M2.5 3.5L5 2L7.5 3.5"/></svg>';

document.getElementById("gen-time").textContent="Generated: "+new Date().toLocaleString();

function addOptions(sel,items){
  items.forEach(function(v){var o=document.createElement("option");o.value=v;o.textContent=v;sel.appendChild(o);});
}
function buildHeaders(){
  theadRow.textContent="";
  FIELDS.forEach(function(f){
    if(!visibleFields.has(f))return;
    var th=document.createElement("th");th.textContent=f;th.setAttribute("data-field",f);
    var sp=document.createElement("span");sp.className="sort-indicator";
    sp.innerHTML=sortField===f?(sortAsc?SVG_UP:SVG_DN):SVG_BOTH;
    if(sortField===f)sp.classList.add("active");
    th.appendChild(sp);
    th.addEventListener("click",function(){sortBy(f);});
    var handle=document.createElement("div");handle.className="col-resize";
    handle.addEventListener("mousedown",function(e){e.stopPropagation();initResize(e,th);});
    th.appendChild(handle);
    theadRow.appendChild(th);
  });
}
function initResize(e,th){
  var startX=e.pageX,startW=th.offsetWidth;
  function onMove(ev){var w=Math.max(40,startW+(ev.pageX-startX));th.style.width=w+"px";th.style.minWidth=w+"px";}
  function onUp(){document.removeEventListener("mousemove",onMove);document.removeEventListener("mouseup",onUp);window.removeEventListener("blur",onUp);}
  document.addEventListener("mousemove",onMove);document.addEventListener("mouseup",onUp);window.addEventListener("blur",onUp);
}
function populateFilters(){
  var sv={},te={},mi={},ac={};
  DATA.forEach(function(r){
    if(r.severity)sv[r.severity]=1;if(r.technique)te[r.technique]=1;
    if(r.mitre_id)mi[r.mitre_id]=1;if(r.access_gained)ac[r.access_gained]=1;
  });
  addOptions(filterSev,Object.keys(sv).sort());
  addOptions(filterTech,Object.keys(te).sort());
  addOptions(filterMitre,Object.keys(mi).sort());
  addOptions(filterAccess,Object.keys(ac).sort());
}
function getFilteredData(){
  var q=searchEl.value.toLowerCase();
  var sv=filterSev.value,te=filterTech.value,mi=filterMitre.value,ac=filterAccess.value;
  var out=DATA.filter(function(r){
    if(sv&&r.severity!==sv)return false;
    if(te&&r.technique!==te)return false;
    if(mi&&r.mitre_id!==mi)return false;
    if(ac&&r.access_gained!==ac)return false;
    if(q){var m=false;FIELDS.forEach(function(f){if(String(r[f]!=null?r[f]:"").toLowerCase().indexOf(q)!==-1)m=true;});if(!m)return false;}
    return true;
  });
  if(sortField!==null){
    out.sort(function(a,b){
      var va=String(a[sortField]!=null?a[sortField]:""),vb=String(b[sortField]!=null?b[sortField]:"");
      var c=va.localeCompare(vb,undefined,{numeric:true,sensitivity:"base"});
      return sortAsc?c:-c;
    });
  }
  return out;
}
function renderTable(){
  var rows=getFilteredData(),frag=document.createDocumentFragment();
  rows.forEach(function(r){frag.appendChild(renderRow(r));});
  tbody.textContent="";tbody.appendChild(frag);
  rowCountEl.textContent=rows.length+" / "+DATA.length+" rows";
}
function renderRow(row){
  var tr=document.createElement("tr");
  FIELDS.forEach(function(f){
    if(!visibleFields.has(f))return;
    var td=document.createElement("td");
    td.title=String(row[f]!=null?row[f]:"");
    if(f==="severity"){
      var sp=document.createElement("span");
      sp.className="badge badge-"+String(row[f]||"").toLowerCase();
      sp.textContent=row[f]||"";td.appendChild(sp);
    }else{td.textContent=row[f]!=null?String(row[f]):"";}
    tr.appendChild(td);
  });
  tr.addEventListener("contextmenu",function(e){showContextMenu(e,row);});
  return tr;
}
function sortBy(field){
  if(sortField===field){sortAsc=!sortAsc;}else{sortField=field;sortAsc=true;}
  updateSortIndicators();renderTable();
}
function updateSortIndicators(){
  theadRow.querySelectorAll("th").forEach(function(th){
    var f=th.getAttribute("data-field"),ind=th.querySelector(".sort-indicator");
    if(f===sortField){ind.innerHTML=sortAsc?SVG_UP:SVG_DN;ind.classList.add("active");}
    else{ind.innerHTML=SVG_BOTH;ind.classList.remove("active");}
  });
}
function showContextMenu(e,row){
  e.preventDefault();ctxRow=row;
  var sha=row.sha256||"";
  document.getElementById("ctx-vt-sha256").style.display=sha?"":"none";
  document.getElementById("ctx-copy-sha256").style.display=sha?"":"none";
  ctxMenu.style.display="block";
  var x=e.clientX,y=e.clientY,mw=ctxMenu.offsetWidth,mh=ctxMenu.offsetHeight;
  if(x+mw>window.innerWidth)x=window.innerWidth-mw-5;
  if(y+mh>window.innerHeight)y=window.innerHeight-mh-5;
  ctxMenu.style.left=x+"px";ctxMenu.style.top=y+"px";
}
function hideContextMenu(){ctxMenu.style.display="none";ctxRow=null;}
function handleContextAction(action){
  if(!ctxRow)return;
  var sel=window.getSelection().toString().trim();
  var term=sel||(ctxRow.value||"");
  switch(action){
    case"vt-search":window.open("https://www.virustotal.com/gui/search/"+encodeURIComponent(term));break;
    case"vt-sha256":window.open("https://www.virustotal.com/gui/file/"+encodeURIComponent(ctxRow.sha256||""));break;
    case"google":window.open("https://www.google.com/search?q="+encodeURIComponent(term));break;
    case"copy-value":navigator.clipboard.writeText(ctxRow.value||"");break;
    case"copy-sha256":navigator.clipboard.writeText(ctxRow.sha256||"");break;
    case"copy-path":navigator.clipboard.writeText(ctxRow.path||"");break;
    case"copy-json":navigator.clipboard.writeText(JSON.stringify(ctxRow,null,2));break;
  }
  hideContextMenu();
}
var dt;searchEl.addEventListener("input",function(){clearTimeout(dt);dt=setTimeout(renderTable,200);});
[filterSev,filterTech,filterMitre,filterAccess].forEach(function(el){el.addEventListener("change",renderTable);});
document.getElementById("reset-filters").addEventListener("click",function(){
  searchEl.value="";filterSev.value="";filterTech.value="";filterMitre.value="";filterAccess.value="";
  sortField=null;sortAsc=true;visibleFields=new Set(FIELDS);buildColPicker();buildHeaders();renderTable();
});
document.addEventListener("click",function(e){hideContextMenu();if(!colPicker.contains(e.target))colPicker.classList.remove("open");});
document.addEventListener("scroll",hideContextMenu,true);
document.addEventListener("keydown",function(e){if(e.key==="Escape")hideContextMenu();});
ctxMenu.querySelectorAll(".ctx-item").forEach(function(btn){
  btn.addEventListener("click",function(e){e.stopPropagation();handleContextAction(btn.getAttribute("data-action"));});
});
function buildColPicker(){
  colPicker.textContent="";
  FIELDS.forEach(function(f){
    var lbl=document.createElement("label");
    var cb=document.createElement("input");cb.type="checkbox";cb.checked=visibleFields.has(f);
    cb.addEventListener("change",function(){
      if(cb.checked)visibleFields.add(f);else visibleFields.delete(f);
      buildHeaders();renderTable();
    });
    lbl.appendChild(cb);lbl.appendChild(document.createTextNode(f));colPicker.appendChild(lbl);
  });
}
document.getElementById("col-toggle").addEventListener("click",function(e){
  e.stopPropagation();colPicker.classList.toggle("open");
});
buildColPicker();buildHeaders();populateFilters();renderTable();
})();
</script>
</body>
</html>
"""


def _count_severities(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings per severity level for the stats bar."""
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for row in rows:
        sev = row.get("severity", "")
        if sev in counts:
            counts[sev] += 1
    return counts


class HtmlOutput(OutputBase):
    """Renders findings into a dark-mode interactive HTML report."""

    def _write(self, results: list[AnnotatedResult], out: IO[str]) -> None:
        env = Environment(autoescape=True)
        template = env.from_string(_HTML_TEMPLATE)
        rows, fieldnames = self._flatten_results(results)
        safe_json = (
            json.dumps(rows, default=str)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )
        out.write(
            template.render(
                results_json=Markup(safe_json),  # noqa: S704
                fieldnames_json=Markup(  # noqa: S704
                    json.dumps(fieldnames)
                    .replace("<", "\\u003c")
                    .replace(">", "\\u003e")
                    .replace("&", "\\u0026"),
                ),
                total=len(rows),
                severity_counts=_count_severities(rows),
            )
        )
