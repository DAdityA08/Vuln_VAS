"""
Vuln_VAS – Full Automated UI
Run: streamlit run app.py
"""

import json
import os
import subprocess
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from fpdf import FPDF

# ──────────────────────────────────────────────────────────────
# PAGE CONFIG
# ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Vuln_VAS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ──────────────────────────────────────────────────────────────
# GLOBAL CSS
# ──────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

*, *::before, *::after { box-sizing: border-box; }

html, body, .stApp {
    background: #050810 !important;
    font-family: 'Rajdhani', sans-serif;
    color: #c9d1d9;
}

/* Scanline overlay */
.stApp::before {
    content: '';
    position: fixed; top:0; left:0; right:0; bottom:0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,255,100,0.015) 2px,
        rgba(0,255,100,0.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
}

/* Hide streamlit branding */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 1.5rem 2rem !important; max-width: 1400px; }

/* Hero banner */
.vuln-header {
    background: linear-gradient(135deg, #0d1117 0%, #0a1628 50%, #050810 100%);
    border: 1px solid #00ff6420;
    border-radius: 16px;
    padding: 28px 36px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}
.vuln-header::before {
    content: '';
    position: absolute;
    top: -50%; left: -50%;
    width: 200%; height: 200%;
    background: radial-gradient(ellipse at 30% 50%, #00ff6408 0%, transparent 60%),
                radial-gradient(ellipse at 70% 50%, #e74c3c08 0%, transparent 60%);
}
.vuln-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 38px;
    color: #00ff64;
    text-shadow: 0 0 30px #00ff6440;
    margin: 0;
    letter-spacing: 3px;
}
.vuln-subtitle {
    font-size: 14px;
    color: #4a5568;
    font-family: 'Share Tech Mono', monospace;
    margin-top: 4px;
    letter-spacing: 2px;
}

/* Module progress bar */
.module-track {
    display: flex;
    gap: 8px;
    margin-bottom: 24px;
}
.module-step {
    flex: 1;
    background: #0d1117;
    border: 1px solid #1a2332;
    border-radius: 8px;
    padding: 12px 16px;
    text-align: center;
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: #4a5568;
    transition: all 0.3s;
}
.module-step.active {
    border-color: #00ff64;
    color: #00ff64;
    background: #00ff6408;
    box-shadow: 0 0 20px #00ff6415;
}
.module-step.done {
    border-color: #00cc50;
    color: #00cc50;
    background: #00cc5008;
}
.module-step.error {
    border-color: #e74c3c;
    color: #e74c3c;
    background: #e74c3c08;
}

/* Input section */
.scan-input-box {
    background: #0d1117;
    border: 1px solid #1a2332;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
}

/* KPI cards */
.kpi-row { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
.kpi-card {
    flex: 1; min-width: 130px;
    background: #0d1117;
    border-radius: 10px;
    padding: 18px 16px;
    text-align: center;
    border: 1px solid #1a2332;
    position: relative;
    overflow: hidden;
}
.kpi-card::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 2px;
}
.kpi-crit::after { background: #e74c3c; }
.kpi-high::after { background: #e67e22; }
.kpi-med::after  { background: #f1c40f; }
.kpi-low::after  { background: #2ecc71; }
.kpi-score::after{ background: #3498db; }
.kpi-total::after{ background: #9b59b6; }

.kpi-num { font-size: 40px; font-weight: 700; line-height: 1; }
.kpi-lbl { font-size: 11px; color: #4a5568; margin-top: 4px;
           font-family: 'Share Tech Mono', monospace; letter-spacing: 1px; }
.kpi-crit .kpi-num { color: #e74c3c; }
.kpi-high .kpi-num { color: #e67e22; }
.kpi-med  .kpi-num { color: #f1c40f; }
.kpi-low  .kpi-num { color: #2ecc71; }
.kpi-score .kpi-num{ color: #3498db; font-size:32px; }
.kpi-total .kpi-num{ color: #9b59b6; }

/* Section headers */
.sec-header {
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    color: #00ff64;
    letter-spacing: 3px;
    text-transform: uppercase;
    border-bottom: 1px solid #00ff6420;
    padding-bottom: 8px;
    margin: 24px 0 16px;
}

/* Severity badges */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 1px;
}
.badge-critical { background:#e74c3c20; color:#e74c3c; border:1px solid #e74c3c40; }
.badge-high     { background:#e67e2220; color:#e67e22; border:1px solid #e67e2240; }
.badge-medium   { background:#f1c40f20; color:#f1c40f; border:1px solid #f1c40f40; }
.badge-low      { background:#2ecc7120; color:#2ecc71; border:1px solid #2ecc7140; }
.badge-unknown  { background:#95a5a620; color:#95a5a6; border:1px solid #95a5a640; }

/* Threat cards */
.threat-card {
    background: #0d1117;
    border: 1px solid #1a2332;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 10px;
    border-left: 3px solid;
    transition: all 0.2s;
}
.threat-critical { border-left-color: #e74c3c; }
.threat-high     { border-left-color: #e67e22; }
.threat-medium   { border-left-color: #f1c40f; }
.threat-low      { border-left-color: #2ecc71; }

/* Log console */
.log-console {
    background: #020408;
    border: 1px solid #0d2016;
    border-radius: 8px;
    padding: 16px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: #00ff64;
    max-height: 300px;
    overflow-y: auto;
    line-height: 1.8;
}
.log-info  { color: #00ff64; }
.log-warn  { color: #f1c40f; }
.log-error { color: #e74c3c; }
.log-dim   { color: #2a4a35; }

/* Streamlit widget overrides */
.stTextInput > div > div > input {
    background: #0d1117 !important;
    border: 1px solid #1a2332 !important;
    border-radius: 8px !important;
    color: #00ff64 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 16px !important;
}
.stButton > button {
    background: linear-gradient(135deg, #00ff64, #00cc50) !important;
    color: #050810 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-weight: 700 !important;
    font-size: 14px !important;
    letter-spacing: 2px !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 12px 32px !important;
    transition: all 0.2s !important;
}
.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 8px 24px #00ff6430 !important;
}
.stCheckbox > label { color: #4a5568 !important; font-size: 13px !important; }
.stSelectbox > div > div { background: #0d1117 !important; border-color: #1a2332 !important; }
div[data-testid="stExpander"] {
    background: #0d1117 !important;
    border: 1px solid #1a2332 !important;
    border-radius: 10px !important;
}
.stTabs [data-baseweb="tab-list"] { background: #0d1117; border-radius: 10px; }
.stTabs [data-baseweb="tab"] { color: #4a5568; font-family: 'Share Tech Mono', monospace; }
.stTabs [aria-selected="true"] { color: #00ff64 !important; }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────
NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEV_COLORS = {"Critical":"#e74c3c","High":"#e67e22","Medium":"#f1c40f","Low":"#2ecc71","Unknown":"#95a5a6"}
SEV_ORDER  = ["Critical","High","Medium","Low","Unknown"]

RECOMMENDATIONS = {
    "vsftpd"  : "Upgrade vsftpd immediately. CVE-2011-2523 allows unauthenticated remote shell. Disable if not needed.",
    "openssh" : "Upgrade OpenSSH. Enforce key-based auth, disable root login (PermitRootLogin no).",
    "apache"  : "Upgrade Apache httpd. Disable directory listing, review mod_status exposure.",
    "mysql"   : "Upgrade MySQL. Restrict remote root login. Use strong credentials.",
    "samba"   : "Upgrade Samba. Disable SMBv1. Restrict share permissions.",
    "php"     : "Upgrade PHP. Disable dangerous functions (exec, shell_exec) in php.ini.",
    "default" : "Apply vendor patches, restrict network access, review service configuration.",
}


# ──────────────────────────────────────────────────────────────
# SESSION STATE
# ──────────────────────────────────────────────────────────────
for key, val in {
    "scan_running"  : False,
    "scan_done"     : False,
    "logs"          : [],
    "module1_data"  : None,
    "module2_data"  : None,
    "module3_data"  : None,
    "current_module": 0,
    "target"        : "",
    "scan_error"    : None,
}.items():
    if key not in st.session_state:
        st.session_state[key] = val


# ──────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────
def log(msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    st.session_state.logs.append({"ts": ts, "msg": msg, "level": level})


def classify_severity(cvss: float) -> str:
    if cvss >= 9.0: return "Critical"
    if cvss >= 7.0: return "High"
    if cvss >= 4.0: return "Medium"
    if cvss > 0:    return "Low"
    return "Unknown"


def get_rec(service: str) -> str:
    for key, rec in RECOMMENDATIONS.items():
        if key in service.lower():
            return rec
    return RECOMMENDATIONS["default"]


def severity_badge_html(sev: str) -> str:
    cls = sev.lower() if sev.lower() in ["critical","high","medium","low"] else "unknown"
    return f'<span class="badge badge-{cls}">{sev.upper()}</span>'


# ──────────────────────────────────────────────────────────────
# MODULE 1 – RECONNAISSANCE
# ──────────────────────────────────────────────────────────────
def run_module1(target: str) -> dict:
    import re
    # Strip http:// https:// and extract host + port
    clean = re.sub(r'^https?://', '', target).rstrip('/')
    host = clean.split(':')[0]
    port = clean.split(':')[1] if ':' in clean else None
    log(f"Starting Nmap scan on {host}…")
    recon = {
        "target"  : host,
        "base_url": f"http://{clean}",
        "nmap"    : {},
        "services": [],
        "paths"   : [],
        "nikto"   : [],
        "http"    : {},
    }

    try:
        result = subprocess.run(
            ["nmap", "-sV", "-T4", "--open", "-oX", "-", host],
            capture_output=True, text=True, timeout=120
        )
        import xml.etree.ElementTree as ET
        root = ET.fromstring(result.stdout)
        ports_found = []

        for host in root.findall("host"):
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                portid  = int(port.get("portid", 0))
                proto   = port.get("protocol", "tcp")
                name    = service.get("name",    "") if service is not None else ""
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""

                entry = {
                    "service": product or name,
                    "version": version,
                    "port"   : portid,
                    "proto"  : proto,
                }
                recon["services"].append(entry)
                ports_found.append(portid)
                log(f"  Open port {portid}/{proto} → {product} {version}")

        log(f"Nmap complete – {len(ports_found)} open ports found")

    except FileNotFoundError:
        log("Nmap not found – using demo services", "warn")
        recon["services"] = [
            {"service":"vsftpd",      "version":"2.3.4", "port":21, "proto":"tcp"},
            {"service":"OpenSSH",     "version":"4.7p1", "port":22, "proto":"tcp"},
            {"service":"Apache httpd","version":"2.4.54","port":80, "proto":"tcp"},
        ]
        log("Loaded 3 demo services for analysis", "warn")

    except Exception as e:
        log(f"Nmap error: {e}", "error")
        log("Falling back to demo services", "warn")
        recon["services"] = [
            {"service":"vsftpd",      "version":"2.3.4", "port":21, "proto":"tcp"},
            {"service":"OpenSSH",     "version":"4.7p1", "port":22, "proto":"tcp"},
            {"service":"Apache httpd","version":"2.4.54","port":80, "proto":"tcp"},
        ]

    # HTTP fingerprint
    try:
        r = requests.get(f"http://{clean}", timeout=5)
        recon["http"] = {
            "status_code": r.status_code,
            "server"     : r.headers.get("Server",""),
            "title"      : "",
        }
        log(f"HTTP: {r.status_code} – Server: {r.headers.get('Server','unknown')}")
    except Exception:
        log("HTTP fingerprint skipped (host unreachable)", "warn")

    return recon


# ──────────────────────────────────────────────────────────────
# MODULE 2 – DATA PARSING
# ──────────────────────────────────────────────────────────────
def run_module2(recon: dict) -> dict:
    log("Parsing and normalising recon data…")
    services = recon.get("services", [])
    cleaned  = []
    for s in services:
        svc = s.get("service","").strip()
        ver = s.get("version","").strip()
        if not svc:
            continue
        cleaned.append({
            "service": svc,
            "version": ver or "unknown",
            "port"   : s.get("port", 0),
            "proto"  : s.get("proto","tcp"),
        })
    log(f"Parsed {len(cleaned)} services from recon output")
    recon["services"] = cleaned
    return recon


# ──────────────────────────────────────────────────────────────
# MODULE 3 – VULNERABILITY ANALYSIS
# ──────────────────────────────────────────────────────────────
SERVICE_MAP = {
    "apache tomcat/coyote jsp engine": ("Apache Tomcat", ""),
    "apache tomcat": ("Apache Tomcat", ""),
    "apache httpd": ("Apache httpd", ""),
    "openssh": ("OpenSSH", ""),
    "vsftpd": ("vsftpd", ""),
    "mysql": ("MySQL", ""),
    "samba": ("Samba", ""),
    "php": ("PHP", ""),
    "nginx": ("nginx", ""),
    "iis": ("Microsoft IIS", ""),
}

def normalize_service(service: str, version: str):
    key = service.lower().strip()
    for pattern, (clean_name, _) in SERVICE_MAP.items():
        if pattern in key:
            return clean_name, version
    return service, version

def fetch_nvd(service: str, version: str, log_fn) -> list:
    svc_lower = service.lower()
    for pattern, clean in {
        "apache tomcat/coyote jsp engine": "Apache Tomcat",
        "apache tomcat": "Apache Tomcat",
        "coyote": "Apache Tomcat",
        "apache httpd": "Apache httpd",
        "nginx": "nginx",
        "openssh": "OpenSSH",
        "vsftpd": "vsftpd",
        "mysql": "MySQL",
        "samba": "Samba",
        "php": "PHP",
        "iis": "Microsoft IIS",
    }.items():
        if pattern in svc_lower:
            service = clean
            break
    keyword = f"{service} {version}".strip()
    log_fn(f"  Querying NVD for: {keyword}")
    try:
        r = requests.get(NVD_API, params={"keywordSearch": keyword, "resultsPerPage": 5}, timeout=15)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log_fn(f"  NVD error: {e}", "error")
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve_obj = item.get("cve", {})
        cve_id  = cve_obj.get("id","N/A")
        desc    = next((d["value"] for d in cve_obj.get("descriptions",[]) if d.get("lang")=="en"),
                       "No description.")
        cvss = 0.0
        for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            m = cve_obj.get("metrics",{}).get(key,[])
            if m:
                try: cvss = m[0]["cvssData"]["baseScore"]; break
                except: pass
        cves.append({"cve_id":cve_id,"cvss_score":cvss,"severity":classify_severity(cvss),"description":desc[:280]})
    return cves

def run_module3(parsed: dict, log_fn) -> dict:
    services = parsed.get("services", [])
    target   = parsed.get("target", "unknown")
    vulns    = []
    risk     = {"critical":0,"high":0,"medium":0,"low":0,"unknown":0}

    for svc in services:
        service = svc.get("service","")
        version = svc.get("version","")
        port    = svc.get("port",0)
        proto   = svc.get("proto","tcp")

        log_fn(f"Analysing: {service} {version} (port {port})")
        cves    = fetch_nvd(service, version, log_fn)
        time.sleep(1.2)

        if not cves:
            log_fn(f"  No CVEs found for {service} {version}", "warn")
            continue

        best = max(cves, key=lambda c: c["cvss_score"])
        sev  = best["severity"]
        log_fn(f"  → {best['cve_id']} CVSS {best['cvss_score']} [{sev}]")

        vulns.append({
            "service"          : service,
            "version"          : version,
            "port"             : port,
            "proto"            : proto,
            "cve"              : best["cve_id"],
            "all_cves"         : [c["cve_id"] for c in cves],
            "cvss_score"       : best["cvss_score"],
            "severity"         : sev,
            "confidence"       : "High" if best["cvss_score"] >= 7 else "Medium",
            "description"      : best["description"],
            "exploit_reference": f"Exploit-DB (search: {service} {version})",
        })
        risk[sev.lower() if sev.lower() in risk else "unknown"] += 1

    vulns.sort(key=lambda v: v["cvss_score"], reverse=True)

    weights = {"critical":10,"high":7,"medium":4,"low":1,"unknown":2}
    raw     = sum(risk[k] * weights[k] for k in weights)
    score   = min(100, int((raw / max(len(services),1)) * 10))

    return {
        "target"         : target,
        "scan_time"      : datetime.now(timezone.utc).isoformat(),
        "total_services" : len(services),
        "vulnerabilities": vulns,
        "risk_summary"   : {**risk, "overall_risk_score": score},
    }


# ──────────────────────────────────────────────────────────────
# PDF EXPORT
# ──────────────────────────────────────────────────────────────
def gen_pdf(report: dict) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Header
    pdf.set_fill_color(10, 10, 20)
    pdf.rect(0, 0, 210, 20, "F")
    pdf.set_font("Helvetica","B",14)
    pdf.set_text_color(0,255,100)
    pdf.cell(0,20,"Vuln_VAS - Security Assessment Report",align="C")
    pdf.ln(8)

    pdf.set_text_color(30,30,30)
    pdf.set_font("Helvetica","",10)
    pdf.cell(0,6,f"Target: {report.get('target','N/A')}   |   {report.get('scan_time','N/A')}",ln=True,align="C")
    pdf.ln(6)

    # Risk summary
    risk = report.get("risk_summary",{})
    pdf.set_font("Helvetica","B",11)
    pdf.set_fill_color(30,30,40)
    pdf.set_text_color(255,255,255)
    pdf.cell(0,8,"  Risk Summary",ln=True,fill=True)
    pdf.set_text_color(30,30,30)
    pdf.set_font("Helvetica","",9)
    pdf.ln(2)
    for sev,clr in [("critical",(231,76,60)),("high",(230,126,34)),("medium",(241,196,15)),("low",(46,204,113))]:
        pdf.set_fill_color(*clr)
        pdf.set_text_color(255,255,255)
        pdf.cell(44,7,f"  {sev.capitalize()}: {risk.get(sev,0)}",fill=True,ln=False)
    pdf.ln(10)
    pdf.set_text_color(30,30,30)
    pdf.cell(0,6,f"Overall Risk Score: {risk.get('overall_risk_score','N/A')} / 100",ln=True)
    pdf.ln(4)

    # Vulns
    vulns = report.get("vulnerabilities",[])
    pdf.set_font("Helvetica","B",11)
    pdf.set_fill_color(30,30,40)
    pdf.set_text_color(255,255,255)
    pdf.cell(0,8,f"  Vulnerabilities ({len(vulns)})",ln=True,fill=True)
    pdf.set_text_color(30,30,30)
    pdf.ln(2)

    clr_map = {"Critical":(231,76,60),"High":(230,126,34),"Medium":(241,196,15),"Low":(46,204,113),"Unknown":(149,165,166)}
    for i,v in enumerate(vulns,1):
        if pdf.get_y() > 255: pdf.add_page()
        pdf.set_font("Helvetica","B",10)
        pdf.cell(0,6,f"{i}. {v['service']} {v['version']} - Port {v['port']}/{v.get('proto','tcp')}",ln=True)
        pdf.set_x(10)
        r,g,b = clr_map.get(v.get("severity","Unknown"),(149,165,166))
        pdf.set_fill_color(r,g,b); pdf.set_text_color(255,255,255)
        pdf.set_font("Helvetica","B",8)
        pdf.cell(22,5,v.get("severity","").upper(),fill=True,ln=False)
        pdf.set_text_color(30,30,30)
        pdf.set_font("Helvetica","",9)
        pdf.cell(0,5,f"   {v.get('cve','N/A')}  |  CVSS {v.get('cvss_score',0):.1f}  |  {v.get('confidence','N/A')} confidence",ln=True)
        pdf.set_x(10)
        pdf.set_font("Helvetica","I",8)
        pdf.set_text_color(80,80,80)
        pdf.multi_cell(0,5,v.get("description","")[:200])
        pdf.set_x(10)
        pdf.set_font("Helvetica","B",8)
        pdf.set_text_color(0,100,200)
        pdf.cell(0,5,"Rec: " + get_rec(v.get("service","")),ln=True)
        pdf.set_text_color(30,30,30)
        pdf.ln(3)

    import re; target_clean = re.sub(r'[^a-zA-Z0-9_]', '_', report.get('target','')); path = f'/tmp/vuln_report_{target_clean}.pdf'
    pdf.output(path)
    with open(path,"rb") as f:
        return f.read()


# ──────────────────────────────────────────────────────────────
# SCAN PIPELINE
# ──────────────────────────────────────────────────────────────
def run_full_scan(target: str):
    st.session_state.logs          = []
    st.session_state.scan_error    = None
    st.session_state.module1_data  = None
    st.session_state.module2_data  = None
    st.session_state.module3_data  = None
    st.session_state.scan_done     = False

    try:
        # MODULE 1
        st.session_state.current_module = 1
        log("═══ MODULE 1 — RECONNAISSANCE ═══")
        m1 = run_module1(target)
        st.session_state.module1_data = m1
        log(f"Module 1 complete — {len(m1['services'])} services discovered")

        # MODULE 2
        st.session_state.current_module = 2
        log("═══ MODULE 2 — DATA PARSING ═══")
        m2 = run_module2(m1)
        st.session_state.module2_data = m2
        log("Module 2 complete — data normalised")

        # MODULE 3
        st.session_state.current_module = 3
        log("═══ MODULE 3 — VULNERABILITY ANALYSIS ═══")
        m3 = run_module3(m2, log)
        st.session_state.module3_data = m3
        log(f"Module 3 complete — {len(m3['vulnerabilities'])} vulnerabilities found")

        # MODULE 4
        st.session_state.current_module = 4
        log("═══ MODULE 4 — REPORT READY ═══")
        log("Dashboard rendering… ✓")

        st.session_state.scan_done     = True
        st.session_state.current_module = 5

    except Exception as e:
        st.session_state.scan_error    = str(e)
        log(f"SCAN FAILED: {e}", "error")
    finally:
        st.session_state.scan_running  = False


# ──────────────────────────────────────────────────────────────
# RENDER HELPERS
# ──────────────────────────────────────────────────────────────
def module_track(current: int):
    steps = [
        (1,"[ M1 ] RECON"),
        (2,"[ M2 ] PARSE"),
        (3,"[ M3 ] ANALYSE"),
        (4,"[ M4 ] REPORT"),
    ]
    html = '<div class="module-track">'
    for num, label in steps:
        if current > num:
            cls = "done"
            label = "✓ " + label
        elif current == num:
            cls = "active"
        else:
            cls = ""
        html += f'<div class="module-step {cls}">{label}</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)


def render_logs():
    if not st.session_state.logs:
        return
    lines = ""
    for entry in st.session_state.logs[-60:]:
        cls = {"info":"log-info","warn":"log-warn","error":"log-error"}.get(entry["level"],"log-info")
        lines += f'<span class="log-dim">[{entry["ts"]}]</span> <span class="{cls}">{entry["msg"]}</span><br>'
    st.markdown(f'<div class="log-console">{lines}</div>', unsafe_allow_html=True)


def render_kpis(report: dict):
    risk  = report.get("risk_summary", {})
    vulns = report.get("vulnerabilities", [])
    st.markdown(f"""
    <div class="kpi-row">
      <div class="kpi-card kpi-crit"><div class="kpi-num">{risk.get('critical',0)}</div><div class="kpi-lbl">CRITICAL</div></div>
      <div class="kpi-card kpi-high"><div class="kpi-num">{risk.get('high',0)}</div><div class="kpi-lbl">HIGH</div></div>
      <div class="kpi-card kpi-med"><div class="kpi-num">{risk.get('medium',0)}</div><div class="kpi-lbl">MEDIUM</div></div>
      <div class="kpi-card kpi-low"><div class="kpi-num">{risk.get('low',0)}</div><div class="kpi-lbl">LOW</div></div>
      <div class="kpi-card kpi-score"><div class="kpi-num">{risk.get('overall_risk_score',0)}<span style="font-size:16px">/100</span></div><div class="kpi-lbl">RISK SCORE</div></div>
      <div class="kpi-card kpi-total"><div class="kpi-num">{len(vulns)}</div><div class="kpi-lbl">TOTAL VULNS</div></div>
    </div>
    """, unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────
# MAIN UI
# ──────────────────────────────────────────────────────────────
st.markdown("""
<div class="vuln-header">
  <p class="vuln-title">▸ VULN_VAS</p>
  <p class="vuln-subtitle">// AUTOMATED VULNERABILITY ASSESSMENT SYSTEM — v1.0 //</p>
</div>
""", unsafe_allow_html=True)

# ── Module progress track ─────────────────────────────────────
module_track(st.session_state.current_module)

# ── Scan input ───────────────────────────────────────────────
if not st.session_state.scan_done and not st.session_state.scan_running:
    st.markdown('<div class="sec-header">// TARGET CONFIGURATION</div>', unsafe_allow_html=True)

    col_inp, col_btn = st.columns([3, 1])
    with col_inp:
        target_input = st.text_input(
            "",
            placeholder="Enter target IP or hostname (e.g. 192.168.56.101)",
            label_visibility="collapsed",
        )
    with col_btn:
        st.markdown("<br>", unsafe_allow_html=True)
        consent = st.checkbox("I have authorization to scan this target", value=False)

    if st.button("⬡  LAUNCH FULL SCAN", use_container_width=False):
        if not target_input:
            st.error("Please enter a target IP or hostname.")
        elif not consent:
            st.error("You must confirm authorization before scanning.")
        else:
            st.session_state.target       = target_input
            st.session_state.scan_running = True
            st.rerun()

# ── Running scan ─────────────────────────────────────────────
if st.session_state.scan_running:
    st.markdown('<div class="sec-header">// SCAN IN PROGRESS</div>', unsafe_allow_html=True)
    run_full_scan(st.session_state.target)
    render_logs()
    st.rerun()

# ── Scan error ───────────────────────────────────────────────
if st.session_state.scan_error:
    st.error(f"Scan error: {st.session_state.scan_error}")
    render_logs()
    if st.button("↺  RETRY"):
        st.session_state.scan_error = None
        st.rerun()

# ── Results dashboard ─────────────────────────────────────────
if st.session_state.scan_done and st.session_state.module3_data:
    report  = st.session_state.module3_data
    m1      = st.session_state.module1_data or {}
    m2      = st.session_state.module2_data or {}
    vulns   = report.get("vulnerabilities", [])
    risk    = report.get("risk_summary", {})
    target  = report.get("target","N/A")

    st.markdown(f'<div class="sec-header">// SCAN RESULTS — {target} — {report.get("scan_time","")[:19].replace("T"," ")}</div>', unsafe_allow_html=True)
    render_kpis(report)

    # ── Tabs ─────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📡  Module 1 — Recon",
        "🗂  Module 2 — Parsed Data",
        "🔬  Module 3 — Vulnerabilities",
        "📊  Module 4 — Dashboard",
        "📥  Export",
    ])

    # ── TAB 1: RECON ─────────────────────────────────────────
    with tab1:
        st.markdown("#### Discovered Services")
        services = m1.get("services",[])
        if services:
            df1 = pd.DataFrame(services)
            st.dataframe(df1, use_container_width=True, hide_index=True)
        else:
            st.info("No services data.")

        http = m1.get("http",{})
        if http:
            st.markdown("#### HTTP Fingerprint")
            c1,c2 = st.columns(2)
            c1.metric("Status Code", http.get("status_code","N/A"))
            c2.metric("Server", http.get("server","N/A"))

        st.markdown("#### Scan Log")
        render_logs()

    # ── TAB 2: PARSED DATA ───────────────────────────────────
    with tab2:
        st.markdown("#### Normalised Service List")
        services2 = m2.get("services",[])
        if services2:
            df2 = pd.DataFrame(services2)
            st.dataframe(df2, use_container_width=True, hide_index=True)

            st.markdown("#### Port Distribution")
            fig_ports = px.bar(
                df2, x="port", y="service", orientation="h",
                color="service", text="version",
                color_discrete_sequence=px.colors.qualitative.Dark24,
            )
            fig_ports.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#c9d1d9", showlegend=False,
                xaxis=dict(gridcolor="#1a2332"), yaxis=dict(gridcolor="#1a2332"),
                margin=dict(t=10,b=10),
            )
            st.plotly_chart(fig_ports, use_container_width=True)

    # ── TAB 3: VULNERABILITIES ───────────────────────────────
    with tab3:
        if not vulns:
            st.info("No vulnerabilities found.")
        else:
            # Filters
            fc1, fc2, fc3 = st.columns(3)
            sev_filter = fc1.multiselect("Severity", SEV_ORDER, default=SEV_ORDER)
            min_cvss   = fc2.slider("Min CVSS", 0.0, 10.0, 0.0, 0.5)
            sort_by    = fc3.selectbox("Sort by", ["CVSS (High→Low)", "CVSS (Low→High)", "Service"])

            filtered = [v for v in vulns
                        if v.get("severity","Unknown") in sev_filter
                        and v.get("cvss_score",0) >= min_cvss]

            if sort_by == "CVSS (High→Low)":   filtered.sort(key=lambda v: v["cvss_score"], reverse=True)
            elif sort_by == "CVSS (Low→High)": filtered.sort(key=lambda v: v["cvss_score"])
            else:                               filtered.sort(key=lambda v: v["service"])

            st.markdown(f"**{len(filtered)}** findings after filter")

            for v in filtered:
                sev  = v.get("severity","Unknown")
                icon = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}.get(sev,"⚪")
                with st.expander(f"{icon}  {v['service']} {v['version']}  ·  {v.get('cve','N/A')}  ·  CVSS {v.get('cvss_score',0):.1f}  ·  Port {v.get('port','?')}"):
                    r1,r2,r3,r4 = st.columns(4)
                    r1.markdown(f"**Severity**<br>{severity_badge_html(sev)}", unsafe_allow_html=True)
                    r2.markdown(f"**CVSS Score**<br>`{v.get('cvss_score',0):.1f} / 10`", unsafe_allow_html=True)
                    r3.markdown(f"**Confidence**<br>`{v.get('confidence','N/A')}`", unsafe_allow_html=True)
                    r4.markdown(f"**Port**<br>`{v.get('port','N/A')}/{v.get('proto','tcp')}`", unsafe_allow_html=True)

                    st.markdown(f"**CVE:** [{v.get('cve','N/A')}](https://nvd.nist.gov/vuln/detail/{v.get('cve','')})")
                    st.markdown(f"**All CVEs:** `{'  ·  '.join(v.get('all_cves',[v.get('cve','N/A')]))}`")
                    st.markdown(f"**Description:** {v.get('description','')}")
                    st.info(f"💡 **Recommendation:** {get_rec(v.get('service',''))}")

    # ── TAB 4: DASHBOARD ─────────────────────────────────────
    with tab4:
        col_pie, col_gauge = st.columns(2)

        with col_pie:
            st.markdown("#### Severity Distribution")
            labels = [s for s in SEV_ORDER if risk.get(s.lower(),0)>0]
            values = [risk.get(s.lower(),0) for s in labels]
            colors = [SEV_COLORS[s] for s in labels]
            if values:
                fig_pie = go.Figure(go.Pie(
                    labels=labels, values=values, marker_colors=colors,
                    hole=0.5, textinfo="label+percent",
                ))
                fig_pie.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#c9d1d9",showlegend=False,margin=dict(t=10,b=10),
                )
                st.plotly_chart(fig_pie, use_container_width=True)

        with col_gauge:
            st.markdown("#### Risk Score")
            score = risk.get("overall_risk_score",0)
            color = "#e74c3c" if score>=70 else "#e67e22" if score>=40 else "#2ecc71"
            fig_g = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                gauge=dict(
                    axis=dict(range=[0,100], tickcolor="#4a5568"),
                    bar=dict(color=color),
                    bgcolor="#0d1117",
                    steps=[
                        dict(range=[0,40],  color="#0a2016"),
                        dict(range=[40,70], color="#1a1a08"),
                        dict(range=[70,100],color="#1a0808"),
                    ],
                    threshold=dict(line=dict(color=color,width=3),value=score),
                ),
                number=dict(suffix="/100", font=dict(color=color, size=36)),
                title=dict(text="Overall Risk", font=dict(color="#4a5568",size=14)),
            ))
            fig_g.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                height=280, margin=dict(t=20,b=10,l=20,r=20),
            )
            st.plotly_chart(fig_g, use_container_width=True)

        # CVSS bar chart
        if vulns:
            st.markdown("#### CVSS Scores by Service")
            df_v = pd.DataFrame([{
                "Service" : f"{v['service']} {v['version']}",
                "CVSS"    : v.get("cvss_score",0),
                "Severity": v.get("severity","Unknown"),
                "CVE"     : v.get("cve","N/A"),
            } for v in vulns])

            fig_bar = px.bar(
                df_v.sort_values("CVSS",ascending=True),
                x="CVSS", y="Service", orientation="h",
                color="Severity", color_discrete_map=SEV_COLORS,
                hover_data=["CVE"], range_x=[0,10], text="CVSS",
            )
            fig_bar.update_traces(texttemplate="%{text:.1f}", textposition="outside")
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#c9d1d9", margin=dict(t=10,b=10),
                xaxis=dict(gridcolor="#1a2332"), yaxis=dict(gridcolor="#1a2332"),
                height=max(250, len(vulns)*60),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # Threat priority table
        st.markdown("#### Prioritised Threat Table")
        if vulns:
            df_table = pd.DataFrame([{
                "#"           : i+1,
                "Service"     : v["service"],
                "Version"     : v["version"],
                "Port"        : v["port"],
                "CVE"         : v.get("cve","N/A"),
                "CVSS"        : v.get("cvss_score",0),
                "Severity"    : v.get("severity","Unknown"),
                "Confidence"  : v.get("confidence","N/A"),
            } for i,v in enumerate(vulns)])
            st.dataframe(
                df_table, use_container_width=True, hide_index=True,
                column_config={
                    "CVSS": st.column_config.ProgressColumn("CVSS", min_value=0, max_value=10, format="%.1f"),
                    "#"   : st.column_config.NumberColumn(width="small"),
                }
            )

    # ── TAB 5: EXPORT ────────────────────────────────────────
    with tab5:
        st.markdown("#### Download Reports")
        ec1, ec2, ec3 = st.columns(3)

        with ec1:
            st.markdown("**PDF Report**")
            pdf_bytes = gen_pdf(report)
            st.download_button(
                "⬇  Download PDF",
                data=pdf_bytes,
                file_name=f"vuln_report_{target.replace('.','_')}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

        with ec2:
            st.markdown("**JSON Export**")
            st.download_button(
                "⬇  Download JSON",
                data=json.dumps(report, indent=4),
                file_name=f"vuln_analysis_{target.replace('.','_')}.json",
                mime="application/json",
                use_container_width=True,
            )

        with ec3:
            st.markdown("**New Scan**")
            if st.button("↺  Scan New Target", use_container_width=True):
                for k in ["scan_done","scan_running","module1_data","module2_data","module3_data","logs","current_module","scan_error"]:
                    st.session_state[k] = False if "running" in k or "done" in k else ([] if k=="logs" else (0 if k=="current_module" else None))
                st.rerun()
