#!/usr/bin/env python3
"""
Run this once to patch app.py:
  python3 patch_app.py
"""

content = open("app.py").read()
patches_applied = []

# ─────────────────────────────────────────────
# PATCH 1 — Add ML + parallel imports after existing imports
# ─────────────────────────────────────────────
OLD1 = "import streamlit as st\nfrom fpdf import FPDF"
NEW1 = """import streamlit as st
from fpdf import FPDF
from sklearn.tree import DecisionTreeClassifier
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm"""

if OLD1 in content:
    content = content.replace(OLD1, NEW1)
    patches_applied.append("PATCH 1: imports")

# ─────────────────────────────────────────────
# PATCH 2 — Add ML model + exploit check + remediation right after RECOMMENDATIONS dict
# ─────────────────────────────────────────────
OLD2 = '    "default" : "Apply vendor patches, restrict network access, review service configuration.",\n}'
NEW2 = '''    "default" : "Apply vendor patches, restrict network access, review service configuration.",
}

# ─── ML PRIORITY MODEL (DecisionTreeClassifier) ───────────────
_ML_DATA = {
    "cvss"    : [9.8, 9.5, 9.0, 8.5, 8.0, 7.5, 7.0, 6.5, 6.0, 5.0, 4.0, 3.0, 2.0],
    "exploit" : [1,   1,   1,   1,   1,   0,   1,   0,   0,   0,   0,   0,   0  ],
    "port"    : [21,  80,  443, 22,  8080,443, 3306,8080,80,  25,  110, 21,  22 ],
    "priority": [
        "Immediate","Immediate","Immediate","Immediate","High",
        "High","High","Medium","Medium","Medium","Low","Low","Low"
    ],
}
import pandas as _pd
_ml_df    = _pd.DataFrame(_ML_DATA)
_ml_model = DecisionTreeClassifier(random_state=42)
_ml_model.fit(_ml_df[["cvss","exploit","port"]], _ml_df["priority"])

def ml_predict_priority(cvss: float, exploit_available: bool, port: int) -> str:
    """Use trained DecisionTree to predict remediation priority."""
    try:
        pred = _ml_model.predict([[cvss, int(exploit_available), port]])[0]
        return pred
    except Exception:
        if cvss >= 9.0: return "Immediate"
        if cvss >= 7.0: return "High"
        if cvss >= 4.0: return "Medium"
        return "Low"

PRIORITY_ORDER = ["Immediate", "High", "Medium", "Low"]
PRIORITY_COLORS = {
    "Immediate": "#e74c3c",
    "High"     : "#e67e22",
    "Medium"   : "#f1c40f",
    "Low"      : "#2ecc71",
}

# ─── EXPLOIT CHECK (SearchSploit) ─────────────────────────────
def check_exploit_available(cve_id: str) -> bool:
    """Check if an exploit exists in SearchSploit for a given CVE."""
    try:
        result = subprocess.run(
            ["searchsploit", "--cve", cve_id],
            capture_output=True, text=True, timeout=10
        )
        return "Exploit Title" in result.stdout
    except Exception:
        return False

# ─── REMEDIATION ADVICE ───────────────────────────────────────
REMEDIATION_MAP = {
    "vsftpd"     : "Upgrade vsftpd immediately. CVE-2011-2523 allows unauthenticated remote shell. Disable if not needed.",
    "openssh"    : "Upgrade OpenSSH. Enforce key-based auth, disable root login (PermitRootLogin no).",
    "apache"     : "Upgrade Apache httpd. Disable directory listing, review mod_status exposure.",
    "tomcat"     : "Update Apache Tomcat and secure AJP connector (disable if unused).",
    "mysql"      : "Upgrade MySQL. Restrict remote root login. Use strong credentials.",
    "samba"      : "Upgrade Samba. Disable SMBv1. Restrict share permissions.",
    "php"        : "Upgrade PHP. Disable dangerous functions (exec, shell_exec) in php.ini.",
    "nginx"      : "Upgrade nginx. Review proxy settings and disable server tokens.",
    "iis"        : "Apply latest Windows/IIS patches. Disable WebDAV if not needed.",
    "default"    : "Apply vendor patches, restrict network access, review service configuration.",
}

def get_remediation(service: str) -> str:
    svc = service.lower()
    for key, advice in REMEDIATION_MAP.items():
        if key in svc:
            return advice
    return REMEDIATION_MAP["default"]'''

if OLD2 in content:
    content = content.replace(OLD2, NEW2)
    patches_applied.append("PATCH 2: ML model + exploit check + remediation")

# ─────────────────────────────────────────────
# PATCH 3 — Replace fetch_nvd with parallel version + exploit check
# ─────────────────────────────────────────────
OLD3 = '''def fetch_nvd(service: str, version: str, log_fn) -> list:'''
NEW3 = '''def fetch_nvd_single(service: str, version: str) -> list:
    """Fetch CVEs from NVD for one service (used in parallel)."""
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
    try:
        r = requests.get(NVD_API, params={"keywordSearch": keyword, "resultsPerPage": 5}, timeout=15)
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []
    cves = []
    for item in data.get("vulnerabilities", []):
        cve_obj = item.get("cve", {})
        cve_id  = cve_obj.get("id", "N/A")
        desc    = next((d["value"] for d in cve_obj.get("descriptions", []) if d.get("lang") == "en"),
                       "No description.")
        cvss = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = cve_obj.get("metrics", {}).get(key, [])
            if m:
                try: cvss = m[0]["cvssData"]["baseScore"]; break
                except: pass
        cves.append({"cve_id": cve_id, "cvss_score": cvss,
                     "severity": classify_severity(cvss), "description": desc[:280]})
    return cves


def fetch_nvd(service: str, version: str, log_fn) -> list:'''

if 'def fetch_nvd(service: str, version: str, log_fn) -> list:' in content and 'fetch_nvd_single' not in content:
    content = content.replace(OLD3, NEW3)
    patches_applied.append("PATCH 3: parallel fetch_nvd")

# ─────────────────────────────────────────────
# PATCH 4 — Replace run_module3 with parallel + ML version
# ─────────────────────────────────────────────
OLD4 = '''def run_module3(parsed: dict, log_fn) -> dict:
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
    }'''

NEW4 = '''def run_module3(parsed: dict, log_fn) -> dict:
    services = parsed.get("services", [])
    target   = parsed.get("target", "unknown")
    vulns    = []
    risk     = {"critical":0,"high":0,"medium":0,"low":0,"unknown":0}

    log_fn(f"Running parallel CVE lookup for {len(services)} services...")

    def process_service(svc):
        service = svc.get("service","")
        version = svc.get("version","")
        port    = svc.get("port", 0)
        proto   = svc.get("proto","tcp")
        if not service:
            return None

        cves = fetch_nvd_single(service, version)
        time.sleep(0.5)
        if not cves:
            return None

        best    = max(cves, key=lambda c: c["cvss_score"])
        sev     = best["severity"]
        cve_id  = best["cve_id"]

        # Check exploit availability via SearchSploit
        exploit_available = check_exploit_available(cve_id)

        # ML priority prediction
        ml_priority = ml_predict_priority(best["cvss_score"], exploit_available, port)

        return {
            "service"          : service,
            "version"          : version,
            "port"             : port,
            "proto"            : proto,
            "cve"              : cve_id,
            "all_cves"         : [c["cve_id"] for c in cves],
            "cvss_score"       : best["cvss_score"],
            "severity"         : sev,
            "confidence"       : "High" if best["cvss_score"] >= 7 else "Medium",
            "description"      : best["description"],
            "exploit_available": exploit_available,
            "exploit_reference": f"SearchSploit: {cve_id}" if exploit_available else "None found",
            "ml_priority"      : ml_priority,
            "remediation"      : get_remediation(service),
        }

    # Parallel execution
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(process_service, services))

    for r in results:
        if r is None:
            continue
        log_fn(f"  [{r['ml_priority']}] {r['service']} {r['version']} → {r['cve']} CVSS {r['cvss_score']}")
        vulns.append(r)
        sev_key = r["severity"].lower()
        risk[sev_key if sev_key in risk else "unknown"] += 1

    # Sort by ML priority first, then CVSS
    priority_rank = {p: i for i, p in enumerate(PRIORITY_ORDER)}
    vulns.sort(key=lambda v: (priority_rank.get(v.get("ml_priority","Low"), 3), -v["cvss_score"]))

    weights = {"critical":10,"high":7,"medium":4,"low":1,"unknown":2}
    raw     = sum(risk[k] * weights[k] for k in weights)
    score   = min(100, int((raw / max(len(services),1)) * 10))

    log_fn(f"Module 3 complete — {len(vulns)} vulnerabilities found")
    return {
        "target"         : target,
        "scan_time"      : datetime.now(timezone.utc).isoformat(),
        "total_services" : len(services),
        "vulnerabilities": vulns,
        "risk_summary"   : {**risk, "overall_risk_score": score},
    }'''

if OLD4 in content:
    content = content.replace(OLD4, NEW4)
    patches_applied.append("PATCH 4: ML + parallel Module 3")

# ─────────────────────────────────────────────
# PATCH 5 — Fix PDF title overlap
# ─────────────────────────────────────────────
OLD5 = '''    # Header
    pdf.set_fill_color(10, 10, 20)
    pdf.rect(0, 0, 210, 20, "F")
    pdf.set_font("Helvetica","B",14)
    pdf.set_text_color(0,255,100)
    pdf.cell(0,20,"Vuln_VAS - Security Assessment Report",align="C")
    pdf.ln(8)

    pdf.set_text_color(30,30,30)
    pdf.set_font("Helvetica","",10)
    pdf.cell(0,6,f"Target: {report.get('target','N/A')}   |   {report.get('scan_time','N/A')}",ln=True,align="C")
    pdf.ln(6)'''

NEW5 = '''    # Header — fixed overlap
    pdf.set_fill_color(10, 10, 20)
    pdf.rect(0, 0, 210, 24, "F")
    pdf.set_y(6)
    pdf.set_font("Helvetica","B",13)
    pdf.set_text_color(0,200,80)
    pdf.cell(0, 12, "Vuln_VAS - Security Assessment Report", align="C", ln=True)
    pdf.ln(6)

    pdf.set_text_color(60,60,60)
    pdf.set_font("Helvetica","",9)
    target_str = report.get("target","N/A")[:50]
    time_str   = report.get("scan_time","N/A")[:19].replace("T"," ")
    pdf.cell(0, 6, f"Target: {target_str}   |   Scanned: {time_str}", align="C", ln=True)
    pdf.ln(5)'''

if OLD5 in content:
    content = content.replace(OLD5, NEW5)
    patches_applied.append("PATCH 5: PDF header fix")

# ─────────────────────────────────────────────
# PATCH 6 — Add ML Priority column to vulnerability expanders
# ─────────────────────────────────────────────
OLD6 = '''                with st.expander(f"{icon}  {v['service']} {v['version']}  ·  {v.get('cve','N/A')}  ·  CVSS {v.get('cvss_score',0):.1f}  ·  Port {v.get('port','?')}"):
                    r1,r2,r3,r4 = st.columns(4)
                    r1.markdown(f"**Severity**<br>{severity_badge_html(sev)}", unsafe_allow_html=True)
                    r2.markdown(f"**CVSS Score**<br>`{v.get('cvss_score',0):.1f} / 10`", unsafe_allow_html=True)
                    r3.markdown(f"**Confidence**<br>`{v.get('confidence','N/A')}`", unsafe_allow_html=True)
                    r4.markdown(f"**Port**<br>`{v.get('port','N/A')}/{v.get('proto','tcp')}`", unsafe_allow_html=True)

                    st.markdown(f"**CVE:** [{v.get('cve','N/A')}](https://nvd.nist.gov/vuln/detail/{v.get('cve','')})")
                    st.markdown(f"**All CVEs:** `{'  ·  '.join(v.get('all_cves',[v.get('cve','N/A')]))}`")
                    st.markdown(f"**Description:** {v.get('description','')}")
                    st.info(f"💡 **Recommendation:** {get_rec(v.get('service',''))}") '''

NEW6 = '''                ml_pri = v.get("ml_priority","N/A")
                pri_icon = {"Immediate":"🚨","High":"🔴","Medium":"🟡","Low":"🟢"}.get(ml_pri,"⚪")
                with st.expander(f"{icon}  {v['service']} {v['version']}  ·  {v.get('cve','N/A')}  ·  CVSS {v.get('cvss_score',0):.1f}  ·  {pri_icon} {ml_pri}  ·  Port {v.get('port','?')}"):
                    r1,r2,r3,r4,r5 = st.columns(5)
                    r1.markdown(f"**Severity**<br>{severity_badge_html(sev)}", unsafe_allow_html=True)
                    r2.markdown(f"**CVSS Score**<br>`{v.get('cvss_score',0):.1f} / 10`", unsafe_allow_html=True)
                    r3.markdown(f"**ML Priority**<br>`{ml_pri}`", unsafe_allow_html=True)
                    r4.markdown(f"**Exploit**<br>`{'✅ Yes' if v.get('exploit_available') else '❌ No'}`", unsafe_allow_html=True)
                    r5.markdown(f"**Port**<br>`{v.get('port','N/A')}/{v.get('proto','tcp')}`", unsafe_allow_html=True)

                    st.markdown(f"**CVE:** [{v.get('cve','N/A')}](https://nvd.nist.gov/vuln/detail/{v.get('cve','')})")
                    st.markdown(f"**All CVEs:** `{'  ·  '.join(v.get('all_cves',[v.get('cve','N/A')]))}`")
                    st.markdown(f"**Description:** {v.get('description','')}")
                    st.markdown(f"**Exploit Reference:** `{v.get('exploit_reference','None')}`")
                    st.info(f"💡 **Recommendation:** {v.get('remediation', get_rec(v.get('service','')))}") '''

if OLD6 in content:
    content = content.replace(OLD6, NEW6)
    patches_applied.append("PATCH 6: ML priority in expanders")

# ─────────────────────────────────────────────
# PATCH 7 — Add ML Priority column to threat table
# ─────────────────────────────────────────────
OLD7 = '''            df_table = pd.DataFrame([{
                "#"           : i+1,
                "Service"     : v["service"],
                "Version"     : v["version"],
                "Port"        : v["port"],
                "CVE"         : v.get("cve","N/A"),
                "CVSS"        : v.get("cvss_score",0),
                "Severity"    : v.get("severity","Unknown"),
                "Confidence"  : v.get("confidence","N/A"),
            } for i,v in enumerate(vulns)])'''

NEW7 = '''            df_table = pd.DataFrame([{
                "#"           : i+1,
                "Service"     : v["service"],
                "Version"     : v["version"],
                "Port"        : v["port"],
                "CVE"         : v.get("cve","N/A"),
                "CVSS"        : v.get("cvss_score",0),
                "Severity"    : v.get("severity","Unknown"),
                "ML Priority" : v.get("ml_priority","N/A"),
                "Exploit"     : "✅" if v.get("exploit_available") else "❌",
                "Confidence"  : v.get("confidence","N/A"),
            } for i,v in enumerate(vulns)])'''

if OLD7 in content:
    content = content.replace(OLD7, NEW7)
    patches_applied.append("PATCH 7: ML priority in table")

# ─────────────────────────────────────────────
# PATCH 8 — Add ML Priority chart to Dashboard tab
# ─────────────────────────────────────────────
OLD8 = '''        # Threat priority table
        st.markdown("#### Prioritised Threat Table")'''

NEW8 = '''        # ML Priority Distribution chart
        if vulns:
            st.markdown("#### ML Priority Distribution")
            pri_counts = {}
            for v in vulns:
                p = v.get("ml_priority","Unknown")
                pri_counts[p] = pri_counts.get(p, 0) + 1
            fig_pri = go.Figure(go.Bar(
                x=list(pri_counts.keys()),
                y=list(pri_counts.values()),
                marker_color=[PRIORITY_COLORS.get(k,"#95a5a6") for k in pri_counts.keys()],
                text=list(pri_counts.values()),
                textposition="outside",
            ))
            fig_pri.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#c9d1d9", margin=dict(t=10,b=10),
                xaxis=dict(gridcolor="#1a2332"), yaxis=dict(gridcolor="#1a2332"),
                height=220,
            )
            st.plotly_chart(fig_pri, use_container_width=True)

        # Threat priority table
        st.markdown("#### Prioritised Threat Table")'''

if OLD8 in content:
    content = content.replace(OLD8, NEW8)
    patches_applied.append("PATCH 8: ML priority chart")

# ─────────────────────────────────────────────
# WRITE & REPORT
# ─────────────────────────────────────────────
open("app.py", "w").write(content)

print(f"\n{'='*50}")
print(f"  {len(patches_applied)} patches applied:")
for p in patches_applied:
    print(f"  ✅ {p}")
print(f"{'='*50}\n")

if len(patches_applied) < 8:
    missing = 8 - len(patches_applied)
    print(f"⚠️  {missing} patch(es) not applied (pattern may already exist or differ)")
    print("Run: streamlit run app.py to test what works\n")
else:
    print("🎉 All patches applied! Run: streamlit run app.py\n")
