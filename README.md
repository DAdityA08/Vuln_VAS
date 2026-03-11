# 🛡️ Vuln_VAS — Automated Web Application Vulnerability Assessment System

> **A lightweight, modular, student-friendly penetration testing framework that automates reconnaissance, vulnerability mapping, and security reporting into a single unified pipeline.**

---

Website Link :- https://vulnvas.streamlit.app/

## 📌 Project Info

| Field | Details |
|-------|---------|
| **Institution** | Alliance School of Advanced Computing, Alliance University |
| **Domain** | Cyber Security |
| **Year** | 3rd Year Design Project |
| **Team** | Victor Vikeeth Lobo · D Aditya · Mohammed Suhail · Sahil |
| **Faculty Guide** | Dr. Smitha Rajagopal |

---

## 🎯 What is Vuln_VAS?

Traditional web application penetration testing requires juggling multiple tools — Nmap, Feroxbuster, SearchSploit, CVE databases — and manually correlating their results. This is time-consuming, inconsistent, and difficult for beginners.

**Vuln_VAS** solves this by integrating the entire workflow into a single automated pipeline:

```
Target IP / Hostname
        ↓
[ Module 1 ] Reconnaissance     → Nmap scan, HTTP fingerprint
        ↓
[ Module 2 ] Data Parsing       → Normalize and structure results
        ↓
[ Module 3 ] Vulnerability Analysis → NVD API + SearchSploit CVE lookup
        ↓
[ Module 4 ] Report Generation  → Streamlit dashboard + PDF + JSON export
```

---

## ✨ Key Features

- **One-click full scan** — enter a target IP/hostname and run all 4 modules automatically
- **Live module progress tracker** — see exactly which module is running in real time
- **NVD API integration** — fetches real CVEs with CVSS scores for discovered services
- **SearchSploit / Exploit-DB lookup** — identifies known public exploits
- **CVSS-based threat prioritization** — Critical → High → Medium → Low
- **Interactive Streamlit dashboard** — severity charts, risk gauge, filterable vuln table
- **PDF + JSON export** — professional security reports ready for documentation
- **Ethical safeguards** — consent checkbox and whitelist-based scanning enforced
- **Service name normalization** — maps Nmap output to correct NVD search terms

---

## 🗂️ Project Structure

```
Vuln_VAS/
│
├── app.py                           ← Full automated UI (run this)
├── recon.py                         ← Module 1: Reconnaissance
├── recon_module.py                  ← Module 1: Recon helpers
├── vulnerability_module.py          ← Module 2: Data parsing
├── vulnerability_analysis_module.py ← Module 3: CVE analysis (standalone)
├── reporting_module.py              ← Module 4: PDF/HTML reporting (standalone)
├── main.py                          ← CLI orchestrator (all 4 modules)
├── requirements.txt                 ← Python dependencies
└── README.md
```

---

## ⚙️ Technology Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Streamlit |
| **Backend** | Python 3 |
| **Network Recon** | Nmap, python-nmap |
| **Directory Discovery** | Feroxbuster |
| **Vulnerability DB** | NVD API (NIST), Exploit-DB, SearchSploit |
| **Visualization** | Plotly, Pandas |
| **Report Generation** | fpdf2 |

---

## 🚀 Installation & Setup

### Prerequisites

```bash
# Update system
sudo apt update

# Install Nmap (required for Module 1)
sudo apt install nmap -y

# Install Feroxbuster (optional - for directory discovery)
sudo apt install feroxbuster -y

# Install SearchSploit (optional - for exploit lookup)
sudo apt install exploitdb -y
```

### Install Python Dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

Or manually:

```bash
pip install streamlit plotly pandas fpdf2 requests python-nmap --break-system-packages
```

---

## ▶️ How to Run

### Option 1 — Full Automated UI (Recommended)

```bash
cd Vuln_VAS
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

1. Enter a target IP or hostname (e.g. `192.168.56.101`)
2. Check the **authorization consent** checkbox
3. Click **LAUNCH FULL SCAN**
4. Watch all 4 modules run automatically
5. View results across 5 tabs
6. Download PDF or JSON report

### Option 2 — CLI (All 4 modules)

```bash
python main.py 192.168.56.101
```

Skip recon and use existing JSON:

```bash
python main.py 192.168.56.101 --skip-recon --recon-file recon_output.json
```

### Option 3 — Module 3 Standalone

```bash
python vulnerability_analysis_module.py test_recon.json
```

### Option 4 — Launch Dashboard Only

```bash
streamlit run reporting_module.py
```

---

## 🧪 Test Targets (Legal & Authorized)

| Target | Description |
|--------|-------------|
| `192.168.56.101` | Metasploitable 2 VM (local VirtualBox lab) |
| `scanme.nmap.org` | Nmap's official test server |
| `testphp.vulnweb.com` | Acunetix intentionally vulnerable PHP site |
| `testfire.net` | IBM demo vulnerable banking app |
| `localhost` | OWASP Juice Shop (if running locally) |

> ⚠️ **Only scan systems you own or have explicit written authorization to test. Unauthorized scanning is illegal.**

---

## 📊 Module Breakdown

### Module 1 — Reconnaissance
- Runs `nmap -sV -T4 --open` to detect open ports and service versions
- Performs HTTP fingerprinting (server header, status code)
- Falls back to demo services if Nmap is unavailable

### Module 2 — Data Parsing
- Normalizes and cleans Nmap output
- Extracts structured `{service, version, port, proto}` records
- Prepares data for CVE lookup

### Module 3 — Vulnerability Analysis
- Queries **NVD API** (`services.nvd.nist.gov`) per service+version
- Runs **SearchSploit** for Exploit-DB references
- Applies service name normalization (e.g. `Apache Tomcat/Coyote JSP engine` → `Apache Tomcat`)
- Selects highest CVSS score as primary CVE
- Classifies severity: Critical (≥9.0) · High (≥7.0) · Medium (≥4.0) · Low (>0)
- Calculates overall risk score (0–100)

### Module 4 — Reporting & Visualization
- **Streamlit dashboard** with severity pie chart, risk gauge, CVSS bar chart
- **Filterable vulnerability table** with sort by CVSS / severity / service
- **Per-finding expanders** with CVE links, descriptions, and remediation advice
- **PDF export** — professional security report
- **JSON export** — machine-readable findings

---

## 📸 Sample Output

```
[*] Module 3 – Vulnerability Analysis started for 192.168.56.101
  [+] Analysing: vsftpd 2.3.4 (port 21/tcp)
      Querying NVD for: vsftpd 2.3.4
      NVD returned 23 results
      → CVE-2011-2523  CVSS: 10.0  [Critical]

  [+] Analysing: OpenSSH 4.7p1 (port 22/tcp)
      → CVE-1999-0661  CVSS: 10.0  [Critical]

  [+] Analysing: Apache httpd 2.4.54 (port 80/tcp)
      → CVE-2022-23943  CVSS: 7.5   [High]

[✓] Module 3 complete – 3 vulnerabilities found
[✓] Analysis report saved → vuln_analysis_192_168_56_101.json
```

---

## 🔮 Future Enhancements

- [ ] AI/ML-based vulnerability prediction
- [ ] CI/CD pipeline integration for continuous scanning
- [ ] Advanced false positive filtering using ML heuristics
- [ ] Cloud deployment support (AWS/GCP)
- [ ] Enhanced dashboard analytics and trend tracking
- [ ] Metasploit PoC integration with human-in-the-loop verification

---

## 📄 Algorithms Used

| Algorithm | Purpose |
|-----------|---------|
| Service–Vulnerability Mapping | Maps discovered services to NVD CVE records |
| CVSS-based Prioritization | Ranks vulnerabilities by severity score |
| Service Name Normalization | Translates Nmap product names to NVD-searchable terms |
| Heuristic Risk Scoring | Calculates weighted overall risk score (0–100) |

---

## 🤝 SDG Alignment

- **SDG 9** — Industry, Innovation & Infrastructure: promotes secure digital systems
- **SDG 4** — Quality Education: student-friendly cybersecurity learning tool

---

## ⚖️ Disclaimer

Vuln_VAS is developed for **educational and authorized security testing purposes only**. All scanning must be performed on systems you own or have explicit written permission to test. The authors accept no liability for misuse of this tool.

---

## 📬 Contact

**D Aditya** — [GitHub: DAdityA08](https://github.com/DAdityA08)
