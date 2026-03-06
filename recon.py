"""
Recon & Scanning Module (Suhail's Team Part)
--------------------------------------------
Safe, modular reconnaissance library for the "AutoPwn Web" project.
Includes real-time logging for terminal feedback.
"""

from typing import List, Dict, Any, Optional
import subprocess
import requests
import re
import logging
from bs4 import BeautifulSoup
import nmap  # Requires 'pip install python-nmap' AND Nmap installed on OS

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("ReconModule")

def _run_cmd(cmd: list, timeout: Optional[int] = None) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return {"stdout": p.stdout, "stderr": p.stderr, "rc": p.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "rc": -1}
    except FileNotFoundError as e:
        return {"stdout": "", "stderr": f"Not found: {e}", "rc": 127}


def nikto_scan(url: str, timeout: int = 600) -> List[str]:
    """Call Nikto to find server misconfigurations and outdated software."""
    logger.info(f"Starting Nikto scan on {url}...")
    
    # -h: host, -Tuning: 123c (Interesting files, config, web ports), -nointeractive
    cmd = ["nikto", "-h", url, "-Tuning", "123c", "-nointeractive"]
    
    # Simple SSL logic for Nikto
    if url.startswith("https"):
        cmd.append("-ssl")
    else:
        cmd.append("-nossl")

    res = _run_cmd(cmd, timeout=timeout)
    findings = []
    
    for line in res.get("stdout", "").splitlines():
        line = line.strip()
        if line.startswith("+"):
            findings.append(line.lstrip("+ ").strip())
            
    logger.info(f"Nikto scan complete. Found {len(findings)} items.")
    return findings


def feroxbuster_scan(base_url: str, wordlist: Optional[str] = None, threads: int = 50,
                     extensions: Optional[List[str]] = None, timeout: int = 900) -> List[Dict[str, Any]]:
    logger.info(f"Starting Feroxbuster directory discovery on {base_url}...")
    cmd = ["feroxbuster", "-u", base_url, "-q", "--no-color", "-t", str(threads)]
    if wordlist:
        cmd += ["-w", wordlist]
    if extensions:
        cmd += ["-x", ",".join(extensions)]
        
    res = _run_cmd(cmd, timeout=timeout)
    findings = []
    line_re = re.compile(r"^\s*(\d{3})\s+([A-Z]+)\s+[\d\w]+\w*\s+\S+\s+\S+\s+(.*)$")
    
    for line in res.get("stdout", "").splitlines():
        m = line_re.match(line.strip())
        if m:
            findings.append({
                "status": int(m.group(1)),
                "method": m.group(2),
                "url": m.group(3).strip()
            })
            
    logger.info(f"Feroxbuster complete. Discovered {len(findings)} paths.")
    return findings


def nmap_scan(target: str, args: str = "-sV -T4", timeout: Optional[int] = None) -> Dict[str, Any]:
    logger.info(f"Starting Nmap service detection on {target}...")
    nm = nmap.PortScanner()
    nm.scan(targets=target, arguments=args)
    
    out: Dict[str, Any] = {}
    for host in nm.all_hosts():
        out[host] = {"status": nm[host].state(), "protocols": {}}
        for proto in nm[host].all_protocols():
            out[host]["protocols"][proto] = {}
            for port in nm[host][proto].keys():
                out[host]["protocols"][proto][port] = nm[host][proto][port]
                
    logger.info(f"Nmap scan complete for {target}.")
    return out


def http_fingerprint(url: str, timeout: int = 10) -> Dict[str, Any]:
    logger.info(f"Fingerprinting HTTP headers for {url}...")
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No Title"
        
        data = {
            "final_url": r.url,
            "status_code": r.status_code,
            "server": r.headers.get("Server", "Unknown"),
            "title": title,
            "headers": dict(r.headers),
        }
        logger.info(f"Fingerprint successful: {data['server']} | {title}")
        return data
    except Exception as e:
        logger.error(f"Fingerprint failed: {e}")
        return {"error": str(e)}


def _guess_base_url(host: str, prefer_https: bool = False) -> str:
    if host.startswith(("http://", "https://")):
        return host
    return f"{'https' if prefer_https else 'http'}://{host}"


def run_all_recon(target: str,
                 prefer_https: bool = False,
                 ferox_opts: Optional[Dict[str, Any]] = None,
                 nmap_args: str = "-sV -T4") -> Dict[str, Any]:
    """
    Unified entry point for the Web Reconnaissance module.
    """
    logger.info(f"--- Starting Full Recon Project: {target} ---")
    ferox_opts = ferox_opts or {}
    base_url = _guess_base_url(target, prefer_https=prefer_https)

    # 1. Basic Fingerprint
    http_info = http_fingerprint(base_url)

    # 2. Port Scanning
    nm_data = nmap_scan(target, args=nmap_args)

    # If the web server is up, run deep web tools
    nikto_findings = []
    paths = []
    
    if "error" not in http_info:
        # 3. Web Vulnerability/Config Scanning (Nikto)
        nikto_findings = nikto_scan(base_url)

        # 4. Directory Brute Forcing (Feroxbuster)
        paths = feroxbuster_scan(base_url, **ferox_opts)
    else:
        logger.warning("Target HTTP appears down. Skipping Nikto and Feroxbuster.")

    # Build structured services for the Vuln Team
    services = []
    for host, info in nm_data.items():
        for proto, ports in info.get("protocols", {}).items():
            for port, pinfo in ports.items():
                services.append({
                    "service": (pinfo.get("product") or pinfo.get("name", "")).strip(),
                    "version": pinfo.get("version", "").strip(),
                    "port": port,
                    "proto": proto
                })

    logger.info(f"--- Recon Project for {target} Completed ---")
    return {
        "target": target,
        "base_url": base_url,
        "http": http_info,
        "nmap": nm_data,
        "services": services,
        "paths": paths,
        "nikto": nikto_findings,
        "meta": {"notes": "Authorization required."}
    }
