"""
Recon & Scanning Module (Suhail's Team Part)
--------------------------------------------
Safe, modular reconnaissance library for the "AutoPwn Web" project.

Functions (import these in your app/UI):
- feroxbuster_scan(base_url, wordlist=None, threads=50, extensions=None, timeout=900)
- crtsh_subdomains(domain, timeout=20)
- nmap_scan(target, args="-sV -T4", timeout=None)
- http_fingerprint(url, timeout=10)
- run_all_recon(target, prefer_https=False, ferox_opts=None, nmap_args="-sV -T4")

Notes:
- This module does NOT perform exploitation.
- Use only on systems you own or have explicit written permission to test.
"""

from typing import List, Dict, Any, Optional
import subprocess
import requests
import re
import json
from bs4 import BeautifulSoup
import nmap

def _run_cmd(cmd: list, timeout: Optional[int] = None) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return {"stdout": p.stdout, "stderr": p.stderr, "rc": p.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "rc": -1}
    except FileNotFoundError as e:
        return {"stdout": "", "stderr": f"Not found: {e}", "rc": 127}


def feroxbuster_scan(base_url: str, wordlist: Optional[str] = None, threads: int = 50,
                     extensions: Optional[List[str]] = None, timeout: int = 900) -> List[Dict[str, Any]]:
    """
    Call feroxbuster to brute-force directories/files.
    Returns list of findings: [{status, meth, url, path, length}, ...]
    """
    cmd = ["feroxbuster", "-u", base_url, "-q", "--no-color", "-t", str(threads)]
    if wordlist:
        cmd += ["-w", wordlist]
    if extensions:
        cmd += ["-x", ",".join(extensions)]
    res = _run_cmd(cmd, timeout=timeout)

    findings = []
    line_re = re.compile(r"^\s*(\d{3})\s+([A-Z]+)\s+[\d\w]+\w*\s+\S+\s+\S+\s+(.*)$")
    # Common format: "200        GET    11l     1w      12K  http://host/path"
    for line in res.get("stdout", "").splitlines():
        m = line_re.match(line.strip())
        if m:
            status = int(m.group(1))
            method = m.group(2)
            url = m.group(3).strip()
            path = "/"
            try:
                # extract path from URL if present
                from urllib.parse import urlparse
                path = urlparse(url).path or "/"
            except Exception:
                pass
            findings.append({"status": status, "method": method, "url": url, "path": path})
        else:
            # Fallback: if a line ends with a path-like token
            if "http://" in line or "https://" in line:
                url = line.strip().split()[-1]
                try:
                    from urllib.parse import urlparse
                    p = urlparse(url)
                    path = p.path or "/"
                except Exception:
                    path = "/"
                findings.append({"status": None, "method": None, "url": url, "path": path})
    return findings


def crtsh_subdomains(domain: str, timeout: int = 20) -> List[str]:
    """
    Enumerate subdomains via crt.sh (best-effort).
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        subs = set()
        for rec in r.json():
            name = rec.get("name_value")
            if not name:
                continue
            for n in str(name).split("\\n"):
                n = n.strip()
                if n and "*" not in n:
                    subs.add(n.lower())
        return sorted(subs)
    except Exception:
        return []


def nmap_scan(target: str, args: str = "-sV -T4", timeout: Optional[int] = None) -> Dict[str, Any]:
    """
    Run nmap using python-nmap and return a simple JSON-like dict.
    """
    nm = nmap.PortScanner()
    # python-nmap doesn't expose timeout here; use args responsibly.
    nm.scan(targets=target, arguments=args)
    out: Dict[str, Any] = {}
    for host in nm.all_hosts():
        out[host] = {"status": nm[host].state(), "protocols": {}}
        for proto in nm[host].all_protocols():
            out[host]["protocols"][proto] = {}
            for port in nm[host][proto].keys():
                out[host]["protocols"][proto][port] = nm[host][proto][port]
    return out


def http_fingerprint(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Fetch one URL and extract headers + <title>.
    """
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = dict(r.headers)
        server = headers.get("Server", "")
        powered_by = headers.get("X-Powered-By", "")
        title = ""
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
        except Exception:
            pass
        return {
            "final_url": r.url,
            "status_code": r.status_code,
            "server": server,
            "powered_by": powered_by,
            "title": title,
            "headers": headers,
        }
    except Exception as e:
        return {"error": str(e)}


def _guess_base_url(host: str, prefer_https: bool = False) -> str:
    scheme = "https" if prefer_https else "http"
    if host.startswith("http://") or host.startswith("https://"):
        return host
    return f"{scheme}://{host}"


def run_all_recon(target: str,
                  prefer_https: bool = False,
                  ferox_opts: Optional[Dict[str, Any]] = None,
                  nmap_args: str = "-sV -T4") -> Dict[str, Any]:
    """
    High-level: perform HTTP fingerprint, nmap scan, feroxbuster dir enum.
    Returns a dict that other team members can feed into vuln-analysis.
    """
    ferox_opts = ferox_opts or {}
    base_url = _guess_base_url(target, prefer_https=prefer_https)

    # HTTP fingerprint
    http_info = http_fingerprint(base_url)

    # Nmap services
    nm = nmap_scan(target, args=nmap_args)

    # Directory brute force (only if HTTP seems reachable)
    paths = []
    if not http_info.get("error"):
        paths = feroxbuster_scan(base_url,
                                 wordlist=ferox_opts.get("wordlist"),
                                 threads=ferox_opts.get("threads", 50),
                                 extensions=ferox_opts.get("extensions"),
                                 timeout=ferox_opts.get("timeout", 900))

    # Build service list for the vuln team
    services = []
    for host, info in nm.items():
        for proto, ports in info.get("protocols", {}).items():
            for port, pinfo in ports.items():
                svc = pinfo.get("product") or pinfo.get("name", "")
                ver = pinfo.get("version", "")
                if svc:
                    services.append({"service": svc.strip(), "version": ver.strip(), "port": port, "proto": proto})

    return {
        "target": target,
        "base_url": base_url,
        "http": http_info,
        "nmap": nm,
        "services": services,
        "paths": paths,
        "meta": {
            "notes": "Use only with authorization. Exploitation is out of scope for this module."
        }
    }
