from typing import List, Dict, Any, Optional
import subprocess
import requests
import re
import logging
from bs4 import BeautifulSoup
import nmap
import json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("ReconModule")


def _run_cmd(cmd: list, timeout: Optional[int] = None):

    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

        return {
            "stdout": p.stdout,
            "stderr": p.stderr,
            "rc": p.returncode
        }

    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "rc": -1}

    except FileNotFoundError as e:
        return {"stdout": "", "stderr": str(e), "rc": 127}


def nikto_scan(url: str):

    logger.info(f"Running Nikto on {url}")

    cmd = ["nikto", "-h", url]

    res = _run_cmd(cmd)

    findings = []

    for line in res["stdout"].splitlines():

        if line.startswith("+"):
            findings.append(line.strip("+ ").strip())

    return findings


def feroxbuster_scan(url: str):

    logger.info(f"Running Feroxbuster on {url}")

    cmd = [
        "feroxbuster",
        "-u", url,
        "-q",
        "--no-color"
    ]

    res = _run_cmd(cmd)

    results = []

    for line in res["stdout"].splitlines():

        if "http" in line:
            parts = line.split()

            try:
                results.append({
                    "status": parts[0],
                    "url": parts[-1]
                })
            except:
                pass

    return results


def nmap_scan(target: str):

    logger.info(f"Running Nmap scan on {target}")

    nm = nmap.PortScanner()

    nm.scan(target, arguments="-sV -T4")

    results = {}

    for host in nm.all_hosts():

        results[host] = {"protocols": {}}

        for proto in nm[host].all_protocols():

            results[host]["protocols"][proto] = {}

            for port in nm[host][proto]:

                results[host]["protocols"][proto][port] = nm[host][proto][port]

    return results


def http_fingerprint(url):

    logger.info(f"HTTP fingerprinting {url}")

    try:

        r = requests.get(url, timeout=10)

        soup = BeautifulSoup(r.text, "html.parser")

        title = soup.title.string.strip() if soup.title else ""

        return {
            "status_code": r.status_code,
            "server": r.headers.get("Server"),
            "title": title
        }

    except Exception as e:

        return {"error": str(e)}


def run_all_recon(target):

    base_url = f"http://{target}"

    http_info = http_fingerprint(base_url)

    nmap_data = nmap_scan(target)

    nikto = nikto_scan(base_url)

    paths = feroxbuster_scan(base_url)

    services = []

    for host in nmap_data:

        for proto in nmap_data[host]["protocols"]:

            for port in nmap_data[host]["protocols"][proto]:

                svc = nmap_data[host]["protocols"][proto][port]

                services.append({
                    "service": svc.get("product") or svc.get("name"),
                    "version": svc.get("version"),
                    "port": port
                })

    return {
        "target": target,
        "http": http_info,
        "services": services,
        "paths": paths,
        "nikto": nikto
    }
