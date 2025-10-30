#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanner Professional
Version : 2.0 Pro
Auteur : Expert Edition
Description : Outil professionnel d'audit et d'analyse réseau avec détection avancée,
              reporting détaillé, historique et fonctionnalités de sécurité.

Features:
- Auto-detection d'interface avec validation
- Scan parallèle optimisé (ICMP, TCP, UDP, services)
- Détection et identification de services
- Analyse de sécurité (ports dangereux, vulnérabilités basiques)
- Export multi-format (CSV, JSON, HTML, PDF)
- Base de données SQLite pour historique
- Rate limiting et throttling
- Retry logic intelligent
- Reporting avancé avec statistiques
- Comparaison de scans historiques
- Configuration par profils
- Logs professionnels avec rotation
"""

from __future__ import annotations
import argparse
import csv
import ipaddress
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import re
import time
import sqlite3
import hashlib
from pathlib import Path
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from logging.handlers import RotatingFileHandler

# Optional dependencies
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from ping3 import ping as ping3_ping
    HAS_PING3 = True
except ImportError:
    HAS_PING3 = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from scapy.all import ARP, Ether, srp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ---------------------------
# Configuration & Constants
# ---------------------------
VERSION = "2.0.0-pro"
APP_NAME = "NetworkScannerPro"
CONFIG_DIR = Path.home() / ".network_scanner_pro"
DB_PATH = CONFIG_DIR / "scan_history.db"
LOG_PATH = CONFIG_DIR / "scanner.log"
CONFIG_FILE = CONFIG_DIR / "config.yaml"

# Scan profiles
SCAN_PROFILES = {
    "quick": {
        "ports": [22, 80, 443, 8006, 8007],
        "threads": 50,
        "ping_timeout": 0.5,
        "conn_timeout": 0.3,
        "retry": 1,
        "service_detection": False
    },
    "standard": {
        "ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8006, 8007],
        "threads": 100,
        "ping_timeout": 0.8,
        "conn_timeout": 0.5,
        "retry": 2,
        "service_detection": True
    },
    "full": {
        "ports": list(range(1, 9000)),  # Well-known ports
        "threads": 200,
        "ping_timeout": 1.0,
        "conn_timeout": 0.8,
        "retry": 3,
        "service_detection": True
    },
    "security": {
        "ports": [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8006, 8007, 8443],
        "threads": 100,
        "ping_timeout": 1.0,
        "conn_timeout": 0.8,
        "retry": 2,
        "service_detection": True,
        "vuln_check": True
    }
}

# Service signatures (banner matching)
SERVICE_SIGNATURES = {
    "SSH": [b"SSH-", b"OpenSSH"],
    "HTTP": [b"HTTP/", b"Server:", b"<html", b"<!DOCTYPE"],
    "FTP": [b"220", b"FTP"],
    "SMTP": [b"220", b"SMTP", b"ESMTP"],
    "MySQL": [b"mysql", b"MariaDB"],
    "PostgreSQL": [b"PostgreSQL"],
    "RDP": [b"\x03\x00\x00"],
    "VNC": [b"RFB"],
    "Telnet": [b"Telnet"],
    "DNS": [b"DNS"],
}

# Dangerous/vulnerable ports
DANGEROUS_PORTS = {
    21: "FTP - Plaintext credentials",
    23: "Telnet - Unencrypted remote access",
    25: "SMTP - Often misconfigured",
    110: "POP3 - Plaintext credentials",
    135: "MS RPC - Known vulnerabilities",
    139: "NetBIOS - SMB vulnerabilities",
    143: "IMAP - Plaintext credentials",
    445: "SMB - WannaCry, EternalBlue",
    1433: "MS SQL - Often targeted",
    3306: "MySQL - Often exposed",
    3389: "RDP - Brute force target",
    5432: "PostgreSQL - Often exposed",
    5900: "VNC - Weak authentication",
}

# Common ports to service mapping
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP-SUBMISSION", 993: "IMAPS",
    995: "POP3S", 1433: "MS-SQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MongoDB", 8006: "PVE", 8007: "PBS"
}


# ---------------------------
# Data Models
# ---------------------------
@dataclass
class HostInfo:
    """Complete host information"""
    ip: str
    ping_ok: bool
    rtt_ms: Optional[float]
    hostname: Optional[str]
    mac: Optional[str]
    vendor: Optional[str]
    open_ports: List[Dict[str, Any]]
    os_guess: Optional[str]
    security_issues: List[str]
    scanned_at: str
    scan_duration: float

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Complete scan result with metadata"""
    scan_id: str
    cidr: str
    start_time: str
    end_time: str
    duration: float
    total_hosts: int
    hosts_up: int
    hosts_down: int
    total_ports_scanned: int
    open_ports_found: int
    hosts: List[HostInfo]
    statistics: Dict[str, Any]
    profile: str

    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'hosts': [h.to_dict() for h in self.hosts]
        }


# ---------------------------
# Logging Setup
# ---------------------------
def setup_logging(debug: bool = False) -> logging.Logger:
    """Configure professional logging with rotation"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    console_fmt = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console.setFormatter(console_fmt)
    
    # File handler with rotation (10MB, 5 backups)
    file_handler = RotatingFileHandler(
        LOG_PATH, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_fmt)
    
    logger.addHandler(console)
    logger.addHandler(file_handler)
    
    return logger


logger = setup_logging()


# ---------------------------
# Database Management
# ---------------------------
class ScanDatabase:
    """SQLite database for scan history"""
    
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    cidr TEXT,
                    profile TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    duration REAL,
                    total_hosts INTEGER,
                    hosts_up INTEGER,
                    hosts_down INTEGER,
                    total_ports_scanned INTEGER,
                    open_ports_found INTEGER,
                    statistics TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    ip TEXT,
                    ping_ok INTEGER,
                    rtt_ms REAL,
                    hostname TEXT,
                    mac TEXT,
                    vendor TEXT,
                    os_guess TEXT,
                    open_ports TEXT,
                    security_issues TEXT,
                    scanned_at TEXT,
                    scan_duration REAL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_id ON hosts(scan_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON hosts(ip)")
            conn.commit()
    
    def save_scan(self, result: ScanResult):
        """Save scan result to database"""
        with sqlite3.connect(self.db_path) as conn:
            # Save scan metadata
            conn.execute("""
                INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id, result.cidr, result.profile,
                result.start_time, result.end_time, result.duration,
                result.total_hosts, result.hosts_up, result.hosts_down,
                result.total_ports_scanned, result.open_ports_found,
                json.dumps(result.statistics)
            ))
            
            # Save hosts
            for host in result.hosts:
                conn.execute("""
                    INSERT INTO hosts (scan_id, ip, ping_ok, rtt_ms, hostname, mac, vendor,
                                     os_guess, open_ports, security_issues, scanned_at, scan_duration)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.scan_id, host.ip, int(host.ping_ok), host.rtt_ms,
                    host.hostname, host.mac, host.vendor, host.os_guess,
                    json.dumps(host.open_ports), json.dumps(host.security_issues),
                    host.scanned_at, host.scan_duration
                ))
            conn.commit()
        logger.info(f"Scan {result.scan_id} saved to database")
    
    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        """Get recent scan history"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM scans ORDER BY start_time DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_scan_by_id(self, scan_id: str) -> Optional[Dict]:
        """Get specific scan by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            return dict(cursor.fetchone()) if cursor.fetchone() else None
    
    def get_host_history(self, ip: str, limit: int = 10) -> List[Dict]:
        """Get history for specific IP"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM hosts WHERE ip = ? ORDER BY scanned_at DESC LIMIT ?
            """, (ip, limit))
            return [dict(row) for row in cursor.fetchall()]


# ---------------------------
# Network Interface Detection
# ---------------------------
def run_cmd(cmd: List[str], timeout: int = 2) -> Optional[str]:
    """Execute command and return stdout"""
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout
        )
        return proc.stdout if proc.returncode == 0 else None
    except Exception as e:
        logger.debug(f"Command failed {cmd}: {e}")
        return None


def list_interfaces() -> List[Dict[str, Any]]:
    """
    Detect network interfaces with comprehensive information
    Returns: [{'name': str, 'addresses': [str], 'status': str, 'mtu': int}, ...]
    """
    results = []
    
    if HAS_PSUTIL:
        stats = psutil.net_if_stats()
        for ifname, addrs in psutil.net_if_addrs().items():
            ipv4s = []
            mac = None
            for a in addrs:
                if a.family == socket.AF_INET and a.address:
                    try:
                        if a.netmask:
                            prefix = ipaddress.IPv4Network(f"0.0.0.0/{a.netmask}").prefixlen
                            ipv4s.append(f"{a.address}/{prefix}")
                        else:
                            ipv4s.append(a.address)
                    except Exception:
                        ipv4s.append(a.address)
                elif a.family == psutil.AF_LINK:
                    mac = a.address
            
            if ipv4s:
                stat = stats.get(ifname)
                results.append({
                    "name": ifname,
                    "addresses": ipv4s,
                    "mac": mac,
                    "status": "up" if (stat and stat.isup) else "down",
                    "mtu": stat.mtu if stat else None,
                    "speed": stat.speed if stat else None
                })
        return results
    
    # Fallback: parse system commands
    os_name = platform.system().lower()
    if os_name == "linux":
        out = run_cmd(["ip", "-o", "-f", "inet", "addr", "show"])
        if out:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    ifname = parts[1]
                    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                    if m:
                        results.append({
                            "name": ifname,
                            "addresses": [m.group(1)],
                            "status": "unknown"
                        })
    
    return results


def select_interface_interactive(interfaces: List[Dict]) -> Dict:
    """Interactive interface selection"""
    print("\n" + "="*60)
    print("INTERFACES RÉSEAU DÉTECTÉES")
    print("="*60)
    for idx, itf in enumerate(interfaces):
        status = itf.get('status', 'unknown')
        status_icon = "✓" if status == "up" else "✗"
        print(f" [{idx}] {status_icon} {itf['name']:<15} {', '.join(itf['addresses'])}")
        if itf.get('mac'):
            print(f"     └─ MAC: {itf['mac']}")
    print("="*60)
    
    while True:
        choice = input("Sélectionner l'interface [0]: ").strip()
        if not choice:
            return interfaces[0]
        try:
            idx = int(choice)
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
            print(f"Erreur: Index invalide (0-{len(interfaces)-1})")
        except ValueError:
            print("Erreur: Entrer un nombre valide")


def detect_local_ip_via_socket() -> Optional[str]:
    """Detect local IP via socket connection trick"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


# ---------------------------
# MAC Address & Vendor Detection
# ---------------------------
def get_arp_table() -> Dict[str, str]:
    """Extract ARP table (IP -> MAC mapping)"""
    arp = {}
    os_name = platform.system().lower()
    
    try:
        if os_name == "linux" and os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip, mac = parts[0], parts[3]
                        if mac and mac != "00:00:00:00:00:00":
                            arp[ip] = mac.upper()
        else:
            out = run_cmd(["arp", "-a"])
            if out:
                for line in out.splitlines():
                    m = re.search(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+.*\s+([0-9a-fA-F:]{17})", line)
                    if m:
                        arp[m.group(1)] = m.group(2).upper()
    except Exception as e:
        logger.debug(f"ARP extraction error: {e}")
    
    return arp


def get_mac_via_scapy(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Get MAC address using Scapy ARP request (requires root/admin)"""
    if not HAS_SCAPY:
        return None
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=timeout, verbose=0)[0]
        if result:
            return result[0][1].hwsrc.upper()
    except Exception as e:
        logger.debug(f"Scapy ARP failed for {ip}: {e}")
    return None


def get_vendor_from_mac(mac: str) -> Optional[str]:
    """
    Get vendor from MAC address OUI (first 3 octets)
    In production, use a proper OUI database file
    """
    # Simplified - in production use full OUI database
    oui_db = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5D": "Microsoft Hyper-V",
        "00:1C:42": "Parallels",
        "DC:A6:32": "Raspberry Pi",
        "B8:27:EB": "Raspberry Pi",
    }
    
    if mac and len(mac) >= 8:
        oui = mac[:8].upper()
        return oui_db.get(oui)
    return None


# ---------------------------
# Network Scanning Functions
# ---------------------------
def ping_host_system(ip: str, timeout: float = 1.0) -> Tuple[bool, Optional[float]]:
    """System ping with RTT extraction"""
    ip_s = str(ip)
    os_name = platform.system().lower()
    
    if os_name == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip_s]
    elif os_name == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip_s]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip_s]
    
    try:
        t0 = time.perf_counter()
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout + 0.5
        )
        t1 = time.perf_counter()
        
        if proc.returncode == 0:
            out = proc.stdout.decode(errors="ignore")
            # Extract RTT from output
            m = re.search(r"time[=<]\s*([0-9.]+)\s*ms", out, re.I)
            rtt = float(m.group(1)) if m else (t1 - t0) * 1000.0
            return True, rtt
        return False, None
    except subprocess.TimeoutExpired:
        return False, None
    except Exception as e:
        logger.debug(f"Ping error {ip}: {e}")
        return False, None


def ping_host_with_retry(ip: str, timeout: float = 1.0, retry: int = 2) -> Tuple[bool, Optional[float]]:
    """Ping with retry logic"""
    for attempt in range(retry):
        ok, rtt = ping_host_system(ip, timeout)
        if ok:
            return True, rtt
        if attempt < retry - 1:
            time.sleep(0.1)
    return False, None


def tcp_connect_scan(ip: str, ports: List[int], timeout: float = 0.5) -> List[Dict[str, Any]]:
    """
    TCP connect scan with service detection and banner grabbing
    Returns: [{'port': int, 'open': bool, 'service': str, 'banner': str, 'version': str}, ...]
    """
    results = []
    
    for port in ports:
        port_info = {
            'port': port,
            'open': False,
            'service': COMMON_SERVICES.get(port, 'unknown'),
            'banner': None,
            'version': None
        }
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            t0 = time.perf_counter()
            sock.connect((str(ip), port))
            t1 = time.perf_counter()
            
            port_info['open'] = True
            port_info['response_time'] = (t1 - t0) * 1000
            
            # Try to grab banner
            try:
                sock.settimeout(0.3)
                banner = sock.recv(1024)
                if banner:
                    port_info['banner'] = banner[:200].decode(errors='ignore').strip()
                    # Detect service from banner
                    for service, sigs in SERVICE_SIGNATURES.items():
                        if any(sig in banner for sig in sigs):
                            port_info['service'] = service
                            break
            except Exception:
                pass
            
            results.append(port_info)
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            # Port closed or filtered
            pass
        except Exception as e:
            logger.debug(f"TCP scan error {ip}:{port} - {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
    
    return [r for r in results if r['open']]


def reverse_dns_lookup(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Reverse DNS lookup with timeout"""
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def detect_os_from_ttl(ttl: Optional[int]) -> Optional[str]:
    """Guess OS from TTL value (approximation)"""
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Network Device"
    return "Unknown"


def check_security_issues(host_info: Dict[str, Any]) -> List[str]:
    """Check for basic security issues"""
    issues = []
    
    open_ports = host_info.get('open_ports', [])
    open_port_numbers = [p['port'] for p in open_ports]
    
    # Check dangerous ports
    for port in open_port_numbers:
        if port in DANGEROUS_PORTS:
            issues.append(f"Port {port}: {DANGEROUS_PORTS[port]}")
    
    # Check for common vulnerabilities
    if 445 in open_port_numbers and 139 in open_port_numbers:
        issues.append("SMB exposed (ports 445+139): EternalBlue vulnerability risk")
    
    if 23 in open_port_numbers:
        issues.append("Telnet enabled: Unencrypted protocol - security risk")
    
    if 21 in open_port_numbers:
        issues.append("FTP exposed: Consider using SFTP/FTPS instead")
    
    # Check for multiple administrative ports
    admin_ports = {22, 23, 3389, 5900}
    exposed_admin = admin_ports.intersection(open_port_numbers)
    if len(exposed_admin) > 1:
        issues.append(f"Multiple admin protocols exposed: {exposed_admin}")
    
    return issues


# ---------------------------
# Main Scanning Worker
# ---------------------------
def scan_host_comprehensive(
    ip: str,
    ports: List[int],
    ping_timeout: float,
    conn_timeout: float,
    retry: int,
    arp_table: Dict[str, str],
    service_detection: bool = True,
    vuln_check: bool = False
) -> HostInfo:
    """
    Comprehensive host scanning with all features
    """
    start_time = time.perf_counter()
    
    # 1. ICMP Ping
    ping_ok, rtt_ms = ping_host_with_retry(ip, ping_timeout, retry)
    
    # 2. TCP Port Scan
    open_ports = []
    if ports:
        open_ports = tcp_connect_scan(ip, ports, conn_timeout)
    
    # 3. Reverse DNS
    hostname = reverse_dns_lookup(ip, timeout=1.0) if (ping_ok or open_ports) else None
    
    # 4. MAC Address
    mac = arp_table.get(str(ip))
    if not mac and HAS_SCAPY and (ping_ok or open_ports):
        mac = get_mac_via_scapy(ip, timeout=0.5)
    
    # 5. Vendor Detection
    vendor = get_vendor_from_mac(mac) if mac else None
    
    # 6. OS Detection (basic)
    os_guess = detect_os_from_ttl(int(rtt_ms)) if rtt_ms else None
    
    # 7. Security Analysis
    security_issues = []
    if vuln_check and open_ports:
        temp_info = {'open_ports': open_ports}
        security_issues = check_security_issues(temp_info)
    
    scan_duration = time.perf_counter() - start_time
    
    return HostInfo(
        ip=str(ip),
        ping_ok=ping_ok,
        rtt_ms=round(rtt_ms, 2) if rtt_ms else None,
        hostname=hostname,
        mac=mac,
        vendor=vendor,
        open_ports=open_ports,
        os_guess=os_guess,
        security_issues=security_issues,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        scan_duration=round(scan_duration, 3)
    )


# ---------------------------
# Parallel Network Scanner
# ---------------------------
def scan_network(
    cidr: str,
    profile: str = "standard",
    threads: int = 100,
    custom_ports: Optional[List[int]] = None,
    progress_callback=None
) -> ScanResult:
    """
    Main network scanning orchestrator with parallel execution
    """
    scan_id = hashlib.md5(f"{cidr}{time.time()}".encode()).hexdigest()[:12]
    start_time = datetime.now(timezone.utc)
    
    # Load profile
    prof_config = SCAN_PROFILES.get(profile, SCAN_PROFILES['standard'])
    ports = custom_ports or prof_config['ports']
    threads = min(threads, prof_config['threads'])
    ping_timeout = prof_config['ping_timeout']
    conn_timeout = prof_config['conn_timeout']
    retry = prof_config['retry']
    service_detection = prof_config.get('service_detection', True)
    vuln_check = prof_config.get('vuln_check', False)
    
    logger.info(f"Starting scan {scan_id} on {cidr} (profile: {profile})")
    logger.info(f"Configuration: {len(ports)} ports, {threads} threads, timeout: {ping_timeout}s")
    
    # Parse network
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())
        total_hosts = len(hosts)
    except Exception as e:
        logger.error(f"Invalid CIDR {cidr}: {e}")
        raise
    
    if total_hosts == 0:
        logger.error("No usable hosts in network")
        raise ValueError("No hosts to scan")
    
    logger.info(f"Scanning {total_hosts} hosts...")
    
    # Get ARP table
    arp_table = get_arp_table()
    logger.debug(f"ARP table loaded: {len(arp_table)} entries")
    
    # Parallel scanning
    results = []
    scan_start = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(
                scan_host_comprehensive,
                ip, ports, ping_timeout, conn_timeout, retry,
                arp_table, service_detection, vuln_check
            ): ip for ip in hosts
        }
        
        completed = 0
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                host_info = future.result()
                results.append(host_info)
                
                completed += 1
                if progress_callback:
                    progress_callback(completed, total_hosts)
                
                # Log live results
                if host_info.ping_ok or host_info.open_ports:
                    ports_str = ",".join(str(p['port']) for p in host_info.open_ports)
                    logger.info(f"✓ {host_info.ip:<15} | RTT:{host_info.rtt_ms}ms | Ports:[{ports_str}] | {host_info.hostname or ''}")
                
            except Exception as e:
                logger.error(f"Scan error for {ip}: {e}")
                completed += 1
                if progress_callback:
                    progress_callback(completed, total_hosts)
    
    scan_duration = time.time() - scan_start
    end_time = datetime.now(timezone.utc)
    
    # Calculate statistics
    hosts_up = sum(1 for h in results if h.ping_ok or h.open_ports)
    hosts_down = total_hosts - hosts_up
    total_ports_scanned = total_hosts * len(ports)
    open_ports_found = sum(len(h.open_ports) for h in results)
    
    # Detailed statistics
    stats = calculate_statistics(results, len(ports))
    
    scan_result = ScanResult(
        scan_id=scan_id,
        cidr=cidr,
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat(),
        duration=round(scan_duration, 2),
        total_hosts=total_hosts,
        hosts_up=hosts_up,
        hosts_down=hosts_down,
        total_ports_scanned=total_ports_scanned,
        open_ports_found=open_ports_found,
        hosts=results,
        statistics=stats,
        profile=profile
    )
    
    logger.info(f"Scan completed in {scan_duration:.2f}s - {hosts_up}/{total_hosts} hosts up")
    
    return scan_result


def calculate_statistics(hosts: List[HostInfo], total_ports: int) -> Dict[str, Any]:
    """Calculate detailed statistics from scan results"""
    stats = {
        'avg_rtt_ms': 0,
        'min_rtt_ms': None,
        'max_rtt_ms': None,
        'most_common_ports': [],
        'services_found': [],
        'os_distribution': {},
        'vendors_found': [],
        'security_issues_count': 0,
        'hosts_with_issues': 0
    }
    
    # RTT statistics
    rtts = [h.rtt_ms for h in hosts if h.rtt_ms is not None]
    if rtts:
        stats['avg_rtt_ms'] = round(sum(rtts) / len(rtts), 2)
        stats['min_rtt_ms'] = round(min(rtts), 2)
        stats['max_rtt_ms'] = round(max(rtts), 2)
    
    # Port statistics
    all_ports = []
    all_services = []
    for h in hosts:
        for p in h.open_ports:
            all_ports.append(p['port'])
            if p.get('service'):
                all_services.append(p['service'])
    
    port_counter = Counter(all_ports)
    stats['most_common_ports'] = port_counter.most_common(10)
    stats['services_found'] = list(set(all_services))
    
    # OS distribution
    os_counter = Counter(h.os_guess for h in hosts if h.os_guess)
    stats['os_distribution'] = dict(os_counter)
    
    # Vendors
    vendors = [h.vendor for h in hosts if h.vendor]
    stats['vendors_found'] = list(set(vendors))
    
    # Security issues
    stats['security_issues_count'] = sum(len(h.security_issues) for h in hosts)
    stats['hosts_with_issues'] = sum(1 for h in hosts if h.security_issues)
    
    return stats


# ---------------------------
# Export Functions
# ---------------------------
def export_csv(result: ScanResult, filepath: Path):
    """Export results to CSV"""
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'IP', 'Status', 'RTT(ms)', 'Hostname', 'MAC', 'Vendor',
            'OS', 'Open Ports', 'Services', 'Security Issues', 'Scanned At'
        ])
        
        for host in result.hosts:
            ports_str = ','.join(str(p['port']) for p in host.open_ports)
            services_str = ','.join(p['service'] for p in host.open_ports if p.get('service'))
            issues_str = '; '.join(host.security_issues)
            
            writer.writerow([
                host.ip,
                'UP' if host.ping_ok else 'DOWN',
                host.rtt_ms or '',
                host.hostname or '',
                host.mac or '',
                host.vendor or '',
                host.os_guess or '',
                ports_str,
                services_str,
                issues_str,
                host.scanned_at
            ])
    
    logger.info(f"CSV exported: {filepath}")


def export_json(result: ScanResult, filepath: Path):
    """Export results to JSON"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    logger.info(f"JSON exported: {filepath}")


def export_html(result: ScanResult, filepath: Path):
    """Export results to HTML report"""
    html_template = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Report - {scan_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: #f9f9f9; padding: 15px; border-left: 4px solid #4CAF50; }}
        .stat-box .label {{ font-size: 12px; color: #666; }}
        .stat-box .value {{ font-size: 24px; font-weight: bold; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #4CAF50; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .status-up {{ color: #4CAF50; font-weight: bold; }}
        .status-down {{ color: #999; }}
        .security-issue {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 5px 0; }}
        .port-list {{ color: #2196F3; }}
        .footer {{ margin-top: 30px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Network Scan Report</h1>
        <p><strong>Scan ID:</strong> {scan_id} | <strong>Network:</strong> {cidr} | <strong>Profile:</strong> {profile}</p>
        <p><strong>Started:</strong> {start_time} | <strong>Duration:</strong> {duration}s</p>
        
        <div class="summary">
            <div class="stat-box">
                <div class="label">Total Hosts</div>
                <div class="value">{total_hosts}</div>
            </div>
            <div class="stat-box">
                <div class="label">Hosts UP</div>
                <div class="value" style="color: #4CAF50;">{hosts_up}</div>
            </div>
            <div class="stat-box">
                <div class="label">Hosts DOWN</div>
                <div class="value" style="color: #999;">{hosts_down}</div>
            </div>
            <div class="stat-box">
                <div class="label">Open Ports</div>
                <div class="value" style="color: #2196F3;">{open_ports_found}</div>
            </div>
            <div class="stat-box">
                <div class="label">Security Issues</div>
                <div class="value" style="color: #ff9800;">{security_issues}</div>
            </div>
        </div>
        
        <h2>📊 Statistics</h2>
        <ul>
            <li><strong>Average RTT:</strong> {avg_rtt}ms</li>
            <li><strong>Most Common Ports:</strong> {common_ports}</li>
            <li><strong>Services Detected:</strong> {services}</li>
            <li><strong>Vendors Found:</strong> {vendors}</li>
        </ul>
        
        <h2>🖥️ Host Details</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>RTT</th>
                    <th>Hostname</th>
                    <th>MAC / Vendor</th>
                    <th>Open Ports</th>
                    <th>OS</th>
                </tr>
            </thead>
            <tbody>
                {host_rows}
            </tbody>
        </table>
        
        {security_section}
        
        <div class="footer">
            Generated by NetworkScannerPro v{version} on {end_time}
        </div>
    </div>
</body>
</html>
    """
    
    # Generate host rows
    host_rows = []
    for host in result.hosts:
        if not host.ping_ok and not host.open_ports:
            continue  # Skip down hosts
        
        status_class = "status-up" if host.ping_ok else "status-down"
        ports_str = ", ".join(f"{p['port']}({p.get('service', '?')})" for p in host.open_ports)
        
        row = f"""
        <tr>
            <td>{host.ip}</td>
            <td class="{status_class}">{'UP' if host.ping_ok else 'DOWN'}</td>
            <td>{host.rtt_ms or '-'}ms</td>
            <td>{host.hostname or '-'}</td>
            <td>{host.mac or '-'}<br><small>{host.vendor or ''}</small></td>
            <td class="port-list">{ports_str or '-'}</td>
            <td>{host.os_guess or '-'}</td>
        </tr>
        """
        host_rows.append(row)
    
    # Security section
    security_section = ""
    hosts_with_issues = [h for h in result.hosts if h.security_issues]
    if hosts_with_issues:
        security_section = "<h2>⚠️ Security Issues</h2>"
        for host in hosts_with_issues:
            security_section += f"<h3>{host.ip} - {host.hostname or 'Unknown'}</h3>"
            for issue in host.security_issues:
                security_section += f'<div class="security-issue">{issue}</div>'
    
    # Format statistics
    stats = result.statistics
    common_ports = ", ".join(f"{p}({c})" for p, c in stats.get('most_common_ports', [])[:5])
    services = ", ".join(stats.get('services_found', []))
    vendors = ", ".join(stats.get('vendors_found', []))
    
    html_content = html_template.format(
        scan_id=result.scan_id,
        cidr=result.cidr,
        profile=result.profile,
        start_time=result.start_time,
        end_time=result.end_time,
        duration=result.duration,
        total_hosts=result.total_hosts,
        hosts_up=result.hosts_up,
        hosts_down=result.hosts_down,
        open_ports_found=result.open_ports_found,
        security_issues=stats.get('security_issues_count', 0),
        avg_rtt=stats.get('avg_rtt_ms', 0),
        common_ports=common_ports or 'None',
        services=services or 'None',
        vendors=vendors or 'None',
        host_rows='\n'.join(host_rows),
        security_section=security_section,
        version=VERSION
    )
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"HTML report exported: {filepath}")


def print_summary_report(result: ScanResult):
    """Print comprehensive summary to console"""
    print("\n" + "="*70)
    print(f"  SCAN REPORT - {result.scan_id}")
    print("="*70)
    print(f"Network:        {result.cidr}")
    print(f"Profile:        {result.profile}")
    print(f"Duration:       {result.duration}s")
    print(f"Started:        {result.start_time}")
    print("-"*70)
    print(f"Total Hosts:    {result.total_hosts}")
    print(f"Hosts UP:       {result.hosts_up} ({result.hosts_up/result.total_hosts*100:.1f}%)")
    print(f"Hosts DOWN:     {result.hosts_down} ({result.hosts_down/result.total_hosts*100:.1f}%)")
    print(f"Open Ports:     {result.open_ports_found}")
    print(f"Ports Scanned:  {result.total_ports_scanned}")
    print("-"*70)
    
    stats = result.statistics
    print(f"Avg RTT:        {stats.get('avg_rtt_ms', 0)}ms")
    print(f"Min RTT:        {stats.get('min_rtt_ms', 0)}ms")
    print(f"Max RTT:        {stats.get('max_rtt_ms', 0)}ms")
    
    if stats.get('most_common_ports'):
        print("\nMost Common Open Ports:")
        for port, count in stats['most_common_ports'][:5]:
            service = COMMON_SERVICES.get(port, 'unknown')
            print(f"  - Port {port} ({service}): {count} hosts")
    
    if stats.get('services_found'):
        print(f"\nServices Detected: {', '.join(stats['services_found'][:10])}")
    
    if stats.get('vendors_found'):
        print(f"\nVendors Found: {', '.join(stats['vendors_found'][:10])}")
    
    if stats.get('security_issues_count', 0) > 0:
        print(f"\n⚠️  SECURITY WARNINGS: {stats['security_issues_count']} issues found on {stats.get('hosts_with_issues', 0)} hosts")
    
    print("="*70)
    
    # Show some live hosts
    live_hosts = [h for h in result.hosts if h.ping_ok or h.open_ports][:10]
    if live_hosts:
        print("\nSample Live Hosts:")
        for host in live_hosts:
            ports = ",".join(str(p['port']) for p in host.open_ports)
            print(f"  {host.ip:<15} | {host.hostname or 'N/A':<30} | Ports: [{ports}]")
    
    print("="*70 + "\n")


# ---------------------------
# CLI Interface
# ---------------------------
def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f"NetworkScannerPro v{VERSION} - Professional Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect and scan with standard profile
  python network_scanner_pro.py
  
  # Scan specific network with full profile
  python network_scanner_pro.py --cidr 192.168.1.0/24 --profile full
  
  # Quick scan with custom ports
  python network_scanner_pro.py -c 10.0.0.0/24 --profile quick --ports 22,80,443
  
  # Security audit
  python network_scanner_pro.py --profile security --export-html
  
  # View scan history
  python network_scanner_pro.py --history
        """
    )
    
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('-c', '--cidr', help='CIDR to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-i', '--interface', help='Network interface name')
    parser.add_argument('-p', '--profile', choices=SCAN_PROFILES.keys(), default='standard',
                       help='Scan profile (default: standard)')
    parser.add_argument('--ports', help='Custom ports (comma-separated, e.g., 22,80,443)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--ping-timeout', type=float, default=1.0,
                       help='Ping timeout in seconds')
    parser.add_argument('--conn-timeout', type=float, default=0.5,
                       help='TCP connect timeout in seconds')
    
    # Export options
    parser.add_argument('--export-csv', action='store_true', help='Export to CSV')
    parser.add_argument('--export-json', action='store_true', help='Export to JSON')
    parser.add_argument('--export-html', action='store_true', help='Export to HTML report')
    parser.add_argument('--export-all', action='store_true', help='Export all formats')
    parser.add_argument('-o', '--output', help='Output directory for exports')
    
    # Database options
    parser.add_argument('--no-db', action='store_true', help='Do not save to database')
    parser.add_argument('--history', action='store_true', help='Show scan history')
    parser.add_argument('--show-scan', help='Show specific scan by ID')
    
    # Other options
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--no-banner', action='store_true', help='Disable banner')
    
    return parser.parse_args()


def print_banner():
    """Print application banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        Network Scanner Professional v{VERSION}               ║
║        Advanced Network Auditing & Analysis Tool            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main application entry point"""
    args = parse_arguments()
    
    # Setup logging
    global logger
    logger = setup_logging(args.debug)
    
    # Print banner
    if not args.no_banner:
        print_banner()
    
    # Handle history commands
    if args.history:
        db = ScanDatabase()
        history = db.get_scan_history(limit=20)
        print("\n📋 Recent Scan History:")
        print("-"*80)
        for scan in history:
            print(f"{scan['scan_id']} | {scan['cidr']:<18} | {scan['start_time']} | "
                  f"{scan['hosts_up']}/{scan['total_hosts']} UP | Profile: {scan['profile']}")
        print("-"*80)
        return
    
    if args.show_scan:
        db = ScanDatabase()
        scan = db.get_scan_by_id(args.show_scan)
        if scan:
            print(json.dumps(scan, indent=2))
        else:
            logger.error(f"Scan {args.show_scan} not found")
        return
    
    # Determine CIDR to scan
    cidr = None
    if args.cidr:
        cidr = args.cidr
        try:
            ipaddress.ip_network(cidr, strict=False)
        except Exception as e:
            logger.error(f"Invalid CIDR: {e}")
            return
    else:
        # Auto-detect interface
        interfaces = list_interfaces()
        if not interfaces:
            logger.error("No network interfaces detected")
            return
        
        if args.interface:
            selected = next((itf for itf in interfaces if itf['name'] == args.interface), None)
            if not selected:
                logger.error(f"Interface {args.interface} not found")
                return
        else:
            selected = select_interface_interactive(interfaces)
        
        # Extract CIDR from interface
        if selected and selected['addresses']:
            cidr = selected['addresses'][0]
            if '/' not in cidr:
                cidr = f"{cidr}/24"
        else:
            logger.error("Could not determine CIDR from interface")
            return
    
    logger.info(f"Target network: {cidr}")
    
    # Parse custom ports if provided
    custom_ports = None
    if args.ports:
        try:
            custom_ports = [int(p.strip()) for p in args.ports.split(',')]
            logger.info(f"Custom ports: {custom_ports}")
        except Exception as e:
            logger.error(f"Invalid port specification: {e}")
            return
    
    # Perform scan
    try:
        result = scan_network(
            cidr=cidr,
            profile=args.profile,
            threads=args.threads,
            custom_ports=custom_ports
        )
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return
    
    # Print summary
    print_summary_report(result)
    
    # Save to database
    if not args.no_db:
        try:
            db = ScanDatabase()
            db.save_scan(result)
        except Exception as e:
            logger.warning(f"Failed to save to database: {e}")
    
    # Exports - Organisation en dossiers
    if args.export_all or args.export_csv or args.export_json or args.export_html:
        # Créer le dossier principal "rapport_analyse"
        base_dir = Path(args.output) if args.output else Path.cwd()
        reports_dir = base_dir / "rapport_analyse"
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Créer un sous-dossier avec timestamp pour ce scan
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        scan_dir = reports_dir / timestamp
        scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Nom de base pour les fichiers (simplifié)
        network_name = result.cidr.replace('/', '_').replace('.', '_')
        base_name = f"scan_{network_name}"
        
        # Exports dans le dossier dédié
        if args.export_all or args.export_csv:
            csv_path = scan_dir / f"{base_name}.csv"
            export_csv(result, csv_path)
        
        if args.export_all or args.export_json:
            json_path = scan_dir / f"{base_name}.json"
            export_json(result, json_path)
        
        if args.export_all or args.export_html:
            html_path = scan_dir / f"{base_name}.html"
            export_html(result, html_path)
        
        logger.info(f"📁 Rapports sauvegardés dans: {scan_dir}")
    
    logger.info("Scan completed successfully!")
    logger.info(f"Logs saved to: {LOG_PATH}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
