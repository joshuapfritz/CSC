#!/usr/bin/env python3
"""
simplify_nmap_output.py
Produce a compact hosts report from nmap XML or GNMAP files.

Usage:
  python3 simplify_nmap_output.py full_tcp_version_scan.xml full_udp_top1000.gnmap
If no file args provided, script looks for *.xml then *.gnmap in cwd.
Outputs: hosts_simple.csv and HOSTS_SIMPLE.md
"""

import sys, glob, xml.etree.ElementTree as ET, re, csv, os

def infer_os(evidence_str):
    e = evidence_str.lower()
    # simple priority checks
    if "microsoft" in e or "ms-wbt-server" in e or "rdp" in e or "3389" in e or "microsoft-ds" in e or "445" in e:
        return ("Windows", "High")
    if "openbsd" in e or "freebsd" in e or "netbsd" in e:
        return ("BSD", "High")
    if "openssh" in e or "sshd" in e or "22/tcp" in e:
        return ("Linux/Unix", "High")
    if "apache" in e or "nginx" in e or "http" in e or "80/tcp" in e:
        return ("Likely Linux/Unix (web)", "Medium")
    if "busybox" in e or "goahead" in e or "embedded" in e or "rtsp" in e:
        return ("Embedded / IoT", "High")
    if "oracle" in e or "1521" in e:
        return ("Unix/Linux (Oracle)", "Medium")
    if "postgresql" in e or "5432" in e:
        return ("Linux/Unix (Postgres)", "Medium")
    return ("Unknown", "Low")

def parse_xml(fn, hosts):
    try:
        tree = ET.parse(fn)
        root = tree.getroot()
    except Exception:
        return
    for host in root.findall('host'):
        ip = None
        hostname = ""
        parts = []
        for a in host.findall('address'):
            if a.get('addrtype') == 'ipv4':
                ip = a.get('addr')
        hn = host.find('hostnames')
        if hn is not None:
            h = hn.find('hostname')
            if h is not None:
                hostname = h.get('name') or ""
        # osmatch
        os_el = host.find('os')
        if os_el is not None:
            for m in os_el.findall('osmatch'):
                parts.append("osmatch:"+ (m.get('name') or ""))
        # ports
        ports = host.find('ports')
        if ports is not None:
            for p in ports.findall('port'):
                pid = p.get('portid')
                proto = p.get('protocol')
                state_el = p.find('state')
                state = state_el.get('state') if state_el is not None else ""
                svc = p.find('service')
                svcname = svc.get('name') if svc is not None and svc.get('name') else ""
                prod = svc.get('product') if svc is not None and svc.get('product') else ""
                if pid and (state=="open" or state=="open|filtered"):
                    parts.append(f"{pid}/{proto}/{svcname}/{prod}")
        if ip:
            hosts.setdefault(ip, {'hostname': hostname, 'evidence': []})
            hosts[ip]['evidence'].extend(parts)

def parse_gnmap(fn, hosts):
    try:
        with open(fn, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                if not line.startswith("Host:"):
                    continue
                m = re.search(r'Host:\s+(\S+)', line)
                if not m: continue
                ip = m.group(1)
                hostname = ""
                hnm = re.search(r'\(([^)]*)\)', line)
                if hnm and hnm.group(1):
                    hostname = hnm.group(1).strip()
                ports_part = ""
                if "Ports:" in line:
                    ports_part = line.split("Ports:")[1].strip()
                ports = [p.strip() for p in ports_part.split(',') if p.strip()]
                parts = []
                for p in ports:
                    f = p.split('/')
                    portid = f[0] if len(f)>0 else ""
                    state = f[1] if len(f)>1 else ""
                    svc = f[4] if len(f)>4 else ""
                    if state in ("open","open|filtered"):
                        parts.append(f"{portid}/tcp/{svc}")
                hosts.setdefault(ip, {'hostname': hostname, 'evidence': []})
                hosts[ip]['evidence'].extend(parts)
    except Exception:
        return

def write_outputs(hosts):
    # CSV
    with open("hosts_simple.csv","w",newline='',encoding='utf-8') as csvf:
        w = csv.writer(csvf)
        w.writerow(["IP","Hostname","Inferred OS","Confidence","Evidence"])
        for ip in sorted(hosts.keys(), key=lambda x: tuple(int(p) for p in x.split('.'))):
            h = hosts[ip]
            ev = "; ".join(h['evidence'][:6])
            osname,conf = infer_os(ev)
            w.writerow([ip, h.get('hostname') or "", osname, conf, ev])

    # Markdown
    with open("HOSTS_SIMPLE.md","w",encoding='utf-8') as md:
        md.write("# Hosts (simplified)\n\n")
        md.write("| IP | Hostname | Inferred OS | Confidence | Evidence |\n")
        md.write("|---|---|---|---|---|\n")
        for ip in sorted(hosts.keys(), key=lambda x: tuple(int(p) for p in x.split('.'))):
            h = hosts[ip]
            ev = "; ".join(h['evidence'][:6]).replace("|","\\|")
            osname,conf = infer_os(ev)
            md.write(f"| {ip} | {h.get('hostname') or ''} | {osname} | {conf} | {ev} |\n")

def main():
    args = sys.argv[1:]
    files = []
    if not args:
        files = glob.glob("*.xml") + glob.glob("*.gnmap")
    else:
        for a in args:
            files.extend(glob.glob(a))
    if not files:
        print("No XML or GNMAP files found. Place them here or give filenames as args.")
        return
    hosts = {}
    # prefer xml first if present
    for f in files:
        if f.endswith('.xml'):
            parse_xml(f, hosts)
    # then parse gnmap for any missing or additional info
    for f in files:
        if f.endswith('.gnmap'):
            parse_gnmap(f, hosts)
    write_outputs(hosts)
    print(f"Wrote hosts_simple.csv and HOSTS_SIMPLE.md ({len(hosts)} hosts).")

if __name__ == "__main__":
    main()
