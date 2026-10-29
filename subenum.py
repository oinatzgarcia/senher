#!/usr/bin/env python3
"""
SENHER - Subdomain Enumeration and Reconnaissance Helper

Orquestador de enumeracion de subdominios para Kali Linux.
Integra Subfinder, Amass, Shodan, GAU, AlterX, Gotator, dnsx y whois.

Uso:
  python3 subenum.py ejemplo.com
  python3 subenum.py ejemplo.com --mode passive
  python3 subenum.py ejemplo.com --mode active
"""

import argparse
import html
import os
import random
import re
import shutil
import string
import subprocess
import sys
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

try:
    import shodan
except ImportError:
    sys.exit("[!] Falta 'shodan'. Instala: pip3 install shodan")


BANNER = r"""
   ____             _                 
  / ___|  ___ _ __ | |__   ___ _ __  
  \___ \ / _ \ '_ \| '_ \ / _ \ '__| 
   ___) |  __/ | | | | | |  __/ |    
  |____/ \___|_| |_|_| |_|\___|_|    
  Subdomain enumeration orchestrator
"""

DEFAULT_ACTIVE_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


def run(cmd, outfile=None, stdin_data=None, timeout=None):
    print(f"[*] {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, input=stdin_data, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if p.returncode != 0:
            print(f"[!] Codigo {p.returncode}: {' '.join(cmd)}")
            if p.stderr:
                print(p.stderr.strip()[:1000])
            return ""
        if outfile:
            Path(outfile).write_text(p.stdout, encoding="utf-8")
        return p.stdout
    except FileNotFoundError:
        print(f"[!] Binario no encontrado: {cmd[0]}")
        return ""
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout ejecutando: {' '.join(cmd)}")
        return ""


def write_lines(path, lines):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(lines))) + "\n")


def read_lines(path):
    if not Path(path).exists():
        return []
    return [x.strip() for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]


def in_scope(host, domain):
    h = host.lower().rstrip(".")
    d = domain.lower()
    return h == d or h.endswith("." + d)


def extract_hosts(text, domain):
    hosts = set()
    for token in text.replace(",", "\n").split():
        token = token.strip().lower()
        if "/" in token:
            token = token.split("//", 1)[-1].split("/", 1)[0]
        if ":" in token and not token.count(":") == 1:
            continue
        if in_scope(token, domain):
            hosts.add(token)
    return hosts


def check_bins(required):
    missing = [b for b in required if shutil.which(b) is None]
    if missing:
        print(f"[!] Herramientas no encontradas en PATH: {', '.join(missing)}")
        print("    Instalalas o anade ~/go/bin al PATH:")
        print("    export PATH=$PATH:$(go env GOPATH)/bin")
        sys.exit(1)


def random_label(length=12):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def parse_dnsx_output(lines):
    results = defaultdict(lambda: {"A": [], "AAAA": [], "CNAME": []})
    pattern = re.compile(r"^([^\s]+)\s+\[(.+)\]$")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = pattern.match(line)
        if not match:
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("["):
                host = parts[0]
                values = " ".join(parts[1:]).strip("[]")
                for value in re.split(r"[,]\s*", values):
                    value = value.strip()
                    if ":" in value and "." not in value:
                        results[host]["AAAA"].append(value)
                    elif re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
                        results[host]["A"].append(value)
                    else:
                        results[host]["CNAME"].append(value)
            continue

        host, records = match.groups()
        host = host.lower().rstrip(".")

        for record in re.split(r",\s*", records):
            record = record.strip()
            if not record:
                continue

            parts = record.split()
            if len(parts) >= 2 and parts[0].upper() in ("A", "AAAA", "CNAME"):
                rtype = parts[0].upper()
                value = parts[1]
            else:
                value = record
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
                    rtype = "A"
                elif ":" in value and "." not in value:
                    rtype = "AAAA"
                else:
                    rtype = "CNAME"

            if value not in results[host][rtype]:
                results[host][rtype].append(value)

    return dict(results)


def dnsx_resolve(subs, outfile, resolvers=None, threads=50):
    if not subs:
        return {}
    cmd = ["dnsx", "-silent", "-a", "-aaaa", "-cname", "-resp", "-t", str(threads), "-o", outfile]
    if resolvers and Path(resolvers).exists():
        cmd += ["-r", resolvers]
    run(cmd, stdin_data="\n".join(subs))
    return parse_dnsx_output(read_lines(outfile))


def detect_wildcards(domain, outdir, resolvers=None, threads=50, probes=8):
    print(f"[*] Detectando wildcards con {probes} subdominios aleatorios...")
    probes_hosts = [f"{random_label()}.{domain}" for _ in range(probes)]
    outfile = outdir / "wildcard_probes.txt"
    results = dnsx_resolve(probes_hosts, str(outfile), resolvers, threads)

    ip_counter = Counter()
    for data in results.values():
        ips = set(data.get("A", []) + data.get("AAAA", []))
        ip_counter.update(ips)

    wildcard_ips = {ip for ip, count in ip_counter.items() if count >= 2}
    write_lines(outdir / "04_wildcards.txt", wildcard_ips)

    if wildcard_ips:
        print(f"[!] Wildcards detectados: {len(wildcard_ips)} IP(s)")
        for ip in sorted(wildcard_ips):
            print(f"    - {ip}")
    else:
        print("[+] No se han detectado wildcards.")

    return wildcard_ips


def shodan_enum(domain, api_key, outfile):
    if not api_key:
        print("[*] Shodan: sin API key, se omite.")
        return []
    try:
        api = shodan.Shodan(api_key)
        info = api.dns.domain_info(domain)
        subs = set()
        for item in info.get("subdomains", []):
            host = f"{item}.{domain}" if not item.endswith(domain) else item
            if in_scope(host, domain):
                subs.add(host)
        write_lines(outfile, subs)
        print(f"[+] Shodan: {len(subs)} subdominios.")
        return list(subs)
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}")
        return []


def subfinder_enum(domain, outfile, active=False):
    cmd = ["subfinder", "-d", domain, "-silent", "-o", outfile]
    if active:
        cmd += ["-active"]
    run(cmd)
    return read_lines(outfile)


def amass_enum(domain, outfile, active=False, wordlist=None):
    if active and wordlist:
        cmd = ["amass", "enum", "-active", "-d", domain, "-brute", "-w", wordlist, "-o", outfile]
    else:
        cmd = ["amass", "enum", "-passive", "-d", domain, "-o", outfile]
    run(cmd)
    return read_lines(outfile)


def gau_enum(domain, outfile):
    cmd = ["gau", "--subs", "--threads", "5", "--o", outfile, domain]
    run(cmd)
    urls = read_lines(outfile)
    hosts = extract_hosts("\n".join(urls), domain)
    write_lines(outfile, hosts)
    return hosts


def alterx_permutations(subs, domain, outfile, enrich=True):
    if not subs:
        return []
    cmd = ["alterx", "-silent", "-o", outfile]
    if enrich:
        cmd.append("-enrich")
    out = run(cmd, stdin_data="\n".join(subs))
    perms = read_lines(outfile) if Path(outfile).exists() else extract_hosts(out, domain)
    write_lines(outfile, perms)
    return perms


def gotator_permutations(subs, outfile, perm_file=None, depth=1, numbers=3):
    if not subs:
        return []

    input_file = Path(outfile).with_suffix(".input.txt")
    input_file.write_text("\n".join(subs), encoding="utf-8")

    cmd = [
        "gotator",
        "-sub", str(input_file),
        "-depth", str(depth),
        "-numbers", str(numbers),
        "-mindup", "-silent"
    ]
    if perm_file:
        cmd += ["-perm", perm_file]

    out = run(cmd)
    perms = extract_hosts(out, "")
    write_lines(outfile, perms)
    input_file.unlink(missing_ok=True)
    return perms


def dnsx_validate(subs, outfile, resolvers=None, threads=50):
    if not subs:
        return {}, []
    cmd = ["dnsx", "-silent", "-a", "-aaaa", "-cname", "-resp", "-t", str(threads), "-auto-wildcard", "-o", outfile]
    if resolvers and Path(resolvers).exists():
        cmd += ["-r", resolvers]
    run(cmd, stdin_data="\n".join(subs))
    lines = read_lines(outfile)
    parsed = parse_dnsx_output(lines)
    return parsed, sorted(parsed.keys())


def whois_lookup(domain, outfile):
    out = run(["whois", domain], timeout=30)
    if out:
        Path(outfile).write_text(out, encoding="utf-8")
    return out


def split_wildcard_results(dns_results, wildcard_ips):
    valid = {}
    wildcard_candidates = {}

    for host, data in dns_results.items():
        ips = set(data.get("A", []) + data.get("AAAA", []))
        if ips & wildcard_ips:
            wildcard_candidates[host] = data
        else:
            valid[host] = data

    return valid, wildcard_candidates


def choose_mode(requested_mode):
    if requested_mode in ("passive", "active"):
        return requested_mode

    print("\nSelecciona el tipo de escaneo:")
    print("  1) Pasivo - enumeracion pasiva completa, sin consultas activas")
    print("  2) Activo - enumeracion pasiva completa + Subfinder activo + Amass brute force")

    while True:
        choice = input("Opcion [1/2]: ").strip()
        if choice == "1":
            return "passive"
        if choice == "2":
            return "active"
        print("[!] Introduce 1 o 2.")


def choose_wordlist(requested_wordlist):
    if requested_wordlist and Path(requested_wordlist).exists():
        return requested_wordlist

    if requested_wordlist:
        print(f"[!] Wordlist no encontrada: {requested_wordlist}")

    print(f"\nWordlist por defecto: {DEFAULT_ACTIVE_WORDLIST}")

    if Path(DEFAULT_ACTIVE_WORDLIST).exists():
        use_default = input("Usar la wordlist por defecto? [S/n]: ").strip().lower()
        if use_default in ("", "s", "si", "y", "yes"):
            return DEFAULT_ACTIVE_WORDLIST
    else:
        print("[!] La wordlist por defecto no existe.")

    while True:
        path = input("Ruta de la wordlist para Amass: ").strip()
        if path and Path(path).exists():
            return path
        print("[!] Ruta invalida o archivo inexistente.")


def generate_html_report(domain, outdir, passive, candidates, dns_results, resolved_hosts, wildcard_ips, wildcard_candidates, mode):
    ip_to_hosts = defaultdict(list)
    host_rows = []

    for host in sorted(dns_results.keys()):
        data = dns_results[host]
        ipv4 = sorted(set(data.get("A", [])))
        ipv6 = sorted(set(data.get("AAAA", [])))
        cname = sorted(set(data.get("CNAME", [])))

        for ip in ipv4 + ipv6:
            ip_to_hosts[ip].append(host)

        host_rows.append({
            "host": host,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "cname": cname,
            "source": "Pasivo" if host in passive else "Permutacion",
        })

    def sort_key(row):
        first_ip = row["ipv4"][0] if row["ipv4"] else (row["ipv6"][0] if row["ipv6"] else "zzzz")
        return (first_ip, row["host"])

    host_rows.sort(key=sort_key)
    sorted_ips = sorted(ip_to_hosts.keys(), key=lambda ip: (":" in ip, ip))
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENHER - {html.escape(domain)}</title>
<style>
:root {{ --bg:#0b1020; --card:#111827; --text:#e5e7eb; --muted:#9ca3af; --accent:#22d3ee; --green:#34d399; --yellow:#fbbf24; --red:#f87171; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:Inter,Arial,sans-serif; background:var(--bg); color:var(--text); }}
.container {{ max-width:1200px; margin:0 auto; padding:32px 20px 64px; }}
h1 {{ margin:0 0 8px; font-size:2rem; }}
.subtitle {{ color:var(--muted); margin-bottom:28px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin-bottom:32px; }}
.card {{ background:var(--card); border:1px solid #1f2937; border-radius:14px; padding:18px; }}
.card .value {{ font-size:1.8rem; font-weight:700; color:var(--accent); }}
.card .label {{ color:var(--muted); font-size:.9rem; margin-top:4px; }}
.section {{ background:var(--card); border:1px solid #1f2937; border-radius:14px; padding:22px; margin-bottom:28px; }}
h2 {{ margin-top:0; font-size:1.25rem; }}
table {{ width:100%; border-collapse:collapse; font-size:.92rem; }}
th, td {{ padding:10px 12px; border-bottom:1px solid #1f2937; text-align:left; vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; text-transform:uppercase; font-size:.75rem; letter-spacing:.04em; }}
tr:hover td {{ background:#0f172a; }}
.badge {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:.72rem; font-weight:700; }}
.badge.passive {{ background:rgba(52,211,153,.15); color:var(--green); }}
.badge.perm {{ background:rgba(251,191,36,.15); color:var(--yellow); }}
.badge.mode {{ background:rgba(34,211,238,.15); color:var(--accent); }}
.ip {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--accent); }}
.host {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
.empty {{ color:var(--muted); font-style:italic; }}
a {{ color:var(--accent); text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.footer {{ color:var(--muted); font-size:.8rem; text-align:center; margin-top:40px; }}
</style>
</head>
<body>
<div class="container">
  <h1>SENHER</h1>
  <div class="subtitle">Informe de enumeracion de subdominios para <strong>{html.escape(domain)}</strong> - {now}</div>
  <div class="subtitle">Modo de escaneo: <span class="badge mode">{html.escape(mode.upper())}</span></div>

  <div class="cards">
    <div class="card"><div class="value">{len(passive)}</div><div class="label">Subdominios pasivos</div></div>
    <div class="card"><div class="value">{len(candidates)}</div><div class="label">Permutaciones candidatas</div></div>
    <div class="card"><div class="value">{len(resolved_hosts)}</div><div class="label">Hosts DNS validos</div></div>
    <div class="card"><div class="value">{len(ip_to_hosts)}</div><div class="label">IPs unicas</div></div>
    <div class="card"><div class="value">{len(wildcard_ips)}</div><div class="label">IPs wildcard</div></div>
    <div class="card"><div class="value">{len(wildcard_candidates)}</div><div class="label">Posibles falsos positivos</div></div>
  </div>

  <div class="section">
    <h2>Subdominios agrupados por IP</h2>
"""

    if not sorted_ips:
        html_content += '<p class="empty">No se han resuelto IPs.</p>'
    else:
        html_content += '<table><thead><tr><th>IP</th><th>Subdominios</th><th>Total</th></tr></thead><tbody>'
        for ip in sorted_ips:
            hosts = sorted(ip_to_hosts[ip])
            host_links = "<br>".join(
                f'<span class="host"><a href="https://{html.escape(h)}" target="_blank" rel="noopener">{html.escape(h)}</a></span>'
                for h in hosts
            )
            html_content += f'<tr><td class="ip">{html.escape(ip)}</td><td>{host_links}</td><td>{len(hosts)}</td></tr>'
        html_content += '</tbody></table>'

    html_content += '''
  </div>

  <div class="section">
    <h2>Detalle por subdominio</h2>
    <table>
      <thead>
        <tr><th>Subdominio</th><th>Origen</th><th>IPv4</th><th>IPv6</th><th>CNAME</th></tr>
      </thead>
      <tbody>
'''

    if not host_rows:
        html_content += '<tr><td colspan="5" class="empty">No hay subdominios validos.</td></tr>'
    else:
        for row in host_rows:
            source_class = "passive" if row["source"] == "Pasivo" else "perm"
            ipv4 = "<br>".join(f'<span class="ip">{html.escape(ip)}</span>' for ip in row["ipv4"]) or '<span class="empty">-</span>'
            ipv6 = "<br>".join(f'<span class="ip">{html.escape(ip)}</span>' for ip in row["ipv6"]) or '<span class="empty">-</span>'
            cname = "<br>".join(html.escape(c) for c in row["cname"]) or '<span class="empty">-</span>'
            html_content += (
                f'<tr><td class="host"><a href="https://{html.escape(row["host"])}" target="_blank" rel="noopener">{html.escape(row["host"])}</a></td>'
                f'<td><span class="badge {source_class}">{row["source"]}</span></td>'
                f'<td>{ipv4}</td><td>{ipv6}</td><td>{cname}</td></tr>'
            )

    html_content += '''
      </tbody>
    </table>
  </div>
'''

    html_content += f'''
  <div class="section">
    <h2>Filtro de wildcards</h2>
    <p>IPs que resolvieron en varias sondas aleatorias y se han excluido de los resultados validos.</p>
'''

    if not wildcard_ips:
        html_content += '<p class="empty">No se han detectado wildcards.</p>'
    else:
        html_content += '<table><thead><tr><th>IP wildcard</th><th>Subdominios afectados</th></tr></thead><tbody>'
        for ip in sorted(wildcard_ips):
            affected = sorted(
                host for host, data in wildcard_candidates.items()
                if ip in data.get("A", []) + data.get("AAAA", [])
            )
            hosts_text = "<br>".join(html.escape(h) for h in affected) or '<span class="empty">-</span>'
            html_content += f'<tr><td class="ip">{html.escape(ip)}</td><td>{hosts_text}</td></tr>'
        html_content += '</tbody></table>'

    html_content += '''
  </div>

  <div class="footer">Generado por SENHER - Uso exclusivo en activos autorizados.</div>
</div>
</body>
</html>
'''

    report_path = outdir / "report.html"
    report_path.write_text(html_content, encoding="utf-8")
    return report_path


def generate_markdown_report(domain, outdir, passive, candidates, dns_results, resolved_hosts, wildcard_ips, wildcard_candidates, mode):
    report = outdir / "REPORT.md"
    with open(report, "w", encoding="utf-8") as r:
        r.write(f"# Recon de subdominios: {domain}\n\n")
        r.write(f"- Fecha: {datetime.now().isoformat(timespec='seconds')}\n")
        r.write(f"- Modo: {mode}\n")
        r.write(f"- Subdominios pasivos: {len(passive)}\n")
        r.write(f"- Permutaciones candidatas: {len(candidates)}\n")
        r.write(f"- Hosts DNS validos: {len(resolved_hosts)}\n")
        r.write(f"- IPs wildcard detectadas: {len(wildcard_ips)}\n")
        r.write(f"- Posibles falsos positivos: {len(wildcard_candidates)}\n")
        r.write(f"- Informe HTML: report.html\n\n")

        r.write("## Subdominios validos\n\n```text\n")
        r.write("\n".join(resolved_hosts))
        r.write("\n```\n\n")

        r.write("## Resolucion por IP\n\n")
        ip_map = defaultdict(list)
        for host, data in dns_results.items():
            for ip in data.get("A", []) + data.get("AAAA", []):
                ip_map[ip].append(host)

        for ip in sorted(ip_map.keys(), key=lambda x: (":" in x, x)):
            r.write(f"### {ip}\n\n")
            for host in sorted(ip_map[ip]):
                r.write(f"- {host}\n")
            r.write("\n")

        r.write("## Wildcards detectados\n\n")
        if wildcard_ips:
            for ip in sorted(wildcard_ips):
                r.write(f"- `{ip}`\n")
        else:
            r.write("No se han detectado wildcards.\n")

        r.write("\n## Posibles falsos positivos\n\n")
        if wildcard_candidates:
            for host in sorted(wildcard_candidates.keys()):
                r.write(f"- {host}\n")
        else:
            r.write("No hay posibles falsos positivos por wildcard.\n")

    return report


def main():
    parser = argparse.ArgumentParser(description="Enumeracion automatizada de subdominios")
    parser.add_argument("domain", help="Dominio objetivo, p. ej. ejemplo.com")
    parser.add_argument("--mode", choices=["passive", "active"], help="Tipo de escaneo: passive o active")
    parser.add_argument("-k", "--shodan-key", default=os.getenv("SHODAN_API_KEY", ""))
    parser.add_argument("-o", "--output-dir", default=None)
    parser.add_argument("--resolvers", default="resolvers.txt")
    parser.add_argument("--wordlist", default=None, help="Wordlist para Amass en modo activo")
    parser.add_argument("--perm-list", default=None, help="Wordlist para Gotator")
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--wildcard-probes", type=int, default=8, help="Numero de sondas aleatorias para detectar wildcards")
    parser.add_argument("--skip-wildcard-check", action="store_true", help="Omite la deteccion de wildcards")
    parser.add_argument("--skip-amass", action="store_true")
    parser.add_argument("--skip-gau", action="store_true")
    parser.add_argument("--skip-permutations", action="store_true")
    parser.add_argument("--skip-shodan", action="store_true")
    args = parser.parse_args()

    print(BANNER)
    domain = args.domain.lower().strip()
    mode = choose_mode(args.mode)

    active_wordlist = None
    if mode == "active":
        active_wordlist = choose_wordlist(args.wordlist)
        print(f"[*] Wordlist activa: {active_wordlist}")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.output_dir or f"output/{domain}_{mode}_{stamp}")
    outdir.mkdir(parents=True, exist_ok=True)

    required = ["subfinder", "dnsx", "alterx", "gotator", "whois"]
    if not args.skip_amass:
        required.append("amass")
    if not args.skip_gau:
        required.append("gau")
    check_bins(required)

    print(f"\n[*] Objetivo: {domain}")
    print(f"[*] Modo: {mode.upper()}")
    print(f"[*] Resultados: {outdir}\n")

    passive = set()

    f = outdir / "subfinder.txt"
    passive.update(subfinder_enum(domain, str(f), active=(mode == "active")))

    if not args.skip_amass:
        f = outdir / "amass.txt"
        passive.update(
            amass_enum(
                domain,
                str(f),
                active=(mode == "active"),
                wordlist=active_wordlist if mode == "active" else None,
            )
        )

    if not args.skip_shodan:
        f = outdir / "shodan.txt"
        passive.update(shodan_enum(domain, args.shodan_key, str(f)))

    if not args.skip_gau:
        f = outdir / "gau.txt"
        passive.update(gau_enum(domain, str(f)))

    passive = {h for h in passive if in_scope(h, domain)}
    write_lines(outdir / "01_passive_all.txt", passive)
    print(f"\n[+] Subdominios pasivos unicos: {len(passive)}")

    if not passive:
        print("[!] No se obtuvieron subdominios pasivos.")
        return

    candidates = set(passive)
    if not args.skip_permutations:
        with ThreadPoolExecutor(max_workers=2) as ex:
            fa = outdir / "alterx.txt"
            fg = outdir / "gotator.txt"
            fut_a = ex.submit(alterx_permutations, sorted(passive), domain, str(fa))
            fut_g = ex.submit(gotator_permutations, sorted(passive), str(fg), args.perm_list)
            candidates.update(fut_a.result())
            candidates.update(fut_g.result())

    candidates = {h for h in candidates if in_scope(h, domain) and h not in passive}
    write_lines(outdir / "02_permutations.txt", candidates)
    print(f"[+] Permutaciones nuevas: {len(candidates)}")

    if args.skip_wildcard_check:
        wildcard_ips = set()
        print("[*] Deteccion de wildcards omitida.")
    else:
        wildcard_ips = detect_wildcards(domain, outdir, args.resolvers, args.threads, args.wildcard_probes)

    to_resolve = sorted(passive | candidates)
    f = outdir / "03_resolved.txt"
    dns_results, all_resolved = dnsx_validate(to_resolve, str(f), args.resolvers, args.threads)

    valid_results, wildcard_candidates = split_wildcard_results(dns_results, wildcard_ips)
    resolved_hosts = sorted(valid_results.keys())

    write_lines(outdir / "05_wildcard_candidates.txt", wildcard_candidates.keys())

    print(f"[+] Hosts que resuelven: {len(all_resolved)}")
    print(f"[+] Hosts validos tras filtro wildcard: {len(resolved_hosts)}")
    print(f"[!] Posibles falsos positivos por wildcard: {len(wildcard_candidates)}")

    whois_lookup(domain, str(outdir / "whois.txt"))

    html_report = generate_html_report(
        domain, outdir, passive, candidates, valid_results,
        resolved_hosts, wildcard_ips, wildcard_candidates, mode
    )
    md_report = generate_markdown_report(
        domain, outdir, passive, candidates, valid_results,
        resolved_hosts, wildcard_ips, wildcard_candidates, mode
    )

    print(f"\n[OK] Informe HTML: {html_report}")
    print(f"[OK] Informe Markdown: {md_report}")
    print(f"[OK] Subdominios validos: {outdir / '03_resolved.txt'}")
    print(f"[OK] Posibles falsos positivos: {outdir / '05_wildcard_candidates.txt'}")


if __name__ == "__main__":
    main()
