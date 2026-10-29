#!/usr/bin/env python3
"""
SENHER - Subdomain Enumeration and Reconnaissance Helper

Orquestador de enumeracion de subdominios para Kali Linux.
Integra Subfinder, Amass, Shodan, GAU, AlterX, Gotator, dnsx y whois.

Uso:
  python3 subenum.py ejemplo.com --shodan-key XXXX
  python3 subenum.py ejemplo.com --skip-amass --skip-gau
  python3 subenum.py ejemplo.com --active --wordlist /ruta/words.txt
"""

import argparse
import os
import shutil
import subprocess
import sys
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


def run(cmd, outfile=None, stdin_data=None):
    """Ejecuta un comando externo y opcionalmente guarda stdout."""
    print(f"[*] {' '.join(cmd)}")
    try:
        p = subprocess.run(
            cmd,
            input=stdin_data,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
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


def subfinder_enum(domain, outfile, active=False, wordlist=None):
    cmd = ["subfinder", "-d", domain, "-silent", "-o", outfile]
    if active:
        cmd += ["-active"]
    run(cmd)
    return read_lines(outfile)


def amass_enum(domain, outfile, active=False, wordlist=None):
    cmd = ["amass", "enum", "-passive", "-d", domain, "-o", outfile]
    if active and wordlist:
        cmd = [
            "amass", "enum", "-active", "-d", domain,
            "-brute", "-w", wordlist, "-o", outfile
        ]
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
    cmd = [
        "gotator", "-sub", "-",
        "-depth", str(depth),
        "-numbers", str(numbers),
        "-mindup", "-silent"
    ]
    if perm_file:
        cmd += ["-perm", perm_file]
    out = run(cmd, stdin_data="\n".join(subs))
    perms = extract_hosts(out, "")
    write_lines(outfile, perms)
    return perms


def dnsx_validate(subs, outfile, resolvers=None, threads=50):
    if not subs:
        return []
    cmd = [
        "dnsx", "-silent", "-a", "-aaaa", "-cname",
        "-resp", "-t", str(threads),
        "-auto-wildcard",
        "-o", outfile
    ]
    if resolvers and Path(resolvers).exists():
        cmd += ["-r", resolvers]
    run(cmd, stdin_data="\n".join(subs))
    return read_lines(outfile)


def whois_lookup(domain, outfile):
    out = run(["whois", domain])
    if out:
        Path(outfile).write_text(out, encoding="utf-8")
    return out


def main():
    parser = argparse.ArgumentParser(description="Enumeracion automatizada de subdominios")
    parser.add_argument("domain", help="Dominio objetivo, p. ej. ejemplo.com")
    parser.add_argument("-k", "--shodan-key", default=os.getenv("SHODAN_API_KEY", ""))
    parser.add_argument("-o", "--output-dir", default=None)
    parser.add_argument("--resolvers", default="resolvers.txt")
    parser.add_argument("--wordlist", default=None, help="Wordlist para Amass activo")
    parser.add_argument("--perm-list", default=None, help="Wordlist para Gotator")
    parser.add_argument("--active", action="store_true", help="Habilita enumeracion activa")
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--skip-amass", action="store_true")
    parser.add_argument("--skip-gau", action="store_true")
    parser.add_argument("--skip-permutations", action="store_true")
    parser.add_argument("--skip-shodan", action="store_true")
    args = parser.parse_args()

    print(BANNER)
    domain = args.domain.lower().strip()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.output_dir or f"output/{domain}_{stamp}")
    outdir.mkdir(parents=True, exist_ok=True)

    required = ["subfinder", "dnsx", "alterx", "gotator", "whois"]
    if not args.skip_amass:
        required.append("amass")
    if not args.skip_gau:
        required.append("gau")
    check_bins(required)

    print(f"[*] Objetivo: {domain}")
    print(f"[*] Resultados: {outdir}\n")

    passive = set()

    # Subfinder
    f = outdir / "subfinder.txt"
    passive.update(subfinder_enum(domain, str(f), active=args.active, wordlist=args.wordlist))

    # Amass
    if not args.skip_amass:
        f = outdir / "amass.txt"
        passive.update(amass_enum(domain, str(f), active=args.active, wordlist=args.wordlist))

    # Shodan API directa
    if not args.skip_shodan:
        f = outdir / "shodan.txt"
        passive.update(shodan_enum(domain, args.shodan_key, str(f)))

    # GAU
    if not args.skip_gau:
        f = outdir / "gau.txt"
        passive.update(gau_enum(domain, str(f)))

    passive = {h for h in passive if in_scope(h, domain)}
    write_lines(outdir / "01_passive_all.txt", passive)
    print(f"\n[+] Subdominios pasivos unicos: {len(passive)}")

    if not passive:
        print("[!] No se obtuvieron subdominios pasivos.")
        return

    # Permutaciones
    candidates = set(passive)
    if not args.skip_permutations:
        with ThreadPoolExecutor(max_workers=2) as ex:
            fa = outdir / "alterx.txt"
            fg = outdir / "gotator.txt"
            fut_a = ex.submit(
                alterx_permutations, sorted(passive), domain, str(fa)
            )
            fut_g = ex.submit(
                gotator_permutations, sorted(passive), str(fg), args.perm_list
            )
            candidates.update(fut_a.result())
            candidates.update(fut_g.result())

    candidates = {h for h in candidates if in_scope(h, domain) and h not in passive}
    write_lines(outdir / "02_permutations.txt", candidates)
    print(f"[+] Permutaciones nuevas: {len(candidates)}")

    # Validacion DNS
    to_resolve = sorted(passive | candidates)
    f = outdir / "03_resolved.txt"
    resolved = dnsx_validate(to_resolve, str(f), args.resolvers, args.threads)
    print(f"[+] Hosts que resuelven: {len(resolved)}")

    # Whois
    whois_lookup(domain, str(outdir / "whois.txt"))

    # Informe final
    report = outdir / "REPORT.md"
    with open(report, "w", encoding="utf-8") as r:
        r.write(f"# Recon de subdominios: {domain}\n\n")
        r.write(f"- Fecha: {datetime.now().isoformat(timespec='seconds')}\n")
        r.write(f"- Subdominios pasivos: {len(passive)}\n")
        r.write(f"- Permutaciones candidatas: {len(candidates)}\n")
        r.write(f"- Hosts DNS validos: {len(resolved)}\n\n")
        r.write("## Subdominios validos\n\n```text\n")
        r.write("\n".join(resolved))
        r.write("\n```\n")

    print(f"\n[OK] Informe: {report}")
    print(f"[OK] Subdominios validos: {outdir / '03_resolved.txt'}")


if __name__ == "__main__":
    main()
