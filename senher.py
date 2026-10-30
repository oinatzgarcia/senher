#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
import subenum
from dns_reporting import parse_dnsx_output, generate_html_report
from crtsh_source import install

subenum.parse_dnsx_output = parse_dnsx_output
subenum.generate_html_report = generate_html_report

def main():
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument('--skip-crtsh', action='store_true')
    options.add_argument('--crtsh-refresh', action='store_true')
    options.add_argument('--crtsh-cache-dir', type=Path, default=Path.home() / '.cache' / 'senher' / 'crtsh')
    config, remaining = options.parse_known_args()
    install(subenum, generate_html_report, config.crtsh_cache_dir, config.crtsh_refresh, config.skip_crtsh)
    if '--report-only' not in remaining:
        if '--help' in remaining or '-h' in remaining:
            print('Opciones crt.sh: --skip-crtsh | --crtsh-refresh | --crtsh-cache-dir RUTA')
        sys.argv = [sys.argv[0]] + remaining
        subenum.main()
        return
    parser = argparse.ArgumentParser(description='Regenerar informes sin consultas de red')
    parser.add_argument('--report-only', type=Path, required=True)
    parser.add_argument('--domain', required=True)
    args = parser.parse_args(remaining)
    directory = args.report_only
    raw = directory / '03_resolved.txt'
    if not raw.is_file():
        parser.error('No existe 03_resolved.txt en el directorio indicado')
    results = parse_dnsx_output(raw.read_text(encoding='utf-8').splitlines())
    passive = set(subenum.read_lines(directory / '01_passive_all.txt'))
    candidates = set(subenum.read_lines(directory / '02_permutations.txt'))
    path = subenum.generate_html_report(args.domain, directory, passive, candidates, results, sorted(results), set(), {}, 'reporte guardado, sin refiltrado wildcard')
    print(f'[OK] Informe regenerado: {path}')

if __name__ == '__main__':
    main()
