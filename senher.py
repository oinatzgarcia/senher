#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
import subenum
from dns_reporting import parse_dnsx_output, generate_html_report

subenum.parse_dnsx_output = parse_dnsx_output
subenum.generate_html_report = generate_html_report

def main():
    if '--report-only' not in sys.argv:
        subenum.main()
        return
    parser = argparse.ArgumentParser(description='Regenerar informes sin consultas de red')
    parser.add_argument('--report-only', type=Path, required=True)
    parser.add_argument('--domain', required=True)
    args = parser.parse_args()
    directory = args.report_only
    raw = directory / '03_resolved.txt'
    if not raw.is_file():
        parser.error('No existe 03_resolved.txt en el directorio indicado')
    results = parse_dnsx_output(raw.read_text(encoding='utf-8').splitlines())
    passive = set(subenum.read_lines(directory / '01_passive_all.txt'))
    candidates = set(subenum.read_lines(directory / '02_permutations.txt'))
    path = generate_html_report(args.domain, directory, passive, candidates, results, sorted(results), set(), {}, 'reporte guardado, sin refiltrado wildcard')
    print(f'[OK] Informe regenerado: {path}')

if __name__ == '__main__':
    main()
