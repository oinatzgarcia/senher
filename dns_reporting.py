"""Parser DNS sin colores e informe local de infraestructura compartida."""
import html
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
HOST = re.compile(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$', re.I)

def parse_dnsx_output(lines):
    results = {}
    for raw in lines:
        line = ANSI.sub('', raw).strip()
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        host = parts[0].lower().rstrip('.')
        if not HOST.fullmatch(host):
            continue
        record_type = None
        for block in re.findall(r'\[([^\]]*)\]', parts[1]):
            for token in re.split(r'[,\s]+', block.strip()):
                upper = token.upper()
                if upper in ('A', 'AAAA', 'CNAME'):
                    record_type = upper
                    continue
                if not token:
                    continue
                try:
                    address = ipaddress.ip_address(token)
                    kind = 'A' if address.version == 4 else 'AAAA'
                    value = str(address)
                except ValueError:
                    if record_type != 'CNAME' or not HOST.fullmatch(token.rstrip('.')):
                        continue
                    kind, value = 'CNAME', token.lower().rstrip('.')
                data = results.setdefault(host, {'A': [], 'AAAA': [], 'CNAME': []})
                if value not in data[kind]:
                    data[kind].append(value)
    return results

def ip_key(value):
    address = ipaddress.ip_address(value)
    return address.version, int(address)

def infrastructure(results):
    groups = defaultdict(set)
    for host, data in results.items():
        for value in data.get('A', []) + data.get('AAAA', []):
            try:
                groups[str(ipaddress.ip_address(value))].add(host)
            except ValueError:
                continue
    return [{'ip': ip, 'hosts': sorted(groups[ip]), 'host_count': len(groups[ip]), 'shared': len(groups[ip]) >= 2} for ip in sorted(groups, key=ip_key)]

def generate_html_report(domain, outdir, passive, candidates, dns_results, resolved_hosts, wildcard_ips, wildcard_candidates, mode):
    directory = Path(outdir)
    groups = infrastructure(dns_results)
    shared = [group for group in groups if group['shared']]
    escape = lambda value: html.escape(str(value), quote=True)
    def table(headers, rows):
        head = ''.join('<th>' + escape(h) + '</th>' for h in headers)
        body = ''.join('<tr>' + ''.join('<td>' + escape(c) + '</td>' for c in row) + '</tr>' for row in rows)
        return '<div class=scroll><table><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table></div>'
    doc = ['<!doctype html><html lang=es><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>SENHER</title><style>body{background:#0b1020;color:#e5e7eb;font:15px system-ui;margin:32px}section{background:#111827;padding:20px;border-radius:12px;margin:20px 0}.scroll{overflow:auto}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #334155;overflow-wrap:anywhere}th{color:#22d3ee}p{line-height:1.6}</style>']
    doc += ['<h1>SENHER: ' + escape(domain) + '</h1>', '<p>Modo: ' + escape(mode) + ' | ' + escape(datetime.now().isoformat(timespec='seconds')) + '</p>']
    doc += [f'<p>Hosts con respuesta DNS interpretada: {len(dns_results)} | IPs únicas: {len(groups)} | IPs compartidas: {len(shared)}</p>']
    doc += ['<section><h2>Infraestructura compartida</h2><p>Coincidir en una IP no demuestra mismo servidor físico, propietario ni servicio. Puede tratarse de proxy, CDN, balanceo o alojamiento compartido. No se atribuye proveedor sin evidencia verificada.</p>']
    doc += [table(['IP', 'Número de hosts', 'Subdominios'], [(g['ip'], g['host_count'], ', '.join(g['hosts'])) for g in shared]) if shared else '<p>No se observan IPs con dos o más hosts.</p>', '</section>']
    doc += ['<section><h2>Todas las IPs</h2>', table(['IP', 'Hosts', 'Compartida'], [(g['ip'], ', '.join(g['hosts']), 'Sí' if g['shared'] else 'No') for g in groups]), '</section>']
    rows = []
    for host, data in sorted(dns_results.items()):
        rows.append((host, 'Recolectado' if host in passive else 'Candidato', ', '.join(sorted(data.get('A', []), key=ip_key)) or '-', ', '.join(sorted(data.get('AAAA', []), key=ip_key)) or '-', ', '.join(data.get('CNAME', [])) or '-'))
    doc += ['<section><h2>Detalle por subdominio</h2>', table(['Subdominio', 'Origen', 'IPv4', 'IPv6', 'CNAME'], rows), '</section>']
    doc += ['<section><h2>Revisión de wildcard</h2><p>Hosts separados por el filtro previo: ' + str(len(wildcard_candidates)) + '. La coincidencia de IP es una heurística, no prueba de que un host sea falso.</p>', table(['Host', 'A', 'AAAA', 'CNAME'], [(host, ', '.join(data.get('A', [])), ', '.join(data.get('AAAA', [])), ', '.join(data.get('CNAME', []))) for host, data in sorted(wildcard_candidates.items())]), '</section></html>']
    path = directory / 'report.html'
    path.write_text('\n'.join(doc), encoding='utf-8')
    (directory / 'infrastructure.json').write_text(json.dumps(groups, indent=2, ensure_ascii=False), encoding='utf-8')
    markdown = '# Infraestructura compartida\n\nCoincidencia de IP, no prueba de mismo servidor ni propietario.\n\n'
    for group in shared:
        markdown += '## ' + group['ip'] + '\n' + '\n'.join('- ' + host for host in group['hosts']) + '\n\n'
    (directory / 'INFRASTRUCTURE.md').write_text(markdown, encoding='utf-8')
    return path
