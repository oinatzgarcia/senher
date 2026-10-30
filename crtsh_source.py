"""Fuente crt.sh e integración con el punto de entrada SENHER."""
import html
import json
import re
import time
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')

def normalize(value):
    try:
        name = value.strip().lower().rstrip('.').encode('idna').decode('ascii')
    except (UnicodeError, AttributeError):
        return None
    if len(name) > 253 or not all(LABEL.fullmatch(x) for x in name.split('.')):
        return None
    return name

def extract(payload, domain):
    hosts, wildcards = set(), set()
    for row in payload:
        if not isinstance(row, dict):
            continue
        for field in ('name_value', 'common_name'):
            value = row.get(field)
            if not isinstance(value, str):
                continue
            for item in value.splitlines():
                item = item.strip()
                wildcard = item.startswith('*.')
                name = normalize(item[2:] if wildcard else item)
                if name and (name == domain or name.endswith('.' + domain)):
                    if wildcard:
                        wildcards.add('*.' + name)
                    else:
                        hosts.add(name)
    return sorted(hosts), sorted(wildcards)

def collect(domain, cache_dir, refresh=False, timeout=20):
    domain = normalize(domain)
    if not domain or '.' not in domain:
        raise ValueError('Dominio no válido')
    cache_dir = Path(cache_dir)
    cache_file = cache_dir / (domain + '.json')
    if not refresh:
        try:
            cached = json.loads(cache_file.read_text(encoding='utf-8'))
            age = time.time() - cached['fetched_at']
            if cached['domain'] == domain and 0 <= age < 86400 and isinstance(cached['records'], list):
                hosts, wildcards = extract(cached['records'], domain)
                return {'status': 'cache', 'hosts': hosts, 'wildcards': wildcards}
        except (OSError, ValueError, KeyError, TypeError):
            pass
    url = 'https://crt.sh/?' + urlencode({'q': '%.' + domain, 'output': 'json'})
    error = ''
    for attempt in range(2):
        try:
            request = Request(url, headers={'User-Agent': 'SENHER/1.0', 'Accept': 'application/json'})
            with urlopen(request, timeout=timeout) as response:
                raw = response.read(20 * 1024 * 1024 + 1)
            if len(raw) > 20 * 1024 * 1024:
                raise ValueError('Respuesta superior al límite de 20 MiB')
            records = json.loads(raw)
            if not isinstance(records, list):
                raise ValueError('La respuesta no es una lista JSON')
            hosts, wildcards = extract(records, domain)
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                temporary = cache_file.with_suffix('.tmp')
                temporary.write_text(json.dumps({'domain': domain, 'fetched_at': time.time(), 'records': records}), encoding='utf-8')
                temporary.replace(cache_file)
            except OSError:
                pass
            return {'status': 'ok', 'hosts': hosts, 'wildcards': wildcards}
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            error = str(exc)
            if isinstance(exc, HTTPError) and exc.code not in (429, 500, 502, 503, 504):
                break
            if attempt == 0:
                time.sleep(2)
    return {'status': 'error', 'hosts': [], 'wildcards': [], 'error': error}

def install(app, report, cache_dir, refresh=False, skip=False):
    original_enum = app.subfinder_enum
    def enumerate_with_crtsh(domain, outfile, active=False):
        existing = set(original_enum(domain, outfile, active=active))
        data = {'status': 'skipped', 'hosts': [], 'wildcards': []} if skip else collect(domain, cache_dir, refresh)
        directory = Path(outfile).parent
        (directory / 'crtsh.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
        app.write_lines(directory / 'crtsh.txt', data['hosts'])
        new = set(data['hosts']) - existing
        print(f"[crt.sh] {data['status']}: {len(data['hosts'])} nombres; {len(new)} adicionales respecto a Subfinder")
        if data['status'] == 'error':
            print('[!] crt.sh no disponible; se continúa con las otras fuentes.')
        return sorted(existing | set(data['hosts']))
    app.subfinder_enum = enumerate_with_crtsh
    def report_with_sources(*args, **kwargs):
        path = report(*args, **kwargs)
        directory = Path(path).parent
        sources = {}
        for filename, source in [('subfinder.txt', 'subfinder'), ('amass.txt', 'amass'), ('shodan.txt', 'shodan'), ('gau.txt', 'gau'), ('crtsh.txt', 'crt.sh')]:
            for line in app.read_lines(directory / filename):
                host = normalize(line)
                if host:
                    sources.setdefault(host, set()).add(source)
        serialized = {host: sorted(values) for host, values in sorted(sources.items())}
        (directory / 'sources.json').write_text(json.dumps(serialized, indent=2), encoding='utf-8')
        rows = ''.join('<tr><td>' + html.escape(host) + '</td><td>' + html.escape(', '.join(values)) + '</td></tr>' for host, values in serialized.items())
        section = '<section><h2>Procedencia de candidatos</h2><p>Encontrado en una fuente no implica resolución DNS actual. Los certificados wildcard no se convierten en hosts concretos.</p><div class="scroll"><table><tr><th>Host</th><th>Fuentes</th></tr>' + rows + '</table></div></section>'
        text = Path(path).read_text(encoding='utf-8')
        Path(path).write_text(text.replace('</html>', section + '</html>'), encoding='utf-8')
        return path
    app.generate_html_report = report_with_sources
