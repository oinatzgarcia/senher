"""Adaptador de salida Amass basado en las opciones del binario instalado."""
import re
import subprocess
from pathlib import Path
import subenum

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def names_from_text(text, domain):
    domain = domain.lower().rstrip('.')
    pattern = re.compile(r'(?<![a-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*' + re.escape(domain) + r'(?![a-z0-9_.-])', re.I)
    return {match.group(0).lower() for match in pattern.finditer(ANSI.sub('', text))}


def amass_enum(domain, outfile, active=False, wordlist=None):
    help_result = subprocess.run(['amass', 'enum', '-h'], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    help_text = help_result.stdout + help_result.stderr
    has_prefix = re.search(r'(?m)^\s*-oA\s', help_text) is not None
    has_output = re.search(r'(?m)^\s*-o\s', help_text) is not None
    if not has_prefix and not has_output:
        raise RuntimeError('Amass no anuncia -oA ni -o; revisar amass enum -h antes de continuar')
    output = Path(outfile)
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_directory = output.parent / 'amass_raw'
    raw_directory.mkdir(exist_ok=True)
    prefix = raw_directory / 'enumeration'
    legacy = raw_directory / 'names.txt'
    for old in raw_directory.glob('enumeration.*'):
        if old.is_file():
            old.unlink()
    if legacy.exists():
        legacy.unlink()
    cmd = ['amass', 'enum', '-d', domain]
    if active:
        if not wordlist or not Path(wordlist).is_file():
            raise ValueError('Amass activo requiere una wordlist válida')
        cmd += ['-active', '-brute', '-w', str(wordlist)]
    else:
        cmd += ['-passive']
    if re.search(r'(?m)^\s*-nocolor(?:\s|$)', help_text):
        cmd += ['-nocolor']
    cmd += ['-oA', str(prefix)] if has_prefix else ['-o', str(legacy)]
    # app.run se sustituye por el runner estricto al usar senher_resume.py.
    text = subenum.run(cmd)
    (raw_directory / 'stdout.log').write_text(text, encoding='utf-8')
    files = sorted(raw_directory.glob('enumeration.*')) if has_prefix else [legacy]
    files = [path for path in files if path.is_file()]
    if not files:
        raise RuntimeError('Amass no generó archivos de salida. Revisar configuración, engine y stdout.log; la fase no se marca completada')
    discovered = set()
    for path in files:
        discovered.update(names_from_text(path.read_text(encoding='utf-8', errors='replace'), domain))
    # Los archivos originales se conservan; la lista consumida por SENHER es normalizada.
    subenum.write_lines(output, discovered)
    print(f'[Amass] {len(discovered)} nombres en scope; originales: {raw_directory}')
    return sorted(discovered)
