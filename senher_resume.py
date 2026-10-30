#!/usr/bin/env python3
"""Lanzador Kali con checkpoints por fase; no guarda secretos."""
import argparse
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import senher
import subenum as app


def atomic(path, data):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def encode(value):
    if isinstance(value, set):
        return {'__set__': sorted(value)}
    if isinstance(value, Path):
        return {'__path__': str(value)}
    if isinstance(value, (list, tuple)):
        return [encode(item) for item in value]
    if isinstance(value, dict):
        return {key: encode(item) for key, item in value.items()}
    return value


def decode(value):
    if isinstance(value, list):
        return [decode(item) for item in value]
    if isinstance(value, dict):
        if set(value) == {'__set__'}:
            return set(value['__set__'])
        if set(value) == {'__path__'}:
            return Path(value['__path__'])
        return {key: decode(item) for key, item in value.items()}
    return value


def checked_run(cmd, outfile=None, stdin_data=None, timeout=None):
    print('[*] ' + ' '.join(map(str, cmd)), flush=True)
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    def stop():
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
    try:
        stdout, stderr = process.communicate(input=stdin_data, timeout=timeout)
    except (KeyboardInterrupt, subprocess.TimeoutExpired):
        stop()
        process.communicate()
        raise
    if process.returncode:
        raise RuntimeError(f'{cmd[0]} terminó con código {process.returncode}: {stderr[-4000:]}')
    if outfile:
        Path(outfile).write_text(stdout, encoding='utf-8')
    return stdout


def main():
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument('--resume', type=Path)
    options.add_argument('--session-dir', type=Path)
    config, remaining = options.parse_known_args()
    if '--help' in remaining or '-h' in remaining:
        print('Checkpoints: --session-dir RUTA | --resume RUTA (sin otras opciones)')
        sys.argv = [sys.argv[0]] + remaining
        senher.main()
        return
    if config.resume and (remaining or config.session_dir):
        options.error('--resume recupera la configuración guardada; no admite otras opciones')
    if not config.resume and not remaining:
        options.error('Indica un dominio y opciones, o --resume RUTA')
    if '--report-only' in remaining:
        options.error('Para regenerar informes usa senher.py --report-only')
    if any(token in ('-k', '--shodan-key') or token.startswith(('--shodan-key=', '-k')) for token in remaining):
        options.error('Usa SHODAN_API_KEY como variable de entorno; no se guardan claves en checkpoints')
    if any(token in ('-o', '--output-dir') or token.startswith(('--output-dir=', '-o')) for token in remaining):
        options.error('Usa --session-dir en lugar de --output-dir')
    directory = (config.resume or config.session_dir or Path('output') / ('session_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))).resolve()
    if config.resume and not (directory / 'checkpoint.json').is_file():
        options.error('No existe checkpoint.json; no se importan automáticamente ejecuciones antiguas')
    directory.mkdir(parents=True, exist_ok=True)
    lock = (directory / '.session.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        options.error('Esta sesión ya está siendo utilizada por otro proceso')
    state_path = directory / 'checkpoint.json'
    if config.resume:
        state = json.loads(state_path.read_text(encoding='utf-8'))
        if state.get('version') != 1 or state.get('cwd') != str(Path.cwd()):
            options.error('Versión incompatible o directorio de trabajo distinto al original')
        remaining = state['arguments']
    else:
        if state_path.exists():
            options.error('La sesión ya existe: utiliza --resume')
        state = {'version': 1, 'cwd': str(Path.cwd()), 'arguments': remaining, 'completed': {}, 'status': 'created'}
    state['status'] = 'running'
    atomic(state_path, state)
    app.run = checked_run
    def wrap(name):
        original = getattr(app, name)
        def stage(*args, **kwargs):
            key = name + ':' + hashlib.sha256(json.dumps(encode([args, kwargs]), sort_keys=True).encode()).hexdigest()
            previous = state['completed'].get(key)
            if previous is not None:
                if all((directory / path).is_file() and hashlib.sha256((directory / path).read_bytes()).hexdigest() == digest for path, digest in previous['files'].items()):
                    print('[resume] Reutilizando ' + name)
                    return decode(previous['result'])
                print('[resume] Archivos cambiados o ausentes; repitiendo ' + name)
            state['current'] = name
            atomic(state_path, state)
            result = original(*args, **kwargs)
            files = {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.iterdir() if path.is_file() and path.name not in ('checkpoint.json', 'checkpoint.tmp', '.session.lock')}
            state['completed'][key] = {'result': encode(result), 'files': files}
            atomic(state_path, state)
            return result
        setattr(app, name, stage)
    for name in ('choose_mode', 'choose_wordlist', 'subfinder_enum', 'amass_enum', 'shodan_enum', 'gau_enum', 'alterx_permutations', 'gotator_permutations', 'detect_wildcards', 'dnsx_validate', 'whois_lookup'):
        wrap(name)
    # Evitar escrituras concurrentes del checkpoint durante permutaciones.
    import threading
    mutex = threading.RLock()
    for name in ('alterx_permutations', 'gotator_permutations'):
        original = getattr(app, name)
        def serial(*args, _function=original, **kwargs):
            with mutex:
                return _function(*args, **kwargs)
        setattr(app, name, serial)
    sys.argv = [sys.argv[0]] + remaining + ['--output-dir', str(directory)]
    print('[session] ' + str(directory), flush=True)
    print('[session] Reanudar: python3 senher_resume.py --resume ' + str(directory), flush=True)
    try:
        senher.main()
    except KeyboardInterrupt:
        state['status'] = 'interrupted'
        atomic(state_path, state)
        print('\n[session] Interrumpida; fases terminadas conservadas.')
        return 130
    except (Exception, SystemExit) as exc:
        state['status'] = 'failed'
        atomic(state_path, state)
        print('[session] Error: ' + str(exc), file=sys.stderr)
        return 1
    state['status'] = 'completed'
    state.pop('current', None)
    atomic(state_path, state)
    return 0


if __name__ == '__main__':
    sys.exit(main())
