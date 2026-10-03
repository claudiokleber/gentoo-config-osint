"""Local checks. No network requests and no execution of discovered tools."""
import os
import re
import stat
from pathlib import Path

from .catalog import select


def verify(inv, modules, root=Path('/')):
    results = []
    for tool in select(modules):
        entry = {'tool': tool['id'], 'atom': tool['atom'],
                 'executable_present': inv['executables'].get(tool['id'], False),
                 'package_status': 'not-applicable', 'versions': [],
                 'functional_status': 'not-tested'}
        if inv['is_gentoo']:
            category, package = tool['atom'].split('/')
            db = root / 'var/db/pkg'
            directory = db / category
            try:
                if not db.is_dir():
                    entry['package_status'] = 'unknown'
                else:
                    versions = []
                    if directory.is_dir():
                        with os.scandir(directory) as items:
                            for index, item in enumerate(items):
                                if index >= 20000:
                                    raise ValueError('Package database limit')
                                match = re.fullmatch(re.escape(package) + r'-(\d[0-9A-Za-z._+\-]{0,100})', item.name)
                                if match and item.is_dir(follow_symlinks=False):
                                    versions.append(match.group(1))
                    entry['versions'] = sorted(versions)
                    entry['package_status'] = 'recorded' if versions else 'not-recorded'
            except (OSError, ValueError):
                entry['package_status'] = 'unknown'
        results.append(entry)
    return {'tools': results, 'changes_applied': False,
            'scope': 'Registros em /var/db/pkg e presença de executáveis; não verifica integridade ou funcionamento.'}


def audit(inv, root=Path('/'), environment=None):
    env = os.environ if environment is None else environment
    checks = []
    entries = env.get('PATH', '').split(os.pathsep)
    risky = sum(not x or not Path(x).is_absolute() for x in entries)
    checks.append({'code': 'path-relative', 'status': 'warning' if risky else 'pass',
                   'evidence': f'{risky} entradas vazias ou relativas no PATH.',
                   'recommendation': 'Prefira diretórios absolutos; a resolução Portage ignora esse PATH.'})
    if inv['system'] != 'Linux':
        checks.append({'code': 'linux-permissions', 'status': 'not-applicable',
                       'evidence': 'Permissões POSIX não avaliadas neste sistema.'})
    else:
        for relative in ['etc/portage', 'etc/portage/make.conf', 'etc/tor/torrc', 'etc/ssh/sshd_config']:
            try:
                info = (root / relative).lstat()
                if stat.S_ISLNK(info.st_mode):
                    status = 'review'
                elif info.st_mode & 0o022 or info.st_uid != 0:
                    status = 'warning'
                else:
                    status = 'pass'
                checks.append({'code': relative, 'status': status,
                               'evidence': 'Somente proprietário/modo do caminho; conteúdo não lido.',
                               'recommendation': 'Revisar se alterações por outros usuários são intencionais.'})
            except FileNotFoundError:
                checks.append({'code': relative, 'status': 'not-found'})
            except OSError:
                checks.append({'code': relative, 'status': 'unknown'})
    return {'checks': checks, 'changes_applied': False,
            'scope': 'Triagem local limitada; não é scanner de vulnerabilidades nem certificação de segurança.'}
