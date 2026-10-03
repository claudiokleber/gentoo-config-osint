"""Boundaries for local IO and the sole external command."""
import os
import re
import stat
from pathlib import Path

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
            "PYTHONNOUSERSITE": "1"}


def safe_text(value):
    """Remove terminal controls including C1 and bidirectional formatting."""
    return ''.join(c if c in '\n\t' or (c.isprintable() and c not in '\u2028\u2029')
                   else '?' for c in str(value))


def trusted_emerge():
    """No PATH lookup; resolve merged-/usr symlinks, then inspect ownership/modes."""
    if os.name != 'posix':
        raise ValueError('Execução Portage disponível somente em Linux/Gentoo.')
    try:
        executable = Path('/usr/bin/emerge').resolve(strict=True)
        for item in (executable, *executable.parents, *Path('/usr/bin/emerge').parents):
            info = item.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Caminho do emerge não possui permissões confiáveis.')
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError('emerge não é um arquivo executável.')
    except OSError as exc:
        raise ValueError('Não foi possível validar /usr/bin/emerge.') from exc
    return str(executable)


def write_report(path, content):
    """Exclusive file creation. POSIX parents opened one at a time without symlinks."""
    path = Path(path)
    if '..' in path.parts or path.suffix.lower() not in {'.json', '.md'}:
        raise ValueError('Use um novo arquivo .json ou .md, sem componentes .. no caminho.')
    for part in path.parts[1:] if path.is_absolute() else path.parts:
        if ':' in part or re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part, re.I):
            raise ValueError('Nome reservado ou fluxo alternativo não permitido.')
    absolute = Path(os.path.abspath(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    if os.name == 'posix':
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory_fd = os.open('/', directory_flags)
        try:
            for part in absolute.parent.parts[1:]:
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            fd = os.open(absolute.name, flags, 0o600, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
    else:
        # Windows ACLs apply; reject existing reparse-point parents. This check is
        # not atomic against another process concurrently replacing directories.
        for parent in (absolute.parent, *absolute.parent.parents):
            info = parent.lstat()
            if getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('Diretório com redirecionamento não permitido.')
        fd = os.open(absolute, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
