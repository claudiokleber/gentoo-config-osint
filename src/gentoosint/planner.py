"""Plans are descriptive data, not executable authorization."""
import subprocess

from .catalog import select
from .inventory import collect
from .process import run_bounded
from .security import SAFE_ENV, trusted_emerge


def make_plan(inv, modules):
    selected = select(modules)
    atoms = [t["atom"] for t in selected]
    eligible = inv["is_gentoo"] and inv["emerge_available"]
    return {"schema_version": 1, "mode": "plan-only", "target_eligible": eligible,
            "modules": sorted(set(modules)), "tools": selected,
            "target": {key: inv.get(key) for key in ('system', 'architecture', 'distribution', 'profile', 'init')},
            "pretend_argv": ["emerge", "--pretend", "--verbose", "--autounmask=n", *atoms],
            "install_argv_reference": ["emerge", "--ask", "--autounmask=n", *atoms],
            "resolution": "not-run", "changes_applied": False,
            "notes": ["Presença de executável não comprova instalação gerenciada pelo Portage.",
                      "USE flags, máscaras e dependências precisam ser resolvidas no alvo.",
                      "Nenhuma configuração, serviço ou instalação será aplicada nesta versão."]}


def resolve(plan, runner=None, timeout=120):
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise ValueError('Timeout deve estar entre 1 e 300 segundos.')
    if not isinstance(plan, dict) or plan.get('schema_version') != 1:
        raise ValueError('Plano inválido.')
    # Never execute supplied argv. Rebuild from the curated catalog and live target.
    current = make_plan(collect(), plan.get('modules'))
    for key in ('target', 'target_eligible', 'pretend_argv', 'install_argv_reference', 'tools', 'mode'):
        if plan.get(key) != current[key]:
            raise ValueError('Plano alterado ou ambiente mudou; gere um novo plano.')
    if not current["target_eligible"]:
        raise ValueError("A resolução requer Gentoo Linux com emerge disponível.")
    executable = trusted_emerge()
    argv = [executable, *current['pretend_argv'][1:]]
    runner = runner or run_bounded
    try:
        result = runner(argv, shell=False, timeout=timeout, cwd='/', env=dict(SAFE_ENV),
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, close_fds=True)
    except subprocess.TimeoutExpired:
        return dict(plan, resolution="timeout")
    except OSError:
        return dict(plan, resolution="unavailable")
    return dict(plan, resolution="passed" if result.returncode == 0 else "failed",
                resolver_returncode=result.returncode)
