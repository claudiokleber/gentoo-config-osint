import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .catalog import catalog
from .diagnostics import diagnose
from .inventory import collect
from .planner import make_plan, resolve
from .checks import audit, verify
from .security import safe_text, write_report


def markdown(data):
    # JSON in a fenced block preserves types and makes unknowns explicit.
    body = safe_text(json.dumps(data, ensure_ascii=False, indent=2))
    fence = '`' * max(3, max((len(x) for x in re.findall(r'`+', body)), default=0) + 1)
    return '# GentooSint — relatório\n\nDados locais; nenhuma alteração aplicada.\n\n' + fence + 'json\n' + body + '\n' + fence + '\n'


def parser():
    p = argparse.ArgumentParser(description="GentooSint — diagnóstico e planejamento local", allow_abbrev=False)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    for name in ["doctor", "catalog", "plan", "optimize", "verify", "audit"]:
        cmd = sub.add_parser(name, allow_abbrev=False)
        cmd.add_argument("--format", choices=["json", "markdown"], default="markdown")
        cmd.add_argument("--output", type=Path, help="Novo arquivo; não sobrescreve arquivos existentes")
        if name in {"plan", "verify"}:
            cmd.add_argument("--modules", required=name == 'plan', default='tor,security,osint', help="tor,security,osint")
        if name == "plan":
            cmd.add_argument("--resolve", action="store_true", help="Executa somente emerge --pretend no Gentoo")
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    try:
        result = {"application": "GentooSint", "version": __version__,
                  "collected_at": datetime.now(timezone.utc).isoformat(),
                  "command": args.command}
        code = 0
        if args.command == "catalog":
            result["tools"] = catalog()
        else:
            inv = collect()
            result["inventory"] = inv
            if args.command == "audit":
                result['audit'] = audit(inv)
            elif args.command == 'verify':
                result['verification'] = verify(inv, args.modules.split(','))
            elif args.command == "plan":
                if len(args.modules) > 512:
                    raise ValueError('Lista de módulos excessiva.')
                modules = [m.strip() for m in args.modules.split(",") if m.strip()]
                plan = make_plan(inv, modules)
                if args.resolve:
                    plan = resolve(plan)
                    if plan["resolution"] != "passed": code = 3
                result["plan"] = plan
            else:
                result["findings"] = diagnose(inv)
                result["changes_applied"] = False
                if args.command == "optimize":
                    result["mode"] = "recommendations-only"
                    result["note"] = "Medição pontual; nenhum ganho de desempenho foi demonstrado."
        output = json.dumps(result, ensure_ascii=False, indent=2) + "\n" if args.format == "json" else markdown(result)
        if args.output:
            write_report(args.output, output)
            print("Relatório salvo.")
        else:
            print(safe_text(output), end="")
        return code
    except (ValueError, OSError) as exc:
        print(safe_text(f"Erro: {exc}"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrompido.", file=sys.stderr)
        return 130
