"""Curated package identifiers; availability is resolved on the target machine."""

TOOLS = (
    {"id": "tor", "module": "tor", "atom": "net-vpn/tor", "binary": "tor",
     "description": "Cliente Tor; este plano não ativa serviço ou relay."},
    {"id": "gnupg", "module": "security", "atom": "app-crypt/gnupg", "binary": "gpg",
     "description": "Criptografia e assinaturas OpenPGP."},
    {"id": "exiftool", "module": "osint", "atom": "media-libs/exiftool", "binary": "exiftool",
     "description": "Inspeção de metadados de arquivos."},
    {"id": "dns", "module": "osint", "atom": "net-dns/bind-tools", "binary": "dig",
     "description": "Ferramentas de consulta DNS; consultas não são executadas."},
)


def catalog():
    return [dict(tool, source="https://packages.gentoo.org/packages/" + tool["atom"],
                 source_checked="2026-09-30") for tool in TOOLS]


def select(modules):
    if not isinstance(modules, (list, tuple)) or len(modules) > 16 or any(
            not isinstance(m, str) or len(m) > 32 for m in modules):
        raise ValueError("Lista de módulos inválida ou excessiva.")
    available = {t["module"] for t in TOOLS}
    requested = set(modules)
    unknown = requested - available
    if not requested or unknown:
        raise ValueError("Módulos válidos: " + ", ".join(sorted(available)))
    return [t for t in catalog() if t["module"] in requested]
