"""Conservative, evidence-based findings; no automatic tuning."""


def diagnose(inv):
    findings = []
    def add(code, severity, evidence, action):
        findings.append(dict(code=code, severity=severity, evidence=evidence, recommendation=action))
    if not inv["is_gentoo"]:
        add("unsupported-os", "warning", "O sistema não foi identificado como Gentoo Linux.",
            "Execute novamente no Gentoo para validar o ambiente alvo.")
    elif not inv["emerge_available"]:
        add("missing-emerge", "warning", "emerge não foi encontrado no PATH.",
            "Verifique a instalação do Portage e o PATH antes de planejar pacotes.")
    if inv["is_gentoo"] and inv["init"] == "unknown":
        add("unknown-init", "info", "Sistema de inicialização não identificado.",
            "Confirme o ambiente antes de configurar serviços.")
    disk = inv["disk_root"]
    if disk and disk["free_gib"] < 10:
        add("low-disk", "warning", f"Volume raiz: {disk['free_gib']} GiB livres.",
            "Investigue o espaço necessário para compilações; não remova arquivos automaticamente.")
    total, available = inv["memory_total_kib"], inv["memory_available_kib"]
    if total and available is not None and available / total < .15:
        add("memory-pressure", "warning", "MemAvailable abaixo de 15% de MemTotal nesta coleta.",
            "Repita a medição sem cargas transitórias antes de ajustar paralelismo de compilação.")
    if total and total < 4 * 1024**2:
        add("limited-memory", "info", "Memória total inferior a 4 GiB.",
            "Avalie consumo da compilação e paralelismo; não adote flags universais.")
    if total is None:
        add("unknown-memory", "info", "Dados de memória indisponíveis.",
            "Não emitir recomendação de paralelismo até obter a medição.")
    return findings
