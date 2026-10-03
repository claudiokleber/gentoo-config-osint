# GentooSint 0.2

Aplicativo Python do projeto GentooSec: diagnóstico, verificações locais de segurança
e planejamento modular para Gentoo. Python 3.11+ declarado; biblioteca padrão em runtime.

## Começar

Na pasta do projeto:

```sh
python gentoosint.py doctor
python gentoosint.py audit
python gentoosint.py verify
python gentoosint.py catalog
python gentoosint.py plan --modules tor,security,osint
python gentoosint.py optimize
```

No Gentoo, use `python3` conforme o interpretador disponível. Não precisa executar
diagnóstico como administrador. Opcionalmente, em ambiente virtual, use
`python -m pip install -e .` para disponibilizar `gentoosint`; empacotamento via setuptools.

## Comandos

| Comando | Resultado |
|---|---|
| doctor | Sistema, arquitetura, CPU lógica, memória Windows/Linux, espaço raiz, perfil e init |
| audit | PATH relativo/vazio e proprietário/permissões de caminhos selecionados no Linux |
| verify | Registros dos pacotes do catálogo na base local e presença de executáveis |
| catalog | Tor, GnuPG, ExifTool e ferramentas DNS com fontes oficiais |
| plan | Plano descritivo dos módulos selecionados; nenhum pacote instalado |
| optimize | Recomendações sobre recursos; não aplica ajustes |

`verify --modules tor` restringe a consulta ao módulo Tor. Registros em `/var/db/pkg`
não comprovam integridade ou funcionamento; `functional_status` fica `not-tested`.
Banco ausente/inacessível é `unknown`. No Windows, Portage é `not-applicable`.

`audit` examina `/etc/portage`, `/etc/portage/make.conf`, `/etc/tor/torrc` e
`/etc/ssh/sshd_config` sem ler conteúdo. Symlinks exigem revisão. Um resultado `pass`
refere-se somente à checagem indicada, não à segurança da máquina. Não é scanner de CVEs.

## Relatórios

```sh
python gentoosint.py doctor --format json --output diagnostico-02.json
python gentoosint.py audit --output auditoria-02.md
```

Sem `--output`, imprime no terminal. Com a opção, cria arquivo UTF-8 novo e recusa
sobrescrita. Pasta precisa existir; somente `.json` e `.md`. Não aceita `..`, nomes
de dispositivos, fluxos alternativos ou diretórios com redirecionamento. POSIX: modo
0600. Windows: ACLs da pasta. Falha de escrita pode deixar arquivo parcial.

Não coleta hostname, IP, números de série, ambiente completo ou conteúdo bruto de
configurações. Inclui características gerais de hardware/sistema; revise antes de
compartilhar. Dados ausentes permanecem desconhecidos.

## Resolver no Gentoo

```sh
python3 gentoosint.py plan --modules tor --resolve
```

Revalida o alvo e reconstrói argumentos pelo catálogo. Somente esse modo chama
`/usr/bin/emerge --pretend --verbose --autounmask=n`, após validar dono e permissões
do caminho. Não usa o PATH do usuário. Ambiente restrito; stdin/saída bruta descartados;
timeout de 120 segundos. Timeout/interrupção encerra o grupo Linux criado para a operação.
Falha não é sucesso. Portage e sua configuração local precisam ser confiáveis; ele
pode carregar código e gerar caches/logs. Gentoo Prefix e emerge fora desse caminho
não são suportados. Veja [modelo de segurança](docs/seguranca.md).

Códigos de saída: 0 = comando concluído (pode conter achados); 2 = entrada/IO/alvo
inválido; 3 = resolução falhou/timeout/indisponível; 130 = interrompido.

## Limites

Não instala pacotes, modifica serviços, configura Tor, aplica ajustes ou faz varredura
de rede. Não existe `apply`. `verify` examina registros, não funcionamento. Sem garantia
de suporte universal. Espaço raiz não representa todos os volumes. Recomendações usam
uma coleta pontual; nenhum ganho de desempenho foi demonstrado.

## Testes

```sh
python -m unittest discover -s tests -v
```

Windows/Python 3.14.7: 33 testes aprovados e 1 não executado (symlinks/FIFO POSIX).
Linux é coberto por arquivos e operações simulados. Integração Portage, execução real
dos controles POSIX e Python 3.11 ainda precisam ser testados. Empacotamento pip não
validado nesta etapa. Próximo passo: diagnóstico e simulação em Gentoo, depois aplicação
e configuração com preservação de arquivos e verificação funcional.

[Fontes do catálogo](docs/fontes.md) · [Histórico](CHANGELOG.md).
Licenciado sob a GNU General Public License, somente versão 3 (GPL-3.0-only). Veja os termos completos em [LICENSE](LICENSE).
