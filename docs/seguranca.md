# Modelo de ameaças e limites — 0.2

## Proteções

| Risco | Medida |
|---|---|
| Injeção de shell/opções | Catálogo fechado, módulos validados, argumentos separados, shell=False |
| Plano adulterado/alvo diferente | Inventário recolhido, plano reconstruído, divergências recusadas |
| Executável falso no PATH | Caminho fixo e validação de dono root/modos de emerge e diretórios |
| Variáveis indevidas | Ambiente restrito a PATH fixo, LANG/LC_ALL e PYTHONNOUSERSITE |
| Processo preso | Timeout limitado e encerramento do grupo Linux em timeout/interrupção |
| Leitura excessiva/FIFO | Leitura limitada, abertura não bloqueante POSIX, arquivos regulares, números limitados |
| Sobrescrita | Criação exclusiva, extensão/nomes restritos, sem opção de força |
| Redirecionamento de diretório | POSIX: descritores e O_NOFOLLOW; Windows: checagem de reparse points |
| Controle de terminal | Controles e formatação invisível removidos do texto exibido |

Não importa planos JSON para executar. resolve recebe planos gerados em memória;
campos críticos são validados novamente. Hash de plano sozinho não autentica conteúdo.

## Base confiável e risco residual

Código GentooSint, Python, sistema operacional, Portage e configuração local precisam
ser confiáveis. Não protege contra root malicioso, alteração do próprio aplicativo ou
hooks maliciosos do Portage. Verificar permissões não substitui assinatura ou sandbox.
emerge --pretend pode carregar configuração/código local e gerar caches/logs. Não é
executado automaticamente sem --resolve. Não use o programa como administrador para
analisar um sistema comprometido.

No Windows, a checagem dos diretórios não é atômica contra troca concorrente por outro
processo; use pasta controlada pelo usuário. ACLs não são auditadas. No POSIX, percorre
diretórios com descritores sem seguir symlinks. Falha de escrita pode deixar arquivo
parcial, sem sobrescrita em tentativa posterior.

O encerramento inclui filhos que permaneçam no grupo criado. Um processo malicioso
pode abandonar esse grupo; não é contenção de software hostil. Não há promessa de
imunidade a ataques.

verify consulta registros locais que podem estar obsoletos; limita enumeração por
categoria e retorna unknown em acesso incompleto. Não verifica checksums, serviços,
conexão Tor ou anonimato. audit verifica somente modos/proprietário de caminhos
selecionados e formato do PATH. Nenhum achado é corrigido automaticamente.

## Fontes consultadas

- [Python subprocess](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Python os.open](https://docs.python.org/3/library/os.html#os.open)
- [Gentoo Portage](https://dev.gentoo.org/~zmedico/portage/doc/man/portage.5.html)
- [Microsoft GlobalMemoryStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex)
