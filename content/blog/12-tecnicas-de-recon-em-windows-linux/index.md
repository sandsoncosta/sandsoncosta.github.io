---
title: "Técnicas de Recon em Windows e Linux: Casos de Uso para Red Team, Blue Team e Threat Hunting"
date: 2024-11-05T10:17:41-03:00
draft: false
description: "Neste artigo, abordamos uma lista abrangente de comandos de reconhecimento em Windows e Linux, com foco em casos de uso práticos tanto para Blue Team quanto para Red Team, além de dar uma visão para Threat Hunters e Engenharia de Detecção."
noindex: false
featured: false
pinned: false
comments: false
series:
#  - 
categories:
 - Windows
 - Linux
tags:
 - Recon
 - Reconnaissance
 - Reconhecimento
authors:
 - sandson
images:
#  - 
# menu:
#   main:
#     weight: 100
#     params:
#       icon:
#         vendor: bs
#         name: book
#         color: '#e24d0e'
---

<div class="sharethis-inline-share-buttons"></div>

## 1. Introdução

O reconhecimento (ou "recon") é uma etapa fundamental nas operações de segurança cibernética. Ele envolve a coleta de informações sobre o sistema e a rede para identificar potenciais vulnerabilidades e comportamentos suspeitos. Equipes de segurança, como Red Teams e Blue Teams, utilizam comandos de reconhecimento para mapear o ambiente e entender a infraestrutura que estão protegendo ou testando.

Neste artigo, abordamos uma lista abrangente de comandos de reconhecimento em Windows e Linux, com foco em casos de uso práticos tanto para Blue Team quanto para Red Team, além de dar uma visão para o Threat Hunting e Engenharia de Detecção.

###### Leia também!

{{< bs/bookmark-card
url="https://sandsoncosta.github.io/blog/2024/10/como-o-threat-hunting-pode-contribuir-no-processo-de-maturidade-de-uma-empresa-um-caso-de-uso-pr%C3%A1tico/"
title="Como o Threat Hunting pode contribuir no processo de maturidade de uma empresa - Um Caso de Uso prático" 
img="https://sandsoncosta.github.io/blog/2024/10/como-o-threat-hunting-pode-contribuir-no-processo-de-maturidade-de-uma-empresa-um-caso-de-uso-pr%C3%A1tico/featured-sample_hu15151624785549089067.webp" 
author="Sandson Costa"
authorImg="https://media.licdn.com/dms/image/v2/C4E03AQG1ijVuqWP5mw/profile-displayphoto-shrink_200_200/profile-displayphoto-shrink_200_200/0/1572869751467?e=1732752000&v=beta&t=p72NbGQyfBo-VJ8jTyFLTUux0G5FEt-NbH8AIbq0L1Q"
authorIcon="pencil-square"
authorIconVendor="bootstrap"
>}}

O artigo explora como o Threat Hunting aprimora a segurança nas empresas, com um caso prático sobre um Web Application Firewall (WAF) e a importância da detecção proativa.

{{< /bs/bookmark-card >}}

## 2. O papel do reconhecimento no ciclo de defesa e ataque

Em atividades de Red Team, o reconhecimento serve para mapear o ambiente alvo, identificando portas abertas, serviços vulneráveis e dados expostos. Essas informações permitem uma movimentação lateral eficaz e ataques mais precisos. No contexto do Blue Team, o reconhecimento é utilizado para validar a segurança de sistemas, simular cenários de ataque e melhorar a detecção por meio de políticas e alertas mais eficazes. Para o Threat Hunting, esses comandos ajudam a identificar anomalias, verificar a integridade de sistemas e detectar alterações suspeitas que podem ser usados para criar regras de detecção específicos com base nas ações do atacante, reforçando políticas de segurança.

## 3. Comandos de reconhecimento em Windows

### Informações do sistema

- **Comando:** `systeminfo`
- **Descrição:** Exibe informações detalhadas sobre o sistema operacional e hardware.
- **Caso de uso para Blue Team:** Auxilia na verificação de conformidade com políticas de segurança e no monitoramento de atualizações críticas de segurança.
- **Caso de uso para Red Team:** Usado para coletar informações sobre a versão do sistema operacional e patches instalados, o que ajuda na identificação de vulnerabilidades conhecidas que podem ser exploradas.
---
- **Comando:** `hostname`
- **Descrição:** Mostra o nome do host atual.
- **Caso de uso para Blue Team:** Facilita a identificação de máquinas durante auditorias e resposta a incidentes.
- **Caso de uso para Red Team:** Permite que o red team identifique o nome da máquina alvo durante uma infiltração, ajudando a mapear a rede e os ativos.
---
- **Comando:** `whoami`
- **Descrição:** Mostra o nome do usuário logado atualmente.
- **Caso de uso para Blue Team:** Útil para verificar a identidade do usuário em caso de comportamentos suspeitos ou investigações de atividades.
- **Caso de uso para Red Team:** Ajuda a confirmar a identidade e os privilégios do usuário logado, permitindo o planejamento de elevações de privilégios ou movimentos laterais.
---
- **Comando:** `wmic os get Caption, Version, BuildNumber, OSArchitecture`
- **Descrição:** Exibe detalhes sobre o sistema operacional, incluindo nome, versão, número de build e arquitetura.
- **Caso de uso para Blue Team:** Ajuda na auditoria de conformidade com requisitos de segurança e na identificação de sistemas desatualizados.
- **Caso de uso para Red Team:** Utilizado para coletar detalhes sobre o sistema operacional que podem ser relevantes para a exploração de vulnerabilidades específicas.

### Rede

- **Comando:** `ipconfig /all`
- **Descrição:** Mostra configurações detalhadas de rede.
- **Caso de uso para Blue Team:** Útil para verificar as configurações de rede e detectar possíveis conexões não autorizadas.
- **Caso de uso para Red Team:** Identifica configurações de IP, o que pode revelar informações sobre a topologia da rede e dispositivos conectados.
---
- **Comando:** `netstat -nao`
- **Descrição:** Lista conexões de rede ativas e portas de escuta, com IDs de processo.
- **Caso de uso para Blue Team:** Ajuda a detectar conexões suspeitas que podem indicar a presença de malware ou intrusões.
- **Caso de uso para Red Team:** Permite identificar conexões de rede ativas e processos que podem estar se comunicando com servidores de comando e controle (C2).
---
- **Comando:** `route print`
- **Descrição:** Exibe a tabela de rotas da rede, incluindo gateways e rotas estáticas.
- **Caso de uso para Blue Team:** Utilizado para verificar a tabela de rotas e identificar configurações incorretas que possam comprometer a segurança.
- **Caso de uso para Red Team:** Ajuda a identificar rotas de tráfego que podem ser exploradas para movimentos laterais ou evasão de detecção.
---
- **Comando:** `tracert`
- **Descrição:** Rastreia o caminho que um pacote toma até um host de destino, mostrando cada salto (hop) pelo qual o pacote passa.
- **Caso de uso para Blue Team:** Auxilia na solução de problemas de conectividade e análise de desempenho da rede.
- **Caso de uso para Red Team:** Usado para mapear a rota até o alvo, ajudando a identificar pontos fracos na rede que podem ser explorados.
---
- **Comando:** `arp -a`
- **Descrição:** Lista o cache ARP (Address Resolution Protocol), que associa endereços IP a endereços MAC.
- **Caso de uso para Blue Team:** Facilita a identificação de máquinas durante auditorias e resposta a incidentes.
- **Caso de uso para Red Team:** Com base nos endereços IP e MAC, o atacante pode começar a construir um mapa mental ou físico da rede, identificando possíveis alvos e pontos de entrada.
---
- **Comando:** `ping <host>`
- **Descrição:** Verifica a conectividade entre o sistema e um host remoto.
- **Caso de uso para Blue Team:** Ajuda a detectar falhas de comunicação ou problemas de rede.
- **Caso de uso para Red Team:** Usado para verificar se um alvo está ativo antes de realizar um ataque.

### Usuários e grupos

- **Comando:** `net user`
- **Descrição:** Lista todos os usuários locais no sistema.
- **Caso de uso para Blue Team:** Útil para auditorias de contas de usuário, garantindo que apenas usuários autorizados tenham acesso.
- **Caso de uso para Red Team:** Identifica contas de usuário que podem ser alvos para exploração ou ataque.
---
- **Comando:** `net localgroup`
- **Descrição:** Lista todos os grupos locais do sistema e os usuários que pertencem a esses grupos.
- **Caso de uso para Blue Team:** Usado para monitorar membros de grupos privilegiados e detectar possíveis elevações de privilégios.
- **Caso de uso para Red Team:** Permite identificar grupos com privilégios elevados, facilitando o foco em contas que podem ser comprometidas.
---
- **Comando:** `whoami /priv`
- **Descrição:** Exibe permissões do usuário logado.
- **Caso de uso para Blue Team:** Utilizado para verificar permissões do usuário e identificar possíveis riscos de segurança.
- **Caso de uso para Red Team:** Ajuda a identificar permissões que podem ser exploradas para obter controle adicional do sistema.
---
- **Comando:** `wmic useraccount get name, sid`
- **Descrição:** Lista os nomes de usuários e seus SIDs (identificadores de segurança) no sistema.
- **Caso de uso para Blue Team:** Identifica usuários e grupos para monitorar, detectar anomalias e fortalecer a segurança.
- **Caso de uso para Red Team:** Mapea usuários e grupos para encontrar pontos de entrada e escalar privilégios.

### Políticas de segurança

- **Comando:** `secedit /export /cfg secpol.cfg`
- **Descrição:** Exporta as políticas de segurança locais para um arquivo.
- **Caso de uso para Blue Team:** Usado para verificar se as políticas de segurança estão configuradas corretamente e em conformidade com padrões de segurança.
- **Caso de uso para Red Team:** Permite analisar as políticas de segurança para identificar configurações que podem ser exploradas ou desativadas.
---
- **Comando:** `gpresult /R`
- **Descrição:** Exibe as configurações de política de grupo aplicadas ao sistema.
- **Caso de uso para Blue Team:** Facilita a auditoria das políticas de grupo em vigor para garantir que estejam adequadamente configuradas.
- **Caso de uso para Red Team:** Ajuda a analisar as políticas de grupo aplicadas que podem revelar vulnerabilidades exploráveis.

### Processos e serviços

- **Comando:** `tasklist`
- **Descrição:** Lista todos os processos em execução no sistema.
- **Caso de uso para Blue Team:** Ajuda a detectar processos suspeitos que podem indicar a presença de malware ou ataques.
- **Caso de uso para Red Team:** Identifica processos em execução que podem ser alvos para exploração ou controle.
---
- **Comando:** `tasklist /svc`
- **Descrição:** Lista processos em execução juntamente com os serviços associados, mostrando os serviços que cada processo está executando.
- **Caso de uso para Blue Team:** Utilizado para investigar serviços associados a processos suspeitos.
- **Caso de uso para Red Team:** Permite mapear a relação entre processos e serviços, identificando pontos fracos para exploração.
---
- **Comando:** `sc query`
- **Descrição:** Lista todos os serviços instalados no sistema.
- **Caso de uso para Blue Team:** Usado para identificar serviços desconhecidos ou com comportamentos suspeitos que possam indicar a presença de malware.
- **Caso de uso para Red Team:** Usado para identificar serviços que podem ser explorados para obter acesso a um sistema ou escalar privilégios.
---
- **Comando:** `wmic service list brief`
- **Descrição:** Exibe uma lista breve dos serviços instalados no sistema, incluindo seu status atual e o nome do serviço.
- **Caso de uso para Blue Team:** Verificar se serviços vulneráveis estão em execução e tomar as medidas necessárias para mitigá-las.
- **Caso de uso para Red Team:** Identificar serviços que podem ser configurados para executar payloads maliciosos de forma persistente.

### Permissões e ACLs

- **Comando:** `icacls <caminho>`
- **Descrição:** Exibe permissões de arquivos e pastas.
- **Caso de uso para Blue Team:** Ajuda a garantir que as permissões em arquivos sensíveis estejam configuradas corretamente.
- **Caso de uso para Red Team:** Usado para identificar permissões em arquivos que podem ser exploradas.
---
- **Comando:** `Get-ACL <caminho>`
- **Descrição:** Exibe a lista completa de permissões (ACLs) para um arquivo ou diretório específico, incluindo detalhes sobre quem tem acesso e quais ações são permitidas.
- **Caso de uso para Blue Team:** Usado para auditorias de segurança, garantindo que as permissões estejam em conformidade com as políticas.
- **Caso de uso para Red Team:** Analisando as ACLs, o red team pode identificar permissões excessivas que podem ser exploradas.

### Dispositivos de armazenamento

- **Comando:** `diskpart > list disk`
- **Descrição:** Exibe informações sobre discos e partições.
- **Caso de uso para Blue Team:** Auxilia na detecção de dispositivos de armazenamento não autorizados que podem ser usados para exfiltrar dados ou armazenar malware.
- **Caso de uso para Red Team:** Esconde dados ou malware em discos removíveis para manter a persistência de um ataque.
---
- **Comando:** `wmic logicaldisk get name, description`
- **Descrição:** Lista os discos lógicos (partições) no sistema, com informações sobre nome e tipo de dispositivo (por exemplo, disco local ou unidade de CD/DVD).
- **Caso de uso para Blue Team:** Identificar novas unidades lógicas que possam indicar a presença de dispositivos de armazenamento não autorizados.
- **Caso de uso para Red Team:** Utilizar unidades lógicas para transferir dados entre sistemas sem ser detectado.

### Portas e firewall

- **Comando:** `netsh advfirewall firewall show rule name=all`
- **Descrição:** Exibe todas as regras do firewall.
- **Caso de uso para Blue Team:** Utilizado para verificar regras e assegurar que o firewall está configurado corretamente.
- **Caso de uso para Red Team:** Identifica regras de firewall que podem ser manipuladas ou configuradas incorretamente.
---
- **Comando:** `netsh firewall show state`
- **Descrição:** Mostra o estado atual do firewall, incluindo o status do perfil e configurações globais.
- **Caso de uso para Blue Team:** Usado para validar que o firewall está ativo e em funcionamento conforme esperado.
- **Caso de uso para Red Team:** Ajuda a avaliar o estado do firewall e identificar possíveis brechas de segurança.

### Logs de eventos

- **Comando:** `wevtutil qe Application /f:text /c:5`
- **Descrição:** Exibe os últimos cinco eventos no log de Aplicação.
- **Caso de uso para Blue Team:** Identificar eventos de segurança, erros e avisos que possam indicar a presença de malware ou ataques.
- **Caso de uso para Red Team:** Configurar serviços ou scripts para registrar eventos falsos ou manipular os logs para ocultar atividades maliciosas.
---
- **Comando:** `Get-EventLog -LogName System -Newest 5`
- **Descrição:** Exibe os cinco eventos mais recentes do log de sistema, permitindo uma rápida verificação de eventos do Windows.
- **Caso de uso para Blue Team:** Coletar informações sobre os últimos eventos do sistema para reconstruir a linha do tempo de um incidente de segurança.
- **Caso de uso para Red Team:** Analisar os logs para identificar técnicas de detecção e evitar deixar rastros.

### Programas instalados

- **Comando:** `wmic product get name, version`
- **Descrição:** Lista todos os programas instalados no sistema, mostrando nome e versão de cada um.
- **Caso de uso para Blue Team:** Identificar softwares desatualizados que podem representar uma vulnerabilidade de segurança ou coletar informações sobre os softwares instalados durante uma investigação de incidentes.
- **Caso de uso para Red Team:** Identificar softwares vulneráveis que podem ser explorados para obter acesso a um sistema ou identificar mecanismos de proteção instalados.

## 4. Comandos de reconhecimento em Linux

### Informações do sistema

- **Comando:** `uname -a`
- **Descrição:** Exibe informações detalhadas do sistema e kernel.
- **Caso de uso para Blue Team:** Utilizado para documentar e verificar o sistema operacional e versão do kernel, auxiliando na correção de vulnerabilidades específicas da versão.
- **Caso de uso para Red Team:** Auxilia na identificação de exploits específicos para a versão do kernel, aumentando as chances de explorar vulnerabilidades conhecidas.
---
- **Comando:** `hostnamectl`
- **Descrição:** Exibe informações detalhadas do hostname e sistema operacional.
- **Caso de uso para Blue Team:** Permite auditoria das informações de hostname e sistema, ajudando a garantir consistência nas configurações de nomes de máquinas.
- **Caso de uso para Red Team:** Útil para confirmar o ambiente operacional do alvo e identificar se está em uma VM ou sistema físico.
---
- **Comando:** `cat /etc/os-release`
- **Descrição:** Exibe informações sobre a distribuição do sistema operacional Linux, incluindo nome, versão e ID.
- **Caso de uso para Blue Team:** Confere a distribuição do sistema operacional para compatibilidade de segurança e atualizações.
- **Caso de uso para Red Team:** Identifica a versão do sistema operacional, facilitando a escolha de técnicas de exploração específicas.
---
- **Comando:** `id`
- **Descrição:** Mostra a identificação do usuário atual, incluindo UID (User ID), GID (Group ID) e os grupos aos quais o usuário pertence.
- **Caso de uso para Blue Team:** Verifica a identidade do usuário atual e as permissões atribuídas, monitorando privilégios excessivos.
- **Caso de uso para Red Team:** Confirma os privilégios disponíveis para buscar escalar permissões, especialmente se o usuário atual tiver permissões administrativas. 

### Rede

- **Comando:** `ifconfig`
- **Descrição:** Exibe configurações de interfaces de rede.
- **Caso de uso para Blue Team:** Monitora configurações de rede e detecta interfaces desconhecidas que podem indicar conexões não autorizadas.
- **Caso de uso para Red Team:** Identifica IPs e sub-redes para descobrir possíveis alvos de exploração na rede interna.
---
- **Comando:** `ss -tuln` ou `netstat -tuln`
- **Descrição:** Lista conexões de rede ativas e portas de escuta, com IDs de processo.
- **Caso de uso para Blue Team:** Verifica portas abertas e conexões ativas para identificar possíveis backdoors ou conexões suspeitas.
- **Caso de uso para Red Team:** Mapeia portas e serviços expostos, auxiliando no planejamento de ataques em portas específicas.
---
- **Comando:** `arp -a`
- **Descrição:** Lista o cache ARP (Address Resolution Protocol), que associa endereços IP a endereços MAC.
- **Caso de uso para Blue Team:** Ajuda a identificar dispositivos conectados à rede, detectando endereços MAC suspeitos que possam indicar intrusos.
- **Caso de uso para Red Team:** Exibe dispositivos conhecidos na rede, possibilitando a escolha de alvos para ataques de Man-in-the-Middle (MITM).
---
- **Comando:** `route -n`
- **Descrição:** Exibe a tabela de rotas da rede, incluindo gateways e rotas estáticas.
- **Caso de uso para Blue Team:** Garante que as rotas de rede estão configuradas corretamente, prevenindo acessos não autorizados.
- **Caso de uso para Red Team:** Identifica gateways e rotas configuradas, ajudando a entender o fluxo de rede e planejar ataques avançados.
---
- **Comando:** `ping <host>`
- **Descrição:** Verifica a conectividade entre o sistema e um host remoto.
- **Caso de uso para Blue Team:** Testa a conectividade com hosts conhecidos, ajudando a monitorar a estabilidade da rede.
- **Caso de uso para Red Team:** Verifica a disponibilidade de alvos antes de iniciar ataques mais sofisticados.
---
- **Comando:** `traceroute`
- **Descrição:** Rastreia o caminho que um pacote toma até um host de destino, mostrando cada salto (hop) pelo qual o pacote passa.
- **Caso de uso para Blue Team:** Analisa o caminho de rede, detectando latência anormal que possa indicar interferência.
- **Caso de uso para Red Team:** Mapeia o caminho da rede para identificar pontos vulneráveis e intermediários para ataques MITM.

### Usuários e grupos

- **Comando:** `cat /etc/passwd`
- **Descrição:** Exibe contas de usuários do sistema.
- **Caso de uso para Blue Team:** Revê contas de usuários, ajudando a detectar contas obsoletas ou suspeitas.
- **Caso de uso para Red Team:** Obtém uma lista de usuários para tentar ataques de força bruta ou engenharia social.
---
- **Comando:** `cat /etc/group`
- **Descrição:** Exibe informações sobre os grupos do sistema, incluindo os nomes dos grupos e os usuários que pertencem a cada um deles.
- **Caso de uso para Blue Team:** Verifica a associação de usuários em grupos críticos, ajudando a prevenir a exposição excessiva de privilégios.
- **Caso de uso para Red Team:** Identifica grupos e possíveis usuários com privilégios administrativos, buscando alvos para escalonamento de privilégios.

---
- **Comando:** `last`
- **Descrição:** Lista os últimos logins no sistema.
- **Caso de uso para Blue Team:** Monitora logins recentes para identificar atividades suspeitas, como logins fora do horário de expediente.
- **Caso de uso para Red Team:** Analisa logins válidos, observando comportamentos que podem ajudar a disfarçar atividades maliciosas.
---
- **Comando:** `whoami`
- **Descrição:** Exibe permissões do usuário logado.
- **Caso de uso para Blue Team:** Confirma permissões do usuário logado para detectar abuso de privilégios.
- **Caso de uso para Red Team:** Valida permissões para verificar possibilidade de execução de comandos administrativos.
---
- **Comando:** `who`
- **Descrição:** Mostra uma lista dos usuários atualmente logados no sistema, junto com informações sobre quando e onde cada um deles está conectado.
- **Caso de uso para Blue Team:** Monitora sessões ativas, auxiliando na identificação de atividades anômalas.
- **Caso de uso para Red Team:** Descobre sessões ativas e configurações de terminal, possibilitando ataques direcionados.

### Políticas de segurança

- **Comando:** `sudo -l`
- **Descrição:** Mostra permissões sudo do usuário logado.
- **Caso de uso para Blue Team:** Verifica permissões sudo para garantir que usuários têm acesso restrito às funções necessárias.
- **Caso de uso para Red Team:** Revela permissões sudo que podem ser exploradas para escalonar privilégios.
---
- **Comando:** `getent shadow`
- **Descrição:** Exibe as entradas do arquivo `/etc/shadow`, que contém informações sobre senhas de usuários e seus detalhes de autenticação.
- **Caso de uso para Blue Team:** Examina políticas de senha e detecta contas com senhas fracas ou expiradas.
- **Caso de uso para Red Team:** Pode ser usado para identificar contas com senhas vulneráveis (desde que tenha permissões elevadas).

### Processos e serviços

- **Comando:** `ps aux`
- **Descrição:** Lista todos os processos em execução.
- **Caso de uso para Blue Team:** Identifica processos suspeitos que possam indicar malware em execução.
- **Caso de uso para Red Team:** Lista processos para tentar disfarçar o próprio código malicioso entre serviços legítimos.
---
- **Comando:** `systemctl list-units --type=service`
- **Descrição:** Lista serviços ativos.
- **Caso de uso para Blue Team:** Verifica status dos serviços críticos e detecta atividades maliciosas ou serviços desnecessários.
- **Caso de uso para Red Team:** Confere serviços em execução que podem ser explorados ou modificados para manter persistência.
---
- **Comando:** `top`
- **Descrição:** Apresenta uma visão em tempo real dos processos em execução no sistema, incluindo informações sobre uso de CPU, memória e tempo de execução.
- **Caso de uso para Blue Team:** Monitora o uso de recursos em tempo real, ajudando a identificar processos que consomem muito CPU ou memória, o que pode indicar atividades suspeitas ou malware.
- **Caso de uso para Red Team:** Observa processos em tempo real, buscando identificar atividades que possam indicar a presença de monitoramento ativo, permitindo ajustes na execução de código malicioso.
---
- **Comando:** `service --status-all`
- **Descrição:** Lista todos os serviços gerenciados pelo sistema, indicando se estão ativos, inativos ou em um estado de erro.
- **Caso de uso para Blue Team:** Verifica o status de serviços críticos para identificar serviços inativos ou em estado de erro que podem indicar problemas de segurança.
- **Caso de uso para Red Team:** Identifica serviços ativos e inativos, descobrindo pontos de acesso ou potenciais serviços vulneráveis para exploração.

### Permissões e ACLs

- **Comando:** `ls -l <caminho>`
- **Descrição:** Exibe permissões de arquivos e pastas.
- **Caso de uso para Blue Team:** Audita permissões de arquivos sensíveis, garantindo que estão restritas conforme as melhores práticas.
- **Caso de uso para Red Team:** Verifica arquivos com permissões excessivas que possam ser usados para ataques.
---
- **Comando:** `getfacl <caminho>`
- **Descrição:** Mostra ACLs para um arquivo ou pasta específico.
- **Caso de uso para Blue Team:** Avalia ACLs para garantir segurança em arquivos sensíveis.
- **Caso de uso para Red Team:** Identifica permissões que podem ser exploradas para acessar dados ou executar código.

### Dispositivos de armazenamento

- **Comando:** `df -h`
- **Descrição:** Mostra o uso de espaço em disco por dispositivo.
- **Caso de uso para Blue Team:** Monitora o uso de disco, permitindo identificar rapidamente discos próximos da capacidade máxima, o que pode ser causado por logs excessivos ou atividade maliciosa.
- **Caso de uso para Red Team:** Verifica o uso de disco para determinar espaço disponível para carregar ferramentas adicionais sem esgotar recursos do sistema.
---
- **Comando:** `lsblk`
- **Descrição:** Exibe informações sobre todos os dispositivos de bloco conectados ao sistema, como discos e partições, em uma estrutura hierárquica.
- **Caso de uso para Blue Team:** Permite o mapeamento e monitoramento de discos e partições conectados, ajudando a identificar discos desconhecidos ou dispositivos suspeitos.
- **Caso de uso para Red Team:** Lista dispositivos de armazenamento, ajudando a identificar partições onde arquivos maliciosos podem ser ocultados.
---
- **Comando:** `fdisk -l`
- **Descrição:** Lista todas as partições de disco e suas informações detalhadas, incluindo tamanhos e tipos de sistema de arquivos.
- **Caso de uso para Blue Team:** Avalia as partições e sistemas de arquivos para garantir que todas estejam configuradas corretamente e que não existam partições suspeitas.
- **Caso de uso para Red Team:** Identifica partições de interesse, especialmente aquelas com permissões fracas, para esconder arquivos ou persistir no sistema.

### Portas e firewall

- **Comando:** `iptables -L`
- **Descrição:** Exibe todas as regras do firewall.
- **Caso de uso para Blue Team:** Audita regras de firewall para garantir conformidade com as políticas de segurança.
- **Caso de uso para Red Team:** Identifica regras que podem ser aproveitadas para explorar vulnerabilidades de rede.
---
- **Comando:** `ufw status`
- **Descrição:** Exibe o status do firewall UFW (Uncomplicated Firewall), mostrando quais regras estão ativas e se o firewall está habilitado.
- **Caso de uso para Blue Team:** Monitora regras do firewall para detecção de anomalias.
- **Caso de uso para Red Team:** Confirma regras e configurações do firewall que podem ser usadas para contornar restrições de segurança.
---
- **Comando:** `firewall-cmd --list-all`
- **Descrição:** Mostra a configuração atual do firewall firewalld, incluindo zonas, serviços e regras ativas.
- **Caso de uso para Blue Team:** Verifica as regras do firewall para garantir conformidade com as políticas de segurança, detectando portas abertas indevidamente ou configurações incorretas.
- **Caso de uso para Red Team:** Analisa as regras do firewall para identificar serviços e portas que podem ser explorados para bypass de segurança.

### Logs de eventos

- **Comando:** `tail -n 50 /var/log/syslog`
- **Descrição:** Exibe os últimos 50 eventos no log de sistema.
- **Caso de uso para Blue Team:** Verifica eventos recentes para monitorar atividades anômalas, como falhas de login e erros de serviço, que podem indicar tentativas de invasão.
- **Caso de uso para Red Team:** Analisa eventos recentes para verificar se atividades maliciosas geraram alertas, permitindo ajustar táticas para evitar detecção.
---
- **Comando:** `dmesg | tail`
- **Descrição:** Exibe as últimas mensagens do buffer do kernel, geralmente relacionadas a eventos de hardware e inicialização do sistema.
- **Caso de uso para Blue Team:** Examina eventos de hardware para detectar possíveis anomalias, como falhas de dispositivos que podem indicar atividade suspeita.
- **Caso de uso para Red Team:** Verifica logs de inicialização para identificar dispositivos que podem ser manipulados para manter persistência.
---
- **Comando:** `journalctl -u <serviço>`
- **Descrição:** Exibe logs de um serviço específico gerenciado pelo `systemd`, permitindo a visualização detalhada dos eventos relacionados a esse serviço.
- **Caso de uso para Blue Team:** Revisa logs de serviços específicos, monitorando eventos anômalos ou erros que possam indicar problemas de segurança, identificar a origem do ataque ou detectar incidentes.
- **Caso de uso para Red Team:** Descobrir credenciais armazenadas em logs (embora isso seja considerado uma prática ruim). Explorar informações nos logs para encontrar formas de elevar os privilégios no sistema. Por exemplo, identificar comandos executados com privilégios elevados ou portas abertas para serviços vulneráveis. Tentar limpar logs ou modificar seu conteúdo para dificultar a detecção de suas atividades.

### Programas instalados

- **Comando:** `dpkg -l` para Debian/Ubuntu ou `rpm -qa` para CentOS/RHEL.
- **Descrição:** Lista todos os pacotes instalados no sistema.
- **Caso de uso para Blue Team:** Verifica softwares instalados para identificar e remover aplicações vulneráveis.
- **Caso de uso para Red Team:** Lista softwares que podem ser explorados para execução de vulnerabilidades conhecidas.
---
- **Comando:** `apt list --installed` para Debian/Ubuntu ou `yum list installed` para CentOS/RHEL.
- **Descrição:** Lista todos os pacotes instalados no sistema que utilizam o gerenciador de pacotes APT (Advanced Package Tool).
- **Caso de uso para Blue Team:** Garante a conformidade de pacotes instalados com as políticas de segurança e identifica pacotes desatualizados ou suspeitos.
- **Caso de uso para Red Team:** Lista pacotes instalados para identificar software com vulnerabilidades conhecidas que podem ser exploradas.

### 5. Considerações de segurança e práticas recomendadas

Ao utilizar comandos de reconhecimento, especialmente em ambientes de produção ou redes corporativas, é fundamental adotar práticas seguras para proteger dados sensíveis e garantir o cumprimento de políticas de segurança. Abaixo estão algumas recomendações:

### Controle de acesso e privilégios

Limite o uso de comandos de reconhecimento a usuários com permissões adequadas e sempre mantenha um registro de quem executa esses comandos. Isso reduz a exposição a possíveis abusos e ajuda no rastreamento de atividades.

### Ambiente de testes segregado

Sempre que possível, realize o reconhecimento em um ambiente de testes separado da produção para evitar impacto em sistemas críticos e proteger informações sensíveis contra acessos indevidos.

### Monitoramento e log de atividades

Habilite logs para comandos críticos de reconhecimento. Por exemplo, comandos que listam usuários e grupos, processos, e configurações de rede devem ser monitorados e registrados. Isso auxilia em auditorias e na detecção de atividades suspeitas.

### Desabilitar comandos não necessários

Em servidores e estações de trabalho onde comandos específicos não são necessários, considere restringir seu uso. Ferramentas como AppLocker, no Windows, ou listas de controle de acesso no Linux podem ajudar a bloquear o uso de determinados comandos.

### Práticas de segurança para armazenamento de informações sensíveis

Evite armazenar resultados de reconhecimento em locais não seguros. Caso seja necessário registrar essas informações, use criptografia para proteger os arquivos gerados.

### Limite de frequência de execução

Executar comandos de reconhecimento em intervalos muito curtos pode sobrecarregar o sistema. Defina uma frequência segura para evitar impactos no desempenho, especialmente ao realizar varreduras em larga escala.

### Autorização e compliance

Antes de realizar o reconhecimento, assegure-se de que você possui autorização adequada e que a prática está em conformidade com as políticas internas e regulamentações de segurança aplicáveis, como LGPD ou GDPR, caso envolva dados pessoais.

Essas práticas ajudam a garantir que o reconhecimento seja realizado de maneira segura e minimizam potenciais riscos, mantendo a segurança e o compliance da organização.

## 6. Conclusão

As técnicas de reconhecimento abordadas são ferramentas poderosas para Blue Teams e Red Teams. Além de proporcionarem uma visão completa do sistema e suas configurações, estes comandos formam a base para a criação de políticas de segurança e melhoria contínua das práticas de Threat Hunting e engenharia de detecção. Este guia serve como referência para aprimorar tanto as atividades de defesa quanto de ataque, contribuindo para um ambiente de segurança mais robusto e eficiente.

Muito embora alguns dos comandos listados acima não sejam comumente usados ou vistos no dia a dia, mas cada um deles pode contribuir para levantamento de informações em algum nível, a depender de quem está operando naquele momento. Os exemplos de Casos de Uso listados são apenas alguns exemplos simples, mas não limitados a eles. Eles servem apenas como referência para contribuir para um melhor entendimento do contexto.

Deve-se levar em consideração que, alguns dos comandos listados, são diariamente usados em ambiente de produção, portanto, se você levar em consideração estes comandos para compor regras, tenha em mente trabalhar os falsos-positivos que irão surgir durante a concepção delas.


{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}

---
<!-- begin wwww.htmlcommentbox.com -->
  <div id="HCB_comment_box"><a href="http://www.htmlcommentbox.com">Widget</a> is loading comments...</div>
 <link rel="stylesheet" type="text/css" href="https://www.htmlcommentbox.com/static/skins/bootstrap/twitter-bootstrap.css?v=0" />
<!-- end www.htmlcommentbox.com -->