---
title: "[PRODUÇÃO]Playbook não é Runbook: Entenda as diferenças e como aplicar cada um na prática"
date: 2025-05-29T00:26:48-03:00
draft: false
description: "Playbooks são estratégicos, runbooks são operacionais. Descubra como estruturar adequadamente cada documento." 
noindex: false
featured: false
pinned: false
comments: true
series:
 - 
categories:
 - publicar
tags:
 -
authors:
 - sandson
#images:
---
## 1. Introdução

No universo das operações de segurança, é comum observarmos profissionais utilizando indistintamente os termos **"playbook"** e **"runbook"**, como se fossem sinônimos. Frases como _"Segue o playbook para executar essa ação"_ ou _"Criei um runbook para responder a esse tipo de incidente"_ são frequentes, mas tecnicamente imprecisas.

Embora ambos sejam documentos fundamentais para a operação de um SOC, **playbook** e **runbook** possuem propósitos, estruturas e níveis de abstração completamente diferentes. Esta confusão conceitual pode comprometer a eficiência operacional, causar inconsistências na resposta a incidentes e dificultar a maturação dos processos de segurança.

Este artigo tem como objetivo esclarecer as diferenças práticas entre playbook e runbook, demonstrando como cada um deve ser estruturado e aplicado no contexto de um Centro de Operações de Segurança.

## 2. Conceitos Fundamentais

### 2.1. O que é um Playbook?

Um playbook é um **documento estratégico** que define a abordagem geral para responder a uma categoria específica de incidentes de segurança. Ele estabelece o contexto, os objetivos, as prioridades e o fluxo de decisão, mas não detalha os comandos específicos a serem executados.

**Características principais:**
- **Orientação estratégica:** Foca no "o que fazer" e "por que fazer"
- **Alto nível:** Descreve processos sem entrar em detalhes técnicos específicos
- **Orientado a decisão:** Contém árvores de decisão e fluxos condicionais
- **Contexto de negócio:** Considera impacto, criticidade e tolerância a risco
- **Reutilizável:** Pode ser aplicado a diferentes cenários similares
- **Público-alvo:** Analistas de diferentes níveis, coordenadores e gestores

### 2.2. O que é um Runbook?

Um runbook é um **documento operacional** que contém instruções técnicas detalhadas e específicas para executar uma tarefa ou procedimento. Ele é prescritivo, contendo comandos exatos, telas de sistema e critérios de validação.

**Características principais:**
- **Orientação operacional:** Foca no "como fazer" tecnicamente
- **Baixo nível:** Detalha comandos, clicks e validações específicas
- **Orientado à execução:** Sequência linear de passos técnicos
- **Agnóstico ao contexto:** Funciona independente do cenário de negócio
- **Específico:** Criado para uma tarefa muito particular
- **Público-alvo:** Analistas técnicos e operadores de primeiro nível

### 2.3. Relação com Casos de Uso

Vale ressaltar que nem playbook nem runbook são casos de uso. Um **caso de uso** define **o que detectar** e **por que é importante**, enquanto o **playbook** define **como responder** após a detecção. O runbook, por sua vez, operacionaliza as ações técnicas específicas descritas no playbook.

**Fluxo conceitual:**
Caso de Uso → [Detecção] → Playbook → [Decisão] → Runbook → [Execução]

### 2.4. Comparação Prática

| Aspecto | Playbook | Runbook |
|:-------:|:--------:|:-------:|
| **Objetivo** | Guiar a resposta estratégica | Executar ações técnicas específicas |
| **Nível de abstração** | Alto - conceitual | Baixo - operacional |
| **Conteúdo** | Fluxos de decisão, contexto | Comandos, clicks, validações |
| **Flexibilidade** | Alta - adaptável a cenários | Baixa - sequência fixa |
| **Audiência** | Analistas, coordenadores | Operadores técnicos |
| **Duração de uso** | Longa - reutilizável | Pontual - tarefa específica |
| **Dependência** | Independente de ferramentas | Dependente de ferramentas específicas |

## 3. Implementação Prática

### 3.1. Playbook: Execução Remota e Persistência via PowerShell

**Objetivo:** Responder a detecções de uso malicioso do WinRM e tarefas agendadas para persistência.

**Critérios de Ativação:**
- Alertas das regras: "PowerShell Create Scheduled Task" ou "Enable Windows Remote Management"
- Combinação de múltiplos alertas em janela temporal de 10 minutos
- Hosts críticos ou com acesso privilegiado

**Fluxo de Resposta:**

**Fase 1: Avaliação Inicial (0-5 minutos)**

1. **Classificar criticidade do host afetado**

- Host crítico (Tier 0/1) → Escalação imediata

- Host padrão → Continuar investigação


2. **Verificar contexto temporal**
- Horário comercial + usuário conhecido → Possível falso positivo
- Fora do horário + conta administrativa → Suspeita alta

3. **Correlacionar com outras fontes**
- Verificar alertas de EDR simultâneos
- Consultar logs de autenticação
- Revisar atividade recente do usuário

**Fase 2: Contenção (5-15 minutos)**
1. **Se confirmada atividade suspeita:**
- Isolar o host na rede (quarentena)
- Desabilitar conta de usuário envolvida
- Notificar equipe de resposta a incidentes

2. **Se incerto sobre legitimidade:**
- Monitorar atividade adicional por 30 minutos
- Contactar proprietário do sistema
- Manter logs detalhados da investigação

**Fase 3: Investigação (15-60 minutos)**
1. **Coleta de evidências:**
- Imagem de memória do host
- Logs de PowerShell detalhados
- Análise de tarefas agendadas criadas

2. **Análise de escopo:**
- Identificar outros hosts acessados
- Mapear movimentação lateral
- Verificar exfiltração de dados

**Critérios de Escalação:**
- Múltiplos hosts afetados (>3)
- Acesso a dados classificados
- Falha na contenção inicial
- Evidência de exfiltração

**Métricas de Sucesso:**
- Tempo médio de contenção < 15 minutos
- Taxa de falsos positivos < 10%
- Prevenção de movimentação lateral em 95% dos casos

---

### 3.2. Playbook: Mineração de Criptomoeda em Endpoint

**Objetivo:** Responder a detecções de mineradores de criptomoeda que impactam performance e indicam comprometimento.

**Critérios de Ativação:**
- Alerta da regra: "Possible Coin Miner CPU Priority Param"
- Combinação com alertas de alta utilização de CPU
- Múltiplas detecções em hosts similares

**Fluxo de Resposta:**

**Fase 1: Verificação Imediata (0-2 minutos)**
1. **Confirmar impacto no sistema:**
- CPU > 80% por mais de 5 minutos → Ação imediata
- CPU < 50% → Investigação de baixa prioridade

2. **Identificar criticidade do host:**
- Servidor de produção → Escalação automática
- Workstation → Investigação padrão

**Fase 2: Contenção Rápida (2-10 minutos)**
1. **Encerrar processo malicioso:**
- Usar EDR para kill do processo
- Quarentena do arquivo executável
- Bloquear hash em outros endpoints

2. **Verificar persistência:**
- Analisar tarefas agendadas
- Revisar serviços do sistema
- Verificar inicialização automática

**Fase 3: Análise de Origem (10-30 minutos)**
1. **Identificar vetor de entrada:**
- Downloads recentes do usuário
- E-mails com anexos
- Sites visitados nas últimas 24h

2. **Escopo da infecção:**
- Outros hosts do mesmo usuário
- Compartilhamentos de rede acessados
- Credenciais potencialmente comprometidas

**Critérios de Escalação:**
- Minerador em servidor crítico
- Evidência de movimento lateral
- Impossibilidade de remoção via EDR

**Métricas de Sucesso:**
- Tempo de kill do processo < 5 minutos
- Prevenção de reinfecção em 98% dos casos
- Identificação do vetor em 80% dos casos

---

### 3.3. Playbook: Exfiltração com Wget

**Objetivo:** Responder a tentativas de exfiltração de dados usando wget com arquivos sensíveis.

**Critérios de Ativação:**
- Alerta da regra: "Data Exfiltration with Wget"
- Acesso a arquivos como /etc/shadow, /etc/passwd
- Tráfego de saída suspeito simultâneo

**Fluxo de Resposta:**

**Fase 1: Bloqueio Imediato (0-3 minutos)**
1. **Interromper transferência:**
- Kill do processo wget
- Bloqueio temporário de saída HTTP/HTTPS
- Quarentena do host se necessário

2. **Preservar evidências:**
- Captura de tráfego de rede
- Snapshot do sistema
- Logs de auditd detalhados

**Fase 2: Avaliação de Danos (3-20 minutos)**
1. **Identificar dados exfiltrados:**
- Analisar arquivos no comando wget
- Verificar tamanho da transferência
- Confirmar destino da exfiltração

2. **Classificar sensibilidade:**
- Dados de autenticação → Incidente crítico
- Arquivos de configuração → Incidente alto
- Dados operacionais → Incidente médio

**Fase 3: Resposta Proporcional (20-60 minutos)**
1. **Para dados críticos:**
- Reset de todas as senhas do sistema
- Notificação à equipe jurídica
- Comunicação com autoridades se necessário

2. **Para dados sensíveis:**
- Alteração de configurações expostas
- Reforço de monitoramento
- Análise de outros acessos do atacante

**Critérios de Escalação:**
- Exfiltração confirmada de dados críticos
- Múltiplos sistemas afetados
- Ação de insider threat

**Métricas de Sucesso:**
- Tempo de bloqueio < 3 minutos
- Prevenção de exfiltração em 90% dos casos
- Contenção completa em 95% dos casos

---

### 3.4. Playbook: Uso Malicioso de Ferramentas Sysinternals

**Objetivo:** Responder ao uso suspeito de ferramentas administrativas como PsExec, Procdump.

**Critérios de Ativação:**
- Alerta da regra: "PUA - Sysinternals Tools Execution - Registry"
- Uso fora do horário comercial
- Execução por usuários não autorizados

**Fluxo de Resposta:**

**Fase 1: Contextualização (0-5 minutos)**
1. **Verificar legitimidade:**
- Usuário tem permissão administrativa? → Investigar contexto
- Horário e local de trabalho consistente? → Possível legítimo
- Ferramenta executada remotamente? → Suspeita alta

2. **Correlacionar atividades:**
- Logins simultâneos em múltiplos hosts
- Execução de múltiplas ferramentas
- Criação de arquivos suspeitos

**Fase 2: Investigação Ativa (5-15 minutos)**
1. **Analisar impacto da ferramenta:**
- PsExec → Verificar execução remota não autorizada
- Procdump → Verificar dump de processos sensíveis (lsass)
- Outras → Avaliar propósito e alvos

2. **Mapear atividade relacionada:**
- Outros hosts acessados na sessão
- Arquivos criados ou modificados
- Credenciais potencialmente extraídas

**Fase 3: Ação Proporcional (15-45 minutos)**
1. **Se uso legítimo confirmado:**
- Documentar justificativa
- Ajustar regras para reduzir falsos positivos
- Reforçar treinamento sobre ferramentas aprovadas

2. **Se uso malicioso:**
- Isolar hosts envolvidos
- Reset de credenciais administrativas
- Análise forense completa

**Critérios de Escalação:**
- Dump de memória de processos críticos
- Execução em múltiplos hosts (>5)
- Evidência de exfiltração de credenciais

**Métricas de Sucesso:**
- Taxa de falsos positivos < 15%
- Identificação de uso legítimo vs. malicioso em < 10 minutos
- Contenção de movimentação lateral em 98% dos casos

## 4. Runbooks Operacionais

### 4.1. Runbook: Kill de Processo de Mineração via EDR

**Pré-requisitos:**
- Acesso ao console EDR (CrowdStrike/Defender/SentinelOne)
- Permissões de resposta ativa
- Host ID ou hostname identificado

**Procedimento:**

**Passo 1: Acesso ao Console**
1. Acessar `https://falcon.crowdstrike.com` (ou console equivalente)
2. Fazer login com credenciais de serviço
3. Navegar para `Investigate > Host Search`

**Passo 2: Localizar Host**
1. Na barra de busca, inserir: `hostname:NOME_DO_HOST`
2. Clicar no host nos resultados
3. Verificar status "Online" na aba `Overview`

**Passo 3: Identificar Processo**
1. Clicar na aba `Processes`
2. Filtrar por: `command_line:*cpu-priority*` OR `command_line:*xmrig*`
3. Identificar PID do processo malicioso
4. Anotar: PID, comando completo, usuário

**Passo 4: Encerrar Processo**
1. Selecionar o processo identificado
2. Clicar em `Actions > Kill Process`
3. Confirmar ação inserindo comentário: "Minerador detectado - SOC Response"
4. Executar ação

**Passo 5: Validação**
1. Aguardar 30 segundos
2. Refresh da página de processos
3. Confirmar que PID não aparece mais
4. Verificar CPU usage < 20% na aba `Performance`

**Passo 6: Quarentena de Arquivo**
1. Na aba `Files`, buscar pelo executável
2. Selecionar arquivo e clicar `Quarantine`
3. Confirmar ação com comentário

**Critérios de Sucesso:**
- ✅ Processo não aparece mais na lista
- ✅ CPU usage reduzido
- ✅ Arquivo em quarentena
- ✅ Ação logada no console

**Em caso de falha:**
- Escalar para administrador EDR
- Considerar isolamento completo do host
- Executar runbook de isolamento de rede

---

### 4.2. Runbook: Isolamento de Host via EDR

**Pré-requisitos:**
- Acesso ao console EDR com privilégios de isolamento
- Aprovação verbal do coordenador SOC
- Host ID confirmado

**Procedimento:**

**Passo 1: Preparação**
1. Documentar justificativa no ticket: "Host comprometido - isolamento preventivo"
2. Notificar usuário por telefone (se possível)
3. Anotar horário de início da ação

**Passo 2: Executar Isolamento**
1. No console EDR, localizar host (conforme runbook anterior)
2. Clicar na aba `Network`
3. Clicar em `Network Isolation > Enable`
4. Confirmar com comentário: "Atividade maliciosa confirmada"

**Passo 3: Verificar Isolamento**
1. Status deve mudar para "Network Isolated" em ~60 segundos
2. Verificar timestamp da ação
3. Confirmar conectividade apenas com servidor EDR

**Passo 4: Comunicação**
1. Atualizar ticket com horário exato do isolamento
2. Enviar email para: `soc-coord@empresa.com`
3. Assunto: "HOST ISOLADO - [HOSTNAME] - Ticket #[NUMERO]"

**Passo 5: Monitoramento Pós-Isolamento**
1. Monitorar por 15 minutos para atividade residual
2. Verificar se outros hosts da rede apresentam atividade similar
3. Documentar observações no ticket

**Critérios de Sucesso:**
- ✅ Status "Network Isolated" no console
- ✅ Timestamp registrado
- ✅ Coordenação notificada
- ✅ Usuário comunicado

**Reversão (quando autorizada):**
1. Clicar em `Network Isolation > Disable`
2. Confirmar com comentário: "Investigação concluída - autorizado por [NOME]"
3. Monitorar por 5 minutos pós-reconexão

---

### 4.3. Runbook: Bloqueio de Hash em Múltiplos Endpoints

**Pré-requisitos:**
- Hash SHA256 do arquivo malicioso
- Lista de hosts para aplicar bloqueio
- Acesso ao console EDR com privilégios de IOC management

**Procedimento:**

**Passo 1: Coleta de Informações**
1. Copiar hash SHA256 do arquivo: `[HASH_AQUI]`
2. Verificar se hash está na threat intelligence: `https://virustotal.com`
3. Documentar nome do arquivo e caminho original

**Passo 2: Criar IOC Global**
1. No console EDR, navegar para `Configuration > IOC Management`
2. Clicar `Add IOC`
3. Configurar:
- Type: `SHA256`
- Value: `[HASH_SHA256]`
- Action: `Block`
- Description: `Minerador criptomoeda - Ticket [NUMERO]`
- Severity: `High`

**Passo 3: Aplicar a Grupos**
1. Na seção `Applied To`, selecionar:
- `All Windows Hosts` (se minerador Windows)
- `All Linux Hosts` (se minerador Linux)
2. Clicar `Save IOC`

**Passo 4: Verificar Propagação**
1. Aguardar 5 minutos para sincronização
2. Em host de teste, verificar IOC recebido:
- Windows: `Event Viewer > CrowdStrike`
- Linux: `/var/log/falcon-sensor.log`

**Passo 5: Validação**
1. Tentar executar arquivo conhecido com mesmo hash
2. Verificar bloqueio e alerta gerado
3. Confirmar em 3 hosts diferentes

**Critérios de Sucesso:**
- ✅ IOC criado e ativo
- ✅ Propagado para todos os grupos
- ✅ Bloqueio funcionando em teste
- ✅ Alertas sendo gerados

**Remoção do IOC (quando necessário):**
1. Navegar para `IOC Management`
2. Localizar IOC pelo hash
3. Clicar `Delete` com justificativa
4. Confirmar remoção

---

### 4.4. Runbook: Reset de Senha Administrativa em AD

**Pré-requisitos:**
- Acesso ao Active Directory Users and Computers
- Privilégios de administrador de domínio
- Lista de contas comprometidas
- Aprovação de manager para reset

**Procedimento:**

**Passo 1: Preparação**
1. Conectar ao Domain Controller via RDP/Console
2. Abrir `Active Directory Users and Computers`
3. Documentar contas a serem resetadas

**Passo 2: Gerar Senha Temporária**
1. Usar gerador interno: `https://passwordgen.empresa.com`
2. Configurar: 12 caracteres, alfanumérico + símbolos
3. Anotar senha temporária: `[SENHA_TEMP]`

**Passo 3: Reset da Conta**
1. Localizar usuário: `Find > Advanced > Name: [USERNAME]`
2. Clicar direito na conta > `Reset Password`
3. Inserir nova senha temporária
4. Marcar: ☑️ `User must change password at next logon`
5. Marcar: ☑️ `Account is locked out` (se aplicável)
6. Clicar `OK`

**Passo 4: Verificar Propriedades**
1. Duplo clique na conta
2. Aba `Account`: confirmar senha expirada
3. Aba `Member Of`: verificar grupos de admin
4. Anotar última autenticação

**Passo 5: Comunicação**
1. Ligar para usuário: "Sua senha foi resetada por segurança"
2. Informar senha temporária via canal seguro
3. Orientar sobre mudança obrigatória no próximo login
4. Agendar follow-up em 1 hora

**Passo 6: Monitoramento**
1. Verificar primeiro logon pós-reset em 15 minutos
2. Confirmar troca de senha pelo usuário
3. Monitorar atividade da conta por 24h

**Critérios de Sucesso:**
- ✅ Senha resetada com sucesso
- ✅ Usuário contactado e orientado
- ✅ Primeiro logon confirmado
- ✅ Nova senha definida pelo usuário

**Em caso de problemas:**
- Usuário não consegue trocar senha → Verificar política de senhas
- Conta continua bloqueada → Executar `Unlock Account`
- Usuário não encontrado → Verificar nome completo/SAM account

---

### 4.5. Runbook: Verificação de Exfiltração em Logs de Firewall

**Pré-requisitos:**
- Acesso ao SIEM/Splunk
- Logs de firewall configurados
- Timeframe do incidente identificado
- IP/hostname do host suspeito

**Procedimento:**

**Passo 1: Acesso ao SIEM**
1. Conectar em `https://splunk.empresa.com`
2. Login com conta de serviço SOC
3. Navegar para `Search & Reporting`

**Passo 2: Query Base**
```spl
index=firewall src_ip="[IP_HOST_COMPROMETIDO]" action=allowed
| eval bytes_mb=bytes/1024/1024
| where bytes_mb > 10
| stats sum(bytes_mb) as total_mb, count by dest_ip, dest_port
| sort -total_mb
```

**Passo 3: Refinar por Timeframe**
1. Ajustar tempo: últimas 24 horas do incidente
2. Executar query e aguardar resultados
3. Exportar primeiros 50 resultados para CSV

**Passo 4: Analisar Destinatários**
1. Para cada dest_ip com >100MB:
- Verificar whois: `whois [DEST_IP]`
- Consultar VirusTotal: `https://virustotal.com/gui/ip-address/[IP]`
- Classificar: Legítimo / Suspeito / Malicioso

**Passo 5: Query Detalhada para IPs Suspeitos**
```spl
index=firewall src_ip="[IP_HOST]" dest_ip="[IP_SUSPEITO]"
| eval timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table timestamp, src_port, dest_port, bytes, packets
| sort timestamp
```

**Passo 6: Documentação**
1. Criar tabela de resultados:
- Destino | Bytes Total | Classificação | Ação
2. Para cada IP malicioso: adicionar a blocklist
3. Atualizar ticket com evidências

**Critérios de Suspeita:**
- 🚨 >1GB para IP desconhecido
- 🚨 Múltiplas conexões para mesmo destino externo
- 🚨 Tráfego para IPs com reputação ruim
- 🚨 Portas não padrão (não 80/443)

**Ações de Follow-up:**
- Bloqueio de IPs maliciosos no firewall
- Análise de outros hosts para mesmo destino
- Correlação com threat intelligence

---

## 5. Conclusão

A distinção clara entre playbook e runbook é fundamental para a eficiência operacional de um SOC. Playbooks fornecem o contexto estratégico e as diretrizes de decisão, enquanto runbooks garantem a execução técnica consistente e precisa.

Um SOC maduro utiliza ambos de forma complementar: playbooks para orientar a resposta geral ao incidente e runbooks para operacionalizar as ações técnicas específicas. Esta abordagem estruturada reduz o tempo de resposta, minimiza erros operacionais e garante que a experiência institucional seja preservada e transmitida adequadamente.

A implementação adequada destes documentos não apenas melhora a eficiência operacional, mas também contribui para a maturação dos processos de segurança, permitindo medições consistentes, melhoria contínua e padronização das melhores práticas.

Lembre-se: você não executa um playbook no terminal. Você segue um runbook.

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}
