---
title: "Regra de Detecção não é Caso de Uso: Entenda de uma vez por todas"
date: 2025-05-30T00:26:48-03:00
draft: false
description: "Regras de detecção são lógica técnica. Casos de uso são conceitos estratégicos. Confundir os dois enfraquece a operação de segurança. Saiba por que usar os termos corretos importam, na teoria e na prática do SOC." 
noindex: false
featured: false
pinned: false
comments: false
series:
 - 
categories:
 - Segurança e Defesa
 - Resposta a Incidentes
tags:
 - Threat Hunting
 - Engenharia de Detecção
 - Regras de Detecção
 - Falsos Positivos
 - SIEM
 - Maturidade de Segurança
 - Melhores Práticas
 - Resposta a Incidentes
 - Detecção de Ameaças
authors:
 - sandson
#images:
---
# **1. Introdução**

Em um Centro de Operações de Segurança (SOC) é muito comum no dia a dia ouvirmos frases como: _"Esse caso de uso pra detectar brute force precisa de ajuste"._ _"Precisamos criar um caso de uso pra detectar execução de psexec"._ Mas... o que realmente deveria ser dito é: _"Criei uma regra de detecção pra tal coisa"._ Essa confusão entre os termos **"caso de uso"** e **"regra de detecção"** precisa acabar. Embora relacionados, são conceitos distintos, com propósitos, estruturas e impactos diferentes dentro de uma operação de segurança.

Este artigo demonstra de forma prática e objetiva as diferenças entre **caso de uso** e **regra de detecção**, e por que é importante saber diferenciá-los para construir um SOC mais maduro e eficiente.

# **2. Fundamentos Conceituais**

## 2.1. O que é um Caso de Uso?

Um caso de uso é a representação de um **cenário de segurança ou risco de negócio** que precisa ser monitorado. Ele descrever o que se deseja proteger: Por quê, de quem, e como.

Os elementos que compôem um caso de uso são:

- **Objetivo:** Qual a ameaça ou risco está sendo endereçado?
- **Contexto:** Qual o impacto para o negócio? Por que isso importa?
- **Fonte de dados:** Quais logs ou eventos são necessários?
- **Atores envolvidos:** Usuários, contas privilegiadas, sistemas.
- **Indicadores:** Indicadores de comprometimento (IoCs); Indicadores de Ataque (IoAs); Táticas, Técnicas e Procedimentos (TTPs), etc.
- **Requisitos de Detecção:** Tipos de regras que serão utilizadas (SIEM, EDR, etc.).
- **Fluxo da Ameaça:** Como a ameaça se manifesta?
- **Resposta esperada:** Como o SOC deverá agir ao alertar?

> Pense no **caso de uso** como um projeto de detecção completo com propósito, lógica e justificativa estratégica.

## 2.2. O que é uma Regra de Detecção?

Uma regra de detecção é a implementação técnica e lógica que idenfifica padrões, condições ou comportamentos específicos nos eventos. Ela pode ser implementada em SIEM, EDR, etc. Representa o "como" do caso de uso.

Os elementos que caracterizam uma regra de detecção são:

- **Foco técnico:** Lida apenas com condições técnicas observáveis, sem considerar impacto estratégico.
- **Expressa uma lógica específica:** Define o que deve ser detectado, usando campos, operações e padrões.
- **Depende de dados estruturados:** Só funciona com logs padronizados e bem definidos.
- **Desprovida de contexto de negócio:** Não considera o valor do ativo ou o impacto no negócio.
- **Reutilizável em vários casos de uso:** Uma única regra pode ser usada em diferentes cenários que compartilham a mesma lógica técnica.

> Pense na **regra de detecção** como o código ou instrução lógica para identificar uma condição previamente definida.

## 2.3. Comparação estruturada

### _2.3.1. Visão Geral_

| Aspecto                 | Caso de Uso                                | Regra de Detecção                          |
| :-----------------------: | :------------------------------------------: | :------------------------------------------: |
| **Objetivo**            | Monitorar um cenário de risco              | Identificar um padrão específico de evento |
| **Escopo**              | Estratégico e contextual                   | Tático e técnico                           |
| **Reutilizável?**       | Limitado - específico para um contexto    | Sim - pode ser aplicada a diferentes casos |
| **Dependência técnica** | Média - é mais conceitual                  | Alta - depende do formato dos dados        |
| **Ponto de Partida**    | Necessidade do negócio / risco             | Lógica de correlação baseada em eventos    |
| **Quem constrói**       | Especialista de Segurança / Arquiteto      | Analista Técnico / Engenheiro de Detecção  |

### _2.3.2. Análise Técnica Detalhada_

| **Critério**                                | **Regra de Detecção**                                      | **Caso de Uso**                                                      |
| ------------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------- |
| **É código ou lógica implementável?**       | ✅ Sim. Define condições técnicas em linguagem estruturada. | ❌ Não. É um artefato de planejamento/gestão da detecção.             |
| **Tem objetivo de negócio?**                | ❌ Não. É técnica e neutra quanto ao impacto.               | ✅ Sim. Aborda risco, impacto e valor para o negócio.                 |
| **Pode ser versionada?**                    | ✅ Sim. Armazenada em repositórios (YAML, Sigma, KQL, etc). | ✅ Sim. Versionada como documento ou playbook.                       |
| **É acionável isoladamente?**               | ✅ Sim. Gera alertas ou bloqueios diretamente.              | ❌ Não. Depende de regras para funcionar na prática.                  |
| **É reusável entre ambientes?**             | ✅ Sim. Pode ser aplicada em ambientes distintos.           | ⚠️ Parcialmente. Pode exigir adaptação conforme a criticidade local. |
| **Tem contexto de ameaça?**                 | ❌ Não. Detecta comportamentos técnicos.                    | ✅ Sim. Foca no comportamento e objetivo da ameaça.                   |
| **Precisa de dados estruturados?**          | ✅ Sim. Só funciona com logs padronizados e bem definidos.  | ❌ Não. Pode ser projetado mesmo sem log implementado ainda.          |
| **Serve como base para criação de regras?** | ❌ Não. É o produto final da lógica.                        | ✅ Sim. É o ponto de partida para desenvolver regras.                 |

# **3. Exemplos Práticos**

Abaixo vou descrever 4 casos de uso e 5 regras de detecção, levando em consideração que mais de uma regra pode compor um único caso de uso.

## 3.1. Casos de Uso

{{< bs/alert warning >}}
{{< bs/alert-heading "ATENÇÃO" >}}
As regras associadas ao caso de uso não são inclusas durante a construção. Eu associei as regras ao caso de uso apenas para ilustrar como as regras podem compor a ideia de um caso em uso em si. O caso de uso é independente de regras.
{{< /bs/alert >}}


### _3.1.1. Execução remota e persistência via PowerShell_

- **Objetivo:** Detectar o uso malicioso do `WinRM` e tarefas agendadas para persistência.
- **Contexto:** Técnicas utilizadas em movimentação lateral e persistência pós-exploração que podem comprometer a continuidade do negócio.
- **Fonte de dados:** Logs de Windows, Sysmon, PowerShell e EDR.
- **Atores envolvidos:** Usuários com privilégios administrativos ou comprometidos, endpoints Windows.
- **Indicadores:** Palavras-chave como `New-ScheduledTask`, `schtasks`, execução de `Enable-PSRemoting`, comunicação em portas `5985/5986`.
- **Requisitos de Detecção:** Regras de SIEM baseadas em Sysmon/Windows/PowerShell e regras comportamentais em EDR.
- **Fluxo da Ameaça:** Atacante acessa o host → Ativa o `WinRM` no host remoto → Usa PowerShell para criar uma tarefa agendada que mantém persistência.
- **Resposta esperada:** Investigar origem do processo, isolar o host, revogar credenciais, iniciar resposta a incidentes.

**Regras associadas:**
- **Regra 1:** PowerShell Create Scheduled Task
- **Regra 2:** Enable Windows Remote Management

As regras associadas aqui são apenas ilustrativas ao conteúdo do artigo, não significa que a regra já exista. Lembre-se.

### _3.1.2. Execução de minerador de criptomoeda em endpoint_

- **Objetivo:** Detectar execução de mineradores baseados em linha de comando.
- **Contexto:** Uso indevido de recursos computacionais que afeta performance e pode indicar acesso não autorizado, impactando produtividade e custos operacionais.
- **Fonte de dados:** Logs de Windows, Sysmon, PowerShell e EDR.
- **Atores envolvidos:** Contas locais exploradas, hosts expostos ou vulneráveis.
- **Indicadores:** Execução de processos com parâmetros como `--cpu-priority`, `--donate-level`, binários como `xmrig`.
- **Requisitos de Detecção:** Regras de SIEM com análise de linha de comando, integração com EDR para detecção comportamental.
- **Fluxo da Ameaça:** Adversário executa um minerador no host → Utiliza parâmetros para otimizar o uso de CPU e ocultar a atividade.
- **Resposta esperada:** Encerramento do processo, isolamento do host, análise de persistência e identificação do vetor de entrada.

**Regras associadas:**
- **Regra 3:** Possible Coin Miner CPU Priority Param

### _3.1.3. Exfiltração de Dados com Uso Indevido do Wget_

- **Objetivo:** Detectar comandos que usam `wget` para exfiltrar arquivos sensíveis como `/etc/shadow`.
- **Contexto:** Exfiltração de dados via ferramentas legítimas é uma técnica evasiva que pode indicar comprometimento avançado e violação de dados críticos.
- **Fonte de dados:** Logs de auditd ou sysmonforlinux devidamente configurados.
- **Atores envolvidos:** Usuários locais com sudo mal configurado, processos com permissões elevadas.
- **Indicadores:** Uso de `wget` com parâmetros `--post-file`, acesso a arquivos sensíveis como `/etc/shadow`.
- **Requisitos de Detecção:** Regras de SIEM baseadas em auditd ou sysmonforlinux.
- **Fluxo da Ameaça:** Adversário explora permissões sudo mal configuradas → Usa `wget` para exfiltrar arquivos sensíveis via POST para domínio externo.
- **Resposta esperada:** Investigar origem do processo, revogar permissões sudo, bloquear exfiltração, investigar persistência e movimentação lateral.

**Regras associadas:**
- **Regra 4:** Data Exfiltration with Wget

### _3.1.4. Uso de Ferramentas Administrativas para Ações Maliciosas_

- **Objetivo:** Detectar o uso de ferramentas administrativas que indicam potencial abuso, como `PsExec` ou `Procdump`.
- **Contexto:** Ferramentas legítimas usadas maliciosamente para execução remota, extração de credenciais ou movimentação lateral, representando risco elevado à segurança corporativa.
- **Fonte de dados:** Logs de Windows, Sysmon, PowerShell, EDR.
- **Atores envolvidos:** Usuários com privilégios administrativos ou comprometidos, endpoints Windows.
- **Indicadores:** Criação de chave de registro `accepteula`, execução de ferramentas Sysinternals.
- **Requisitos de Detecção:** Regras de SIEM baseadas em Sysmon/Windows/PowerShell e regras comportamentais em EDR.
- **Fluxo da Ameaça:** Adversário executa `PsExec` ou `Procdump` → Sistema registra a chave `accepteula` no registro ou na linha de comando.
- **Resposta esperada:** Bloquear a execução, identificar o processo pai, correlacionar com movimentações laterais, investigar comprometimento de credenciais.

**Regras associadas:**
- **Regra 5:** PUA - Sysinternals Tools Execution - Registry

## 3.2. Regras de Detecção

### _3.2.1. Regra 1: Powershell Create Scheduled Task_

```yaml
title: Powershell Create Scheduled Task
id: 363eccc0-279a-4ccf-a3ab-24c2e63b11fb
status: test
description: Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.005/T1053.005.md#atomic-test-4---powershell-cmdlet-scheduled-task
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.005/T1053.005.md#atomic-test-6---wmi-invoke-cimmethod-scheduled-task
author: frack113
date: 2021-12-28
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_cmdlet:
        ScriptBlockText|contains:
            - 'New-ScheduledTaskAction'
            - 'New-ScheduledTaskTrigger'
            - 'New-ScheduledTaskPrincipal'
            - 'New-ScheduledTaskSettingsSet'
            - 'New-ScheduledTask'
            - 'Register-ScheduledTask'
    selection_cimmethod:
        ScriptBlockText|contains|all:
            - 'Invoke-CimMethod'
            - '-ClassName'
            - 'PS_ScheduledTask'
            - '-NameSpace'
            - 'Root\Microsoft\Windows\TaskScheduler'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium
```
### _3.2.2. Regra 2: Enable Windows Remote Management_

```yaml
title: Enable Windows Remote Management
id: 991a9744-f2f0-44f2-bd33-9092eba17dc3
status: test
description: Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.006/T1021.006.md#atomic-test-1---enable-windows-remote-management
    - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.2
author: frack113
date: 2022-01-07
tags:
    - attack.lateral-movement
    - attack.t1021.006
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_cmdlet:
        ScriptBlockText|contains: 'Enable-PSRemoting '
    condition: selection_cmdlet
falsepositives:
    - Legitimate script
level: medium
```

### _3.2.3. Regra 3: Possible Coin Miner CPU Priority Param_

```yaml
title: Possible Coin Miner CPU Priority Param
id: 071d5e5a-9cef-47ec-bc4e-a42e34d8d0ed
status: test
description: Detects command line parameter very often used with coin miners
references:
    - https://xmrig.com/docs/miner/command-line-options
author: Florian Roth (Nextron Systems)
date: 2021-10-09
modified: 2022-12-25
tags:
    - attack.privilege-escalation
    - attack.t1068
logsource:
    product: linux
    service: auditd
detection:
    cmd1:
        a1|startswith: '--cpu-priority'
    cmd2:
        a2|startswith: '--cpu-priority'
    cmd3:
        a3|startswith: '--cpu-priority'
    cmd4:
        a4|startswith: '--cpu-priority'
    cmd5:
        a5|startswith: '--cpu-priority'
    cmd6:
        a6|startswith: '--cpu-priority'
    cmd7:
        a7|startswith: '--cpu-priority'
    condition: 1 of cmd*
falsepositives:
    - Other tools that use a --cpu-priority flag
level: critical
```

### _3.2.4. Regra 4: Data Exfiltration with Wget_

```yaml
title: Data Exfiltration with Wget
id: cb39d16b-b3b6-4a7a-8222-1cf24b686ffc
status: test
description: |
    Detects attempts to post the file with the usage of wget utility.
    The adversary can bypass the permission restriction with the misconfigured sudo permission for wget utility which could allow them to read files like /etc/shadow.
references:
    - https://linux.die.net/man/1/wget
    - https://gtfobins.github.io/gtfobins/wget/
author: 'Pawel Mazur'
date: 2021-11-18
modified: 2022-12-25
tags:
    - attack.exfiltration
    - attack.t1048.003
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: EXECVE
        a0: wget
        a1|startswith: '--post-file='
    condition: selection
falsepositives:
    - Legitimate usage of wget utility to post a file
level: medium
```
### _3.2.5. Regra 5: PUA - Sysinternals Tools Execution - Registry_

```yaml
title: PUA - Sysinternals Tools Execution - Registry
id: c7da8edc-49ae-45a2-9e61-9fd860e4e73d
related:
    - id: 25ffa65d-76d8-4da5-a832-3f2b0136e133
      type: derived
    - id: 9841b233-8df8-4ad7-9133-b0b4402a9014
      type: obsolete
status: test
description: Detects the execution of some potentially unwanted tools such as PsExec, Procdump, etc. (part of the Sysinternals suite) via the creation of the "accepteula" registry key.
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-24
modified: 2023-02-07
tags:
    - attack.resource-development
    - attack.t1588.002
logsource:
    product: windows
    category: registry_add
detection:
    selection:
        EventType: CreateKey
        TargetObject|contains:
            - '\Active Directory Explorer'
            - '\Handle'
            - '\LiveKd'
            - '\Process Explorer'
            - '\ProcDump'
            - '\PsExec'
            - '\PsLoglist'
            - '\PsPasswd'
            - '\SDelete'
            - '\Sysinternals' # Global level https://twitter.com/leonzandman/status/1561736801953382400
        TargetObject|endswith: '\EulaAccepted'
    condition: selection
falsepositives:
    - Legitimate use of SysInternals tools. Filter the legitimate paths used in your environment
level: medium
```
# **4. Papéis e responsabilidades**

{{< bs/alert warning >}}
{{< bs/alert-heading "ATENÇÃO" >}}
O contexto dos papéis e responsabilidades aqui, é o cenário ideal para uma operação. Obviamente, leva-se em consideração custo operacional, tamanho da empresa, etc. Mas vale salientar que, atribuir atividades a equipes que não deveria ter essa função, é sobrecarregar a operação ou analista.
{{< /bs/alert >}}


## 4.1. Contexto e realidade operacional

No mundo ideal, organizações maduras possuem equipes estruturadas com papéis bem definidos para desenvolvimento de casos de uso e regras de detecção. Na prática, sabemos que nem toda empresa possui essa estrutura completa ou especialistas dedicados para cada função.

É importante entender que:

- **Adaptação é normal:** Em organizações menores, uma pessoa pode acumular múltiplas responsabilidades (ex: um Security Engineer que tanto define casos de uso quanto implementa regras).
- **Casos de uso são reutilizáveis:** Um caso de uso bem estruturado pode ser adaptado para diferentes clientes ou ambientes que compartilham contextos similares de ameaças e infraestrutura.
- **Reutilização inteligente:** Mesmo reutilizando casos de uso, é essencial adaptá-los à realidade específica do ambiente (criticidade de ativos, fontes de dados disponíveis, capacidades técnicas).
- **Crescimento gradual:** Organizações podem começar com estruturas simples e evoluir conforme amadurecem suas operações de segurança.

O objetivo desta seção é apresentar o cenário ideal de distribuição de responsabilidades, servindo como referência para organizações que buscam estruturar ou evoluir suas equipes de segurança.

## 4.1. Quem cria os Casos de Uso?

**Perfis Responsáveis (Principais):**
- **Arquiteto de Segurança:** Visão estratégica e alinhamento com arquitetura corporativa
- **SOC Manager/Tech Lead:** Conhecimento operacional + visão estratégica do SOC
- **Engenheiro de Segurança Sênior:** Experiência operacional e conhecimento técnico avançado
- **Arquiteto de Detecção:** Especialista dedicado ao desenvolvimento de estratégias de detecção (quando existe o cargo). Aqui ouso dizer que um Analista do Purple Team pode ser muito bem-vindo a fazer isso, já que ele fica em uma área de operação onde se desenvolve pesquisas, formas de atacar e defender, então ele terá uma visão holística da coisa.

**Perfis de Apoio:**
- **Analista de Threat Intelligence:** Fornece contexto atualizado sobre ameaças e TTPs
- **Analista de Risco:** Contribui com contexto de impacto no negócio e criticidade de ativos
- **Threat Hunter:** Insights sobre gaps de detecção identificados durante hunts
- **Analista SOC Sênior:** Feedback operacional sobre eficácia das detecções atuais

**Competências Necessárias:**
- **Conhecimento operacional:** Experiência prática em operação de SOC e ferramentas de detecção
- **Visão estratégica:** Capacidade de alinhar detecções com objetivos de segurança
- **Conhecimento de ameaças:** Entendimento sólido do MITRE ATT&CK e TTPs relevantes
- **Compreensão do ambiente:** Conhecimento da infraestrutura e processos organizacionais
- **Experiência técnica:** Entendimento de fontes de dados e capacidades de detecção
- **Comunicação:** Capacidade de traduzir necessidades técnicas e de negócio

**Responsabilidades:**
- Identificar cenários de risco relevantes baseados na realidade operacional
- Definir objetivos claros e mensuráveis de detecção
- Especificar fontes de dados necessárias e sua viabilidade
- Estabelecer critérios de resposta, escalação e SLAs
- Validar se as regras implementadas atendem ao caso de uso
- Manter documentação atualizada e versionada dos casos de uso
- Revisar periodicamente a eficácia dos casos de uso implementados

## 4.2. Quem Cria as Regras de Detecção?

**Perfis Responsáveis:**
- **Engenheiro de Detecção:** Especialista em implementação de regras e correlações
- **Analista SOC Sênior:** Experiência prática em ferramentas SIEM/EDR
- **DevSecOps Engineer:** Conhecimento em automação e versionamento de regras
- **Detection Engineer:** Especialização específica em desenvolvimento de detecções

**Competências Necessárias:**
- **Expertise técnica:** Domínio em linguagens de consulta (KQL, SPL, Sigma, etc.)
- **Conhecimento de ferramentas:** SIEM, EDR, SOAR e plataformas de detecção
- **Análise de logs:** Compreensão profunda de estruturas de dados e eventos
- **Depuração:** Habilidade para identificar e corrigir falsos positivos
- **Versionamento:** Conhecimento em Git e práticas de DevOps

**Responsabilidades:**
- Traduzir casos de uso em lógica técnica implementável
- Desenvolver e testar regras de detecção
- Otimizar performance das regras
- Gerenciar falsos positivos e ajustar thresholds
- Documentar regras com comentários técnicos
- Manter versionamento e controle de mudanças

## 4.3. Modelo de Colaboração

**Fluxo Ideal:**
1. **Identificação da Necessidade** → SOC Manager/Arquiteto identifica gap de detecção
2. **Definição do Caso de Uso** → Arquiteto/Security Engineer documenta cenário estratégico
3. **Refinamento Técnico** → Discussão entre criador do caso de uso e Engenheiro de Detecção
4. **Implementação das Regras** → Engenheiro desenvolve lógica técnica
5. **Validação** → Testada pelo Engenheiro, validada pelo responsável do caso de uso
6. **Operacionalização** → Monitorada e ajustada pelos Analistas SOC

**Comunicação Essencial:**
- **Criador do Caso de Uso → Engenheiro:** Especificações claras e contexto de negócio
- **Engenheiro → Criador:** Feedback sobre viabilidade técnica e limitações
- **Ambos → Analistas SOC:** Treinamento sobre novas detecções e procedimentos
- **Analistas → Ambos:** Feedback operacional, falsos positivos e melhorias
- **Threat Intel → Criador:** Atualizações sobre TTPs e contexto de ameaças

## 4.4. Relacionamento Prático: Do Caso de Uso à Regra de Detecção

Um exemplo de fluxo de trabalho maduro seria:

1. **Identificação do Risco:** Time de segurança identifica a necessidade de detectar movimentação lateral via PowerShell
2. **Criação do Caso de Uso:** Define-se o caso de uso "Execução Remota e Persistência via PowerShell"
3. **Desenvolvimento das Regras:** Engenheiros criam regras específicas baseadas no caso de uso
4. **Implementação:** Regras são implementadas no SIEM/EDR
5. **Validação:** Testa-se se as regras atendem ao objetivo do caso de uso
6. **Refinamento:** Ajustes baseados em falsos positivos e eficácia

# **5. Impacto na Maturidade do SOC**

## 5.1. SOC Imaturo
- Foca apenas na criação de regras sem contexto estratégico
- Não documenta casos de uso
- Dificuldade para justificar investimentos em segurança
- Alto número de falsos positivos
- Baixa eficiência operacional

## 5.2. SOC Maduro
- Desenvolve casos de uso alinhados com riscos do negócio
- Cria regras baseadas em casos de uso bem definidos
- Documenta e versiona ambos os artefatos
- Métricas claras de eficácia
- Melhoria contínua baseada em dados

# **6. Conclusão**

Chamar uma regra de detecção de "caso de uso" é tecnicamente incorreto e prejudica a maturidade operacional. **Casos de uso são estratégias de detecção; regras são mecanismos técnicos.** Um SOC maduro entende que um não substitui o outro.

O uso correto de ambos os conceitos garante:
- **Eficiência operacional:** Detecções alinhadas com riscos reais
- **Redução de falsos positivos:** Regras contextualizadas e bem fundamentadas  
- **Melhoria contínua:** Processo estruturado de evolução das capacidades de detecção
- **Justificativa de investimentos:** ROI claro das iniciativas de segurança

Lembre-se: **você não escreve um caso de uso no SIEM. Você escreve uma regra.** Mas essa regra deve sempre nascer de um caso de uso bem estruturado e justificado estrategicamente.

# **7. Referências**

- [GoHacking Security Operation Center Foundations - GoHacking](https://gohacking.com.br/curso/gohacking-security-operation-center-foundations)

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}
