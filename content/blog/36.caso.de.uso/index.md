---
title: "[PUBLICAR]Regra de Detecção não é Caso de Uso - Entenda de uma vez por todas"
date: 2025-05-08T00:26:48-03:00
draft: false
description: "Regras de detecção são lógicos. Casos de uso são conceitos. Confundir os dois enfraquece a operação de segurança. Saiba por que usar os termos certos importa na prática do SOC." 
noindex: false
featured: false
pinned: false
comments: false
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
# 1. Introdução

Em um Centro de Operações de Segurança (SOC) é muito comum no dia a dia ouvirmos frases como: _"Esse caso de uso pra detectar brute force precisa de ajuste"._ _"Precisamos criar um caso de uso pra detectar execução de psexec"._ Mas... o que realmente esse analista quis dizer é: _"Criei uma regra de detecção pra tal coisa"._ Essa confusão entre os termos **"caso de uso"** e **"regra de detecção"** precisa acabar. Embora relacionados, são conceitos distintos, com propósitos, estruturas e impactos diferentes dentro de uma operação.

Este artigo tem como objetivo demonstrar (ao menos tentar), as diferenças e contextos de aplicação entre casos de uso e regras de detecção, pois não são a mesma coisa e não podemos tratar tudo como caso de uso.

# 2. Do conceito

## 2.1. O que é um Caso de Uso?

Um caso de uso é o conjunto de elementos que justificam e estruturam a criação de uma ou mais regras de detecção. Representa um cenário de segurança ou negócio que precisa ser monitorado para identificar determinados comportamentos anômalos, atividades maliciosas ou violações de segurança. Nele, nós descrevemos o que se deseja proteger: Por quê, de quem, e como.

Os elementos que permeiam um caso de uso são:

- **Objetivo:** Qual a ameaça ou risco está sendo tratado?
- **Contexto:** Qual o valor para o negócio?
- **Fonte de dados:** Quais logs ou eventos são necessários?
- **Atores envolvidos:** Usuários, contas privilegiadas, sistemas.
- **Métricas e Indicadores:** Indicadores de Comprometimento (IoCs), Indicadores de Ataque (IoAs).
- **Requisitos de Detecção:** Tipos de regras que serão utilizadas (SIEM, EDR, etc.).
- **Fluxo do Evento:** Qual a ameaça ou risco está sendo tratado?
- **Objetivo:** Representação do passo a passo da ameaça.
- **Resposta esperada:** Como o SOC deverá agir diante de um alerta.

> Pense no **caso de uso** como um projeto de detecção completo com propósito, lógica e justificativa.

## 2.2. O que é uma Regra de Detecção?

Uma regra de detecção é a implementação lógica que idenfifica os padrões, condições ou comportamentos específicos nos eventos. Ela pode ser implementada em SIEM, EDR, NDR, etc. Ela representa o "como" do caso de uso.

Os elementos que permeiam uma regra de detecção são:

- **Foco técnico:** Lida apenas com as condições técnicas observáveis, sem considerar impacto estratégico.
- **Expressa uma lógica específica:** Define o que deve ser detectado, usando campos, operações e padrões.
- **Depende de dados estruturados:** Só funciona com logs padronizados e bem definidos.
- **Desprovida de contexto de negócio:** Não considera o valor do ativo ou o impacto no negócio.
- **Reutilizável em vários casos de uso:** Uma única regra pode ser usada em diferentes cenários que compartilham da mesma lógica técnica.

> Pense na **regra de detecção** como o código ou instrução lógica para identificar uma condição previamente definida.

## 2.3. Comparação entre os dois

| Aspecto                 | Caso de Uso                                | Regra de Detecção                          |
| :-----------------------: | :------------------------------------------: | :------------------------------------------: |
| **Objetivo**            | Monitorar um cenário de risco              | Identificar um padrão específico de evento |
| **Escopo**              | Estratégico e contextual                   | Tático e técnico                           |
| **Reutilizável?**       | Pouco - é mais específico para um contexto | Sim - pode ser aplicada a diferentes casos |
| **Dependência técnica** | Média - é mais conceitual                  | Alta - depende do formato dos dados        |
| **Ponto de Partida**    | Necessidade do negócio / risco             | Lógica de correlação baseada em eventos    |
| **Quem constrói**       | Especialista de Segurança / Arquitetura    | Analista Técnico / Engenheiro de Detecção  |

## 2.4. Resumo técnico

| **Critério**                                | **Regra de Detecção**                                      | **Caso de Uso**                                                      |
| ------------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------- |
| **É código ou lógica implementável?**       | ✅ Sim. Define condições técnicas em linguagem estruturada. | ❌ Não. É um artefato de planejamento/gestão da detecção.             |
| **Tem objetivo de negócio?**                | ❌ Não. É técnica e neutra quanto ao impacto.               | ✅ Sim. Aborda risco, impacto e valor para o negócio.                 |
| **Pode ser versionada?**                    | ✅ Sim. Armazenada em repositórios (YAML, Sigma, KQL, etc). | ✅ Sim. Versão controlada como documento ou playbook.                 |
| **É acionável isoladamente?**               | ✅ Sim. Gera alertas ou bloqueios diretamente.              | ❌ Não. Depende de regras para funcionar na prática.                  |
| **Faz parte de pipeline CI/CD?**            | ✅ Sim. Pode ser testada e implantada automaticamente.      | ❌ Não diretamente. Pode ser referenciada na documentação do ciclo.   |
| **É reusável entre ambientes?**             | ✅ Sim. Pode ser aplicada em ambientes distintos.           | ⚠️ Parcialmente. Pode exigir adaptação conforme a criticidade local. |
| **Tem contexto de ameaça/atacante?**        | ❌ Não. Detecta comportamentos técnicos.                          | ✅ Sim. Foca no comportamento e objetivo do atacante.                 |
| **Precisa de dados estruturados?**          | ✅ Sim. Só funciona com logs padronizados e bem definidos.      | ❌ Não. Pode ser projetado mesmo sem log implementado ainda.          |
| **Serve como base para criação de regras?** | ❌ Não. É o produto final da lógica.                        | ✅ Sim. É o ponto de partida para desenvolver regras.                 |

Abaixo vou descrever 4 casos de uso e 5 regras de detecção, levando em consideração que mais de uma regra pode compor um único caso de uso.

# 3. Do cenário prático

## 3.1. Casos de Uso

### 3.1.1. Execução remota e persistência via PowerShell

- **Objetivo:** Detectar e responder à persistência remota ou execução de código via agendadores de tarefas e gerenciamento remoto (`WinRM`).
- **Contexto:** Técnicas de execução remota e persistência são amplamente utilizadas em movimentos laterais ou permanência pós-comprometimento.
- **Fonte de dados:** Logs de Windows, logs de Sysmon, logs de PowerShell, logs do EDR.
- **Atores envolvidos:** Usuários com privilégios administrativos ou comprometidos, endpoints Windows.
- **Métricas e Indicadores:** Palavras-chave como `New-ScheduledTask`, `schtasks`, execução de `Enable-PSRemoting`, comunicação em portas `5985/5986`.
- **Requisitos de Detecção:** Regras de SIEM baseadas em Sysmon/Windows/PowerShell e regras comportamentais em EDR.
- **Fluxo do Evento:** Atacante acessa o host → Ativa o `WinRM` no host remoto → Usar PowerShell para criar uma tarefa agendada que persiste execução.
- **Resposta esperada:** Investigar origem do processo, bloquear o host, revogação de credenciais, resposta a incidentes.

**Regras associadas:**
- **Regra 1:** Powershell Create Scheduled Task
- **Regra 2:** Enable Windows Remote Management

As regras associadas aqui são apenas ilustrativos, não significa que a regra já exista. Lembre-se.

### 3.1.2. Execução de minerador de criptomoeda em endpoint

- **Objetivo:** Detectar execução de mineradores baseados em linha de comando.
- **Contexto:** Comprometimento de recursos computacionais que afeta performance e pode indicar controle remoto do ativo.
- **Fonte de dados:** Logs de Windows, logs de Sysmon, logs de PowerShell, logs do EDR.
- **Atores envolvidos:** Contas locais exploradas, hosts expostos ou vulneráveis.
- **Métricas e Indicadores:** Execução de processos com parâmetros como `-t`, `-cpu-priority`, `-donate-level`, `xmrig`.
- **Requisitos de Detecção:** Regras de SIEM com análise de linha de comando, integração com EDR para detecção de comportamento.
- **Fluxo do Evento:** Adversário executa um minerador no host → Utiliza parâmetros para otimizar o uso de CPU e ocultar a atividade.
- **Resposta esperada:** Encerramento do processo, isolamento do host, análise de persistência e identificação do vetor de entrada.

**Regras associadas:**
- **Regra 3:** Possible Coin Miner CPU Priority Param

As regras associadas aqui são apenas ilustrativos, não significa que a regra já exista. Lembre-se.

### 3.1.3. Exfiltração de dados com uso indevido do Wget

- **Objetivo:** Detectar uso malicioso do `wget` para exfiltrar arquivos sensíveis.
- **Contexto:** Exfiltração de dados via ferramentas legítimas é uma técnica evasiva que pode indicar comprometimento avançado.
- **Fonte de dados:** Log de auditd ou sysmonforlinux devidamente configurados.
- **Atores envolvidos:** Usuários locais com sudo indevido, processos com permissões elevadas.
- **Métricas e Indicadores:** Uso de `wget` com parâmetros `--post-file`, acesso a arquivos sensíveis como `/etc/shadow`.
- **Requisitos de Detecção:** Regras de SIEM baseadas em auditd ou sysmonforlinux.
- **Fluxo do Evento:** Adversário usa `sudo wget` com permissões mal configuradas. → Exfiltra arquivos sensíveis via POST para domínio externo.
- **Resposta esperada:** Investigar origem do processo, revogação de permissões sudo, bloqueio de saída de dados, investigação de persistência e movimentação lateral.

**Regras associadas:**
- **Regra 4:** Data Exfiltration with Wget

As regras associadas aqui são apenas ilustrativos, não significa que a regra já exista. Lembre-se.

### 3.1.4. Uso de ferramentas administrativas para ações maliciosas

- **Objetivo:** Detectar o uso de ferramentas administrativas que indicam potencial abuso, como `PsExec` ou `Procdump`.
- **Contexto:** Ferramentas legítimas usadas de forma maliciosa para execução remota, extração de credenciais ou movimentação lateral.
- **Fonte de dados:** Logs de Windows, logs de Sysmon, logs de PowerShell, logs do EDR.
- **Atores envolvidos:** Usuários com privilégios administrativos ou comprometidos, endpoints Windows.
- **Métricas e Indicadores:** Criação de chave de registro `accepteula`, execução de ferramentas Sysinternals.
- **Requisitos de Detecção:** Regras de SIEM baseadas em Sysmon/Windows/PowerShell e regras comportamentais em EDR.
- **Fluxo do Evento:** Adversário executa `PsExec` ou `Procdump` → Sistema registra a chave `accepteula` no registro ou linha de comando.
- **Resposta esperada:** Bloqueio da execução, identificação do processo pai, correlação com movimentações laterais, investigação de credenciais.

**Regras associadas:**
- **Regra 5:** PUA - Sysinternals Tools Execution - Registry

As regras associadas aqui são apenas ilustrativos, não significa que a regra já exista. Lembre-se.

## 3.2. Regras de Detecção

### 3.2.1. Regra 1: Powershell Create Scheduled Task

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
### 3.2.2. Regra 2: Enable Windows Remote Management

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

### 3.2.3. Regra 3: Possible Coin Miner CPU Priority Param

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

### 3.2.4. Regra 4: Data Exfiltration with Wget

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
### 3.2.5. Regra 5: PUA - Sysinternals Tools Execution - Registry

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

# 4. Conclusão

Chamar uma regra de detecção de "caso de uso" é tecnicamente incorreto. Casos de uso são estratégias de detecção; regras são mecanismos técnicos. Um SOC maduro entende que um não substitui o outro. O uso correto de ambos garante eficiência operacional, redução de falsos positivos e melhoria contínua do processo de defesa. Você não escreve um caso de uso no SIEM. Você escreve uma regra.

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}
