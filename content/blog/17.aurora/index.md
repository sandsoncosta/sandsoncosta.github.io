---
title: "Aurora e Sigma Rules: Melhorando a eficiência e visibilidade na detecção de ameaças em Windows"
date: 2024-12-25T12:57:03-03:00
draft: false
description: Aurora, combinado com regras Sigma, aprimora a detecção de ameaças em Windows, oferecendo uma solução robusta e flexível para ambientes corporativos.
noindex: false
featured: false
pinned: false
comments: false
series:
#  - 
categories:
 - Threat Hunting
 - EDR
 - Engenharia de Detecção
 - Regras Sigma
 - Windows
tags:
 - Sigma
 - Detecção de Ameaças
 - Análise de Ameaças
 - Ferramentas de SIEM
 - Segurança Multiplataforma
 - Threat Intelligence
 - Resposta a Incidentes
 - Segurança de Endpoints
 - Automação de Segurança
images:
authors:
 - sandson
---
## 1. Introdução

Cada dia mais as ameaças cibernéticas se desenvolvem rapidamente e evoluem em um ritmo acelerado, ter ferramentas robustas e flexíveis para detecção e resposta é essencial para uma postura de segurança. Neste artigo, vamos explorar como o Aurora pode aumentar a visibilidade de segurança na sua organização, com foco nas vantagens em integrar regras Sigma para aprimorar a detecção de ameaças.

## 2. O que é o Aurora?

O Aurora, é uma _Custom Sigma-based Endpoint Agent_, uma solução criada pela Nextron Systems.

É um agente de endpoint leve e personalizável baseado em Sigma. Ele usa o _Event Tracing for Windows (ETW)_ para recriar eventos muito semelhantes aos eventos gerados pelo Sysmon da Microsoft e aplica regras Sigma e IOCs a eles. O AURORA complementa o padrão aberto Sigma com "ações de resposta" que permitem aos usuários reagir a uma correspondência Sigma.

Ele é completamente transparente e totalmente personalizável devido ao conjunto de regras Sigma aberto e aos arquivos de configuração. Podendo ser configurado para detecções locais e até mesmo integrar-se ao SIEM.

Ele possui uma versão empresarial e uma versão "Lite", que é gratuita. A versão gratuita usa apenas o conjunto de regras Sigma disponíveis pela comunidade, a versão empresarial conta com regras "Premium" disponibilizadas pela própria empresa e possui um gerenciamento mais centralizado.

## 3. Download, instalação e configuração do Aurora

Acesse o site oficial da Nextron Systems e baixe a última versão do Aurora: https://www.nextron-systems.com/aurora/. Você precisa se cadastrar para receber uma licença e o link de download do instalador.

### 3.1. Sistemas suportados

| Sistemas Suportados        |
|:----------------------------:|
| Windows 7 x86 / x64        |
| Windows Server 2008 R2 x64 |
| Windows 8.1                |
| Windows Server 2012        |
| Windows Server 2012 R2     |
| Windows 10                 |
| Windows 11                 |
| Windows Server 2016        |
| Windows Server 2019        |
| Windows Server 2022        |

### 3.2. Instalação

Extraia os arquivos do pacote baixado para a pasta de sua preferência, também inclua na pasta o arquivo de licença que você recebeu no seu e-mail.

Abra um terminal e navegue até a pasta.

Aqui temos algumas formas de instalação que podemos configurar. Por _default_, o Aurora é configurado com logs gerados no `Application` no _Event Viewer_.

### 3.3. Para uma instalação com notificação no _system tray_.

Execute o comando:
```powershell
.\aurora-agent-64.exe --install --dashboard
```
Essa configuração irá mostrar as notificações sempre que uma regra Sigma der _match_ com algum evento no Windows e também ele configura um Dashboard que você pode consultar em `http://localhost:17494/ui/dashboard/overview`. Esse Dashboard é local e não é possível gerenciá-lo com a versão Lite.

<figure style="display: flex; flex-direction: column; align-items: center; margin: 0 auto; max-width: 100%;">
  <video style="width: 100%; max-width: 640px; height: auto;" controls>
    <source src="exemplo.mp4" type="video/mp4">
    Seu navegador não suporta a tag de vídeo.
  </video>
  <figcaption style="margin-top: 8px; text-align: center; font-style: italic;">
    Exemplo do Aurora identificando uma execução PowerShell encodado e notificação no System Tray.
  </figcaption>
</figure>


### 3.4. Para uma instalação sem notificação no _system tray_

Execute o comando:
```powershell
.\aurora-agent-64.exe --install
```
Essa configuração não irá instalar o Dashboard nem gerar notificações, ficando apenas a geração de logs no _Event Viewer_.

### 3.5. Para integrar os logs ao SIEM

Execute o comando:
```powershell
.\aurora-agent-64.exe --install --tcp-target 192.168.56.100:515
```
Aqui eu não setei o dashboard, pois como vamos coletar via SIEM, não há necessidade de gerar um dashboard, até porque não é gerenciável na versão Lite.

Esse comando acima, tanto envia para um coletor quanto gera logs no _Application_.

Para remover a geração de logs no _Event Viewer_, execute o comando:
```powershell
.\aurora-agent-64.exe --install --tcp-target 192.168.56.100:515 --no-eventlog
```
Com isso, ele apenas irá enviar para o coletor.

O programa também envia a saída no formato JSON, que é uma saída que não gera muitas dificuldades no _parsing_ em SIEMs.

Para enviar os logs no formato JSON, execute o comando:
```powershell
.\aurora-agent-64.exe --install --tcp-target 192.168.56.100:515 --no-eventlog --json
```
### 3.6. Resposta e mitigação a ataques

O Aurora tem 4 níveis detecção: _Standard_, _Reduced_, _Minimal_ e _Intense_. Você também pode configurar o quanto de processamento de CPU ele pode consumir, e quais níveis de serveridade (_low_, _medium_ ou _high_) você quer usar. O padrão de instalação é o _Standard_. A depender de como você configura, ele pode gerar muitos falsos-positivos e gerar muitos logs. Ficará a cargo do analista o desafio de trabalhar o ambiente durante o processo para reduzir os falsos-positivos.

Ele também conta com _active response_, que mata o processo em execução, caso alguma regra Sigma der _match_.

As _responses_ são uma extensão do padrão Sigma usado nos agentes do Aurora. Eles podem ser usados para realizar certas ações e responder imediatamente a uma correspondência de uma regra Sigma. As _responses_ podem ajudar a conter uma ameaça ou limitar danos, mas também podem levar a sérios problemas quando não são manuseados com cuidado.

{{< bs/alert warning >}}
{{< bs/alert-heading "Atenção!" >}}
  Use apenas nos casos em que você tem certeza absoluta de que uma regra não crie falsos-positivos.
{{< /bs/alert >}}

Exemplos de uso:
 - Contenção de Worms.
 - Contenção de Ransomwares.
 - Contenção de uso de ferramentas não homologadas (Caso não seja usado o AppLocker da Microsoft, que é o mais recomendado).

Ele conta com ações pré-definidas e customizadas. As pré-definidas são: _suspend_, _kill_ e _dump_. As customizadas são ações de chamadas para outros executáveis ou fazer uma cópia do artefato malicioso para outro local de segurança para ser analisado posteriormente. Maiores informações podem ser consultadas na documentação. O link está marcado em **Referências**.

Por padrão a ação de resposta não é habilitada, é preciso incluir a flag durante a instalação, mas antes, precisamos entender como configura a ação de resposta.

Para configurar a ação de _kill_ pelo Aurora, você precisa ir na pasta que você baixou e ir na pasta `response-sets`. Dentro dessa pasta contém um arquivo chamado `aurora-lite.yml`. Abra esse arquivo e verá o seguinte conteúdo:

```yml
description: Nextron Preset Responses for Aurora Lite - Ransomware Focus
id: 75fe2da6-353b-451f-b09c-24cace2be74b
group: aurora-lite
response:
  type: predefined
  action: kill
  lowprivonly: true
  ancestors: all
  recursive: true
rule-ids:
  # Removal of recovery options: 
  - 'c947b146-0abc-4c87-9c64-b17e9d7274a2'  # Shadow Copies Deletion Using Operating Systems Utilities
  - '89f75308-5b1b-4390-b2d8-d6b2340efaf8'  # Wbadmin Delete Systemstatebackup
  - '1444443e-6757-43e4-9ea4-c8fc705f79a2'  # Modification of Boot Configuration
  # Entry vectors: malicious documents, stage1 loaders etc.
  - '438025f9-5856-4663-83f7-52f878a70a50'  # Microsoft Office Product Spawning Windows Shell
  - 'ca2092a1-c273-4878-9b4b-0d60115bf5ea'  # Suspicious Encoded PowerShell Command Line
  - 'fb843269-508c-4b76-8b8d-88679db22ce7'  # Suspicious Execution of Powershell with Base64
```

Em `rule-ids` você irá colocar o ID da regra Sigma. No meu caso, a título de exemplo, eu incluí a regra Sigma `Suspicious Execution of Powershell with Base64` para exemplicar a ação.

Com as regras de _active response_ configuradas, pode iniciar a instação.

Execute o comando:
```powershell
.\aurora-agent-64.exe --install --tcp-target 192.168.56.100:515 --no-eventlog --json --activate-responses --response-set  .\response-sets\aurora-lite.yml
```

Com isso a resposta à ação já está habilitada.

<figure style="text-align: center;">
  <video width="640" height="340" controls>
    <source src="response.mp4" type="video/mp4">
    Seu navegador não suporta a tag de vídeo.
  </video>
  <figcaption><i>Regra Sigma "Suspicious Execution of Powershell with Base64" em ação.</i></figcaption>
</figure>

### 3.7. Configurando novas regras Sigma

Para incluir novas regras é bem simples, basta ir ao caminho `C:/Program Files/Aurora-Agent` e incluir as regras dentro da pasta `custom-signatures`.

## 4. Observações

Os sistemas de proteção identificam os arquivos `.yml` como maliciosos, então, é necessário colocar em exceção a pasta descompactada (eu costumo colocar em uma pasta `C:/aurora`) e o caminho `C:/Program Files/Aurora-Agent`.

### 4.1. Exemplo de logs JSON

Log de exemplo com integração direta ao SIEM:

```txt
<13>Dec 26 17:34:08 192.168.56.10 {"CommandLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ep bypass -e cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACIAYwBhAGwAYwAuAGUAeABlACIA","Company":"Microsoft Corporation","Computer":"kingslanding","Correlation_ActivityID":"{00000000-0000-0000-0000-000000000000}","CurrentDirectory":"C:\\Users\\vagrant\\","Description":"Windows PowerShell","DirectoryTableBase":"0x8F53A000","EventID":"1","Execution_ProcessID":"8672","Execution_ThreadID":"8320","ExitStatus":"259","FileAge":"2294d13h53m33s","FileCreationDate":"2018-09-15T00:14:14","FileVersion":"10.0.17763.1 (WinBuild.160101.0800)","Flags":"0","GrandparentCommandLine":"C:\\Windows\\Explorer.EXE","GrandparentImage":"C:\\Windows\\explorer.exe","GrandparentProcessId":"7888","Hashes":"MD5=7353F60B1739074EB17C5F4DDDEFE239,SHA1=6CBCE4A295C163791B60FC23D285E6D84F28EE4C,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C,IMPHASH=741776AACCFC5B71FF59832DCDCACE0F","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ImageFileName":"powershell.exe","Keywords":"0x0","Level":"0","Match_Strings":"' -e ' in CommandLine, \\powershell.exe in Image","Module":"Sigma","Opcode":"1","OriginalFileName":"PowerShell.EXE","ParentCommandLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" ","ParentId":"0x21E0","ParentImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ParentProcessId":"8672","ParentUser":"SEVENKINGDOMS\\vagrant","ProcessId":"2736","ProcessTree":"C:\\Windows\\explorer.exe|C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe|C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","Product":"Microsoft® Windows® Operating System","Provider_Guid":"{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}","Provider_Name":"SystemTraceProvider-Process","Rule_Author":"frack113","Rule_Description":"Commandline to launch powershell with a base64 payload","Rule_FalsePositives":"Unknown","Rule_Id":"fb843269-508c-4b76-8b8d-88679db22ce7","Rule_Level":"medium","Rule_Link":"https://github.com/SigmaHQ/sigma/blob/r2024-12-19/rules/windows/process_creation/proc_creation_win_powershell_encode.yml","Rule_Modified":"2022-01-02","Rule_Path":"public\\windows\\process_creation\\proc_creation_win_powershell_encode.yml","Rule_References":"https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-20---powershell-invoke-known-malicious-cmdlets, https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/, https://mikefrobbins.com/2017/06/15/simple-obfuscation-with-powershell-using-base64-encoding/","Rule_Sigtype":"public","Rule_Title":"Suspicious Execution of Powershell with Base64","SessionId":"1","Task":"0","TimeCreated_SystemTime":"2024-12-26T14:34:06.1325873-08:00","Timestamp":"2074-02-28T09:48:58","UniqueProcessKey":"0xFFFFE68EDBA57080","User":"SEVENKINGDOMS\\vagrant","UserSID":"\\\\SEVENKINGDOMS\\vagrant","UtcTime":"2024-12-26 22:34:06","Version":"4","Winversion":"17763","aurora_eventid":1,"level":"notice","msg":"Sigma match found","time":"2024-12-26T14:34:08-08:00"}
```

Log de exemplo coletado pelo `Application`:

```txt
<13>Dec 26 17:40:00 192.168.56.10 {"EventTime":"2024-12-26 14:39:59","Hostname":"kingslanding.sevenkingdoms.local","Keywords":36028797018963968,"EventType":"INFO","SeverityValue":2,"Severity":"INFO","EventID":1,"SourceName":"AuroraAgent","Task":0,"RecordNumber":3818,"ProcessID":0,"ThreadID":0,"Channel":"Application","Message":"{\"CommandLine\":\"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\" -ep bypass -e cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgACIAYwBhAGwAYwAuAGUAeABlACIA\",\"Company\":\"Microsoft Corporation\",\"Computer\":\"kingslanding\",\"Correlation_ActivityID\":\"{00000000-0000-0000-0000-000000000000}\",\"CurrentDirectory\":\"C:\\\\Users\\\\vagrant\\\\\",\"Description\":\"Windows PowerShell\",\"DirectoryTableBase\":\"0x634F2000\",\"EventID\":\"1\",\"Execution_ProcessID\":\"8996\",\"Execution_ThreadID\":\"5260\",\"ExitStatus\":\"259\",\"FileAge\":\"2294d13h53m33s\",\"FileCreationDate\":\"2018-09-15T00:14:14\",\"FileVersion\":\"10.0.17763.1 (WinBuild.160101.0800)\",\"Flags\":\"0\",\"GrandparentCommandLine\":\"C:\\\\Windows\\\\Explorer.EXE\",\"GrandparentImage\":\"C:\\\\Windows\\\\explorer.exe\",\"GrandparentProcessId\":\"7888\",\"Hashes\":\"MD5=7353F60B1739074EB17C5F4DDDEFE239,SHA1=6CBCE4A295C163791B60FC23D285E6D84F28EE4C,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C,IMPHASH=741776AACCFC5B71FF59832DCDCACE0F\",\"Image\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"ImageFileName\":\"powershell.exe\",\"Keywords\":\"0x0\",\"Level\":\"0\",\"Match_Strings\":\"' -e ' in CommandLine, \\\\powershell.exe in Image\",\"Module\":\"Sigma\",\"Opcode\":\"1\",\"OriginalFileName\":\"PowerShell.EXE\",\"ParentCommandLine\":\"\\\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\\" \",\"ParentId\":\"0x2324\",\"ParentImage\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"ParentProcessId\":\"8996\",\"ParentUser\":\"SEVENKINGDOMS\\\\vagrant\",\"ProcessId\":\"1732\",\"ProcessTree\":\"C:\\\\Windows\\\\explorer.exe|C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe|C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"Product\":\"Microsoft® Windows® Operating System\",\"Provider_Guid\":\"{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}\",\"Provider_Name\":\"SystemTraceProvider-Process\",\"Rule_Author\":\"frack113\",\"Rule_Description\":\"Commandline to launch powershell with a base64 payload\",\"Rule_FalsePositives\":\"Unknown\",\"Rule_Id\":\"fb843269-508c-4b76-8b8d-88679db22ce7\",\"Rule_Level\":\"medium\",\"Rule_Link\":\"https://github.com/SigmaHQ/sigma/blob/r2024-12-19/rules/windows/process_creation/proc_creation_win_powershell_encode.yml\",\"Rule_Modified\":\"2022-01-02\",\"Rule_Path\":\"public\\\\windows\\\\process_creation\\\\proc_creation_win_powershell_encode.yml\",\"Rule_References\":\"https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-20---powershell-invoke-known-malicious-cmdlets, https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/, https://mikefrobbins.com/2017/06/15/simple-obfuscation-with-powershell-using-base64-encoding/\",\"Rule_Sigtype\":\"public\",\"Rule_Title\":\"Suspicious Execution of Powershell with Base64\",\"SessionId\":\"1\",\"Task\":\"0\",\"TimeCreated_SystemTime\":\"2024-12-26T14:39:57.0745575-08:00\",\"Timestamp\":\"2074-02-28T09:48:58\",\"UniqueProcessKey\":\"0xFFFFE68ED8CB9080\",\"User\":\"SEVENKINGDOMS\\\\vagrant\",\"UserSID\":\"\\\\\\\\SEVENKINGDOMS\\\\vagrant\",\"UtcTime\":\"2024-12-26 22:39:57\",\"Version\":\"4\",\"Winversion\":\"17763\",\"level\":\"notice\",\"msg\":\"Sigma match found\",\"time\":\"2024-12-26T14:39:59-08:00\"}\n","Opcode":"Info","EventReceivedTime":"2024-12-26 14:39:59","SourceModuleName":"in","SourceModuleType":"im_msvistalog"}
```

### 4.2. Exemplos de regras Sigma em ação e integrados ao SIEM

Eventos da execução de comando em base64 identificados por regras Sigma:

<img src="rules.png" alt="" style="display: block; margin-left: auto; margin-right: auto; max-width: 100%; height: auto;">

Eventos da resposta de matar o processo malicioso em execução do comando em base64 identificados por regras Sigma:

<img src="response.png" alt="" style="display: block; margin-left: auto; margin-right: auto; max-width: 100%; height: auto;">

Eventos identificados por regras Sigma da execução do Mimikatz em memória. Nesse exemplo não coloquei em _active response_:

<img src="mimi.png" alt="" style="display: block; margin-left: auto; margin-right: auto; max-width: 100%; height: auto;">

Como pode ser visto e como mencionei mais acima, ele pode gerar muitos eventos, por isso é necessário um trabalho de refinamento.

## 5. Conclusão

O Aurora se destaca como uma ferramenta poderosa e versátil para detecção e resposta a ameaças cibernéticas, especialmente para organizações que desejam integrar regras Sigma em suas estratégias de segurança. Sua capacidade de personalização, leveza e suporte tanto para detecção local quanto integração com SIEMs o torna uma escolha atrativa para equipes de segurança que buscam melhorar sua visibilidade e resposta a incidentes.

Além disso, a funcionalidade de _active response_ agrega uma camada adicional de defesa, permitindo ações automatizadas para conter ameaças em tempo real, embora seu uso requeira cautela para evitar interrupções indesejadas.

Ao configurar e implementar o Aurora, é essencial dedicar tempo ao ajuste fino de regras e ações, garantindo um equilíbrio entre segurança eficaz e um ambiente operacional estável. Com uma boa configuração e monitoramento contínuo, o Aurora pode ser uma adição valiosa ao arsenal de qualquer profissional de segurança cibernética.

## 7. Referências

- [Aurora](https://www.nextron-systems.com/aurora/)
- [Aurora Agent Overview](https://www.nextron-systems.com/wp-content/uploads/2022/04/Aurora_Agent_Overview_EN_2022_Mar.pdf)
- [Documentação Oficial](https://aurora-agent-manual.nextron-systems.com/en/latest/index.html)

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}

---
<!-- begin wwww.htmlcommentbox.com -->
  <div id="HCB_comment_box"><a href="http://www.htmlcommentbox.com">Widget</a> is loading comments...</div>
 <link rel="stylesheet" type="text/css" href="https://www.htmlcommentbox.com/static/skins/bootstrap/twitter-bootstrap.css?v=0" />
<!-- end www.htmlcommentbox.com -->