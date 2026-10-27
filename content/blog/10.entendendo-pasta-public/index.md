---
title: "Restringindo e auditando a escrita em C:\\Users\\Public via GPO"
date: 2024-12-04T16:12:08-03:00
lastmod: 2026-10-26T22:30:00-03:00
draft: false
description: "Como restringir a escrita em C:\\Users\\Public por GPO, impedir execução de binários e scripts a partir dela com AppLocker e gerar telemetria útil para detecção, com um passo a passo reproduzível em laboratório."
noindex: false
featured: false
pinned: false
comments: true
series:
  - 
categories:
  - publicar
tags:
  - gpo
  - applocker
  - auditoria
  - windows
  - deteccao
  - threat-hunting
authors:
  - sandson
images:
---

## 1. Introdução

`C:\Users\Public` é um dos poucos diretórios do Windows com caminho previsível, presente em toda instalação e gravável por qualquer usuário interativo sem elevação. Essa combinação faz dele um local recorrente de staging em intrusões: loaders baixam o segundo estágio para lá, scripts de persistência copiam binários para lá e ferramentas de ransomware usam a pasta para deixar utilitários e notas antes da execução. No MITRE ATT&CK, esse comportamento aparece principalmente em T1074.001 (Local Data Staging) e T1105 (Ingress Tool Transfer), seguido de execução (T1059, T1204).

Este artigo trata de três controles complementares, aplicados por GPO:

1. Restringir a escrita na pasta a um grupo específico, mantendo leitura para os demais usuários.
2. Bloquear a execução de binários e scripts a partir da pasta com AppLocker.
3. Configurar auditoria (SACL + política de auditoria avançada) para gerar eventos que possam virar detecção no SIEM.

No final há um roteiro de laboratório com os comandos, os testes e os eventos esperados.

Um ponto de escopo antes de começar: a pasta pública é local. Ela só fica acessível pela rede se o compartilhamento de pasta pública estiver habilitado nas configurações avançadas de compartilhamento ou se alguém criar um compartilhamento SMB apontando para ela. O risco principal não é acesso remoto à pasta, e sim o uso dela por código que já está rodando no host com privilégios de usuário comum.

## 2. Por que a pasta pública é um problema

Os riscos práticos são:

- Staging de payloads: qualquer processo do usuário consegue gravar um executável, DLL ou script ali sem precisar de elevação, e o caminho é o mesmo em todas as máquinas, o que simplifica scripts de ataque.
- Compartilhamento de artefatos entre contas: como a pasta é comum a todos os perfis do host, um arquivo deixado por um usuário fica visível para outro. Isso pode ser usado para induzir outro usuário (ou um administrador) a executar algo.
- Pouca visibilidade: sem SACL configurada, o Windows não registra quem criou ou alterou arquivos ali. A única fonte de dados acaba sendo telemetria de endpoint (EDR ou Sysmon), quando existe.

Vale deixar claro também o limite do controle. Restringir `C:\Users\Public` não elimina o staging, porque existem outros diretórios graváveis por usuários comuns (`%TEMP%`, `%APPDATA%`, `C:\ProgramData`, subpastas de `C:\Windows` como `Tasks` e `Tracing`). O ganho real está em remover um local óbvio e, principalmente, em transformar tentativas de uso desse local em eventos que o SOC consegue ver. As regras de detecção devem cobrir a classe de diretórios graváveis, não só este.

## 3. Estratégia: auditar antes de restringir

Algumas aplicações legítimas gravam em `C:\Users\Public` (softwares de licenciamento, ferramentas de digitalização que salvam em `Public\Documents`, instaladores que criam atalhos em `Public\Desktop`). Remover a escrita de uma vez pode quebrar essas aplicações sem que ninguém saiba o motivo.

A ordem recomendada é:

1. Levantar a ACL padrão e documentar.
2. Aplicar apenas a auditoria (SACL e política de auditoria) e o AppLocker em modo Audit Only.
3. Coletar eventos por algumas semanas e identificar quem grava e executa legitimamente na pasta.
4. Criar o grupo de exceção com as contas ou computadores necessários.
5. Aplicar a ACL restritiva e passar o AppLocker para Enforce, primeiro em um grupo piloto e depois no restante.

## 4. Restringindo permissões por GPO

### 4.1. Levantando a ACL atual

Antes de qualquer alteração, registre a ACL existente em uma máquina de referência:

```powershell
icacls C:\Users\Public
icacls C:\Users\Public\* 
icacls C:\Users\Public /save C:\Temp\public-acl-baseline.txt /t
```

O `/save` gera um arquivo que pode ser restaurado com `icacls C:\Users /restore C:\Temp\public-acl-baseline.txt` caso seja preciso reverter manualmente. Observe que as subpastas (`Desktop`, `Documents`, `Downloads` etc.) podem ter entradas próprias. O modo de substituição da GPO, descrito abaixo, sobrescreve essas entradas, então é bom ter o registro do que existia.

### 4.2. Grupo de escrita

Crie um grupo de domínio para quem precisa gravar na pasta. Neste artigo ele se chama `GG-PublicFolder-Write`. Se a exceção for de uma aplicação que roda como serviço, inclua a conta do serviço ou a conta de computador, não usuários individuais.

### 4.3. Configurando a ACL na GPO

No Gerenciamento de Política de Grupo, crie uma GPO vinculada à OU das estações de trabalho e navegue até:

`Configuração do Computador > Políticas > Configurações do Windows > Configurações de Segurança > Sistema de Arquivos`

Clique com o botão direito em Sistema de Arquivos, escolha Adicionar Arquivo e informe `%SystemDrive%\Users\Public`. Configure as permissões:

| Principal | Permissão | Aplica-se a |
|---|---|---|
| SYSTEM | Controle total | Esta pasta, subpastas e arquivos |
| Administradores | Controle total | Esta pasta, subpastas e arquivos |
| Usuários Autenticados | Ler e executar | Esta pasta, subpastas e arquivos |
| GG-PublicFolder-Write | Modificar | Esta pasta, subpastas e arquivos |

Desmarque a herança do objeto pai na tela de permissões avançadas, para que a ACL de `C:\Users` não reintroduza permissões de escrita.

Ao confirmar, a GPO pergunta como tratar os objetos filhos. As opções são:

- Configurar esta pasta e propagar as permissões herdáveis para subpastas e arquivos: aplica a ACL e mantém entradas explícitas existentes nos filhos.
- Substituir as permissões existentes em todas as subpastas e arquivos por permissões herdáveis: remove entradas explícitas dos filhos. É a opção indicada aqui, porque garante que nenhum filho mantenha escrita para Usuários.
- Não permitir que as permissões deste arquivo ou pasta sejam substituídas: a GPO não altera a ACL.

Duas observações operacionais. A extensão de segurança da GPO reaplica as configurações periodicamente (por padrão, a cada 16 horas, mesmo sem mudança na GPO), então alterações manuais na ACL serão revertidas no ciclo seguinte. E a opção de substituição percorre toda a árvore a cada aplicação, o que em `C:\Users\Public` costuma ser rápido, mas não deve ser replicado para diretórios grandes.

Para versionamento ou revisão, a configuração fica gravada no `GptTmpl.inf` da GPO, em `\\<domínio>\SYSVOL\<domínio>\Policies\{GUID}\Machine\Microsoft\Windows NT\SecEdit\`, na seção `[File Security]`. O formato é o caminho, o modo (0 = propagar, 1 = não substituir, 2 = substituir) e o descritor em SDDL. Uma linha equivalente à tabela acima seria parecida com:

```ini
[File Security]
"%SystemDrive%\Users\Public",2,"D:PAR(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)(A;OICI;0x1301bf;;;S-1-5-21-...-1105)"
```

`0x1200a9` corresponde a Ler e executar e `0x1301bf` a Modificar. O SID do final é o do grupo de escrita. Prefira configurar pela interface e usar o arquivo apenas para conferência: o GPMC também grava a SACL na mesma linha, e a sintaxe completa é fácil de errar à mão.

### 4.4. Bloqueando execução com AppLocker

Restringir a escrita não impede que um administrador, ou um processo rodando como SYSTEM, deixe um binário na pasta. Bloquear a execução a partir dela cobre esse caso e é o controle de maior valor contra o uso da pasta como staging.

Na mesma GPO (ou em uma GPO de AppLocker já existente):

`Configuração do Computador > Políticas > Configurações do Windows > Configurações de Segurança > Políticas de Controle de Aplicativo > AppLocker`

Pontos importantes sobre o funcionamento do AppLocker:

- Ele funciona por lista de permissões. Quando uma coleção de regras (Executáveis, Scripts, Windows Installer, DLL, Aplicativos Empacotados) tem pelo menos uma regra, tudo o que não for explicitamente permitido nessa coleção é bloqueado. Por isso, antes da regra de negação, gere as regras padrão (clique com o botão direito na coleção > Criar Regras Padrão), que liberam `%PROGRAMFILES%`, `%WINDIR%` e tudo para Administradores.
- Regras de negação têm precedência sobre regras de permissão.
- O serviço Identidade do Aplicativo (`AppIDSvc`) precisa estar em execução. Configure-o como automático pela própria GPO em Serviços do Sistema.
- Verifique se a edição do Windows dos endpoints é suportada pelo AppLocker antes de contar com ele em produção.

Crie, nas coleções de Executáveis e de Scripts, uma regra de Negar para Todos com condição de caminho `%OSDRIVE%\Users\Public\*`. A regra de negação também vale para administradores, o que é desejado neste caso.

Sobre scripts: para `.bat`, `.cmd`, `.vbs` e `.js`, a execução é bloqueada. Para `.ps1`, o comportamento é diferente: com regras de script ativas, o PowerShell passa a rodar scripts não permitidos em Constrained Language Mode, em vez de recusá-los. Isso limita bastante o que um script malicioso consegue fazer, mas não deve ser descrito como bloqueio total.

Comece com a imposição em Somente Auditoria (propriedades do AppLocker > Imposição). Nesse modo nada é bloqueado e os eventos mostram o que teria sido.

Uma alternativa mais moderna é o App Control for Business (antigo WDAC), que tem modelo de confiança mais forte e não depende do `AppIDSvc`. Para o objetivo pontual deste artigo, o AppLocker é mais simples de implantar e testar.

## 5. Auditoria

### 5.1. Política de auditoria avançada

Use a política de auditoria avançada em vez da política legada em Políticas Locais > Política de Auditoria. Misturar as duas causa conflitos de precedência difíceis de diagnosticar.

`Configuração do Computador > Políticas > Configurações do Windows > Configurações de Segurança > Configuração Avançada de Política de Auditoria > Políticas de Auditoria > Acesso a Objetos`

- Auditar Sistema de Arquivos: Sucesso e Falha.
- Auditar Manipulação de Identificador (opcional): Sucesso. Gera o 4658 (fechamento de handle), útil para correlação, mas aumenta bastante o volume. Para o caso de uso deste artigo pode ficar desligado.

Habilite também `Políticas Locais > Opções de Segurança > Auditoria: forçar configurações de subcategoria da política de auditoria (Windows Vista ou posterior) para substituir as configurações de categoria`.

A política de auditoria sozinha não gera nenhum evento de arquivo. Ela só define que o Windows vai registrar os acessos que casarem com alguma SACL. Sem SACL no objeto, nada aparece.

### 5.2. SACL na pasta

A SACL pode ser configurada na mesma entrada de Sistema de Arquivos da GPO (aba Auditoria nas permissões avançadas), o que mantém ACL e SACL no mesmo lugar e sob o mesmo ciclo de reaplicação.

O cuidado principal é volume. Auditar leitura em uma pasta acessada pelo Explorer, por antivírus e por indexação gera milhares de eventos por host sem valor de detecção. Audite somente operações de escrita e de alteração de segurança:

| Principal | Tipo | Permissões auditadas | Aplica-se a |
|---|---|---|---|
| Todos | Sucesso e Falha | Criar arquivos/gravar dados, Criar pastas/acrescentar dados, Gravar atributos estendidos, Excluir subpastas e arquivos, Excluir, Alterar permissões, Apropriar-se | Esta pasta, subpastas e arquivos |

Com isso:

- Uma tentativa de escrita negada por um usuário fora do grupo gera falha.
- Uma escrita bem-sucedida por um membro do grupo gera sucesso, o que serve como inventário de uso legítimo.
- Qualquer alteração de ACL ou de dono na pasta gera evento, o que permite detectar alguém tentando desfazer o controle localmente.

### 5.3. Eventos relevantes

Todos no log Security:

| Evento | Significado | Uso |
|---|---|---|
| 4656 | Um handle para o objeto foi solicitado | Em falha, indica tentativa de acesso negada pela ACL. É o principal evento da fase de restrição. |
| 4663 | Uma tentativa de acesso ao objeto foi feita | Registra o acesso efetivamente exercido. Em sucesso, mostra escrita ou exclusão realizada. |
| 4660 | Um objeto foi excluído | Aparece junto com o 4663 de DELETE. |
| 4670 | As permissões de um objeto foram alteradas | Alteração da DACL na pasta ou em arquivos dela. |
| 4658 | O handle foi fechado | Só com Manipulação de Identificador habilitada. |

Os campos que importam no 4656/4663 são `SubjectUserName`, `ObjectName`, `ProcessName`, `AccessList` e `AccessMask`. Quando o coletor envia os dados sem renderização (comum com Winlogbeat e NXLog), `AccessList` chega como códigos. Os mais úteis aqui:

| Código | Direito |
|---|---|
| %%4416 | ReadData / ListDirectory |
| %%4417 | WriteData / AddFile |
| %%4418 | AppendData / AddSubdirectory |
| %%4420 | WriteEA |
| %%4422 | DeleteChild |
| %%4424 | WriteAttributes |
| %%1537 | DELETE |
| %%1539 | WRITE_DAC |
| %%1540 | WRITE_OWNER |

Em diretórios, `%%4417` (AddFile) é a criação de arquivo dentro da pasta, e `%%4418` (AddSubdirectory) é a criação de subpasta.

O AppLocker registra em `Applications and Services Logs > Microsoft > Windows > AppLocker`:

| Log | Auditoria (teria sido bloqueado) | Bloqueado |
|---|---|---|
| EXE and DLL | 8003 | 8004 |
| MSI and Script | 8006 | 8007 |

Esses canais não fazem parte do log Security, então o coletor precisa ser configurado para incluí-los.

### 5.4. Complemento com Sysmon

A auditoria nativa diz quem tentou gravar e se conseguiu, mas não diz de onde o arquivo veio nem o que aconteceu depois. Se o ambiente tem Sysmon, vale incluir regras específicas para a pasta:

```xml
<RuleGroup name="Public folder" groupRelation="or">
  <FileCreate onmatch="include">
    <TargetFilename condition="begin with">C:\Users\Public\</TargetFilename>
  </FileCreate>
</RuleGroup>
<RuleGroup name="Public folder exec" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="begin with">C:\Users\Public\</Image>
  </ProcessCreate>
</RuleGroup>
```

O EID 11 traz o processo que criou o arquivo (por exemplo, `certutil.exe`, `bitsadmin.exe`, `powershell.exe` ou o navegador), e o EID 1 cobre execução que tenha passado pelo AppLocker, seja por estar em modo de auditoria, seja por usar um tipo de arquivo não coberto pelas coleções configuradas.

## 6. Laboratório

O roteiro abaixo usa um ambiente no estilo GOAD. Ajuste nomes de domínio, hosts e contas ao seu lab.

- Domínio: `north.sevenkingdoms.local`
- DC: `winterfell`
- Host alvo: `castelblack` (pode ser substituído por uma estação Windows 10/11 do domínio)
- Usuário comum: `arya.stark`
- Usuário do grupo de escrita: `samwell.tarly`
- Administrador: `eddard.stark`

### 6.1. Baseline no host alvo

Em `castelblack`, como administrador:

```powershell
New-Item -ItemType Directory C:\Temp -Force | Out-Null
icacls C:\Users\Public | Tee-Object C:\Temp\public-acl-antes.txt
(Get-Acl C:\Users\Public -Audit).Sddl | Out-File C:\Temp\public-sddl-antes.txt
auditpol /get /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}"
```

O GUID corresponde à subcategoria Sistema de Arquivos. Usar o GUID evita o problema de nome localizado (o `auditpol` em português espera "Sistema de Arquivos", em inglês "File System").

Teste o comportamento padrão com `arya.stark`, abrindo uma sessão como ela (`runas /user:north\arya.stark powershell`):

```powershell
Set-Content C:\Users\Public\teste-antes.txt "escrita com usuario comum"
Get-Item C:\Users\Public\teste-antes.txt
```

Se a gravação funcionar, você confirmou o cenário que o artigo trata. Remova o arquivo depois.

### 6.2. Grupo e GPO no DC

Em `winterfell`:

```powershell
Import-Module ActiveDirectory, GroupPolicy

New-ADGroup -Name "GG-PublicFolder-Write" -GroupScope Global -GroupCategory Security `
  -Path "CN=Users,DC=north,DC=sevenkingdoms,DC=local"
Add-ADGroupMember "GG-PublicFolder-Write" -Members samwell.tarly

# OU de teste para o host alvo
New-ADOrganizationalUnit -Name "LAB-PublicFolder" -Path "DC=north,DC=sevenkingdoms,DC=local"
Get-ADComputer castelblack | Move-ADObject -TargetPath "OU=LAB-PublicFolder,DC=north,DC=sevenkingdoms,DC=local"

New-GPO -Name "SEC - Pasta Publica - ACL, Auditoria e AppLocker" |
  New-GPLink -Target "OU=LAB-PublicFolder,DC=north,DC=sevenkingdoms,DC=local"
```

Se `castelblack` tiver papéis do GOAD que dependam da OU onde ele está (GPOs do próprio GOAD, por exemplo), crie a OU nova e vincule a GPO, mas avalie antes de mover. Uma alternativa é vincular a GPO na OU atual e usar filtragem de segurança para aplicá-la só a esse computador.

Edite a GPO pelo GPMC e configure, nesta ordem:

1. Configuração Avançada de Política de Auditoria > Acesso a Objetos > Auditar Sistema de Arquivos: Sucesso e Falha.
2. Opções de Segurança > Auditoria: forçar configurações de subcategoria: Habilitado.
3. Sistema de Arquivos > `%SystemDrive%\Users\Public`: ACL da seção 4.3, SACL da seção 5.2, modo Substituir.
4. Serviços do Sistema > Identidade do Aplicativo: Automático.
5. AppLocker > Regras Executáveis e Regras de Script: regras padrão + regra de Negar para Todos em `%OSDRIVE%\Users\Public\*`. Imposição: Somente Auditoria.

Para validar a primeira fase (auditoria antes de restrição), você pode aplicar primeiro só os itens 1, 2, 4 e 5 e a SACL, deixando a ACL para depois. No lab dá para fazer tudo de uma vez, mas repetir o processo em duas etapas ajuda a enxergar o volume de eventos em cada fase.

### 6.3. Aplicação e verificação

Em `castelblack`:

```powershell
gpupdate /force
gpresult /r /scope computer | Select-String "Pasta Publica"

icacls C:\Users\Public
(Get-Acl C:\Users\Public -Audit).Audit | Format-Table IdentityReference, FileSystemRights, AuditFlags
auditpol /get /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}"
Get-Service AppIDSvc
Get-AppLockerPolicy -Effective -Xml | Select-String "Users\\Public"
```

Confira que Usuários Autenticados aparece com `(RX)`, que o grupo de escrita aparece com `(M)`, que não há entrada de `BUILTIN\Users` ou `INTERACTIVE` com escrita e que a SACL lista Todos com Sucesso e Falha.

Para testar a restrição de ACL, a sessão do usuário comum precisa ser nova, porque o token de uma sessão aberta antes da mudança de grupo não reflete a associação nova. Para o `samwell.tarly`, faça logoff e logon depois de incluí-lo no grupo.

### 6.4. Cenários de teste

Teste 1: usuário comum tenta gravar.

```powershell
# sessão como north\arya.stark
Set-Content C:\Users\Public\teste-arya.txt "deve falhar"
```

Resultado esperado: acesso negado. No log Security, evento 4656 com palavra-chave Falha de Auditoria, `SubjectUserName = arya.stark`, `ObjectName = C:\Users\Public\teste-arya.txt` e `AccessList` contendo `%%4417`.

Teste 2: membro do grupo grava.

```powershell
# sessão como north\samwell.tarly
Set-Content C:\Users\Public\teste-sam.txt "deve funcionar"
Remove-Item C:\Users\Public\teste-sam.txt
```

Resultado esperado: gravação e exclusão funcionam. Eventos 4663 de sucesso com `%%4417` na criação e `%%1537` (DELETE) na exclusão, seguidos de 4660.

Teste 3: simulação de staging e execução.

Como administrador, copie um binário legítimo para a pasta, simulando o que um dropper faria:

```powershell
Copy-Item C:\Windows\System32\whoami.exe C:\Users\Public\update.exe
Set-Content C:\Users\Public\run.bat "C:\Users\Public\update.exe /all > C:\Users\Public\out.txt"
```

Depois, como `arya.stark`:

```powershell
C:\Users\Public\update.exe
cmd /c C:\Users\Public\run.bat
```

Com o AppLocker em Somente Auditoria, os comandos executam e você deve ver 8003 (EXE) e 8006 (script) nos logs do AppLocker. O `run.bat` ainda tenta gravar `out.txt`, o que gera um 4656 de falha para a `arya.stark`, mostrando no mesmo teste a ACL e o AppLocker atuando. Mude a imposição para Impor Regras, rode `gpupdate /force` e repita: a execução deve ser recusada e os eventos passam a ser 8004 e 8007.

Se o Sysmon estiver instalado, compare com os EID 11 da cópia e os EID 1 da execução no modo de auditoria.

Teste 4: tentativa de desfazer o controle.

Como administrador:

```powershell
icacls C:\Users\Public /grant "BUILTIN\Users:(OI)(CI)M"
```

Resultado esperado: evento 4670 em `C:\Users\Public` com o processo `icacls.exe`. Rode `gpupdate /force` (ou aguarde o ciclo de reaplicação) e confira com `icacls` que a ACL voltou ao estado definido na GPO. Na prática, para forçar a reaplicação da extensão de segurança mesmo sem mudança na GPO, use `gpupdate /force`; a reaplicação automática segue o intervalo da política de processamento de segurança.

Teste 5: variação com LOLBin.

Para gerar um evento mais próximo de um ataque real sem tráfego externo, suba um servidor HTTP em outra VM do lab (por exemplo, `python -m http.server 8080` em uma máquina Linux da rede 192.168.56.0/24) e, como `arya.stark`:

```powershell
certutil -urlcache -split -f http://192.168.56.X:8080/arquivo.txt C:\Users\Public\arquivo.txt
```

A gravação deve falhar com 4656 de falha tendo `ProcessName = C:\Windows\System32\certutil.exe`. Essa combinação de processo e destino já é, por si só, um bom candidato a alerta.

### 6.5. Consultas no Graylog

Os nomes de campos dependem do coletor e do pipeline (Sidecar com Winlogbeat, NXLog, GELF). Os exemplos abaixo usam os nomes do Winlogbeat achatados pelo Graylog. Ajuste para o seu mapeamento.

Tentativas de escrita negadas:

```
winlogbeat_winlog_event_id:4656 AND winlogbeat_winlog_keywords:"Audit Failure" AND winlogbeat_winlog_event_data_ObjectName:C\:\\Users\\Public\\*
```

Escritas bem-sucedidas, para inventário de uso legítimo na fase de auditoria:

```
winlogbeat_winlog_event_id:4663 AND winlogbeat_winlog_event_data_ObjectName:C\:\\Users\\Public\\* AND winlogbeat_winlog_event_data_AccessList:*4417*
```

Alteração de ACL na pasta:

```
winlogbeat_winlog_event_id:4670 AND winlogbeat_winlog_event_data_ObjectName:C\:\\Users\\Public*
```

Execução bloqueada ou que seria bloqueada:

```
winlogbeat_winlog_event_id:(8003 OR 8004 OR 8006 OR 8007) AND winlogbeat_winlog_provider_name:"Microsoft-Windows-AppLocker"
```

Sugestões de alerta a partir disso:

- 4656 de falha em `C:\Users\Public` com `ProcessName` em uma lista de LOLBins (`certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`).
- 4663 de sucesso com `%%4417` por uma conta que não pertence ao grupo de escrita. Isso não deveria acontecer e indica que a ACL foi alterada ou que a GPO não está aplicada naquele host.
- Qualquer 4670 na pasta fora de janela de mudança.
- 8004 ou 8007 com caminho em `C:\Users\Public`, que em ambiente com a restrição já aplicada tem baixa chance de ser legítimo.

Na fase de auditoria, o volume de 4656 de falha é o melhor indicador de quanto o ambiente depende da pasta. Agrupe por `ProcessName` e `SubjectUserName` antes de decidir quem entra no grupo de exceção.

## 7. Considerações operacionais

- Escopo: aplique a GPO em OUs de estações e use grupo piloto. Servidores de aplicação e servidores de Terminal Services merecem avaliação separada, porque é onde aplicações legadas mais usam a pasta.
- Contas de serviço: se uma aplicação legítima precisar gravar, prefira incluir a conta do serviço ou a conta de computador no grupo em vez de reabrir a escrita para Usuários.
- Controle sobre a GPO: restrinja quem pode editar essa GPO e audite alterações nela (eventos 5136 no DC, com auditoria de Alterações no Serviço de Diretório habilitada). Uma GPO de segurança que qualquer administrador de helpdesk pode editar é um ponto fraco.
- Retenção de log: SACL de escrita em uma pasta pouco usada gera volume baixo, mas confira o tamanho máximo do log Security e o encaminhamento para o SIEM antes de ampliar o escopo da auditoria.
- Revisão periódica: compare a ACL efetiva dos hosts com a definida na GPO. O alerta de 4663 por conta fora do grupo já cobre boa parte disso de forma contínua.

## 8. Conclusão

Restringir a escrita em `C:\Users\Public` por GPO é simples e reduz um local de staging muito usado, mas o valor maior vem da combinação com AppLocker e auditoria. A ACL impede o uso casual da pasta, o AppLocker impede a execução mesmo quando algo privilegiado grava ali, e a SACL transforma cada tentativa em um evento com usuário, processo e caminho, que pode ser usado diretamente em regras de detecção. Fazer a implantação em fases, começando pela auditoria, evita quebrar aplicações e ainda gera um inventário de uso que serve de base para as exceções.

## Referências

- Microsoft Learn: Audit File System (subcategoria de auditoria avançada).
- Microsoft Learn: eventos 4656, 4663, 4660 e 4670.
- Microsoft Learn: AppLocker overview e Understanding AppLocker rule behavior.
- Microsoft Learn: Security policy settings / Security Templates (formato do `GptTmpl.inf`).
- MITRE ATT&CK: T1074.001 Local Data Staging, T1105 Ingress Tool Transfer.
- CIS Benchmarks para Microsoft Windows 10/11 Enterprise.

---
<!-- begin wwww.htmlcommentbox.com -->
  <div id="HCB_comment_box"><a href="http://www.htmlcommentbox.com">Widget</a> is loading comments...</div>
 <link rel="stylesheet" type="text/css" href="https://www.htmlcommentbox.com/static/skins/bootstrap/twitter-bootstrap.css?v=0" />
<!-- end www.htmlcommentbox.com -->