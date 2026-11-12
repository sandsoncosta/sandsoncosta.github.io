---
title: "Hardening de LDAP no Active Directory"
url: "/blog/hardening-de-ldap-no-active-directory"
date: 2026-11-10T12:00:00-03:00
draft: false
description: "Como hardenizar o LDAP em um controlador de domínio: signing, channel binding e assinatura no cliente, aplicados por GPO, com auditoria antes do bloqueio e validação do antes/depois no laboratório."
noindex: false
featured: false
pinned: false
comments: true
series:
 - "Auditorias do Windows"
categories:
 - Hardening
tags:
 - LDAP
 - Active Directory
 - Hardening
 - GPO
images:
authors:
 - Sandson
---
## 1. Contexto

Toda conexão LDAP a um controlador de domínio começa com um bind, que pode ser anônimo (sem credencial), simple (DN e senha) ou SASL (NTLM, Kerberos, Digest). O risco não está em "ser LDAP", e sim em como a credencial trafega e se o canal tem integridade. Um _simple bind_ sobre a porta 389 envia a senha em texto claro. Um bind SASL sem assinatura deixa a sessão sem integridade e aberta a relay. É esse o risco que o Windows sinaliza no Event ID 2889, e é por padrão que os controladores aceitam esses binds inseguros.

Tentar detectar "bind anônimo LDAP" no SIEM quase nunca funciona. O 2889 não é anônimo, ele registra bind com credencial sem assinatura (Binding Type 0 ou 1), com a identidade preenchida. O `ANONYMOUS LOGON` que aparece nele está no campo de conta do registro (SID `S-1-5-7`), que é o contexto de gravação do evento, não a identidade do bind. Um bind 100% anônimo não gera 2889 nenhum, e a enumeração anônima o próprio DC já bloqueia por padrão.

Detecção, portanto, não resolve a raiz. O que muda a postura é hardening: fechar o bind inseguro. Para os conceitos de sessão, acesso e enumeração por trás disso, há um artigo complementar.

{{< leia-tambem "blog/86.gpo.anonymous.logon">}}

As políticas e seus valores:

| Política | Valor | Registro |
|---|---|---|
| Domain controller: LDAP server signing requirements | Require signing | `LdapServerIntegrity = 2` |
| Domain controller: LDAP server channel binding token requirements | Always (ou When supported) | `LdapEnforceChannelBinding = 2` (ou `1`) |
| Network security: LDAP client signing requirements | Require signing | `LDAPClientIntegrity = 2` |
| dsHeuristics (operação anônima no diretório) | padrão (anônimo só no rootDSE) | atributo forest-wide |

Cada uma governa um canal diferente, e nenhuma resolve tudo sozinha. O signing exige integridade no bind e cobre a porta 389. O _channel binding_ amarra o bind ao canal TLS e cobre a 636/3269. O _client signing_ garante que as próprias máquinas do domínio negociem assinatura. O `dsHeuristics` controla se o anônimo pode operar além do rootDSE. Signing e channel binding precisam ser aplicados **juntos**, um sem o outro deixa caminho de relay, porque binds SASL sobre TLS usam a segurança do TLS, não a do LDAP signing.

A base oficial é o ADV190023 (Ver referências), que trata justamente dos defaults inseguros de signing e channel binding nos controladores.

## 2. Pré-requisito: certificado e LDAPS

O channel binding só tem efeito sobre binds em TLS (porta 636/3269). Sem um certificado válido no controlador de domínio, não há LDAPS, os clientes não têm como sair do texto claro, e o channel binding não tem o que proteger. Então, antes de enforçar, garanta que o DC tem um certificado adequado (emitido por uma CA confiável no ambiente, com o FQDN do DC) e que o LDAPS responde na 636.

## 3. Configurar via GPO

### 3.1 Criar e vincular a GPO

1. Abra o Group Policy Management (`gpmc.msc`).
2. Na OU **Domain Controllers**, escolha **Create a GPO in this domain, and Link it here**, com um nome descritivo, por exemplo `AUD-SRC-HardeningLDAP`.
3. As políticas de servidor (signing e channel binding) vão nessa GPO, na OU Domain Controllers. A de cliente (`LDAP client signing requirements`) deve ser vinculada à OU das estações e servidores membros.
4. Clique com o botão direito na GPO e escolha **Edit**.

### 3.2 Aplicar as opções de segurança

No editor, navegue até:

```
Computer Configuration
  > Policies
    > Windows Settings
      > Security Settings
        > Local Policies
          > Security Options
```

Defina as três políticas da tabela da seção 1: `LDAP server signing requirements` = Require signing, `LDAP server channel binding token requirements` = Always (ou When supported, se ainda houver clientes incompatíveis), e, na GPO dos clientes, `LDAP client signing requirements` = Require signing.

Esse nó, **Security Options** (Opções de Segurança), reúne as configurações de segurança nomeadas do Windows, agrupadas por categoria (Domain controller, Network access, Network security…). Cada política mapeia para um valor de registro ou configuração do sistema. As três políticas de LDAP acima são Security Options.

### 3.3 Confirme qual GPO está prevalecendo

É comum a `Default Domain Controllers Policy` já trazer o signing em "None" e, por precedência, sobrescrever a GPO de hardening vinculada mais abaixo. O valor efetivamente aplicado se confere na base de segurança:

```powershell
secedit /export /cfg C:\secpol.cfg /quiet
Select-String -Path C:\secpol.cfg -Pattern "LDAPServerIntegrity"   # =4,2 é Require; =4,1 é None
```

E a GPO que prevalece de cada Security Option aparece no relatório HTML:

```powershell
gpresult /h C:\gp.html /f
```

Abra o HTML em Security Options e olhe a coluna **Winning GPO**. Se quem prevalece for a `Default Domain Controllers Policy` em "None", ou você ajusta o valor nela, ou marca o link da sua GPO de hardening como **Enforced** para passar na frente.

{{< bs/alert danger >}}
{{< bs/alert-heading "Atenção!" >}}
Mexer na <strong>Default Domain Controllers Policy</strong> não é a prática recomendada. Prefira a GPO dedicada com Enforced.
{{< /bs/alert >}}



### 3.4 Aplicar e propagar

```powershell
gpupdate /force
```

O valor de signing é lido pelo serviço de diretório. Para o LDAP server passar a enforçar de fato, reinicie o serviço (ou o DC):

```powershell
Restart-Service NTDS -Force
```

## 4. Alternativa local (laboratório ou host isolado)

Sem domínio, ou no lab, dá para setar direto no registro. Lembre que, em domínio, a GPO sobrescreve isso na próxima atualização de diretiva.

```powershell
$p = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
Set-ItemProperty -Path $p -Name "LdapServerIntegrity"       -Value 2 -Type DWord
Set-ItemProperty -Path $p -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord

# signing no cliente (hive diferente)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" -Name "LDAPClientIntegrity" -Value 2 -Type DWord

Restart-Service NTDS -Force
```

Para o lado anônimo do diretório, confirme o `dsHeuristics`:

```powershell
Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" -Properties dSHeuristics |
  Select-Object -ExpandProperty dSHeuristics
```

Vazio ou 7º caractere diferente de `2` significa anônimo restrito ao rootDSE, que é o padrão seguro. _Forest-wide_ aqui significa que o valor é único para toda a floresta: o `dsHeuristics` fica no objeto Directory Service da partição de Configuração, replicada a todos os DCs de todos os domínios, e passa a valer sem reinicialização assim que replica. Por isso não é uma Security Option (que é por GPO) nem uma chave de registro local, é um ajuste de escopo de floresta. O detalhe das políticas de acesso anônimo (SAM, shares, named pipes) está no artigo abaixo.

{{< leia-tambem "blog/12.anonymous.logon">}}

## 5. Cuidado: auditar antes de impor

Esta é a parte que pode quebrar algo legítimo. Forçar signing rejeita qualquer cliente que ainda faça simple bind sem TLS ou bind SASL sem assinatura: aparelhos, apps legados, integrações e scanners costumam fazer isso. Levante quem seria bloqueado **antes** de enforçar.

Habilite o diagnóstico que registra cada bind inseguro, por cliente:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "16 LDAP Interface Events" -Value 2 -Type DWord
```

Com isso, o DC gera 2889 com IP e identidade de cada cliente fazendo bind unsigned. Deixe rodando, mapeie as origens, corrija ou isole, e só então aplique o Require.

## 6. Validação

Com o DC ainda em `LdapServerIntegrity = 1`, gere os dois tipos de bind inseguro a partir de um host na rede (no exemplo, o laboratório GOAD contra o DC `kingslanding` em `192.168.56.10`):

```bash
# Binding Type 1 - simple bind cleartext com credencial
ldapsearch -x -H ldap://192.168.56.10:389 \
  -D "stannis.baratheon@sevenkingdoms.local" -w "Drag0nst0ne" \
  -b "DC=sevenkingdoms,DC=local" -s base "(objectClass=*)" defaultNamingContext

# Binding Type 0 - SASL/NTLM sem assinatura
python3 -c '
from ldap3 import Server, Connection, NTLM
s = Server("192.168.56.10", port=389)
c = Connection(s, user="SEVENKINGDOMS\\stannis.baratheon", password="Drag0nst0ne", authentication=NTLM)
print("bind:", c.bind(), c.result); c.unbind()'
```

No DC, os dois aparecem com a identidade real e o Binding Type correspondente:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Directory Service';Id=2889;StartTime=(Get-Date).AddMinutes(-10)} |
  ForEach-Object {
    $m=$_.Message
    [pscustomobject]@{
      Identity = ([regex]::Match($m,'authenticate as:\s*([^\r\n]+)')).Groups[1].Value.Trim()
      Binding  = ([regex]::Match($m,'Binding Type:\s*(\d+)')).Groups[1].Value
    }
  } | Format-Table -AutoSize
```

Aplique o Require signing, confirme o `=4,2` no secpol e reinicie o serviço. Refaça os dois binds: com signing exigido, ambos passam a ser rejeitados com `strongerAuthRequired (8)`: _"the server requires binds to turn on integrity checking if SSL/TLS are not already active"_. Essa recusa no lado do cliente é a evidência direta de que o hardening funcionou. Não é preciso nenhum evento no DC para confirmar.

No DC, o comportamento dos eventos merece cuidado. O **2889** continua sendo gerado: ele registra que um cliente _tentou_ um bind unsigned/cleartext e identifica a origem, mas não prova que o bind foi aceito, por isso aparece tanto antes quanto depois do hardening. O que muda é o resultado do bind, de aceito para rejeitado. A contagem de binds rejeitados vai para o **2888**, que é um sumário periódico (a cada ~24h), não um evento imediato. Por isso você não o vê logo após o teste. Para o antes/depois instantâneo, fique com o resultado do próprio bind: sucesso antes, `strongerAuthRequired` depois.

**Um ponto que vale fixar:** Require signing não bloqueia o LDAP, bloqueia o LDAP **inseguro**. A mesma conta binda normalmente se assinar o bind ou usar TLS. Por exemplo, o mesmo simple bind sobre LDAPS (636) volta a funcionar, porque o canal já está protegido por TLS. O que o controle fecha é o que depende de bind unsigned/cleartext: captura de credencial em texto claro e, principalmente, NTLM relay. Enumeração autenticada continua possível para quem tem credencial, e é aí que a detecção entra.

Para checar a postura dos dois controles numa linha, o `netexec` (nxc) é prático: mostra signing, channel binding, o resultado do bind e a enumeração de uma vez.

```bash
nxc ldap 192.168.56.10 -u stannis.baratheon -p Drag0nst0ne --users
```

Com o hardening completo, a saída traz `(signing:Enforced) (channel binding:Always)`, o bind autenticado e a linha `Enumerated 28 domain users`. Os dois primeiros campos confirmam as chaves (`LdapServerIntegrity = 2`, `LdapEnforceChannelBinding = 2`). O bind e os usuários confirmam que o LDAP segue funcionando para quem tem credencial e assina. A enumeração autenticada que o hardening não impede.

O nxc também deixa explícito o vínculo com o LDAPS: o channel binding só aparece como `Always` porque o DC tem LDAPS na 636 com certificado. Sem LDAPS, ele fica em `Never` mesmo com a chave setada, já que não há canal TLS a que amarrar o bind. Por isso o certificado da seção 2 é pré-requisito do channel binding, não um opcional.

## 7. O que o hardening não bloqueia: o rootDSE

Vale deixar explícito um limite do signing, porque confunde. Mesmo com `LdapServerIntegrity = 2`, uma consulta anônima ao rootDSE continua respondendo:

```bash
ldapsearch -x -H ldap://192.168.56.10:389  -s base -b ""
ldapsearch -x -H ldap://192.168.56.10:3268 -s base -b ""   # idem no Global Catalog
```

Isso é por design, não é falha do hardening. O rootDSE é sempre legível anonimamente, e o LDAP signing trata da integridade do bind, não da autorização de leitura do rootDSE. O que esse acesso devolve são metadados de descoberta do serviço: naming contexts, mecanismos SASL suportados, níveis funcionais, hostname do DC. E não objetos do diretório. Consultar o rootDSE anonimamente não enumera usuário, grupo nem computador. A enumeração o DC já nega por padrão, como detalhado no artigo de Anonymous Logon.

Como não é bind inseguro, essa consulta também não gera 2889. Não há evento nativo confiável para "alertar sobre leitura anônima do rootDSE", é metadado de baixo valor ofensivo. Se ainda assim você quiser impedir esse acesso, isso é controle de **rede** (segmentar e restringir 389/636/3268/3269 às origens confiáveis), não uma configuração de LDAP ou de signing.

## 8. Detecção complementar

Dois pré-requisitos valem lembrar, porque costumam faltar: os eventos 2889 e 1644 vivem no canal **Directory Service**. Coletar só o Security deixa a detecção LDAP cega. O 1644 (reconhecimento LDAP, o caso real de ferramentas como BloodHound) permite identificar esse recon, mas a um custo alto: só existe habilitando o diagnóstico de busca (`15 Field Engineering = 5`) e calibrando os três thresholds que definem o que é registrado: `Expensive Search Results Threshold`, `Inefficient Search Results Threshold` e `Search Time Threshold (msecs)`, e um DC gera um volume enorme de consultas LDAP legítimas. Sem thresholds bem calibrados e baseline das service accounts, ele inunda o log Directory Service e a ingestão no SIEM, o que o torna quase improdutivo em produção.

É uma configuração volumosa, que exige tuning e auditoria antes — não é algo que se liga e esquece. Para o bind em si, incluindo o mecanismo, a visibilidade está na telemetria de rede ou em uma solução de identidade como o **Microsoft Defender for Identity**, que inspeciona o LDAP direto no controlador. O 2889, uma vez coletado, serve bem como detecção de bind inseguro, que é justamente o que este hardening elimina.

Uma vez que o hardening está no lugar: signing e channel binding exigidos, anônimo limitado ao rootDSE, a detecção de "bind anônimo" perde o objeto. O risco foi eliminado na origem, não apenas alertado. Para esse caso de uso específico, não é preciso coleta do canal Directory Service só para sustentar um alerta que nunca terá o que detectar.

O canal segue valendo por outra razão: o 1644, de reconhecimento LDAP **autenticado**, que o hardening não impede, e o 2888, dos binds inseguros rejeitados após o enforce. Ou seja, colete o Directory Service se quiser detectar recon autenticado, não precisa coletá-lo apenas por "bind anônimo", porque aí o hardening já resolveu.

## 9. Conclusão

Endurecer o LDAP é mais eficaz do que tentar detectá-lo: o bind anônimo não gera evento, a enumeração anônima o DC já bloqueia, e o bind inseguro é um problema de configuração, não de alerta. Exija signing e channel binding juntos, inclua a assinatura no cliente, garanta o certificado para LDAPS, e aplique tudo em modo auditoria antes do bloqueio, usando o 2889 para encontrar quem ainda faz bind inseguro. Confirme a diretiva efetiva no host, valide que o bind unsigned passou a ser rejeitado, e deixe a detecção complementar para o recon autenticado a cargo do **Microsoft Defender for Identity**, não como substituta do hardening.

## 10. Referências

- [ADV190023 — Microsoft Guidance for Enabling LDAP Channel Binding and LDAP Signing](https://msrc.microsoft.com/en-us/security-guidance/advisory/ADV190023) — Fonte: Microsoft MSRC, orientação oficial de signing e channel binding (KB4520412, FAQ KB4546509).
- [Microsoft Defender for Identity architecture](https://learn.microsoft.com/en-us/defender-for-identity/architecture) — Fonte: Microsoft Learn, como o sensor inspeciona tráfego e eventos LDAP no controlador.
- [Reconnaissance and discovery alerts (MDI)](https://learn.microsoft.com/en-us/defender-for-identity/reconnaissance-discovery-alerts) — Fonte: Microsoft Learn, detecções de reconhecimento LDAP (ex.: Security principal reconnaissance, ID 2038).
- [Security Options](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/security-options) — Fonte: Microsoft Learn, o nó Local Policies > Security Options e as categorias de políticas que ele agrupa.
- [Anonymous LDAP operations to Active Directory are disabled on domain controllers (KB326690)](https://support.microsoft.com/kb/326690) — Fonte: Microsoft Support, o dsHeuristics como ajuste forest-wide (7º caractere) e o padrão que restringe o anônimo ao rootDSE.
- [Configure LDAP signing by using Group Policy for Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy?tabs=windows-server-2025) — Fonte: Microsoft Learn, gerenciando o LDAP signing por GPO.

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}