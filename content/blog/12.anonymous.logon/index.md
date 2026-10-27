---
title: "Anonymous Logon no Windows: separando sessão, acesso e enumeração"
date: 2026-10-27T02:16:13-03:00
draft: false
description: "O que é o ANONYMOUS LOGON, por que não é incidente por si só, e como separar sessão, acesso e enumeração no Active Directory — com demonstração no GOAD, baseline e hardening."
noindex: false
featured: false
pinned: false
comments: true
series:
  - "SMB no Active Directory: ataque e detecção"
categories:
  - Detection Engineering
tags:
  - Active Directory
  - SMB
  - Hardening
images: []
authors:
  - sandson
---

## 1. Introdução

O termo **ANONYMOUS LOGON** aparece com frequência em investigações de segurança do Windows e, não raramente, é tratado como sinônimo de invasão ou de uma configuração insegura do SMB. Nenhuma dessas interpretações é necessariamente correta.

O Windows possui uma identidade especial chamada **ANONYMOUS LOGON**, identificada pelo SID `S-1-5-7`. Ela representa um contexto de acesso sem uma identidade de usuário autenticada. A existência desse principal é normal. O risco depende dos recursos e operações que esse contexto consegue acessar.

Um exemplo clássico é a **null session**: uma sessão SMB sem credenciais de usuário, frequentemente associada ao compartilhamento `IPC$`, utilizado para comunicação entre processos e acesso a interfaces RPC. Dependendo das configurações do servidor, essas interfaces podem expor informações sobre contas, grupos e políticas do domínio.

Neste artigo, vamos distinguir conexão de autorização, demonstrar comportamentos diferentes em dois controladores de domínio do laboratório GOAD e mapear quais eventos nativos do Windows registram o acesso anônimo. O ponto central é evitar uma conclusão precipitada: **acesso anônimo ao `IPC$` ou ao pipe `samr` não comprova, sozinho, enumeração de contas**.

Vale situar este episódio dentro da série. O acesso anônimo é o caso mais fácil de fechar por configuração e o mais ruidoso de monitorar: procurar `ANONYMOUS LOGON` de forma genérica é agulha no palheiro, porque o volume é alto e quase todo benigno. Por isso o papel deste texto é desmistificação, baseline e hardening, não uma regra de alerta. A detecção de maior valor vem nos episódios seguintes, enumeração autenticada e coerção com NTLM relay, onde o sinal tem forma e não só volume.

## 2. O que é ANONYMOUS LOGON?

No Windows, um *security principal* é uma entidade identificável por um SID, utilizado no controle de acesso. Contas, grupos e identidades especiais participam desse modelo. O `ANONYMOUS LOGON` é uma dessas identidades especiais e possui o SID bem conhecido `S-1-5-7`.

É importante separar alguns conceitos:

- **`S-1-5-7` não é um protocolo de autenticação:** É o identificador do contexto anônimo. Não concede privilégios por si só.
- **`ANONYMOUS LOGON` e `Everyone` não são equivalentes:** O tratamento do acesso anônimo nas permissões de `Everyone` depende da configuração de segurança do Windows. A política *Network access: Let Everyone permissions apply to anonymous users* normalmente permanece desabilitada.
- **Acesso anônimo no IIS é outra situação:** Uma aplicação web pode usar uma identidade configurada, como `IUSR`, sem que isso represente uma null session SMB.
- **O grupo `Pre-Windows 2000 Compatible Access` merece atenção:** Sua composição e as permissões que recebe podem ampliar a leitura de informações do diretório, mas sua presença não garante, isoladamente, que chamadas anônimas ao SAMR sejam autorizadas.

Assim, observar `ANONYMOUS LOGON` no evento 4624 significa que o Windows registrou uma sessão com essa identidade. **Não significa que houve acesso indevido ou que a enumeração tenha sido bem-sucedida.**

## 3. Null session, IPC$ e RPC: o que pode ser exposto?

O compartilhamento administrativo `IPC$` é utilizado para comunicação entre processos. Em cenários SMB/RPC, o cliente pode acessar *named pipes* que transportam chamadas a diferentes interfaces.

Entre as interfaces relevantes para reconhecimento estão:

| Interface | Pipe comum | Exemplos de operações |
|---|---|---|
| SAMR (*Security Account Manager Remote Protocol*) | `samr` | Consultar contas, grupos e informações do domínio |
| LSARPC (*Local Security Authority RPC*) | `lsarpc` | Consultar informações de política e resolver nomes/SIDs, conforme permissões |
| Netlogon | `netlogon` | Operações legítimas de autenticação e relacionamento com o domínio |

Quando uma configuração permite consultas anônimas, um agente pode obter nomes de usuários, RIDs, informações de grupos ou descrições de contas. Essas informações podem facilitar reconhecimento e tentativas posteriores de acesso, como *password spraying*.

Por outro lado, **uma null session não fornece automaticamente hashes, execução remota nem acesso a todos os compartilhamentos**. Cada recurso possui verificações de autorização próprias.

Também não se deve confundir null session com **MS17-010/EternalBlue**. Trata-se de uma vulnerabilidade do SMBv1 corrigida por atualizações de segurança. A possibilidade de exploração sem credenciais e a permissão para enumeração anônima são questões distintas.

## 4. Demonstração no laboratório GOAD

Os testes foram realizados no **Game of Active Directory (GOAD)**, laboratório criado para simular configurações vulneráveis e cenários de segurança em ambientes Windows.

| Controlador de domínio | Endereço IP | Domínio do laboratório |
|---|---|---|
| `kingslanding` | `192.168.56.10` | `sevenkingdoms` |
| `winterfell` | `192.168.56.11` | `north` |

Os resultados abaixo descrevem **o estado observado durante os testes**. Não foi feita, neste artigo, uma comparação completa das GPOs e permissões efetivas para identificar a causa exata das diferenças entre os controladores.

### 4.1. Sessão anônima SMB

No Kali Linux, a tentativa de listar compartilhamentos foi realizada com:

```bash
smbclient -L //192.168.56.10 -N
```

A ferramenta apresentou:

```text
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.56.10 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

A mensagem `Anonymous login successful` indica que a etapa de sessão anônima foi aceita. Contudo, **nenhum compartilhamento foi retornado na listagem apresentada**.

A tentativa posterior de listagem legada de *workgroups* falhou. Esse erro **não demonstra, isoladamente, que o SMBv1 esteja desabilitado**. Para confirmar isso, é necessário verificar a configuração do servidor ou a negociação do protocolo.

A conexão ao `IPC$`, mesmo quando aceita, não implica autorização para executar consultas SAMR ou LSARPC.

### 4.2. Enumeração via SAMR: comportamentos diferentes

O `rpcclient`, integrante do conjunto Samba, permite testar chamadas RPC. A operação `enumdomusers` consulta contas por meio do protocolo SAMR.

No `kingslanding`, o teste retornou acesso negado:

```text
$ rpcclient -U "" -N 192.168.56.10
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

No `winterfell`, a mesma operação retornou usuários e RIDs:

```text
$ rpcclient -U "" -N 192.168.56.11
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[arya.stark] rid:[0x456]
user:[sansa.stark] rid:[0x45a]
user:[brandon.stark] rid:[0x45b]
user:[rickon.stark] rid:[0x45c]
user:[hodor] rid:[0x45d]
user:[jon.snow] rid:[0x45e]
user:[samwell.tarly] rid:[0x45f]
user:[jeor.mormont] rid:[0x460]
user:[sql_svc] rid:[0x461]
user:[sshd] rid:[0xa2a]
```

Esse contraste demonstra que a **sessão anônima e a autorização para enumerar contas são decisões distintas**.

A consulta `querydispinfo` retornou informações adicionais, incluindo as descrições das contas:

```text
rpcclient $> querydispinfo
index: 0x189d RID: 0x456 acb: 0x00000210 Account: arya.stark    Desc: Arya Stark
index: 0x18ab RID: 0x45d acb: 0x00000210 Account: hodor         Desc: Brainless Giant
index: 0x18af RID: 0x45f acb: 0x00000210 Account: samwell.tarly Desc: Samwell Tarly (Password : Heartsbane)
```

A descrição de `samwell.tarly` contém uma senha em texto claro — um dado inserido propositalmente no laboratório. O exemplo ilustra um risco real: **campos descritivos de contas não devem armazenar credenciais**, pois podem ser consultados por identidades que tenham permissão de leitura.

Com um RID específico, o `queryuser` detalha uma conta, por exemplo `queryuser 0x456` para a `arya.stark`, trazendo data da última troca de senha, flags da conta e contadores de logon.

### 4.3. LSARPC e resolução de SIDs

O SAMR não é a única interface que pode expor informações sobre identidades. O LSARPC permite, entre outras operações, consultas e tradução entre SIDs e nomes, dependendo da autorização.

No `winterfell`, a consulta de informações do domínio retornou:

```text
rpcclient $> lsaquery
Domain Name: NORTH
Domain Sid: S-1-5-21-1847776851-1272285915-1110307894
```

Entretanto, a tentativa de resolver um SID específico falhou:

```text
rpcclient $> lookupsids S-1-5-21-1847776851-1272285915-1110307894-500
result was NT_STATUS_ACCESS_DENIED
```

O RID `500` é associado à conta administrativa interna do domínio. A tentativa mostrada consulta **um único SID**. O termo **RID cycling** descreve a técnica de testar sequencialmente diferentes RIDs para identificar quais correspondem a contas ou grupos existentes.

O resultado observado indica que, neste teste, a operação de tradução de SID foi negada. Não se deve concluir que todas as operações LSARPC estejam bloqueadas: a própria consulta `lsaquery` retornou informações.

## 5. O que os logs nativos registram

Ao investigar uma conexão anônima, é preciso separar três níveis de evidência:

1. **Sessão anônima estabelecida:** o Windows registrou uma sessão de rede sem identidade de usuário autenticada.
2. **Acesso a recurso SMB/RPC:** houve acesso a um compartilhamento ou verificação de acesso a um *named pipe*.
3. **Enumeração de identidades:** foram observadas consultas a contas, grupos ou objetos do diretório com evidência suficiente para sustentar essa interpretação.

Os dois primeiros níveis não comprovam automaticamente o terceiro, e a auditoria nativa raramente fecha o terceiro.

### 5.1. Eventos relevantes

| Event ID | Canal | O que ajuda a observar | Limitação |
|---|---|---|---|
| **4624** | Security | Logon de rede, inclusive `ANONYMOUS LOGON` com `LogonType=3` | Não informa quais operações RPC foram executadas |
| **5140** | Security | Acesso a compartilhamentos, como `IPC$` | Não identifica enumeração |
| **5145** | Security | Verificação de acesso a arquivos e *named pipes*, como `samr` e `lsarpc` | Não revela o método RPC invocado |
| **4661** | Security | Solicitação de acesso a objetos SAM, quando auditada | Pode não ser gerado para cada consulta; não comprova sucesso da enumeração |

A geração dos eventos depende da configuração de auditoria, da versão do Windows e das operações realizadas. Em especial, o **5145 exige a subcategoria de auditoria `Detailed File Share`**, e o **4661 depende da auditoria aplicável a objetos SAM**.

No evento 4624, prefira o SID `S-1-5-7` ao nome localizado da identidade: o campo `TargetUserSid` identifica o contexto anônimo de forma estável. E eventos 4624 anônimos podem trazer a informação `NTLM V1`, que não é prova de autenticação NTLMv1 real. A Microsoft orienta ignorar a versão de NTLM quando a identidade é `ANONYMOUS LOGON`.

### 5.2. Os eventos mostram o acesso, não o método

Em um evento **5145**, o campo `RelativeTargetName` pode apresentar `samr`, indicando verificação de acesso ao pipe SAMR por SMB. Isso ocorre tanto em laboratório quanto em produção, inclusive por aplicações legítimas.

O ponto a fixar: **`samr` no 5145 não equivale a `enumdomusers`**. O evento registra que o pipe foi acessado, não qual chamada RPC foi executada, e o `AccessMask` também não distingue enumeração ofensiva de acesso legítimo. Pela mesma razão, o pipe `netlogon` não serve como indicador isolado de enumeração: ele participa de operações normais e frequentes do domínio.

É essa limitação que define o valor defensivo deste episódio. Os eventos contextualizam uma conexão anônima durante uma investigação, mas não provam enumeração. O ganho prático está em conhecer o que é normal no ambiente — quais origens falam anônimo com os controladores de domínio — e em endurecer a configuração, não em alertar sobre cada ocorrência.

## 6. Hardening: políticas a revisar

Versões modernas do Windows já restringem boa parte da enumeração anônima por padrão, mas os controles são vários e independentes: não existe um único botão que explique todo o comportamento entre SAMR, LSARPC e SMB, e os padrões efetivos variam conforme a versão e a função do servidor. As políticas de **Network access** ficam, em geral, em:

`Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`

| Política | Diretriz de revisão | Registro relacionado |
|---|---|---|
| **Do not allow anonymous enumeration of SAM accounts** | Habilitar conforme o papel e os requisitos do servidor | `RestrictAnonymousSAM` |
| **Do not allow anonymous enumeration of SAM accounts and shares** | Avaliar aplicabilidade e habilitar quando apropriado | `RestrictAnonymous` |
| **Allow anonymous SID/Name translation** | Manter desabilitada, salvo necessidade justificada | Configuração de segurança correspondente |
| **Let Everyone permissions apply to anonymous users** | Manter desabilitada, salvo exceção formal | `EveryoneIncludesAnonymous` |
| **Restrict anonymous access to Named Pipes and Shares** | Manter habilitada e revisar exceções | `RestrictNullSessAccess` |
| **Restrict clients allowed to make remote calls to SAM** | Definir permissões restritivas após validar compatibilidade e função do servidor | `RestrictRemoteSam` (SDDL) |

As chaves `RestrictAnonymous`, `RestrictAnonymousSAM`, `EveryoneIncludesAnonymous` e `RestrictRemoteSam` estão relacionadas a configurações sob `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`. 

As configurações `RestrictNullSessAccess`, `NullSessionShares` e `NullSessionPipes` estão relacionadas a `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`.

Em controladores de domínio, revise também as permissões e a composição do grupo `Pre-Windows 2000 Compatible Access`. **Não altere indiscriminadamente políticas ou grupos em produção**: faça inventário de dependências, teste em homologação e valide a configuração efetiva após a mudança.

Antes de fechar, verifique aplicações legadas, integrações de inventário e serviços de impressão que possam depender de acesso anônimo a um recurso específico — a necessidade deve ser demonstrada por teste, não presumida. Quando uma exceção for indispensável, documente a aplicação, a origem, o recurso, o responsável e o prazo de revisão, em vez de ampliar permissões globais.

A política **Accounts: Limit local account use of blank passwords to console logon only** trata de contas locais com senha em branco. Ela **não é equivalente** ao controle de sessões com a identidade especial `ANONYMOUS LOGON`.

{{< leia-tambem "blog/86.gpo.anonymous.logon">}}

## 7. Boas práticas defensivas

- **Restrinja SMB por segmentação e firewall**, permitindo acesso apenas entre sistemas que necessitam do protocolo.
- **Habilite a auditoria necessária** nos controladores de domínio e valide quais eventos realmente são produzidos.
- **Evite senhas em descrições de contas** e outros campos legíveis do diretório.
- **Registre e revise exceções** de acesso anônimo a pipes e compartilhamentos.

## 8. Conclusão

O `ANONYMOUS LOGON` não representa, por si só, uma vulnerabilidade. É uma identidade especial do Windows que pode aparecer em conexões legítimas e cujo alcance depende das permissões efetivas do ambiente.

No GOAD, os testes demonstraram essa diferença: o `kingslanding` negou a enumeração anônima via SAMR, enquanto o `winterfell` retornou usuários, RIDs e descrições de contas. A consulta de tradução de SID pelo LSARPC, por sua vez, foi negada no teste apresentado. **A mesma identidade anônima não recebeu as mesmas autorizações para todas as operações.**

Para o defensor, a principal lição é distinguir **sessão estabelecida**, **acesso a interfaces RPC** e **enumeração efetivamente evidenciada**. Os eventos 4624, 5140 e 5145 são úteis para contextualizar conexões anônimas, mas não revelam, isoladamente, quais métodos SAMR foram executados.

Como peça da série, este episódio cumpre o papel de base: entender o anônimo, perfilar o que é normal e endurecer o que precisa. Detecção que se sustenta como alerta aparece nos episódios de enumeração autenticada e de coerção com relay, onde é possível evidência, não apenas volume.

## 9. Referências

- [Network access: Do not allow anonymous enumeration of SAM accounts and shares](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares) — Microsoft Learn: `RestrictAnonymous` e a enumeração anônima de contas e compartilhamentos.
- [Network access: Restrict clients allowed to make remote calls to SAM](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls) — Microsoft Learn: `RestrictRemoteSam`, SDDL e o modo de auditoria antes do bloqueio.
- [Entidades de segurança](https://learn.microsoft.com/pt-br/windows-server/identity/ad-ds/manage/understand-security-principals) — Microsoft Learn: definição de principal de segurança e sua relação com SIDs, tokens e ACLs.
- [Grupos de identidade especiais](https://learn.microsoft.com/pt-br/windows-server/identity/ad-ds/manage/understand-special-identities-groups) — Microsoft Learn: o ANONYMOUS LOGON como identidade especial (SID, objectClass, local no AD).
- [Identificadores de segurança](https://learn.microsoft.com/pt-br/windows-server/identity/ad-ds/manage/understand-security-identifiers) — Microsoft Learn: o que é um SID, o `S-1-5-7` e a distinção do acesso anônimo do IIS (IUSR).
- [Event 4624: An account was successfully logged on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) — Microsoft Learn: referência do 4624, tipos de logon e campos.
- [Event 5140: A network share object was accessed](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5140) — Microsoft Learn: acesso a compartilhamento, como `IPC$`.
- [Event 5145: A network share object was checked to see whether client can be granted desired access](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145) — Microsoft Learn: verificação de acesso a arquivos e named pipes (exige Detailed File Share).
- [Event 4661: A handle to an object was requested](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4661) — Microsoft Learn: solicitação de acesso a objetos, incluindo objetos SAM quando auditado.
- [Audit use of NTLMv1 on a domain controller](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1) — Microsoft Learn: origens benignas de logon anônimo e por que ignorar o "NTLM V1" nesses eventos.
- [GOAD — Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) — Orange Cyberdefense: laboratório de AD vulnerável usado na demonstração.

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}
