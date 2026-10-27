---
title: "Configurando a GPO para restringir o Anonymous Logon"
date: 2026-10-27T12:00:00-03:00
draft: false
description: "Passo a passo para aplicar via Group Policy as políticas que restringem o acesso anônimo no Windows: GPMC, equivalentes em PowerShell/registro, o cuidado com RestrictRemoteSam e como validar no laboratório."
noindex: false
featured: false
pinned: false
comments: true
series:
 - "Auditorias do Windows"
categories:
 - Hardening
tags:
 - GPO
 - Active Directory
 - Anonymous Logon
 - Hardening
images:
authors:
 - Sandson
---
## 1. Contexto

O **ANONYMOUS LOGON** é a identidade que o Windows atribui a uma conexão de rede feita sem credencial, identificada pelo SID `S-1-5-7`. As versões modernas do Windows já restringem parte do acesso anônimo por padrão, mas configurações legadas, exceções mal revisadas e controladores de domínio migrados de versões antigas podem manter aberta a enumeração anônima de contas, grupos e compartilhamentos. Isso serve de reconhecimento para quem ainda não tem credencial nenhuma: nomes de usuário, RIDs e políticas de senha saem de graça e alimentam ataques posteriores, como password spraying. Fechar esse acesso é um item básico de hardening de Active Directory.

Este artigo trata da parte prática: como aplicar, por Group Policy, as políticas que restringem o acesso anônimo, os equivalentes em PowerShell e registro para o laboratório, o cuidado com a única delas que pode quebrar algo legítimo, e como validar que a mudança pegou.

As políticas e seus valores:

| Política (Network access) | Valor | Registro |
|---|---|---|
| Do not allow anonymous enumeration of SAM accounts | Habilitado | `RestrictAnonymousSAM = 1` |
| Do not allow anonymous enumeration of SAM accounts and shares | Habilitado | `RestrictAnonymous = 1` |
| Allow anonymous SID/Name translation | Desabilitado | (política de segurança) |
| Let Everyone permissions apply to anonymous users | Desabilitado | `EveryoneIncludesAnonymous = 0` |
| Restrict anonymous access to Named Pipes and Shares | Habilitado | `RestrictNullSessAccess = 1` |
| Restrict clients allowed to make remote calls to SAM | Administradores | `RestrictRemoteSam` (SDDL) |

Cada uma dessas políticas governa um canal diferente — enumeração do SAM, tradução de SID/nome, acesso a named pipes e chamadas remotas ao SAM —, e não existe um controle único que resolva tudo de uma vez. Para os conceitos por trás disso (o que é o ANONYMOUS LOGON, como a enumeração acontece na prática e o que os logs nativos registram), há um artigo complementar.

{{< leia-tambem "blog/12.anonymous.logon">}}

## 2. Configurar via GPO (GPMC)

### 2.1 Criar e vincular a GPO

1. Abra o Group Policy Management (`gpmc.msc`).
2. Clique com o botão direito na OU que contém os computadores-alvo e escolha **Create a GPO in this domain, and Link it here**. Dê um nome descritivo, por exemplo `Hardening - Anonymous Access`.
3. Para políticas que afetam controladores de domínio, vincule a GPO à OU **Domain Controllers**. Para servidores membros e estações, vincule à OU correspondente. Evite vincular na raiz do domínio sem necessidade.
4. Clique com o botão direito na GPO recém-criada e escolha **Edit**.

### 2.2 Aplicar as opções de segurança

No editor, navegue até:

```
Computer Configuration
  > Policies
    > Windows Settings
      > Security Settings
        > Local Policies
          > Security Options
```

Para cada linha da tabela da seção 1, dê duplo clique na política correspondente (todas começam com **Network access:**), marque **Define this policy setting** e selecione o valor indicado. A política *Allow anonymous SID/Name translation* é definida aqui como Desabilitada; ela é uma opção de segurança, não uma chave de registro solta.

### 2.3 Controladores de domínio: Pre-Windows 2000 Compatible Access

Esta parte não é uma Opção de Segurança, e sim pertinência de grupo, então não entra na GPO acima. Em um DC, abra o Active Directory Users and Computers, vá ao contêiner **Builtin** e verifique o grupo **Pre-Windows 2000 Compatible Access**. Se `Anonymous Logon` (ou `Everyone`) constar como membro, remova, salvo se algum sistema legado comprovadamente depender disso. É esse grupo que faz a enumeração anônima voltar a funcionar em DCs mesmo com as políticas acima aplicadas.

### 2.4 Aplicar e propagar

A GPO é aplicada na próxima atualização de diretiva. Para forçar no alvo:

```powershell
gpupdate /force
```

Em domínio, aguarde a replicação entre DCs ou rode o `gpupdate` no computador-alvo. Nenhuma dessas políticas exige reinicialização.

## 3. Alternativa local (host único ou laboratório)

Para um único host, ou no lab onde não há domínio, use a Local Security Policy (`secpol.msc`), no mesmo caminho `Local Policies > Security Options`. As políticas e valores são idênticos, muda só o escopo, que passa a ser a máquina local.

## 4. Cuidado com o RestrictRemoteSam

Esta é a única política da lista com risco real de quebrar algo legítimo. Restringir as chamadas SAMR remotas a Administradores pode afetar aplicações que enumeram contas, como geração de catálogo de endereços no Exchange e algumas soluções de inventário.

A orientação da Microsoft é testar em modo auditoria antes de impor, observando os eventos relacionados para identificar quem seria bloqueado, e só então aplicar o modo de bloqueio. Em servidores membros e estações, o padrão a partir do Windows 10 1607 / Server 2016 já restringe a Administradores. Em DCs, normalmente não vem definido, então é lá que o ganho e o risco se concentram.

## 5. Validação

O teste é direto: o que antes enumerava, agora deve falhar. De um host na rede (no exemplo, o laboratório GOAD, contra o DC `kingslanding` em `192.168.56.10`), faça a enumeração anônima:

```bash
rpcclient -U "" -N 192.168.56.10 -c "enumdomusers"
nxc smb 192.168.56.10 -u '' -p '' --users
```

Com as políticas aplicadas, a chamada passa a retornar `NT_STATUS_ACCESS_DENIED` em vez da lista de contas. Esse antes/depois é a evidência de que a GPO surtiu efeito.

Para confirmar que a diretiva chegou ao host, independentemente do teste de enumeração:

```powershell
gpresult /r            # mostra as GPOs aplicadas
# ou abra rsop.msc para inspecionar as Security Options efetivas
```

## 6. Conclusão

Restringir o acesso anônimo é um passo básico no hardening de Active Directory. Ele tira de um atacante sem credencial uma via fácil de reconhecimento — nomes de conta, RIDs e política de senha — e, na maioria dos ambientes, não interfere na operação legítima. Como o controle está repartido em políticas independentes, a proteção só fica completa quando todas são revisadas em conjunto. Não há uma única chave que resolva.

A GPO é a forma de aplicar em escala, enquanto o `secpol.msc` e o registro atendem a hosts isolados e ao laboratório. A exceção que pede cuidado é o `RestrictRemoteSam`, que pode afetar aplicações legítimas e deve ser validado em auditoria antes de impor. Depois da mudança, confirme a diretiva efetiva no host e verifique que a enumeração anônima, antes bem-sucedida, passou a falhar.

## 7. Referências

- [Network access: Do not allow anonymous enumeration of SAM accounts and shares](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares) — Microsoft Learn: `RestrictAnonymous` e a enumeração anônima.
- [Network access: Restrict clients allowed to make remote calls to SAM](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls) — Microsoft Learn: `RestrictRemoteSam`, SDDL e modo de auditoria antes do bloqueio.
- [Network access: Allow anonymous SID/Name translation](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-allow-anonymous-sidname-translation) — Microsoft Learn: a política de tradução anônima de SID/nome.

{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}