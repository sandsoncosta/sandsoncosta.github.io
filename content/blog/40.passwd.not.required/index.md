---
title: "Password Not Required: Um vetor de ataque silencioso e perigoso"
date: 2025-07-04T00:26:48-03:00
draft: false
description: "Exploração do sinalizador 'Password Not Required' no Active Directory. Como atacantes podem abusar desse sinalizador para definir senhas vazias e manter persistência."
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
authors:
 - sandson
#images:
---
## 1. Introdução

Recentemente, em um hunting em um cliente, me deparei com um cenário que é bastante interessante e que traz riscos significativos à segurança corporativa. A opção de permitir que um usuário possa ter a senha vazia mesmo que ele possua senha habilitada. Estou falando da opção **"Password Not Required"** presente no Active Directory.

Ao replicar o cenário em laboratório, explorei essa configuração que é negligenciada ou pouco conhecida por administradores. No cenário em específico, o cliente utiliza terceirizados para suporte, o que aumenta ainda mais o risco e utiliza um sistema automatizado para criação de usuários, o que também gera um risco, pois o mal uso do sistema pode causar esse tipo de vulnerabilidade.

No hunting em questão, não foram todos os usuários criados em um X período que estavam com essa sinalizador habilitada. Essa sinalizador pode parecer inofensiva, mas se bem explorada, pode causar um estrago.

## 2. Hipótese

Um atacante obtém acesso privilegiado em uma estação ou servidor (via credenciais vazadas ou escalação de privilégios). Com uma shell administrativa, ele decide criar ou manipular uma conta com um conjunto específico de sinalizadores no AD.

Esses sinalizadores são combinados numericamente e controlam diversos aspectos da conta.

Por exemplo:

- 66080 = 512 + 32 + 65536
  - 512 = NORMAL_ACCOUNT (0x0200)
  - 32 = PASSWD_NOTREQD (0x0020)
  - 65536 = DONT_EXPIRE_PASSWORD (0x10000)
  - 66080 = NORMAL_ACCOUNT|PASSWD_NOTREQD|DONT_EXPIRE_PASSWORD (0x10220)

- 544 = 512 + 32
  - 512 = NORMAL_ACCOUNT (0x0200)
  - 32 = PASSWD_NOTREQD (0x0020)
  - 544 = NORMAL_ACCOUNT|PASSWD_NOTREQD (0x0220)

Em ambos os casos, o sinalizador 32 (Password Not Required) está presente.

## 3. Cenários

### 3.1. Sobre o sinalizador 32

O sinalizador `32` indica que **nenhuma senha é exigida para o usuário**. Mas isso não significa necessariamente que a conta não tenha senha, mas sim que **é permitido o uso de senha vazia, desde que a política do domínio permita** ou **seja ultilizado outros métodos que contornem essa verificação**, que é o que veremos aqui mais a frente.

### 3.2. Identificando contas com o sinalizador 32 no AD

Você pode utilizar o seguinte comando abaixo para identificar usuários no AD que possuam esse sinalizador:

```powershell
Get-ADUser -Filter * -Properties userAccountControl |
Where-Object { ($_.userAccountControl -band 32) -eq 32 } |
Select-Object Name, SamAccountName, userAccountControl
```

---

Eu encontrei diversos sites nesse mesmo _modus operandi_:

<figure style="text-align: center;">
  <img src="image-5.png" alt="" style="display: block; background-color: white; margin-left: auto; margin-right: auto; max-width: 100%; height: 400px;">
  <figcaption>
    <i><strong>Figura 1.</strong> Identificação de outros sites com o mesmo padrão no FOFA.</i>
  </figcaption>
</figure>




{{< bs/alert warning >}}
{{< bs/alert-heading "Encontrou algum erro? Quer sugerir alguma mudança ou acrescentar algo?" >}}
Por favor, entre em contato comigo pelo meu <a href="https://www.linkedin.com/in/sandsoncosta">LinkedIn</a>.<br>Vou ficar muito contente em receber um feedback seu.
{{< /bs/alert >}}
