---
# type: docs
title: "Auditoria de GPO"
date: 2024-08-06T23:40:31-03:00
featured: true
draft: false
comment: true
toc: true
reward: true
pinned: false
carousel: true
description: Identifique quando suas GPOs forem criadas, modificadas, restauradas, movidas ou deletadas.
series:
#  - 
categories:
 - Active Directory
tags:
 - Windows Server
 - AD
 - GPO
authors:
  - sandson
images:
#  - 
# menu:
#   main:
#     weight: 100
#     params:
#       icon:
#         vendor: bs
#         name: book
#         color: '#e24d0e'
---

## Criação da GPO

Criar uma nova GPO "Auditoria de GPO".

Clicar com o direito e clicar em Edit.

![1](1.png)

Seguir para o caminho: *Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > DS Access*.

Clicar 2 vezes em *Audit Directory Service Changes* e marcar somente *Success*.

![2](2.png)

Seguir para o caminho: *Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Object Access*.

Clicar 2 vezes em *Audit File System* e marcar somente *Success*.

![3](3.png)

Force a atualização das políticas de GPO.


## Configurando a auditoria de objetos groupPolicyContainer usando ADSI Edit

No menu iniciar pesquise por ADSI Edit e inicie como admin.

Com o botão direito, clique em *Connect to...*.

Clique em OK.

Expanda o Domain naming context.

Expanda o DC=domain.

Expanda o CN=System.

Clique com o botão direito em *CN=Policies* e selecione Properties.

Em *Security* clique em *Advanced*.

![4](4.png)

Na janela que abrir, clique em *Auditing*.

Depois clique em *Add*.

![5](5.png)

Na janela que abrir, clique em *Select a principal*.

Na janela que abrir, pesquise por *Everyone* e dê OK.

![6](6.png)

Em *Type* deixe *Success*.

Em *Applies to* deixe *This object and all descendant objects*.

![7](7.png)

Na lista logo abaixo, pesquise por *Create groupPolicyContainer objects* e *Delete groupPolicyContainer objects*, marque as duas opções e dê OK.

![8](8.png)

Pode dar OK em todas as janelas logo após isso.

## Configurando a auditoria da pasta SYSVOL


Navegue até *C:\\Windows\\SYSVOL\\domain*.

Abra as propriedades da pasta *Policies*.

Na janela que abrir, vá até *Security*, clique em *Advanced*.

Na janela que abrir, vá até *Auditing*. Se uma janela de bloqueio aparecer, clique em *Continue*.

Clique em *Add*.

Na janela que abrir, clique em *Select a principal*, depois pesquise por *Everyone* novamente e dê OK.

![9](9.png)

Em *Advanced Permissions*, clique em *Show advanced permissions* para listar todas as permissões avançadas. Logo após listar todas as opções, clique em *Full control* e dê OK.

![10](10.png)

Pode dar OK em todas as janelas logo após isso.

Pronto!

## Lista dos EventID gerados

| Event ID |                     Descrição                     |
|:--------:|:-------------------------------------------------:|
|   5136   | Um objeto de serviço de diretório foi modificado. |
|   5137   |   Um objeto de serviço de diretório foi criado.   |
|   5138   | Um objeto de serviço de diretório foi recuperado. |
|   5139   |   Um objeto de serviço de diretório foi movido.   |
|   5141   |  Um objeto de serviço de diretório foi deletado.  |

![11](11.png)

Para ver o nome da GPO via PowerShell:
```powershell
$gpoGuid = "4289D558-1E11-417D-95DE-19A1FCDD6AA1"
$gpo = Get-GPO -Guid $gpoGuid
$gpo.DisplayName

OUTPUT
-----------
Auditoria de GPO
```
